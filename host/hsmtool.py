#!/usr/bin/env python3
"""CLI do host para o HSM educacional (Artix-7 / NEORV32).

FRONTEIRA: tudo aqui esta FORA. Este programa nunca ve chave em claro --
so key blocks wrapped, KCVs, criptogramas, handles e log. Se algum comando
futuro fizer material de chave aparecer neste arquivo, o comando esta errado,
nao o script.

Protocolo (PLANO.md secao 2, espelhando fw/include/cmd.h):

    pedido    LEN(2) | CMD(1)    | PAYLOAD | CRC32(4)
    resposta  LEN(2) | STATUS(1) | PAYLOAD | CRC32(4)

Tudo big-endian. LEN cobre CMD/STATUS + PAYLOAD, e nao se inclui nem inclui
o CRC. O CRC32 cobre LEN + CMD/STATUS + PAYLOAD -- todos os bytes menos os
quatro dele proprio -- com o polinomio IEEE 802.3 refletido, que e
exatamente o zlib.crc32.

Uso:
    hsmtool.py selftest              # sem placa: confere o codec
    hsmtool.py ping
    hsmtool.py version
    hsmtool.py bench -n 10000        # criterio de aceitacao da fase 1
    hsmtool.py raw --op 0x01
"""

import argparse
import glob
import sys
import time
import zlib

try:
    import serial
except ImportError:
    serial = None


# --------------------------------------------------------------------
# Constantes -- espelham fw/include/cmd.h e fw/include/hsm_status.h.
# Divergir daqui e a forma mais rapida de gastar uma tarde.
# --------------------------------------------------------------------

BAUD_RATE = 115200
TIMEOUT_S = 2.0                 # PLANO.md secao 2

MAX_PAYLOAD = 512
MIN_LEN = 1
MAX_LEN = MAX_PAYLOAD + 1

CMD_PING = 0x01
CMD_GET_VERSION = 0x02
CMD_GET_DNA = 0x03

STATUS_NAMES = {
    0x00: "OK",
    0x01: "BAD_CRC",
    0x02: "BAD_LEN",
    0x03: "TIMEOUT",
    0x10: "UNKNOWN_CMD",
    0x11: "BAD_PARAM",
    0x12: "NOT_IMPLEMENTED",
    0x20: "WRONG_STATE",
    0x21: "NOT_AUTHORIZED",
    0x22: "NOT_EXPORTABLE",
    0x30: "SELFTEST_FAIL",
    0x31: "TAMPERED",
    0xFF: "INTERNAL_ERROR",
}

STATE_NAMES = {0: "UNINITIALIZED", 1: "AUTHORIZED", 2: "OPERATIONAL", 3: "TAMPERED"}

# O firmware resincroniza depois de CMD_INTERBYTE_TIMEOUT_MS sem bytes.
# Esperar um pouco mais que isso e a forma de voltar ao inicio de frame
# depois de um erro, sem adivinhar onde o frame anterior terminou.
FW_INTERBYTE_TIMEOUT_S = 0.250


class ProtocolError(Exception):
    pass


class CrcError(ProtocolError):
    pass


class FrameTimeout(ProtocolError):
    pass


class HsmError(Exception):
    """O dispositivo respondeu um frame valido com STATUS != OK."""

    def __init__(self, status, payload=b""):
        self.status = status
        self.payload = payload
        name = STATUS_NAMES.get(status, "?")
        super().__init__("STATUS_%s (0x%02X)" % (name, status))


# --------------------------------------------------------------------
# Codec -- sem dependencia de porta serial, para poder ser testado sozinho
# --------------------------------------------------------------------


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def build_request(opcode: int, payload: bytes = b"") -> bytes:
    """Monta um frame de pedido completo."""
    if not 0 <= opcode <= 0xFF:
        raise ValueError("opcode fora de faixa: %r" % opcode)
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload de %d bytes excede o maximo de %d"
                         % (len(payload), MAX_PAYLOAD))

    body = bytes([opcode]) + payload
    head = len(body).to_bytes(2, "big") + body
    return head + crc32(head).to_bytes(4, "big")


def parse_response(frame: bytes):
    """Valida um frame de resposta completo. Devolve (status, payload)."""
    if len(frame) < 2 + MIN_LEN + 4:
        raise ProtocolError("frame curto demais: %d bytes" % len(frame))

    length = int.from_bytes(frame[0:2], "big")
    if not MIN_LEN <= length <= MAX_LEN:
        raise ProtocolError("LEN invalido: %d" % length)
    if len(frame) != 2 + length + 4:
        raise ProtocolError("frame tem %d bytes, LEN=%d pedia %d"
                            % (len(frame), length, 2 + length + 4))

    calc = crc32(frame[:2 + length])
    got = int.from_bytes(frame[2 + length:], "big")
    if calc != got:
        raise CrcError("CRC32 calculado %08X, recebido %08X" % (calc, got))

    return frame[2], frame[3:2 + length]


# --------------------------------------------------------------------
# Transporte
# --------------------------------------------------------------------


# O canal do HSM sai pelo CP2102 do core board (pinos T15/T14).
CP210X_VID = 0x10C4
CP210X_PID = 0xEA60

# O adaptador JTAG "DLC9LP" e um FT232H que tambem cria uma /dev/ttyUSB*.
# Ela NAO e a UART do HSM -- e o cabo de gravacao.
FTDI_JTAG_VID = 0x0403
FTDI_JTAG_PID = 0x6014


def default_port():
    """Escolhe a porta do HSM por VID:PID, nao por ordem alfabetica.

    Com o cabo de gravacao ligado existem duas /dev/ttyUSB*, e a primeira
    costuma ser o adaptador JTAG -- escolher pelo nome acerta o cabo errado
    e o sintoma e um timeout sem explicacao. Descoberto na bancada.
    """
    try:
        from serial.tools import list_ports
    except ImportError:
        candidates = sorted(glob.glob("/dev/ttyUSB*")) + sorted(glob.glob("/dev/ttyACM*"))
        return candidates[0] if candidates else None

    ports = list(list_ports.comports())

    for p in ports:
        if (p.vid, p.pid) == (CP210X_VID, CP210X_PID):
            return p.device

    # Sobrou alguma que nao seja o gravador?
    others = [p for p in ports
              if (p.vid, p.pid) != (FTDI_JTAG_VID, FTDI_JTAG_PID)]
    if others:
        return sorted(others, key=lambda p: p.device)[0].device

    return None


class HsmClient:
    def __init__(self, port, baud=BAUD_RATE, timeout=TIMEOUT_S):
        if serial is None:
            raise RuntimeError(
                "pyserial nao instalado: sudo apt install python3-serial")
        self.ser = serial.Serial(port, baud, timeout=timeout)
        self.timeout = timeout

        # O dispositivo e mudo ate ser perguntado -- nao ha banner para
        # descartar. Ainda assim, limpar uma vez na abertura remove lixo de
        # uma sessao anterior interrompida no meio de um frame.
        time.sleep(FW_INTERBYTE_TIMEOUT_S)
        self.ser.reset_input_buffer()

    def close(self):
        self.ser.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.ser.read(n - len(buf))
            if not chunk:
                raise FrameTimeout(
                    "sem resposta apos %.1f s (%d de %d bytes)"
                    % (self.timeout, len(buf), n))
            buf += chunk
        return buf

    def resync(self):
        """Volta ao inicio de frame depois de um erro.

        Espera mais que o timeout de inter-byte do firmware, para que ele
        tambem abandone qualquer frame parcial, e so entao descarta o que
        estiver na entrada.
        """
        time.sleep(FW_INTERBYTE_TIMEOUT_S * 1.5)
        self.ser.reset_input_buffer()

    def transact(self, opcode, payload=b""):
        """Envia um comando e devolve (status, payload) do frame de resposta.

        Nao limpa a entrada antes de enviar, de proposito: byte inesperado
        na linha e sintoma de dessincronizacao, e engolir isso em silencio
        transformaria o teste de 10.000 pings numa medida sem valor.
        """
        self.ser.write(build_request(opcode, payload))

        head = self._read_exact(2)
        length = int.from_bytes(head, "big")
        if not MIN_LEN <= length <= MAX_LEN:
            self.resync()
            raise ProtocolError("LEN invalido na resposta: %d" % length)

        rest = self._read_exact(length + 4)
        return parse_response(head + rest)

    def command(self, opcode, payload=b""):
        """Como transact, mas levanta HsmError se o status nao for OK."""
        status, data = self.transact(opcode, payload)
        if status != 0x00:
            raise HsmError(status, data)
        return data


# --------------------------------------------------------------------
# Selftest do codec -- roda sem placa
# --------------------------------------------------------------------

# Bytes conferidos contra TRES implementacoes independentes: o firmware em C,
# o testbench em Verilog (tb_uart_frame) e o zlib. Sao vetores fixos de
# proposito -- se fossem gerados por este mesmo modulo, o teste so provaria
# que o codigo concorda consigo mesmo.
VECTORS = [
    ("pedido PING",        build_request, (CMD_PING,),        "000101915dd8c5"),
    ("pedido GET_VERSION", build_request, (CMD_GET_VERSION,), "0001020854897f"),
]

RESP_PONG = bytes.fromhex("00050050" + "4f4e47" + "fb283d2a")


def selftest():
    fails = 0

    for name, fn, args, expect in VECTORS:
        got = fn(*args).hex()
        if got != expect:
            print("FAIL  %-20s esperado %s, obtido %s" % (name, expect, got))
            fails += 1
        else:
            print("ok    %-20s %s" % (name, got))

    # resposta valida
    try:
        status, payload = parse_response(RESP_PONG)
        if status != 0x00 or payload != b"PONG":
            print("FAIL  resposta PONG      status=0x%02X payload=%r" % (status, payload))
            fails += 1
        else:
            print("ok    resposta PONG      status=OK payload=b'PONG'")
    except ProtocolError as e:
        print("FAIL  resposta PONG      %s" % e)
        fails += 1

    # CRC corrompido tem de ser recusado
    bad = bytearray(RESP_PONG)
    bad[-1] ^= 0x01
    try:
        parse_response(bytes(bad))
        print("FAIL  CRC corrompido     aceito, deveria ser recusado")
        fails += 1
    except CrcError:
        print("ok    CRC corrompido     recusado")

    # um bit trocado no payload tambem
    bad = bytearray(RESP_PONG)
    bad[3] ^= 0x01
    try:
        parse_response(bytes(bad))
        print("FAIL  payload alterado   aceito, deveria ser recusado")
        fails += 1
    except CrcError:
        print("ok    payload alterado   recusado")

    # limites de LEN
    for length in (0, MAX_LEN + 1):
        head = length.to_bytes(2, "big") + b"\x00"
        frame = head + crc32(head).to_bytes(4, "big")
        try:
            parse_response(frame)
            print("FAIL  LEN=%d            aceito, deveria ser recusado" % length)
            fails += 1
        except ProtocolError:
            print("ok    LEN=%-14d recusado" % length)

    # payload grande demais no pedido
    try:
        build_request(CMD_PING, b"\x00" * (MAX_PAYLOAD + 1))
        print("FAIL  payload > maximo   aceito, deveria ser recusado")
        fails += 1
    except ValueError:
        print("ok    payload > maximo   recusado")

    print()
    if fails:
        print("selftest: %d falha(s)" % fails)
    else:
        print("selftest: OK")
    return 1 if fails else 0


# --------------------------------------------------------------------
# Comandos da CLI
# --------------------------------------------------------------------


def cmd_ping(client, args):
    t0 = time.perf_counter()
    payload = client.command(CMD_PING)
    dt = (time.perf_counter() - t0) * 1000.0

    if payload != b"PONG":
        print("resposta inesperada: %r" % payload)
        return 1
    print("PONG  (%.2f ms)" % dt)
    return 0


def cmd_version(client, args):
    p = client.command(CMD_GET_VERSION)
    if len(p) != 4:
        print("payload inesperado: %r" % p)
        return 1
    major, minor, patch, state = p
    print("firmware : v%d.%d.%d" % (major, minor, patch))
    print("estado   : %s (%d)" % (STATE_NAMES.get(state, "?"), state))
    return 0


def cmd_dna(client, args):
    """Identidade de fabrica do die: 57 bits, big-endian em 8 bytes.

    NAO E SEGREDO. Qualquer um com um cabo JTAG le o mesmo valor, e ele nao
    muda nunca. Serve para identificar a placa em log de auditoria e em
    inventario. Derivar chave dele e um erro classico -- o valor e publico e
    constante, que sao exatamente as duas propriedades que uma chave nao
    pode ter.
    """
    p = client.command(CMD_GET_DNA)
    if len(p) != 8:
        print("payload inesperado: %r" % p)
        return 1

    v = int.from_bytes(p, "big")
    if v >> 57:
        print("DNA fora de 57 bits: %s" % p.hex())
        return 1

    print("DNA: %015X  (57 bits)" % v)
    return 0


def cmd_raw(client, args):
    payload = bytes.fromhex(args.payload) if args.payload else b""
    status, data = client.transact(args.op, payload)
    print("status : 0x%02X %s" % (status, STATUS_NAMES.get(status, "?")))
    print("payload: %s" % (data.hex() if data else "(vazio)"))
    return 0


def cmd_bench(client, args):
    """Criterio de aceitacao da fase 1 (PLANO.md secao 2):
    10.000 iteracoes sem erro de CRC, cada uma em menos de 50 ms."""
    n = args.count
    limit_ms = args.limit
    times = []
    errors = {}

    print("%d pings, limite de %.0f ms cada..." % (n, limit_ms))
    t_start = time.perf_counter()

    for i in range(n):
        t0 = time.perf_counter()
        try:
            payload = client.command(CMD_PING)
            dt = (time.perf_counter() - t0) * 1000.0
            if payload != b"PONG":
                errors["payload errado"] = errors.get("payload errado", 0) + 1
                continue
            times.append(dt)
        except (ProtocolError, HsmError) as e:
            kind = type(e).__name__
            errors[kind] = errors.get(kind, 0) + 1
            try:
                client.resync()
            except Exception:
                pass

        if (i + 1) % 1000 == 0:
            print("  %d/%d" % (i + 1, n), flush=True)

    total = time.perf_counter() - t_start

    print()
    print("iteracoes  : %d em %.1f s (%.0f/s)" % (n, total, n / total if total else 0))
    print("erros      : %d %s" % (sum(errors.values()), errors if errors else ""))

    if times:
        times.sort()
        print("latencia   : min %.2f  mediana %.2f  p99 %.2f  max %.2f ms"
              % (times[0], times[len(times) // 2],
                 times[int(len(times) * 0.99)], times[-1]))

    over = [t for t in times if t > limit_ms]
    ok = (not errors) and (not over) and len(times) == n

    if over:
        print("ACIMA DO LIMITE: %d iteracoes passaram de %.0f ms" % (len(over), limit_ms))
    if errors:
        print("FALHOU: houve erro de protocolo")
    print()
    print("criterio de aceitacao: %s" % ("OK" if ok else "FALHOU"))
    return 0 if ok else 1


# --------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(description="CLI do HSM educacional")
    ap.add_argument("-p", "--port", default=None,
                    help="porta serial (padrao: primeira /dev/ttyUSB*)")
    ap.add_argument("-b", "--baud", type=int, default=BAUD_RATE)
    ap.add_argument("-t", "--timeout", type=float, default=TIMEOUT_S)

    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest", help="confere o codec sem precisar da placa")
    sub.add_parser("ping")
    sub.add_parser("version")
    sub.add_parser("dna")

    p_raw = sub.add_parser("raw", help="envia um opcode arbitrario")
    p_raw.add_argument("--op", type=lambda s: int(s, 0), required=True)
    p_raw.add_argument("--payload", default="", help="payload em hex")

    p_bench = sub.add_parser("bench", help="teste de aceitacao: N pings")
    p_bench.add_argument("-n", "--count", type=int, default=10000)
    p_bench.add_argument("--limit", type=float, default=50.0,
                         help="limite por iteracao em ms (padrao 50)")

    args = ap.parse_args(argv)

    if args.cmd == "selftest":
        return selftest()

    port = args.port or default_port()
    if port is None:
        print("nenhuma porta serial encontrada; use --port", file=sys.stderr)
        return 2

    handlers = {
        "ping": cmd_ping,
        "version": cmd_version,
        "dna": cmd_dna,
        "raw": cmd_raw,
        "bench": cmd_bench,
    }

    try:
        with HsmClient(port, args.baud, args.timeout) as client:
            return handlers[args.cmd](client, args)
    except HsmError as e:
        print("dispositivo recusou: %s" % e, file=sys.stderr)
        return 1
    except ProtocolError as e:
        print("erro de protocolo: %s" % e, file=sys.stderr)
        return 1
    except OSError as e:
        print("erro de porta serial: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
