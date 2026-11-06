#!/usr/bin/env python3
"""glitch.py -- varre o injetor de falha de clock (fase 6).

So funciona com o bitstream de ataque na placa (rtl/soc/glitch_inj.v). Para
cada atraso, arma o injetor e manda o comando alvo; depois classifica:

  ok        respondeu certo
  detectou  o dispositivo percebeu a falha e recusou
  ERRADO    respondeu sucesso com resultado errado: a falha passou
  ERRADO-crc  idem, com CRC errado: o host recusa, mas quem ataca le os dados
  crc-so    so o CRC saiu errado, com os dados certos
  mudo      nao respondeu
  lixo      respondeu um frame invalido

Mudo e estado perdido se recuperam reconfigurando da flash pelo JTAG.
"""
import argparse
import subprocess
import sys
import time
import zlib

from hsmtool import (CMD_ENCRYPT, CMD_MAC_GENERATE, CMD_MAC_VERIFY, CMD_PING,
                     CMD_SELFTEST, FrameTimeout,
                     HsmClient, ProtocolError, build_request, default_port)

CMD_ARMA = 0xF7       # o firmware recusa; quem le e o injetor
ST_UNKNOWN = 0x10
ST_MAC_INVALID = 0x25

IV = bytes(16)
DADOS = bytes(range(256))


def arma(c, atraso, largura, alvo_bytes):
    corpo = (b"GL" + atraso.to_bytes(3, "big") + bytes([largura])
             + alvo_bytes.to_bytes(2, "big"))
    st, _ = c.transact(CMD_ARMA, corpo)
    if st != ST_UNKNOWN:
        raise ProtocolError("armar: status 0x%02x" % st)


def selftest(c):
    """Devolve (classe, detalhe) de um SELFTEST."""
    st, dado = c.transact(CMD_SELFTEST)
    if st == 0 and dado[:1] == b"\x00":
        return "ok", ""
    return "detectou", "st=%02x mask=%s" % (st, dado[:1].hex())


def alvo_selftest(_c, _handle):
    return selftest, len(build_request(CMD_SELFTEST))


def alvo_encrypt(c, handle):
    """A referencia vem do proprio dispositivo, sem pulso armado."""
    pedido = bytes([handle]) + IV + DADOS
    st, certo = c.transact(CMD_ENCRYPT, pedido)
    if st != 0:
        raise SystemExit("ENCRYPT de referencia: status 0x%02x" % st)

    def tenta(cc):
        # Le o frame cru: o CRC e do transporte, nao controle de seguranca, e
        # quem ataca le os dados de um frame com CRC errado do mesmo jeito.
        cc.ser.write(build_request(CMD_ENCRYPT, pedido))
        cabeca = cc._read_exact(2)
        n = int.from_bytes(cabeca, "big")
        if n == 0 or n > len(certo) + 1:
            cc.resync()
            return "lixo", "LEN=%d" % n
        resto = cc._read_exact(n + 4)
        st, dado = resto[0], resto[1:n]
        crc_ok = zlib.crc32(cabeca + resto[:n]) == int.from_bytes(resto[n:], "big")
        if st != 0:   # recusa: frame so com o status, mais curto que o certo
            return "detectou", "st=%02x" % st
        if n != len(certo) + 1:
            return "lixo", "LEN=%d st=00" % n
        if dado == certo:
            return ("ok", "") if crc_ok else ("crc-so", "dados certos")
        erros = sum(1 for a, b in zip(dado, certo) if a != b)
        classe = "ERRADO" if crc_ok else "ERRADO-crc"
        return classe, "%d bytes diferentes: %s" % (erros, dado.hex())

    return tenta, len(build_request(CMD_ENCRYPT, pedido))


def alvo_mac_verify(c, handle):
    """Tag errada de proposito: o sucesso e a recusa."""
    st, tag = c.transact(CMD_MAC_GENERATE, bytes([handle]) + DADOS)
    if st != 0:
        raise SystemExit("MAC de referencia: status 0x%02x" % st)
    pedido = bytes([handle]) + bytes([tag[0] ^ 1]) + tag[1:] + DADOS

    def tenta(cc):
        st, _ = cc.transact(CMD_MAC_VERIFY, pedido)
        if st == ST_MAC_INVALID:
            return "ok", ""
        if st == 0:
            return "ERRADO", "tag falsa aceita"
        return "detectou", "st=%02x" % st

    return tenta, len(build_request(CMD_MAC_VERIFY, pedido))


ALVOS = {"selftest": alvo_selftest, "encrypt": alvo_encrypt,
         "mac-verify": alvo_mac_verify}


def vivo(c):
    """Responde a PING sem estar em TAMPERED?"""
    try:
        return c.transact(CMD_PING)[0] == 0
    except ProtocolError:
        c.resync()
        return False


def recupera(cabo):
    subprocess.run(["openFPGALoader", "-c", cabo, "-r"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=30, check=False)
    time.sleep(1.5)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--alvo", choices=ALVOS, default="selftest")
    ap.add_argument("--handle", type=int, default=1)
    ap.add_argument("--de", type=int, default=0, help="atraso inicial, ciclos")
    ap.add_argument("--ate", type=int, default=1000000)
    ap.add_argument("--passo", type=int, default=50000)
    ap.add_argument("--largura", type=int, default=40)
    ap.add_argument("--repete", type=int, default=1)
    ap.add_argument("--cabo", default="digilent_hs2")
    ap.add_argument("-o", "--saida", default="glitch.csv")
    a = ap.parse_args()

    porta = default_port()
    conta = {}
    c = HsmClient(porta, timeout=1.0)
    funcao, n_bytes = ALVOS[a.alvo](c, a.handle)
    with open(a.saida, "w") as f:
        f.write("atraso,largura,classe,detalhe\n")
        for atraso in range(a.de, a.ate + 1, a.passo):
            for _ in range(a.repete):
                try:
                    arma(c, atraso, a.largura, n_bytes)
                    classe, detalhe = funcao(c)
                except FrameTimeout:
                    classe, detalhe = "mudo", ""
                except ProtocolError as e:
                    classe, detalhe = "lixo", str(e)[:40]
                conta[classe] = conta.get(classe, 0) + 1
                f.write("%d,%d,%s,%s\n" % (atraso, a.largura, classe, detalhe))
                f.flush()
                print("%8d %-9s %s" % (atraso, classe, detalhe), flush=True)
                if classe != "ok" or not vivo(c):
                    c.close()
                    recupera(a.cabo)
                    c = HsmClient(porta, timeout=1.0)
    c.close()
    print("resumo:", conta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
