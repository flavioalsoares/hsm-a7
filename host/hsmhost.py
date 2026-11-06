#!/usr/bin/env python3
"""hsmhost.py -- cliente da porta HOST: command set ASCII (fase 5).

O hsmtool.py fala o protocolo binario, que desde a fase 5 e o CONSOLE:
cerimonia, estado, diagnostico, log. Este aqui fala a porta HOST, que e a
que um sistema de pagamento usaria: mensagens ASCII sem sessao, em que a
chave de trabalho viaja DENTRO do comando como key block sob a LMK.
Formato, comandos e erros: doc/fase5-notas.md.

O host guarda os key blocks. Este script nao tem banco de dados: os blocos
entram e saem pela linha de comando, e quem quiser guardar redireciona.

Uso:
    hsmhost.py diag                         # D0: estado, KCV da LMK, versao
    hsmhost.py gen [--uso D0 --modo B --exp E]
    hsmhost.py check BLOCO                  # K2: cabecalho e KCV
    hsmhost.py export KEK BLOCO             # K4: sob a LMK -> sob a KEK
    hsmhost.py import KEK BLOCO             # K6: sob a KEK -> sob a LMK
    hsmhost.py encrypt BLOCO IV DADOS       # C0, hex
    hsmhost.py decrypt BLOCO IV DADOS       # C2, hex
    hsmhost.py mac BLOCO DADOS              # M0
    hsmhost.py mac-verify BLOCO MAC DADOS   # M2: o veredito e o codigo
    hsmhost.py confere --lmk HEX [-n N]     # o Python conferindo o C
    hsmhost.py selftest                     # codec, sem placa

Transporte: pela ponte (--tcp HOST:PORTA, padrao 127.0.0.1:1500, ver
hsm_ponte.py) ou direto na serial (--serial [--porta PORTA]).
"""

import argparse
import os
import socket
import struct
import sys

CAB_PADRAO = b"0000"
ASCII_DADOS_MAX = 160

ERROS = {
    0: "sem erro",
    1: "verificacao falhou",
    10: "key block invalido",
    11: "o modo do bloco nao permite",
    12: "a chave nao e exportavel",
    13: "o bloco de protecao nao e uma KEK (K0)",
    15: "dados invalidos",
    16: "parametro invalido",
    20: "estado nao permite",
    21: "comando desconhecido",
    22: "mensagem malformada",
    27: "falha no log de auditoria",
    90: "erro interno",
    91: "erro grave: dupla execucao discordou",
}


class HostErro(Exception):
    def __init__(self, codigo, comando):
        self.codigo = codigo
        super().__init__("%s: erro %02d (%s)"
                         % (comando, codigo, ERROS.get(codigo, "?")))


# --------------------------------------------------------------------
# Codec -- sem transporte, testavel sozinho
# --------------------------------------------------------------------
def monta(cabecalho: bytes, comando: str, campos: bytes = b"") -> bytes:
    if len(cabecalho) != 4:
        raise ValueError("cabecalho tem 4 caracteres")
    if not (0x30 <= cabecalho[0] <= 0x7E):
        # O primeiro byte separa os protocolos na UART: fora desta faixa o
        # dispositivo leria um frame binario. Ver doc/fase5-notas.md.
        raise ValueError("cabecalho comeca com caractere de '0' a '~'")
    return cabecalho + comando.encode("ascii") + campos


def resposta_esperada(comando: str) -> str:
    return comando[0] + chr(ord(comando[1]) + 1)


def analisa(resp: bytes, cabecalho: bytes, comando: str):
    """Devolve (erro, campos). Confere cabecalho e codigo de resposta."""
    if len(resp) < 8:
        raise ValueError("resposta curta: %r" % resp)
    if resp[:4] != cabecalho:
        raise ValueError("cabecalho trocado: %r" % resp[:4])
    if resp[4:6].decode("ascii", "replace") != resposta_esperada(comando):
        raise ValueError("resposta %r para o comando %s"
                         % (resp[4:6], comando))
    return int(resp[6:8]), resp[8:]


def dados(b: bytes) -> bytes:
    return b"%04d" % len(b) + b.hex().upper().encode()


def le_dados(campos: bytes):
    n = int(campos[:4])
    return bytes.fromhex(campos[4:4 + 2 * n].decode()), campos[4 + 2 * n:]


# --------------------------------------------------------------------
# Transporte: LEN(2) + mensagem, igual por TCP e pela UART
# --------------------------------------------------------------------
class Tcp:
    def __init__(self, destino, timeout=5.0):
        host, porta = destino.rsplit(":", 1)
        self.s = socket.create_connection((host, int(porta)), timeout=timeout)

    def _le(self, n):
        buf = b""
        while len(buf) < n:
            c = self.s.recv(n - len(buf))
            if not c:
                raise ConnectionError("a ponte fechou a conexao")
            buf += c
        return buf

    def troca(self, msg: bytes) -> bytes:
        self.s.sendall(struct.pack(">H", len(msg)) + msg)
        n = struct.unpack(">H", self._le(2))[0]
        return self._le(n)

    def close(self):
        self.s.close()


class Serial:
    def __init__(self, porta=None, timeout=2.0):
        import serial
        from hsmtool import default_port
        porta = porta or default_port()
        if porta is None:
            raise RuntimeError("nenhuma porta serial encontrada")
        self.ser = serial.Serial(porta, 115200, timeout=timeout)
        self.ser.reset_input_buffer()

    def _le(self, n):
        buf = self.ser.read(n)
        if len(buf) != n:
            raise TimeoutError("resposta incompleta (%d de %d bytes)"
                               % (len(buf), n))
        return buf

    def troca(self, msg: bytes) -> bytes:
        self.ser.write(struct.pack(">H", len(msg)) + msg)
        n = struct.unpack(">H", self._le(2))[0]
        return self._le(n)

    def close(self):
        self.ser.close()


class Host:
    def __init__(self, transporte, cabecalho=CAB_PADRAO):
        self.t = transporte
        self.cab = cabecalho

    def pede(self, comando, campos=b"", aceita=(0,)):
        resp = self.t.troca(monta(self.cab, comando, campos))
        erro, resto = analisa(resp, self.cab, comando)
        if erro not in aceita:
            raise HostErro(erro, comando)
        return erro, resto

    # -- os comandos --------------------------------------------------
    def diag(self):
        _, c = self.pede("D0")
        return {"estado": int(c[0:1]), "kcv_lmk": c[1:7].decode(),
                "versao": "%d.%d.%d" % (int(c[7:9]), int(c[9:11]),
                                        int(c[11:13]))}

    def gen(self, uso="D0", modo="B", exp="E"):
        _, c = self.pede("K0", (uso + modo + exp).encode())
        n = int(c[1:5])
        return c[:n].decode(), c[n:n + 6].decode()

    def check(self, bloco):
        _, c = self.pede("K2", bloco.encode())
        return {"uso": c[0:2].decode(), "algoritmo": c[2:3].decode(),
                "modo": c[3:4].decode(), "exportabilidade": c[4:5].decode(),
                "kcv": c[5:11].decode()}

    def _rebloco(self, comando, kek, bloco):
        _, c = self.pede(comando, kek.encode() + bloco.encode())
        n = int(c[1:5])
        return c[:n].decode(), c[n:n + 6].decode()

    def exporta(self, kek, bloco):
        """K4: bloco sob a LMK -> o mesmo sob a KEK, para outra instituicao."""
        return self._rebloco("K4", kek, bloco)

    def importa(self, kek, bloco):
        """K6: bloco recebido sob a KEK -> sob a LMK, para guardar aqui."""
        return self._rebloco("K6", kek, bloco)

    def cripto(self, bloco, iv, d, cifrar):
        _, c = self.pede("C0" if cifrar else "C2",
                         bloco.encode() + iv.hex().upper().encode() + dados(d))
        return le_dados(c)[0]

    def mac(self, bloco, d):
        _, c = self.pede("M0", bloco.encode() + dados(d))
        return bytes.fromhex(c[:32].decode())

    def mac_verifica(self, bloco, tag, d):
        erro, _ = self.pede("M2", bloco.encode() + tag.hex().upper().encode()
                            + dados(d), aceita=(0, 1))
        return erro == 0


# --------------------------------------------------------------------
# Selftest do codec (sem placa)
# --------------------------------------------------------------------
def selftest():
    m = monta(b"AB12", "C0", b"xyz")
    assert m == b"AB12C0xyz"
    assert resposta_esperada("K0") == "K1"
    assert resposta_esperada("M2") == "M3"
    assert analisa(b"AB12K100resto", b"AB12", "K0") == (0, b"resto")
    assert analisa(b"AB12M301", b"AB12", "M2") == (1, b"")
    for ruim, motivo in ((b"AB12K1", "curta"), (b"XX12K100", "cabecalho"),
                         (b"AB12K300", "codigo")):
        try:
            analisa(ruim, b"AB12", "K0")
        except ValueError:
            pass
        else:
            raise AssertionError("resposta %s aceita" % motivo)
    try:
        monta(b"\x01AAA", "D0")
    except ValueError:
        pass
    else:
        raise AssertionError("cabecalho que seria lido como binario aceito")
    assert dados(b"\x01\xab") == b"0002" + b"01AB"
    assert le_dados(b"000201ABresto") == (b"\x01\xab", b"resto")
    print("selftest: OK")
    return 0


# --------------------------------------------------------------------
# confere: o Python conferindo o C pela porta host
# --------------------------------------------------------------------
def confere(h, lmk, n):
    """Gera chaves pela porta host e confere tudo com implementacao
    independente: o tr31.py abre o bloco com a LMK, e o AES e o CMAC da
    biblioteca `cryptography` refazem o que o dispositivo fez.

    ⚠ PRECISA DA LMK -- o brinquedo aparecendo, como no keycycle do
    console. Um host de verdade nunca tem a chave mestra."""
    import tr31
    from hsmtool import _kcv_local

    d = h.diag()
    if d["kcv_lmk"] != _kcv_local(lmk).hex().upper():
        print("KCV da LMK nao confere: dispositivo %s, informada %s"
              % (d["kcv_lmk"], _kcv_local(lmk).hex().upper()))
        return 1

    for volta in range(n):
        bloco, kcv = h.gen("D0", "B", "E")
        chave, cab = tr31.desembrulha(lmk, bloco)
        assert _kcv_local(chave).hex().upper() == kcv, "KCV do K0"
        iv, texto = os.urandom(16), os.urandom(16 * (1 + volta % 10))
        cif = h.cripto(bloco, iv, texto, True)
        assert cif == tr31._cbc(chave, iv, texto, True), "C0"
        assert h.cripto(bloco, iv, cif, False) == texto, "C2"

        bloco_m, _ = h.gen("M0", "C", "N")
        chave_m, _ = tr31.desembrulha(lmk, bloco_m)
        msg = os.urandom(volta % (ASCII_DADOS_MAX + 1))
        tag = h.mac(bloco_m, msg)
        assert tag == tr31.cmac_aes(chave_m, msg), "M0"
        assert h.mac_verifica(bloco_m, tag, msg), "M2"
        ruim = bytes([tag[0] ^ 1]) + tag[1:]
        assert not h.mac_verifica(bloco_m, ruim, msg), "M2 com bit trocado"

        # O sentido inverso: um bloco que o PYTHON fez, sob a mesma LMK.
        minha = os.urandom(32)
        meu = tr31.embrulha(lmk, minha, modo="B")
        assert h.check(meu)["kcv"] == _kcv_local(minha).hex().upper(), "K2"
        assert h.cripto(meu, iv, texto, True) == \
            tr31._cbc(minha, iv, texto, True), "C0 com bloco do Python"

        # KEK: o Python faz o papel da OUTRA instituicao, que tem a KEK
        # em claro (la ela veio de componentes; aqui, do bloco aberto).
        kek_lmk, kcv_kek = h.gen("K0", "B", "E")
        kek, _ = tr31.desembrulha(lmk, kek_lmk)
        assert _kcv_local(kek).hex().upper() == kcv_kek, "KCV da KEK"
        sai, kcv_sai = h.exporta(kek_lmk, bloco)
        aberta, cab_sai = tr31.desembrulha(kek, sai)
        assert aberta == chave and kcv_sai == kcv, "K4"
        assert cab_sai == cab, "K4: cabecalho mudou na exportacao"

        dela = os.urandom(32)
        recebido = tr31.embrulha(kek, dela, modo="E", exportabilidade="N")
        aqui, kcv_aqui = h.importa(kek_lmk, recebido)
        guardada, cab_aqui = tr31.desembrulha(lmk, aqui)
        assert guardada == dela, "K6"
        assert kcv_aqui == _kcv_local(dela).hex().upper(), "K6: KCV"
        assert cab_aqui["modo"] == "E" and \
            cab_aqui["exportabilidade"] == "N", "K6: cabecalho"
        assert h.cripto(aqui, iv, texto, True) == \
            tr31._cbc(dela, iv, texto, True), "C0 com a chave importada"

        def recusa(codigo, comando, *args):
            try:
                getattr(h, comando)(*args)
            except HostErro as e:
                assert e.codigo == codigo, "%s: %d, esperado %d" % (
                    comando, e.codigo, codigo)
            else:
                raise AssertionError("%s aceito, esperado %d"
                                     % (comando, codigo))
        recusa(12, "exporta", kek_lmk, aqui)        # 'N' nao segue adiante
        recusa(12, "exporta", kek_lmk, bloco_m)
        recusa(13, "exporta", bloco, bloco)         # chave de dados nao e KEK
        recusa(13, "importa", bloco, recebido)
        so_e, _ = h.gen("K0", "E", "E")             # KEK que so embrulha
        recusa(11, "importa", so_e, recebido)
        outra = tr31.embrulha(os.urandom(32), dela)  # sob outra KEK
        recusa(10, "importa", kek_lmk, outra)
        adulterado = recebido[:-1] + ("0" if recebido[-1] != "0" else "1")
        recusa(10, "importa", kek_lmk, adulterado)

        # O uso manda junto com o modo.
        recusa(11, "cripto", kek_lmk, iv, texto, True)   # KEK nao cifra
        recusa(11, "cripto", kek_lmk, iv, texto, False)  # nem decifra
        recusa(11, "mac", kek_lmk, msg)                  # nem autentica
        d_c, _ = h.gen("D0", "C", "E")                   # modo de MAC, uso D0
        recusa(11, "mac", d_c, msg)
        m_b, _ = h.gen("M0", "B", "E")                   # modo de cifra, uso M0
        recusa(11, "cripto", m_b, iv, texto, True)
        print("volta %d: K0/K2/C0/C2/M0/M2/K4/K6 conferidos" % (volta + 1))
    print("%d de %d voltas conferidas" % (n, n))
    return 0


# --------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="porta HOST do HSM (ASCII)")
    tr = ap.add_mutually_exclusive_group()
    tr.add_argument("--tcp", default="127.0.0.1:1500",
                    help="ponte TCP (padrao 127.0.0.1:1500)")
    tr.add_argument("--serial", action="store_true",
                    help="direto na serial, sem a ponte")
    ap.add_argument("--porta", default=None,
                    help="porta serial (com --serial; padrao: CP2102)")
    ap.add_argument("--cab", default="0000", help="cabecalho, 4 caracteres")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest")
    sub.add_parser("diag")
    p = sub.add_parser("gen")
    p.add_argument("--uso", default="D0")
    p.add_argument("--modo", default="B", choices=list("EDBGVCN"))
    p.add_argument("--exp", default="E", choices=list("ENS"))
    p = sub.add_parser("check"); p.add_argument("bloco")
    for nome in ("export", "import"):
        p = sub.add_parser(nome); p.add_argument("kek"); p.add_argument("bloco")
    for nome in ("encrypt", "decrypt"):
        p = sub.add_parser(nome)
        p.add_argument("bloco"); p.add_argument("iv"); p.add_argument("dados")
    p = sub.add_parser("mac"); p.add_argument("bloco"); p.add_argument("dados")
    p = sub.add_parser("mac-verify")
    p.add_argument("bloco"); p.add_argument("mac"); p.add_argument("dados")
    p = sub.add_parser("confere")
    p.add_argument("--lmk", required=True, help="LMK em hex (brinquedo)")
    p.add_argument("-n", type=int, default=10)

    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()

    t = Serial(a.porta) if a.serial else Tcp(a.tcp)
    h = Host(t, a.cab.encode())
    try:
        if a.cmd == "diag":
            d = h.diag()
            nomes = {0: "UNINITIALIZED", 1: "AUTHORIZED", 2: "OPERATIONAL"}
            print("estado     : %s (%d)" % (nomes.get(d["estado"], "?"),
                                            d["estado"]))
            print("KCV da LMK : %s" % d["kcv_lmk"])
            print("firmware   : v%s" % d["versao"])
        elif a.cmd == "gen":
            bloco, kcv = h.gen(a.uso, a.modo, a.exp)
            print(bloco)
            print("KCV %s" % kcv, file=sys.stderr)
        elif a.cmd == "check":
            for k, v in h.check(a.bloco).items():
                print("%-16s: %s" % (k, v))
        elif a.cmd in ("export", "import"):
            f = h.exporta if a.cmd == "export" else h.importa
            bloco, kcv = f(a.kek, a.bloco)
            print(bloco)
            print("KCV %s" % kcv, file=sys.stderr)
        elif a.cmd in ("encrypt", "decrypt"):
            print(h.cripto(a.bloco, bytes.fromhex(a.iv),
                           bytes.fromhex(a.dados),
                           a.cmd == "encrypt").hex().upper())
        elif a.cmd == "mac":
            print(h.mac(a.bloco, bytes.fromhex(a.dados)).hex().upper())
        elif a.cmd == "mac-verify":
            ok = h.mac_verifica(a.bloco, bytes.fromhex(a.mac),
                                bytes.fromhex(a.dados))
            print("MAC confere" if ok else "MAC NAO confere")
            return 0 if ok else 1
        elif a.cmd == "confere":
            return confere(h, bytes.fromhex(a.lmk), a.n)
    except HostErro as e:
        print("dispositivo recusou: %s" % e, file=sys.stderr)
        return 1
    finally:
        t.close()
    return 0


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main())
