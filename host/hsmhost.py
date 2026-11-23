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
    hsmhost.py rsa-verify N E DIGEST S      # R4: RSA-2048, PKCS#1 v1.5, SHA-256
    hsmhost.py rsa-cavp [--lmk HEX]         # R4 com os vetores do CAVP; com a
                                            # LMK, tambem R2 com a chave do CAVP
    hsmhost.py rsa-sign BLOCO DIGEST        # R2: assina com a chave do bloco
    hsmhost.py rsa-gen [--exp E]            # R0: gera par RSA-2048
    hsmhost.py rsa-confere [-n N]           # R0 + R2 + R4, conferidos aqui
    hsmhost.py ecdsa-verify QX QY DIGEST R S  # E4: ECDSA P-256
    hsmhost.py ecdsa-cavp [--lmk HEX]       # E4 com os vetores do CAVP; com a
                                            # LMK, tambem E2 com a chave do CAVP
    hsmhost.py ecdsa-sign BLOCO DIGEST      # E2: assina com a chave do bloco
    hsmhost.py ecdsa-gen [--exp E]          # E0: gera par P-256
    hsmhost.py ecdsa-confere [-n N]         # E0 + E2 + E4, conferidos aqui
    hsmhost.py confere --lmk HEX [-n N]     # o Python conferindo o C
    hsmhost.py selftest                     # codec, sem placa

Transporte: pela ponte (--tcp HOST:PORTA, padrao 127.0.0.1:1500, ver
hsm_ponte.py) ou direto na serial (--serial [--porta PORTA]).
"""

import argparse
import hashlib
import os
import re
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
    14: "PIN block invalido",
    15: "dados invalidos",
    16: "parametro invalido",
    17: "tabela de decimalizacao nao autorizada",
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

    def espera(self, segundos):
        self.s.settimeout(segundos)

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

    def espera(self, segundos):
        self.ser.timeout = segundos

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

    def gen(self, uso="D0", modo="B", exp="E", alg=""):
        """K0. `alg` vazio e AES-256; "T2" e 3DES de comprimento duplo,
        "T3" e 3DES de comprimento triplo, "A4" e AES-256 por extenso."""
        _, c = self.pede("K0", (uso + modo + exp + alg).encode())
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

    def rsa_verifica(self, n, e, digest, s):
        """R4: so dados publicos entram, e sai um bit (o codigo de erro)."""
        campos = (n.to_bytes(256, "big") + e.to_bytes(4, "big") + digest
                  + s.to_bytes(256, "big"))
        erro, _ = self.pede("R4", campos.hex().upper().encode(), aceita=(0, 1))
        return erro == 0

    def rsa_gera(self, exp="E"):
        """R0: (key block da chave privada, n, e). Leva segundos: o
        dispositivo procura dois primos de 1024 bits."""
        self.t.espera(120.0)
        try:
            _, c = self.pede("R0", exp.encode())
        finally:
            self.t.espera(5.0)
        bloco = c[:-520].decode()
        return bloco, int(c[-520:-8].decode(), 16), int(c[-8:].decode(), 16)

    def rsa_assina(self, bloco, digest):
        """R2: a chave privada vai no key block sob a LMK; sai S."""
        _, c = self.pede("R2", bloco.encode() + digest.hex().upper().encode())
        return int(c[:512].decode(), 16)


    def ecdsa_verifica(self, qx, qy, digest, r, s):
        """E4: so dados publicos entram, e sai um bit (o codigo de erro).
        Chave publica fora da curva e erro 16, e sobe como HostErro."""
        campos = b"".join(v.to_bytes(32, "big") for v in (qx, qy)) + digest \
            + r.to_bytes(32, "big") + s.to_bytes(32, "big")
        self.t.espera(10.0)
        try:
            erro, _ = self.pede("E4", campos.hex().upper().encode(), aceita=(0, 1))
        finally:
            self.t.espera(5.0)
        return erro == 0

    def ecdsa_gera(self, exp="E"):
        """E0: (key block da chave privada, Qx, Qy)."""
        self.t.espera(10.0)
        try:
            _, c = self.pede("E0", exp.encode())
        finally:
            self.t.espera(5.0)
        bloco = c[:-128].decode()
        return bloco, int(c[-128:-64].decode(), 16), int(c[-64:].decode(), 16)

    def ecdsa_assina(self, bloco, digest):
        """E2: a chave privada vai no key block sob a LMK; saem r e s."""
        self.t.espera(10.0)
        try:
            _, c = self.pede("E2", bloco.encode() + digest.hex().upper().encode())
        finally:
            self.t.espera(5.0)
        return int(c[:64].decode(), 16), int(c[64:128].decode(), 16)

    def pin_traduz(self, origem, destino, pan, bloco, formatos="44"):
        """P0: o PIN block sai da chave de origem para a de destino. As duas
        chaves vao como key block sob a LMK. `formatos`: o de origem e o de
        destino, '4' (AES, 16 bytes) ou '0' (3DES, 8 bytes)."""
        campos = (origem + destino + formatos + "%02d" % len(pan) + pan
                  + bloco.hex().upper())
        _, c = self.pede("P0", campos.encode())
        return bytes.fromhex(c[:(16 if formatos[1] == "0" else 32)].decode())

    # -- DUKPT (fase 8, etapas 8.8a e 8.8b) ---------------------------
    def dukpt_traduz(self, bdk, destino, ksn, pan, bloco, formatos="00",
                     trabalho=""):
        """P2: o PIN block do terminal DUKPT (BDK + KSN) sai sob a chave de
        zona `destino`. `formatos`: origem ('0' com BDK 3DES, '4' com BDK
        AES) e destino ('0' ou '4'). `trabalho`, so com BDK AES: '2' (chave
        de PIN AES-128) ou '4' (AES-256). O KSN tem 10 bytes no TDES e 12 no
        AES."""
        campos = (bdk + destino + ksn.hex().upper() + trabalho + formatos
                  + "%02d" % len(pan) + pan + bloco.hex().upper())
        _, c = self.pede("P2", campos.encode())
        return bytes.fromhex(c[:(16 if formatos[1] == "0" else 32)].decode())

    def ipek(self, kek, bdk, ksn):
        """I0: a chave inicial do terminal do `ksn` (a IPEK, ou a IK do DUKPT
        AES), sob a KEK. Devolve (bloco, KCV)."""
        _, c = self.pede("I0", kek.encode() + bdk.encode()
                         + ksn.hex().upper().encode())
        n = int(c[1:5])
        return c[:n].decode(), c[n:n + 6].decode()

    # -- verificacao de PIN (fase 8, etapa 8.5) -----------------------
    @staticmethod
    def _pin_comum(kpin, pvk, formato, pan, bloco):
        return kpin + pvk + formato + "%02d" % len(pan) + pan \
            + bloco.hex().upper()

    def offset_gera(self, kpin, pvk, formato, pan, bloco, tabela, dados_v):
        """V0. `tabela`: o bloco autorizado, 32 caracteres. `dados_v`: os
        dados de validacao, 8 bytes. Devolve o offset."""
        campos = (self._pin_comum(kpin, pvk, formato, pan, bloco) + tabela
                  + dados_v.hex().upper())
        _, c = self.pede("V0", campos.encode())
        n = int(c[:2])
        return c[2:2 + n].decode()

    def offset_verifica(self, kpin, pvk, formato, pan, bloco, tabela,
                        dados_v, offset):
        """V2: sai um bit."""
        campos = (self._pin_comum(kpin, pvk, formato, pan, bloco) + tabela
                  + dados_v.hex().upper() + "%02d" % len(offset) + offset)
        erro, _ = self.pede("V2", campos.encode(), aceita=(0, 1))
        return erro == 0

    def pvv_gera(self, kpin, pvk, formato, pan, bloco, indice):
        """V4. Devolve o PVV, 4 digitos."""
        campos = self._pin_comum(kpin, pvk, formato, pan, bloco) + indice
        _, c = self.pede("V4", campos.encode())
        return c[:4].decode()

    def pvv_verifica(self, kpin, pvk, formato, pan, bloco, indice, pvv):
        """V6: sai um bit."""
        campos = (self._pin_comum(kpin, pvk, formato, pan, bloco) + indice
                  + pvv)
        erro, _ = self.pede("V6", campos.encode(), aceita=(0, 1))
        return erro == 0

    # -- CVV, CVV2 e iCVV (fase 8, etapa 8.6) -----------------------
    @staticmethod
    def _cvv_campos(cvk, pan, validade, servico):
        return cvk + "%02d" % len(pan) + pan + validade + servico

    def cvv_gera(self, cvk, pan, validade, servico):
        """W0. `servico`: o da tarja para o CVV, 000 para o CVV2, 999 para
        o iCVV. Devolve os 3 digitos."""
        _, c = self.pede("W0", self._cvv_campos(cvk, pan, validade,
                                                 servico).encode())
        return c[:3].decode()

    def cvv_verifica(self, cvk, pan, validade, servico, cvv):
        """W2: sai um bit."""
        campos = self._cvv_campos(cvk, pan, validade, servico) + cvv
        erro, _ = self.pede("W2", campos.encode(), aceita=(0, 1))
        return erro == 0


# --------------------------------------------------------------------
# ECDSA P-256: a conferencia em Python, com inteiros. E a segunda
# implementacao -- nao usa nada do firmware.
EC_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
EC_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
EC_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
EC_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def ec_soma(p1, p2):
    """Soma de pontos afins; None e o ponto no infinito."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % EC_P == 0:
            return None
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, EC_P) % EC_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, EC_P) % EC_P
    x3 = (lam * lam - x1 - x2) % EC_P
    return x3, (lam * (x1 - x3) - y1) % EC_P


def ec_mult(k, p):
    r = None
    while k:
        if k & 1:
            r = ec_soma(r, p)
        p = ec_soma(p, p)
        k >>= 1
    return r


def ecdsa_confere_py(q, digest, r, s):
    """Verificacao ECDSA em Python (FIPS 186-5, 6.4.2)."""
    x, y = q
    if not (0 <= x < EC_P and 0 <= y < EC_P) or \
            (y * y - (x**3 - 3 * x + EC_B)) % EC_P != 0:
        return False
    if not (0 < r < EC_N and 0 < s < EC_N):
        return False
    e = int.from_bytes(digest, "big")
    w = pow(s, -1, EC_N)
    ponto = ec_soma(ec_mult(e * w % EC_N, EC_G), ec_mult(r * w % EC_N, q))
    return ponto is not None and ponto[0] % EC_N == r


def ecdsa_vetores(nome):
    """Os casos da secao [P-256,SHA-256] de um arquivo do CAVP."""
    raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    casos, atual = [], {}
    with open(os.path.join(raiz, "vectors", "ecdsa", nome)) as f:
        for linha in f:
            m = re.match(r"^(\w+) = (.*)$", linha.strip())
            if m:
                atual[m[1]] = m[2].strip()
            elif atual:
                casos.append(atual)
                atual = {}
    if atual:
        casos.append(atual)
    return [c for c in casos if "Qx" in c]


def ecdsa_confere(h, voltas):
    """Gera pares no dispositivo e confere cada um daqui, so com Q: a
    assinatura do E2 tem de verificar em Python, e o E4 tem de aceita-la e
    recusar a adulterada."""
    import time
    for v in range(voltas):
        t0 = time.monotonic()
        bloco, qx, qy = h.ecdsa_gera()
        dt = time.monotonic() - t0
        anteriores = set()
        for i in range(3):
            digest = hashlib.sha256(b"ecdsa-confere %d %d" % (v, i)).digest()
            r, s = h.ecdsa_assina(bloco, digest)
            if not ecdsa_confere_py((qx, qy), digest, r, s):
                print("par %d: assinatura %d NAO verifica" % (v, i))
                return 1
            if r in anteriores:
                print("par %d: r repetido -- o k se repetiu" % v)
                return 1
            anteriores.add(r)
            if not h.ecdsa_verifica(qx, qy, digest, r, s):
                print("par %d: o E4 recusou a propria assinatura" % v)
                return 1
            if h.ecdsa_verifica(qx, qy, digest, r, s ^ 1):
                print("par %d: o E4 aceitou assinatura adulterada" % v)
                return 1
        print("par %d: gerado em %.2f s, 3 assinaturas conferidas" % (v, dt))
    return 0


def ecdsa_cavp(h, lmk=None):
    """SigVer: cada vetor tem de dar o veredito do CAVP. PKV: chave publica
    invalida tem de ser recusada com 16. Com a LMK, tambem assina com as
    chaves do SigGen do CAVP e confere aqui."""
    if lmk is not None:
        import pkcs8
        import tr31
        for i, c in enumerate(ecdsa_vetores("SigGen_P256.txt")[:3]):
            chave = pkcs8.ec_der(int(c["d"], 16))
            bloco = tr31.embrulha(lmk, chave, uso="S0", algoritmo="E", modo="S",
                                  exportabilidade="E")
            digest = hashlib.sha256(bytes.fromhex(c["Msg"])).digest()
            r, s = h.ecdsa_assina(bloco, digest)
            if not ecdsa_confere_py((int(c["Qx"], 16), int(c["Qy"], 16)), digest, r, s):
                print("E2 %d: assinatura ERRADA" % i)
                return 1
            print("E2 %d: assinatura com a chave do CAVP confere" % i)
    vs = ecdsa_vetores("SigVer_P256.rsp")
    for i, c in enumerate(vs):
        digest = hashlib.sha256(bytes.fromhex(c["Msg"])).digest()
        espera = c["Result"].startswith("P")
        try:
            ok = h.ecdsa_verifica(int(c["Qx"], 16), int(c["Qy"], 16), digest,
                                  int(c["R"], 16), int(c["S"], 16))
        except HostErro as e:
            ok = None if e.codigo == 16 else "erro %d" % e.codigo
        # "Q changed" pode tirar o ponto da curva: ai a recusa e o 16.
        if ok is not espera and not (ok is None and not espera):
            print("vetor %d: esperado %s, veio %r" % (i, c["Result"], ok))
            return 1
        print("vetor %d: %s" % (i, c["Result"]))
    pk = ecdsa_vetores("PKV_P256.rsp")
    for i, c in enumerate(pk):
        if len(c["Qx"]) > 64 or len(c["Qy"]) > 64:
            continue                    # nem cabe no campo do comando
        espera = c["Result"].startswith("P")
        try:
            h.ecdsa_verifica(int(c["Qx"], 16), int(c["Qy"], 16), b"\0" * 31 + b"\1", 1, 1)
            aceita = True
        except HostErro as e:
            if e.codigo != 16:
                raise
            aceita = False
        if aceita != espera:
            print("PKV %d: esperado %s" % (i, c["Result"]))
            return 1
    print("%d vetores de SigVer e %d de PKV do CAVP conferidos" % (len(vs), len(pk)))
    return 0


def chave_cavp():
    """A primeira chave de 2048 bits do KeyGen do CAVP, em PKCS#8, que e o
    conteudo do key block. Devolve (chave, n, e, d)."""
    raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    caminho = os.path.join(raiz, "vectors", "rsa", "KeyGen_RandomProbablyPrime3_3.rsp")
    with open(caminho) as f:
        texto = f.read().split("[mod = 2048]")[1].split("[mod =")[0]
    m = re.search(r"e = (\w+)\s+p = (\w+)\s+q = (\w+)\s+n = (\w+)\s+d = (\w+)", texto)
    e, p, q, n, d = (int(x, 16) for x in m.groups())
    import pkcs8
    return pkcs8.rsa_der(p, q, e, d), n, e, d


def em_pkcs1(digest):
    """O EM de PKCS#1 v1.5 com SHA-256, como inteiro."""
    t = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    return int.from_bytes(b"\0\1" + b"\xff" * (253 - len(t)) + b"\0" + t, "big")


def vetores_cavp():
    """Os vetores SHA-256 de 2048 bits do SigGen15 do CAVP: (n, e, digest, S)."""
    raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(raiz, "vectors", "rsa", "SigGen15_186-3.rsp")) as f:
        texto = f.read().split("[mod = 3072]")[0]
    n = int(re.search(r"^n = (\w+)", texto, re.M)[1], 16)
    e = int(re.search(r"^e = (\w+)", texto, re.M)[1], 16)
    bloco = texto.split("SHAAlg = SHA256")[1:]
    vs = []
    for b in bloco:
        msg = bytes.fromhex(re.search(r"^Msg = (\w+)", b, re.M)[1])
        sig = int(re.search(r"^S = (\w+)", b, re.M)[1], 16)
        vs.append((n, e, hashlib.sha256(msg).digest(), sig))
    return vs


def rsa_confere(h, voltas):
    """Gera pares no dispositivo e confere cada um daqui, so com n e e: a
    assinatura do R2 tem de verificar em Python, e o R4 tem de aceita-la.
    Se p ou q nao fossem primos, a assinatura por CRT nao verificaria."""
    import time
    for v in range(voltas):
        t0 = time.monotonic()
        bloco, n, e = h.rsa_gera()
        dt = time.monotonic() - t0
        if e != 65537 or n.bit_length() != 2048 or n % 2 == 0:
            print("par %d: n ou e fora do esperado" % v)
            return 1
        for i in range(3):
            digest = hashlib.sha256(b"rsa-confere %d %d" % (v, i)).digest()
            s = h.rsa_assina(bloco, digest)
            if pow(s, e, n) != em_pkcs1(digest):
                print("par %d: assinatura %d NAO verifica" % (v, i))
                return 1
            if not h.rsa_verifica(n, e, digest, s):
                print("par %d: o R4 recusou a propria assinatura" % v)
                return 1
        print("par %d: gerado em %.1f s, 3 assinaturas conferidas" % (v, dt))
    return 0


def rsa_cavp(h, lmk=None):
    """Cada vetor tem de conferir, e com um bit trocado em S, nao. Com a LMK,
    tambem assina com a chave do CAVP e confere a assinatura aqui."""
    if lmk is not None:
        import tr31
        chave, n, e, d = chave_cavp()
        bloco = tr31.embrulha(lmk, chave, uso="S0", algoritmo="R", modo="S",
                              exportabilidade="E")
        for i in range(3):
            digest = hashlib.sha256(b"hsm-a7 R2 %d" % i).digest()
            s = h.rsa_assina(bloco, digest)
            if s != pow(em_pkcs1(digest), d, n) or pow(s, e, n) != em_pkcs1(digest):
                print("R2 %d: assinatura ERRADA" % i)
                return 1
            print("R2 %d: assinatura com a chave do CAVP confere" % i)
    vs = vetores_cavp()
    for i, (n, e, d, sig) in enumerate(vs):
        if not h.rsa_verifica(n, e, d, sig):
            print("vetor %d: assinatura valida RECUSADA" % i)
            return 1
        if h.rsa_verifica(n, e, d, sig ^ (1 << (i * 97 % 2040))):
            print("vetor %d: assinatura adulterada ACEITA" % i)
            return 1
        print("vetor %d: valida aceita, adulterada recusada" % i)
    print("%d vetores do CAVP conferidos" % len(vs))
    return 0


# --------------------------------------------------------------------
# Selftest do codec (sem placa)
# --------------------------------------------------------------------
def selftest():
    m = monta(b"AB12", "C0", b"xyz")
    assert m == b"AB12C0xyz"
    assert resposta_esperada("K0") == "K1"
    assert resposta_esperada("M2") == "M3"
    assert resposta_esperada("R4") == "R5"
    assert resposta_esperada("R2") == "R3"
    _, n, e, d = chave_cavp()
    assert pow(pow(em_pkcs1(bytes(32)), d, n), e, n) == em_pkcs1(bytes(32))
    assert len(vetores_cavp()) == 10
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


def pkcs8_confere(h, lmk, n):
    """A chave assimetrica no key block e PKCS#8: prova de interoperabilidade
    com a biblioteca `cryptography`, nos dois sentidos.

      - o equipamento gera o par (R0, E0); o Python abre o bloco com a LMK,
        carrega o PKCS#8 na biblioteca, assina com ela, e o equipamento
        verifica (R4, E4). A chave publica da biblioteca tem de ser a que o
        equipamento devolveu;
      - a biblioteca gera o par; o Python o embrulha sob a LMK; o
        equipamento assina (R2, E2), e a biblioteca verifica.

    ⚠ PRECISA DA LMK, como o `confere`."""
    import pkcs8
    import tr31
    from hsmtool import _kcv_local
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

    d = h.diag()
    if d["kcv_lmk"] != _kcv_local(lmk).hex().upper():
        print("KCV da LMK nao confere: dispositivo %s, informada %s"
              % (d["kcv_lmk"], _kcv_local(lmk).hex().upper()))
        return 1
    pre = utils.Prehashed(hashes.SHA256())

    for volta in range(n):
        digest = os.urandom(32)

        # ---- curva: do equipamento para a biblioteca ----
        bloco, qx, qy = h.ecdsa_gera()
        der, cab = tr31.desembrulha(lmk, bloco)
        assert cab["algoritmo"] == "E" and cab["uso"] == "S0", "cabecalho E0"
        k = pkcs8.le(der)
        pub = k.public_key().public_numbers()
        assert (pub.x, pub.y) == (qx, qy), "E0: chave publica do PKCS#8"
        r, s = utils.decode_dss_signature(k.sign(digest, ec.ECDSA(pre)))
        assert h.ecdsa_verifica(qx, qy, digest, r, s), "E4 sobre a biblioteca"
        # ---- curva: da biblioteca para o equipamento ----
        k = ec.generate_private_key(ec.SECP256R1())
        meu = tr31.embrulha(lmk, pkcs8.ec_der(k.private_numbers().private_value),
                            uso="S0", algoritmo="E", modo="S")
        r, s = h.ecdsa_assina(meu, digest)
        k.public_key().verify(utils.encode_dss_signature(r, s), digest,
                              ec.ECDSA(pre))

        # ---- RSA: da biblioteca para o equipamento ----
        k = rsa.generate_private_key(65537, 2048)
        nums = k.private_numbers()
        meu = tr31.embrulha(lmk, pkcs8.rsa_der(nums.p, nums.q, 65537, nums.d),
                            uso="S0", algoritmo="R", modo="S")
        sig = h.rsa_assina(meu, digest)
        k.public_key().verify(sig.to_bytes(256, "big"), digest,
                              padding.PKCS1v15(), pre)
        # ---- RSA: do equipamento para a biblioteca (uma vez: e lento) ----
        if volta == 0:
            bloco, mod, e = h.rsa_gera()
            der, cab = tr31.desembrulha(lmk, bloco)
            assert cab["algoritmo"] == "R" and cab["uso"] == "S0", "cabecalho R0"
            k = pkcs8.le(der)
            pub = k.public_key().public_numbers()
            assert (pub.n, pub.e) == (mod, e), "R0: chave publica do PKCS#8"
            sig = int.from_bytes(k.sign(digest, padding.PKCS1v15(), pre), "big")
            assert h.rsa_verifica(mod, e, digest, sig), "R4 sobre a biblioteca"
            assert h.rsa_assina(bloco, digest) == sig, "R2 igual a biblioteca"
        print("volta %d: PKCS#8 conferido nos dois sentidos" % (volta + 1))
    print("%d de %d voltas conferidas" % (n, n))
    return 0


def tdes_confere(h, lmk, n):
    """Chaves 3DES pela porta host (K0 com T2/T3, K2, K4), conferidas com o
    des.py e o tr31.py. O KCV que o equipamento devolve e calculado com o
    3DES do firmware; o Python o refaz com a chave aberta do bloco.

    ⚠ PRECISA DA LMK, como o `confere`."""
    import des
    import tr31
    from hsmtool import _kcv_local

    d = h.diag()
    if d["kcv_lmk"] != _kcv_local(lmk).hex().upper():
        print("KCV da LMK nao confere: dispositivo %s, informada %s"
              % (d["kcv_lmk"], _kcv_local(lmk).hex().upper()))
        return 1

    def recusa(codigo, f, *args):
        try:
            f(*args)
        except HostErro as e:
            assert e.codigo == codigo, "%d, esperado %d" % (e.codigo, codigo)
        else:
            raise AssertionError("aceito, esperado %d" % codigo)

    vistas = set()
    for volta in range(n):
        for alg, tam in (("T2", 16), ("T3", 24)):
            bloco, kcv = h.gen("P0", "B", "E", alg)
            chave, cab = tr31.desembrulha(lmk, bloco)
            assert cab["algoritmo"] == "T" and cab["uso"] == "P0", "cabecalho"
            assert len(chave) == tam, "tamanho da chave"
            assert des.paridade_ok(chave), "paridade"
            assert chave[:8] != chave[8:16], "K1 = K2"
            assert des.kcv(chave).hex().upper() == kcv, "KCV do K0"
            assert chave not in vistas, "chave repetida"
            vistas.add(chave)
            info = h.check(bloco)
            assert info["algoritmo"] == "T" and info["kcv"] == kcv, "K2"

            # O sentido inverso: um bloco que o PYTHON fez.
            minha = des.paridade_impar(os.urandom(tam))
            meu = tr31.embrulha(lmk, minha, uso="P0", algoritmo="T", modo="B")
            assert h.check(meu)["kcv"] == des.kcv(minha).hex().upper(), \
                "K2 com bloco do Python"

            # A chave 3DES sai sob uma KEK AES: a mais forte protege a mais
            # fraca.
            kek_b, _ = h.gen("K0", "B", "E")
            kek, _ = tr31.desembrulha(lmk, kek_b)
            fora, kcv_f = h.exporta(kek_b, bloco)
            aberta, cab_f = tr31.desembrulha(kek, fora)
            assert aberta == chave and kcv_f == kcv, "K4 com chave 3DES"
            volta_b, kcv_v = h.importa(kek_b, fora)
            assert tr31.desembrulha(lmk, volta_b)[0] == chave, "K6"

            # O que a chave 3DES NAO faz, por enquanto ou nunca.
            iv, texto = bytes(16), bytes(16)
            d0, _ = h.gen("D0", "B", "E", alg)
            recusa(11, h.cripto, d0, iv, texto, True)      # C0 e AES
            m0, _ = h.gen("M0", "C", "E", alg)
            recusa(11, h.mac, m0, texto)                   # M0 e CMAC-AES

            # Etapa 8.7: KEK 3DES deste comprimento. Ela leva chave 3DES de
            # comprimento igual ou menor, em bloco versao B, e nada mais.
            k3_b, _ = h.gen("K0", "B", "E", alg)
            k3, _ = tr31.desembrulha(lmk, k3_b)
            for alg2, tam2 in (("T2", 16), ("T3", 24)):
                b2, kcv2 = h.gen("D0", "B", "E", alg2)
                c2, _ = tr31.desembrulha(lmk, b2)
                if tam2 > tam:
                    recusa(13, h.exporta, k3_b, b2)        # tripla sob dupla
                    meu = tr31.embrulha(k3, c2, uso="D0", algoritmo="T",
                                        modo="B", versao="B")
                    recusa(10, h.importa, k3_b, meu)
                    continue
                fora, kcv_f = h.exporta(k3_b, b2)
                assert fora[0] == "B", "K4 sob KEK 3DES: versao B"
                assert tr31.desembrulha(k3, fora)[0] == c2 and kcv_f == kcv2, \
                    "K4 sob KEK 3DES"
                volta_b, kcv_v = h.importa(k3_b, fora)
                assert tr31.desembrulha(lmk, volta_b)[0] == c2 and \
                    kcv_v == kcv2, "K6 sob KEK 3DES"
                # o sentido inverso: um bloco B que o Python fez
                minha = des.paridade_impar(os.urandom(tam2))
                meu = tr31.embrulha(k3, minha, uso="P0", algoritmo="T",
                                    modo="E", exportabilidade="N", versao="B")
                vb, kv = h.importa(k3_b, meu)
                ab, cb = tr31.desembrulha(lmk, vb)
                assert ab == minha and cb["exportabilidade"] == "N" and \
                    kv == des.kcv(minha).hex().upper(), "K6 com bloco B do Python"
            aes_d, _ = h.gen("D0", "B", "E")
            recusa(13, h.exporta, k3_b, aes_d)             # AES sob KEK 3DES
            aes_c = os.urandom(32)
            recusa(10, h.importa, k3_b,                    # AES num bloco B
                   tr31.embrulha(k3, aes_c, uso="D0", algoritmo="A",
                                 modo="B", versao="B"))
            recusa(10, h.importa, k3_b,                    # bloco D sob KEK 3DES
                   tr31.embrulha(os.urandom(32), os.urandom(32),
                                 uso="D0", algoritmo="A", modo="B"))
            k3e, _ = h.gen("K0", "E", "E", alg)            # so exporta
            recusa(11, h.importa, k3e, fora)
            aes_p, _ = h.gen("P0", "B", "E")
            recusa(11, h.pin_traduz, bloco, aes_p, "999999012345", bytes(16))
        recusa(16, h.gen, "P0", "B", "E", "T1")            # DES simples
        recusa(16, h.gen, "P0", "B", "E", "T4")
        recusa(16, h.gen, "P0", "B", "E", "A2")            # AES-128
        recusa(22, h.gen, "P0", "B", "E", "T")
        b_a4, kcv_a4 = h.gen("D0", "B", "E", "A4")
        assert _kcv_local(tr31.desembrulha(lmk, b_a4)[0]).hex().upper() \
            == kcv_a4, "A4"
        print("volta %d: chaves 3DES duplas e triplas conferidas" % (volta + 1))
    print("%d de %d voltas conferidas" % (n, n))
    return 0


def pinv_confere(h, lmk, n, bloco_console=None, kcv_console=None):
    """Verificacao de PIN (V0, V2, V4, V6), conferida com o pinverif.py. O
    Python faz o papel do terminal, que cifra o PIN, e o do emissor, que
    refaz a conta com a chave de verificacao em claro.

    A tabela autorizada e calculada AQUI, com a LMK e o KCV da chave V1: e a
    prova de que o equipamento e o Python derivam a mesma chave de MAC. Com
    `bloco_console` (o que `hsmtool tabela-autoriza` devolveu) e o KCV da
    chave para a qual ele foi feito, confere tambem esse.

    ⚠ PRECISA DA LMK. E o brinquedo aparecendo, como no `confere`.
    ⚠ Os PANs sao inventados (prefixo 999999). Nenhum PAN real, nunca."""
    import des
    import pinblock
    import pinverif
    import tr31
    from hsmtool import _kcv_local

    d = h.diag()
    if d["kcv_lmk"] != _kcv_local(lmk).hex().upper():
        print("KCV da LMK nao confere: dispositivo %s, informada %s"
              % (d["kcv_lmk"], _kcv_local(lmk).hex().upper()))
        return 1

    def recusa(codigo, fn, *args):
        try:
            fn(*args)
        except HostErro as e:
            assert e.codigo == codigo, "%s: %d, esperado %d" % (
                fn.__name__, e.codigo, codigo)
        else:
            raise AssertionError("%s aceito, esperado %d"
                                 % (fn.__name__, codigo))

    if bloco_console is not None:
        if kcv_console is None:
            print("--tabela pede --kcv, o KCV da chave V1 da tabela")
            return 2
        esperado = pinverif.tabela_autoriza(lmk, bloco_console[:16],
                                            bytes.fromhex(kcv_console))
        assert bloco_console.upper() == esperado, \
            "o MAC do console nao e o do Python: %s" % esperado
        print("tabela do console: o MAC confere com o Python")

    tabelas = [pinverif.TABELA_PADRAO, "1234567890123456", "9876543210987654"]
    for volta in range(n):
        tab = tabelas[volta % len(tabelas)]
        f = "0" if volta % 2 else "4"
        np = pinblock.PIN_MIN + volta % (pinblock.PIN_MAX - pinblock.PIN_MIN + 1)
        na = 13 + volta % 7
        pin = "".join(str(b % 10) for b in os.urandom(np))
        pan = "999999" + "".join(str(b % 10) for b in os.urandom(na - 6))
        dados_v = bytes.fromhex(pan[-16:].rjust(16, "F"))

        kp_b, _ = h.gen("P0", "B", "E", ("T2" if volta % 4 == 1 else "T3")
                        if f == "0" else "")
        kp, _ = tr31.desembrulha(lmk, kp_b)
        bloco = (pinblock.cifra0 if f == "0" else pinblock.cifra)(kp, pin, pan)

        # ---- offset ------------------------------------------------
        v1_b, _ = h.gen("V1", "C", "E", "T2" if volta % 2 else "T3")
        v1, _ = tr31.desembrulha(lmk, v1_b)
        tab_b = pinverif.tabela_autoriza(lmk, tab, des.kcv(v1))
        off = h.offset_gera(kp_b, v1_b, f, pan, bloco, tab_b, dados_v)
        assert off == pinverif.offset_gera(v1, tab, dados_v, pin), "V0: offset"
        assert h.offset_verifica(kp_b, v1_b, f, pan, bloco, tab_b, dados_v,
                                 off), "V2: recusou o offset certo"
        for k in range(np):                     # um digito errado por vez
            ruim = off[:k] + str((int(off[k]) + 1 + volta % 9) % 10) + off[k + 1:]
            assert not h.offset_verifica(kp_b, v1_b, f, pan, bloco, tab_b,
                                         dados_v, ruim), "V2: aceitou %d" % k
        if np > 4:                              # offset mais curto que o PIN
            assert not h.offset_verifica(kp_b, v1_b, f, pan, bloco, tab_b,
                                         dados_v, off[:-1]), "V2: tamanho"
        outros = bytes([dados_v[0] ^ 0x10]) + dados_v[1:]
        assert h.offset_gera(kp_b, v1_b, f, pan, bloco, tab_b, outros) == \
            pinverif.offset_gera(v1, tab, outros, pin), "V0: outros dados"

        # a tabela: so com o MAC certo
        mac_ruim = tab_b[:-1] + ("0" if tab_b[-1] != "0" else "1")
        recusa(17, h.offset_gera, kp_b, v1_b, f, pan, bloco, mac_ruim, dados_v)
        outra = tabelas[(volta + 1) % len(tabelas)] + tab_b[16:]
        recusa(17, h.offset_verifica, kp_b, v1_b, f, pan, bloco, outra,
               dados_v, off)
        # a mesma tabela, autorizada para OUTRA chave V1: nao vale com esta
        v1o_b, _ = h.gen("V1", "C", "E", "T2")
        v1o, _ = tr31.desembrulha(lmk, v1o_b)
        tab_outra = pinverif.tabela_autoriza(lmk, tab, des.kcv(v1o))
        recusa(17, h.offset_gera, kp_b, v1_b, f, pan, bloco, tab_outra,
               dados_v)
        assert h.offset_gera(kp_b, v1o_b, f, pan, bloco, tab_outra,
                             dados_v) == \
            pinverif.offset_gera(v1o, tab, dados_v, pin), "V0: outra chave"
        # modos e usos
        so_v, _ = h.gen("V1", "V", "E", "T2")
        recusa(11, h.offset_gera, kp_b, so_v, f, pan, bloco, tab_b, dados_v)
        so_g, _ = h.gen("V1", "G", "E", "T2")
        recusa(11, h.offset_verifica, kp_b, so_g, f, pan, bloco, tab_b,
               dados_v, off)

        # ---- PVV ---------------------------------------------------
        v2_b, _ = h.gen("V2", "C", "E", "T3" if volta % 2 else "T2")
        v2, _ = tr31.desembrulha(lmk, v2_b)
        ind = str(volta % 10)
        pvv = h.pvv_gera(kp_b, v2_b, f, pan, bloco, ind)
        assert pvv == pinverif.pvv_gera(v2, pan, ind, pin), "V4: PVV"
        assert h.pvv_verifica(kp_b, v2_b, f, pan, bloco, ind, pvv), \
            "V6: recusou o PVV certo"
        for k in range(4):
            ruim = pvv[:k] + str((int(pvv[k]) + 1 + volta % 9) % 10) + pvv[k + 1:]
            assert not h.pvv_verifica(kp_b, v2_b, f, pan, bloco, ind, ruim), \
                "V6: aceitou %d" % k
        outro_i = str((volta + 1) % 10)
        assert h.pvv_gera(kp_b, v2_b, f, pan, bloco, outro_i) == \
            pinverif.pvv_gera(v2, pan, outro_i, pin), "V4: outro indice"
        # as chaves nao trocam de metodo
        recusa(11, h.pvv_gera, kp_b, v1_b, f, pan, bloco, ind)
        recusa(11, h.offset_gera, kp_b, v2_b, f, pan, bloco, tab_b, dados_v)
        recusa(11, h.pvv_gera, kp_b, kp_b, f, pan, bloco, ind)
        v2_v, _ = h.gen("V2", "V", "E", "T2")
        recusa(11, h.pvv_gera, kp_b, v2_v, f, pan, bloco, ind)
        aes_v, _ = h.gen("V2", "C", "E")
        recusa(11, h.pvv_gera, kp_b, aes_v, f, pan, bloco, ind)
        # PIN block adulterado
        ruim_b = bytes([bloco[0] ^ 1]) + bloco[1:]
        recusa(14, h.pvv_gera, kp_b, v2_b, f, pan, ruim_b, ind)
        recusa(14, h.offset_verifica, kp_b, v1_b, f, pan, ruim_b, tab_b,
               dados_v, off)
        print("volta %d: V0 V2 V4 V6 conferidos (formato %s, PIN de %d, "
              "PAN de %d)" % (volta + 1, f, np, na))
    print("%d de %d voltas conferidas" % (n, n))
    return 0


def cvv_confere(h, lmk, n):
    """CVV, CVV2 e iCVV (W0, W2), conferidos com o cvv.py. O Python faz o
    papel do emissor, que refaz a conta com a chave em claro.

    ⚠ PRECISA DA LMK, para abrir o bloco da CVK. E o brinquedo aparecendo,
    como no `confere`.
    ⚠ Os PANs sao inventados (prefixo 999999). Nenhum PAN real, nunca."""
    import cvv
    import tr31
    from hsmtool import _kcv_local

    d = h.diag()
    if d["kcv_lmk"] != _kcv_local(lmk).hex().upper():
        print("KCV da LMK nao confere: dispositivo %s, informada %s"
              % (d["kcv_lmk"], _kcv_local(lmk).hex().upper()))
        return 1

    def recusa(codigo, fn, *args):
        try:
            fn(*args)
        except HostErro as e:
            assert e.codigo == codigo, "%s: %d, esperado %d" % (
                fn.__name__, e.codigo, codigo)
        else:
            raise AssertionError("%s aceito, esperado %d"
                                 % (fn.__name__, codigo))

    def digitos(k):
        return "".join(str(b % 10) for b in os.urandom(k))

    tarja = ["101", "201", "221", "120"]
    for volta in range(n):
        na = 12 + volta % 8
        pan = "999999" + digitos(na - 6)
        val = digitos(4)
        k_b, _ = h.gen("C0", "C", "E", "T2")
        k, _ = tr31.desembrulha(lmk, k_b)
        for sc in (tarja[volta % len(tarja)], cvv.CVV2, cvv.ICVV):
            c = h.cvv_gera(k_b, pan, val, sc)
            assert c == cvv.gera(k, pan, val, sc), "W0: codigo %s" % sc
            assert h.cvv_verifica(k_b, pan, val, sc, c), \
                "W2: recusou o certo (%s)" % sc
            for j in range(3):                 # um digito errado por vez
                ruim = c[:j] + str((int(c[j]) + 1 + volta % 9) % 10) + c[j + 1:]
                assert not h.cvv_verifica(k_b, pan, val, sc, ruim), \
                    "W2: aceitou %d (%s)" % (j, sc)
        # outra validade, outro PAN: a conta acompanha
        outra = "%04d" % ((int(val) + 1) % 10000)
        assert h.cvv_gera(k_b, pan, outra, "000") == \
            cvv.gera(k, pan, outra, "000"), "W0: outra validade"
        # modos, usos, comprimento e algoritmo
        so_v, _ = h.gen("C0", "V", "E", "T2")
        recusa(11, h.cvv_gera, so_v, pan, val, "000")
        so_g, _ = h.gen("C0", "G", "E", "T2")
        recusa(11, h.cvv_verifica, so_g, pan, val, "000", "123")
        tripla, _ = h.gen("C0", "C", "E", "T3")
        recusa(11, h.cvv_gera, tripla, pan, val, "000")
        aes, _ = h.gen("C0", "C", "E")
        recusa(11, h.cvv_gera, aes, pan, val, "000")
        pvk, _ = h.gen("V2", "C", "E", "T2")
        recusa(11, h.cvv_gera, pvk, pan, val, "000")
        # forma
        recusa(16, h.cvv_gera, k_b, pan[:11], val, "000")
        recusa(16, h.cvv_gera, k_b, pan, val[:3] + "A", "000")
        recusa(16, h.cvv_verifica, k_b, pan, val, "000", "12A")
        print("volta %d: W0 W2 conferidos (CVV, CVV2, iCVV; PAN de %d)"
              % (volta + 1, na))
    print("%d de %d voltas conferidas" % (n, n))
    return 0


def _dukpt_anexo():
    """O cabecalho e as transacoes de vectors/dukpt/x924_1_tdes.rsp."""
    cab, txs, atual = {}, [], {}
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                           "vectors", "dukpt", "x924_1_tdes.rsp")) as f:
        for ln in f:
            ln = ln.strip()
            if " = " not in ln or ln.startswith("#"):
                continue
            k, v = ln.split(" = ", 1)
            if k in ("BDK", "IKSN", "IPEK", "PINBLOCK", "PAN"):
                cab[k] = v
            elif k != "COUNT":
                atual[k] = bytes.fromhex(v)
                if k == "EPB":
                    txs.append(atual)
                    atual = {}
    return cab, txs


def dukpt_confere(h, lmk, n):
    """DUKPT TDES (P2, I0), conferido com o dukpt.py. O Python faz o papel do
    terminal (cifra o PIN sob a chave da transacao) e do outro lado da zona
    (abre o PIN block traduzido com a chave de zona em claro).

    Tambem leva a BDK do anexo A.4 da X9.24-1 para dentro do equipamento,
    por K6, e exige a IPEK e o PIN publicados.

    ⚠ PRECISA DA LMK, como o `confere`.
    ⚠ Os PANs sao inventados (prefixo 999999), menos o do anexo da norma,
    que e padrao de teste. Nenhum PAN real, nunca."""
    import dukpt
    import pinblock
    import tr31
    from hsmtool import _kcv_local

    d = h.diag()
    if d["kcv_lmk"] != _kcv_local(lmk).hex().upper():
        print("KCV da LMK nao confere: dispositivo %s, informada %s"
              % (d["kcv_lmk"], _kcv_local(lmk).hex().upper()))
        return 1

    def recusa(codigo, fn, *args):
        try:
            fn(*args)
        except HostErro as e:
            assert e.codigo == codigo, "%s: %d, esperado %d" % (
                fn.__name__, e.codigo, codigo)
        else:
            raise AssertionError("%s aceito, esperado %d"
                                 % (fn.__name__, codigo))

    def digitos(k):
        return "".join(str(b % 10) for b in os.urandom(k))

    def ksn_novo(uns):
        base = int.from_bytes(os.urandom(10), "big") & ~dukpt.CONTADOR_MASCARA
        bits = set()
        while len(bits) < uns:
            bits.add(os.urandom(1)[0] % 21)
        return (base | sum(1 << b for b in bits)).to_bytes(10, "big")

    # KEKs: uma AES, uma 3DES dupla, as duas so para embrulhar
    kek_a, _ = h.gen("K0", "E", "E")
    kek_t, _ = h.gen("K0", "E", "E", "T2")
    kek_a_c, _ = tr31.desembrulha(lmk, kek_a)
    kek_t_c, _ = tr31.desembrulha(lmk, kek_t)

    # 1. a BDK do anexo, por K6 sob uma KEK de importar
    cab, txs = _dukpt_anexo()
    kek_i, _ = h.gen("K0", "D", "E")
    kek_i_c, _ = tr31.desembrulha(lmk, kek_i)
    bdk_anexo = bytes.fromhex(cab["BDK"])
    bdk_a, _ = h.importa(kek_i, tr31.embrulha(kek_i_c, bdk_anexo, "B0", "T",
                                              "X", "E"))
    zona0, _ = h.gen("P0", "E", "E", "T2")
    zona0_c, _ = tr31.desembrulha(lmk, zona0)
    pan_anexo = cab["PAN"].rstrip("F")
    for t in (txs[0], txs[20], txs[21], txs[-1]):
        saida = h.dukpt_traduz(bdk_a, zona0, t["KSN"], pan_anexo, t["EPB"])
        assert pinblock.decifra0(zona0_c, saida, pan_anexo) == "1234", \
            "P2: PIN do anexo"
    b, kcv = h.ipek(kek_a, bdk_a, bytes.fromhex(cab["IKSN"]))
    ipek_c, c = tr31.desembrulha(kek_a_c, b)
    assert ipek_c.hex().upper() == cab["IPEK"], "I0: IPEK do anexo"
    assert (c["uso"], c["algoritmo"], c["modo"], c["exportabilidade"]) == \
        ("B1", "T", "X", "N"), "I0: cabecalho %r" % c
    print("anexo A.4: 4 transacoes traduzidas para PIN 1234, IPEK %s"
          % cab["IPEK"])

    for volta in range(n):
        bdk_b, _ = h.gen("B0", "X", "E", "T2")
        bdk, _ = tr31.desembrulha(lmk, bdk_b)
        na = 13 + volta % 7
        pan = "999999" + digitos(na - 6)
        pin = digitos(4 + volta % 9)
        ksn = ksn_novo(1 + volta % 10)
        epb = dukpt.cifra_pin(bdk, ksn, pinblock.claro0(pin, pan))
        # destino formato 0 (3DES) e 4 (AES)
        saida = h.dukpt_traduz(bdk_b, zona0, ksn, pan, epb, "00")
        assert pinblock.decifra0(zona0_c, saida, pan) == pin, "P2 00"
        zona4, _ = h.gen("P0", "E", "E")
        zona4_c, _ = tr31.desembrulha(lmk, zona4)
        saida = h.dukpt_traduz(bdk_b, zona4, ksn, pan, epb, "04")
        assert pinblock.decifra(zona4_c, saida, pan) == pin, "P2 04"
        # I0 sob as duas KEKs: versao D e versao B
        for kek, kek_c, versao in ((kek_a, kek_a_c, "D"), (kek_t, kek_t_c, "B")):
            b, kcv = h.ipek(kek, bdk_b, ksn)
            assert b[0] == versao, "I0: versao %s" % b[0]
            ipek_c, _ = tr31.desembrulha(kek_c, b)
            assert ipek_c == dukpt.ipek(bdk, ksn), "I0: IPEK"
            assert dukpt._tdes(ipek_c, bytes(8))[:3].hex().upper() == kcv, \
                "I0: KCV"
        # recusas
        ksn0 = ksn[:7] + bytes([ksn[7] & 0xE0, 0, 0])
        recusa(16, h.dukpt_traduz, bdk_b, zona0, ksn0, pan, epb)
        recusa(16, h.dukpt_traduz, bdk_b, zona0, ksn_novo(11), pan, epb)
        # Um bit trocado no PIN block: o Python diz se o bloco aberto ainda e
        # formato 0 valido (raro); se nao for, o equipamento tem de dar 14.
        outro = bytes([epb[0] ^ 0x01]) + epb[1:]
        try:
            pinblock.le_claro0(dukpt.decifra_pin(bdk, ksn, outro), pan)
        except pinblock.PinErro:
            recusa(14, h.dukpt_traduz, bdk_b, zona0, ksn, pan, outro)
        recusa(11, h.dukpt_traduz, bdk_b, zona0, ksn, pan, epb + bytes(8), "40")
        so_e, _ = h.gen("P0", "D", "E", "T2")          # destino que nao cifra
        recusa(11, h.dukpt_traduz, bdk_b, so_e, ksn, pan, epb)
        nao_x, _ = h.gen("B0", "B", "E", "T2")         # BDK sem modo X
        recusa(11, h.dukpt_traduz, nao_x, zona0, ksn, pan, epb)
        recusa(11, h.ipek, kek_a, nao_x, ksn)
        tripla, _ = h.gen("B0", "X", "E", "T3")        # BDK tripla
        recusa(11, h.dukpt_traduz, tripla, zona0, ksn, pan, epb)
        aes, _ = h.gen("B0", "X", "E")                 # BDK AES: origem 0
        recusa(11, h.dukpt_traduz, aes, zona0, ksn + bytes(2), pan, epb,
               "00", "2")
        recusa(11, h.dukpt_traduz, zona0, zona0, ksn, pan, epb)  # P0 como BDK
        recusa(13, h.ipek, zona0, bdk_b, ksn)          # P0 como KEK
        recusa(11, h.ipek, kek_i, bdk_b, ksn)          # KEK so de importar
        print("volta %d: P2 (00, 04) e I0 (D, B) conferidos, KSN com %d bit(s) 1"
              % (volta + 1, 1 + volta % 10))
    print("%d de %d voltas TDES conferidas" % (n, n))
    return dukpt_aes_confere(h, lmk, n, kek_a, kek_a_c, kek_t, kek_i, kek_i_c,
                             zona0, zona0_c, recusa, digitos)


def _dukpt_aes_vetores(nome):
    """O cabecalho e as transacoes de vectors/dukpt/x924_3_aes*.rsp."""
    cab, txs, atual = {}, [], None
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                           "vectors", "dukpt", nome)) as f:
        for ln in f:
            ln = ln.strip()
            if " = " not in ln or ln.startswith("#"):
                continue
            k, v = ln.split(" = ", 1)
            if k == "COUNT":
                atual = {}
                txs.append(atual)
            elif atual is None:
                cab[k] = bytes.fromhex(v)
            else:
                atual[k] = bytes.fromhex(v)
    return cab, txs


def dukpt_aes_confere(h, lmk, n, kek_a, kek_a_c, kek_t, kek_i, kek_i_c,
                      zona0, zona0_c, recusa, digitos):
    """DUKPT AES (P2, I0; etapa 8.8b), conferido com o dukpt.py. As BDKs AES
    entram por K6, sob uma KEK de importar: e como a BDK AES-128 chega aqui
    sem a cerimonia de componentes (que precisa dos botoes)."""
    import dukpt
    import pinblock
    import tr31

    def ksn_aes(uns):
        bits = set()
        while len(bits) < uns:
            bits.add(os.urandom(1)[0] % 32)
        return os.urandom(8) + sum(1 << b for b in bits).to_bytes(4, "big")

    def importa_bdk(bdk):
        b, _ = h.importa(kek_i, tr31.embrulha(kek_i_c, bdk, "B0", "A", "X", "E"))
        return b

    zona4, _ = h.gen("P0", "E", "E")
    zona4_c, _ = tr31.desembrulha(lmk, zona4)

    # 1. as BDKs dos valores de terceiros (X9.24-3), AES-128 e AES-256
    for nome, nb in (("x924_3_aes128.rsp", 16), ("x924_3_aes256.rsp", 32)):
        cab, txs = _dukpt_aes_vetores(nome)
        bdk_b = importa_bdk(cab["BDK"])
        b, kcv = h.ipek(kek_a, bdk_b, cab["IKID"] + bytes(4))
        ik, c = tr31.desembrulha(kek_a_c, b)
        assert ik == cab["IK"], "I0: IK de %s" % nome
        assert (c["uso"], c["algoritmo"], c["modo"], c["exportabilidade"]) == \
            ("B1", "A", "X", "N"), "I0: cabecalho %r" % c
        assert dukpt._aes_ecb(ik, bytes(16))[:3].hex().upper() == kcv, "I0: KCV"
        recusa(13, h.ipek, kek_t, bdk_b, cab["IKID"] + bytes(4))   # KEK 3DES
        if nb == 16:
            pan = "4111111111111111"       # o PAN de teste dos valores publicados
            assert pinblock.campo_pan(pan) == cab["PANFIELD"]
            pin = pinblock.le_campo_pin(cab["PINFIELD"])
            ok = 0
            for t in txs:
                if "EPB" in t:
                    saida = h.dukpt_traduz(bdk_b, zona4, t["KSN"], pan, t["EPB"],
                                           "44", "2")
                    assert pinblock.decifra(zona4_c, saida, pan) == pin, "P2 44"
                    ok += 1
            print("%s: IK %s; %d PIN blocks publicados traduzidos para PIN %s"
                  % (nome, cab["IK"].hex().upper(), ok, pin))
        else:
            print("%s: IK %s" % (nome, cab["IK"].hex().upper()))

    # 2. BDKs ao acaso, as quatro combinacoes de BDK e chave de trabalho
    for volta in range(n):
        nb = (16, 32)[volta % 2]
        nt = (16, 32)[(volta // 2) % 2]
        bdk = os.urandom(nb)
        bdk_b = importa_bdk(bdk)
        na = 13 + volta % 7
        pan = "999999" + digitos(na - 6)
        pin = digitos(4 + volta % 9)
        ksn = ksn_aes(1 + volta % 16)
        k = dukpt.aes_chave_pin(bdk, ksn, nt)
        epb = pinblock.cifra(k, pin, pan)
        tr = "2" if nt == 16 else "4"
        saida = h.dukpt_traduz(bdk_b, zona4, ksn, pan, epb, "44", tr)
        assert pinblock.decifra(zona4_c, saida, pan) == pin, "P2 44"
        saida = h.dukpt_traduz(bdk_b, zona0, ksn, pan, epb, "40", tr)
        assert pinblock.decifra0(zona0_c, saida, pan) == pin, "P2 40"
        b, kcv = h.ipek(kek_a, bdk_b, ksn)
        ik, _ = tr31.desembrulha(kek_a_c, b)
        assert ik == dukpt.aes_ik(bdk, ksn[:8]), "I0: IK"
        # recusas
        recusa(16, h.dukpt_traduz, bdk_b, zona4, ksn[:8] + bytes(4), pan, epb,
               "44", tr)
        recusa(16, h.dukpt_traduz, bdk_b, zona4, ksn[:8] + b"\x00\x01\xFF\xFF",
               pan, epb, "44", tr)                     # 17 bits 1
        recusa(16, h.dukpt_traduz, bdk_b, zona4, ksn, pan, epb, "44", "3")
        recusa(11, h.dukpt_traduz, bdk_b, zona0, ksn, pan, epb[:8], "00", tr)
        # Um bit trocado: se o Python ainda abrir um campo valido (raro), pula.
        outro = bytes([epb[0] ^ 0x01]) + epb[1:]
        try:
            pinblock.decifra(k, outro, pan)
        except pinblock.PinErro:
            recusa(14, h.dukpt_traduz, bdk_b, zona4, ksn, pan, outro, "44", tr)
        recusa(13, h.ipek, kek_t, bdk_b, ksn)
        print("volta %d: P2 (44, 40) e I0 conferidos, BDK AES-%d, trabalho "
              "AES-%d, KSN com %d bit(s) 1"
              % (volta + 1, nb * 8, nt * 8, 1 + volta % 16))
    # 3. AES-128 so na BDK: uma chave de dados AES-128 e recusada ao entrar.
    recusa(10, h.importa, kek_i, tr31.embrulha(kek_i_c, os.urandom(16), "D0",
                                               "A", "B", "E"))
    recusa(10, h.importa, kek_i, tr31.embrulha(kek_i_c, os.urandom(16), "B0",
                                               "A", "B", "E"))
    print("%d de %d voltas AES conferidas; AES-128 fora da BDK recusado"
          % (n, n))
    return 0


def pin_confere(h, lmk, n):
    """Traducao de PIN (P0), conferida com o pinblock.py. O Python faz o
    papel do terminal, que cifra o PIN sob a chave de origem, e o do
    destino, que abre o bloco traduzido.

    ⚠ PRECISA DA LMK, para abrir os blocos das duas chaves de PIN. E o
    brinquedo aparecendo, como no `confere`.
    ⚠ Os PANs sao inventados (prefixo 999999). Nenhum PAN real, nunca."""
    import pinblock
    import tr31
    from hsmtool import _kcv_local

    d = h.diag()
    if d["kcv_lmk"] != _kcv_local(lmk).hex().upper():
        print("KCV da LMK nao confere: dispositivo %s, informada %s"
              % (d["kcv_lmk"], _kcv_local(lmk).hex().upper()))
        return 1

    def recusa(codigo, *args):
        try:
            h.pin_traduz(*args)
        except HostErro as e:
            assert e.codigo == codigo, "P0: %d, esperado %d" % (e.codigo,
                                                                codigo)
        else:
            raise AssertionError("P0 aceito, esperado %d" % codigo)

    for volta in range(n):
        ko_b, _ = h.gen("P0", "B", "E")
        kd_b, _ = h.gen("P0", "B", "E")
        ko, _ = tr31.desembrulha(lmk, ko_b)
        kd, _ = tr31.desembrulha(lmk, kd_b)

        np = pinblock.PIN_MIN + volta % (pinblock.PIN_MAX - pinblock.PIN_MIN + 1)
        na = 12 + volta % 8
        pin = "".join(str(b % 10) for b in os.urandom(np))
        pan = "999999" + "".join(str(b % 10) for b in os.urandom(na - 6))

        entrada = pinblock.cifra(ko, pin, pan)
        saida = h.pin_traduz(ko_b, kd_b, pan, entrada)
        assert pinblock.decifra(kd, saida, pan) == pin, "P0: PIN mudou"
        outra = h.pin_traduz(ko_b, kd_b, pan, entrada)
        assert outra != saida, "P0: o aleatorio nao mudou"
        assert pinblock.decifra(kd, outra, pan) == pin, "P0: segunda saida"
        # e de volta, pela chave de destino
        volta_b = h.pin_traduz(kd_b, ko_b, pan, saida)
        assert pinblock.decifra(ko, volta_b, pan) == pin, "P0: volta"

        # recusas
        ruim = bytes([entrada[0] ^ 1]) + entrada[1:]
        recusa(14, ko_b, kd_b, pan, ruim)                  # bloco adulterado
        outro_pan = pan[:-1] + str((int(pan[-1]) + 1) % 10)
        recusa(14, ko_b, kd_b, outro_pan, entrada)         # PAN trocado
        recusa(14, kd_b, ko_b, pan, entrada)               # chave trocada
        dados_b, _ = h.gen("D0", "B", "E")
        recusa(11, dados_b, kd_b, pan, entrada)            # origem nao e P0
        recusa(11, ko_b, dados_b, pan, entrada)            # destino nao e P0
        so_e, _ = h.gen("P0", "E", "E")
        recusa(11, so_e, kd_b, pan, entrada)               # origem so cifra
        so_d, _ = h.gen("P0", "D", "E")
        recusa(11, ko_b, so_d, pan, entrada)               # destino so decifra
        adulterado = ko_b[:-1] + ("0" if ko_b[-1] != "0" else "1")
        recusa(10, adulterado, kd_b, pan, entrada)
        # a chave de PIN nao cifra dados
        try:
            h.cripto(ko_b, bytes(16), entrada, False)
        except HostErro as e:
            assert e.codigo == 11, "C2 com chave de PIN: %d" % e.codigo
        else:
            raise AssertionError("C2 aceitou uma chave de PIN")
        # ---- formato 0 (3DES), e a traducao entre formatos -------------
        import des
        na0 = 13 + volta % 7
        pan0 = "999999" + "".join(str(b % 10) for b in os.urandom(na0 - 6))
        to_b, _ = h.gen("P0", "B", "E", "T2" if volta % 2 else "T3")
        td_b, _ = h.gen("P0", "B", "E", "T3" if volta % 2 else "T2")
        to, _ = tr31.desembrulha(lmk, to_b)
        td, _ = tr31.desembrulha(lmk, td_b)
        e0 = pinblock.cifra0(to, pin, pan0)
        # 0 -> 0: sem aleatorio, o bloco de saida e previsivel
        s0 = h.pin_traduz(to_b, td_b, pan0, e0, "00")
        assert s0 == pinblock.cifra0(td, pin, pan0), "P0 00: bloco"
        assert h.pin_traduz(to_b, td_b, pan0, e0, "00") == s0, "P0 00: mudou"
        # 0 -> 4, e o caminho de volta 4 -> 0
        s4 = h.pin_traduz(to_b, kd_b, pan0, e0, "04")
        assert pinblock.decifra(kd, s4, pan0) == pin, "P0 04: PIN mudou"
        v0 = h.pin_traduz(kd_b, to_b, pan0, s4, "40")
        assert v0 == e0, "P0 40: bloco"
        # o digito verificador nao entra no formato 0
        outro_v = pan0[:-1] + str((int(pan0[-1]) + 1) % 10)
        assert h.pin_traduz(to_b, td_b, outro_v, e0, "00") == s0, "verificador"

        def recusa_f(codigo, formatos, *args):
            try:
                h.pin_traduz(*args, formatos)
            except HostErro as e:
                assert e.codigo == codigo, "P0 %s: %d, esperado %d" % (
                    formatos, e.codigo, codigo)
            else:
                raise AssertionError("P0 %s aceito, esperado %d"
                                     % (formatos, codigo))

        ruim0 = bytes([e0[0] ^ 1]) + e0[1:]
        recusa_f(14, "00", to_b, td_b, pan0, ruim0)        # bloco adulterado
        # O penultimo digito do PAN cai sob o ultimo nibble do campo, que e
        # sempre enchimento (o PIN tem no maximo 12 digitos, e ha 14 casas).
        outro0 = pan0[:-2] + str((int(pan0[-2]) + 1) % 10) + pan0[-1]
        recusa_f(14, "00", to_b, td_b, outro0, e0)         # PAN trocado
        recusa_f(11, "00", ko_b, td_b, pan0, e0)           # origem AES
        recusa_f(11, "00", to_b, kd_b, pan0, e0)           # destino AES
        recusa_f(11, "40", to_b, td_b, pan0, s4)           # origem 3DES, f. 4
        recusa_f(11, "04", to_b, td_b, pan0, e0)           # destino 3DES, f. 4
        d3_b, _ = h.gen("D0", "B", "E", "T2")
        recusa_f(11, "00", d3_b, td_b, pan0, e0)           # 3DES, mas nao P0
        recusa_f(16, "00", to_b, td_b, "999999012345", e0) # PAN de 12
        recusa_f(16, "10", to_b, td_b, pan0, e0)           # formato 1
        recusa_f(16, "03", to_b, td_b, pan0, e0)           # formato 3
        recusa_f(22, "00", to_b, td_b, pan0, e0 + b"\x00") # bloco longo
        print("volta %d: P0 conferido (PIN de %d, PAN de %d e de %d, "
              "formatos 4 e 0)" % (volta + 1, np, na, na0))
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
    p.add_argument("--alg", default="", choices=["", "A4", "T2", "T3"],
                   help="A4 = AES-256 (padrao), T2/T3 = 3DES duplo/triplo")
    p = sub.add_parser("check"); p.add_argument("bloco")
    for nome in ("export", "import"):
        p = sub.add_parser(nome); p.add_argument("kek"); p.add_argument("bloco")
    for nome in ("encrypt", "decrypt"):
        p = sub.add_parser(nome)
        p.add_argument("bloco"); p.add_argument("iv"); p.add_argument("dados")
    p = sub.add_parser("mac"); p.add_argument("bloco"); p.add_argument("dados")
    p = sub.add_parser("mac-verify")
    p.add_argument("bloco"); p.add_argument("mac"); p.add_argument("dados")
    p = sub.add_parser("rsa-verify")
    for c in ("n", "e", "digest", "s"):
        p.add_argument(c)
    p = sub.add_parser("rsa-cavp")
    p.add_argument("--lmk", default=None, help="LMK em hex (brinquedo)")
    p = sub.add_parser("rsa-sign"); p.add_argument("bloco"); p.add_argument("digest")
    p = sub.add_parser("rsa-gen"); p.add_argument("--exp", default="E", choices=list("ENS"))
    p = sub.add_parser("rsa-confere"); p.add_argument("-n", type=int, default=3)
    p = sub.add_parser("ecdsa-verify")
    for c in ("qx", "qy", "digest", "r", "s"):
        p.add_argument(c)
    p = sub.add_parser("ecdsa-cavp")
    p.add_argument("--lmk", default=None, help="LMK em hex (brinquedo)")
    p = sub.add_parser("ecdsa-sign"); p.add_argument("bloco"); p.add_argument("digest")
    p = sub.add_parser("ecdsa-gen"); p.add_argument("--exp", default="E", choices=list("ENS"))
    p = sub.add_parser("ecdsa-confere"); p.add_argument("-n", type=int, default=3)
    p = sub.add_parser("pkcs8-confere")
    p.add_argument("--lmk", required=True, help="LMK em hex (brinquedo)")
    p.add_argument("-n", type=int, default=3)
    p = sub.add_parser("tdes-confere")
    p.add_argument("--lmk", required=True, help="LMK em hex (brinquedo)")
    p.add_argument("-n", type=int, default=5)
    p = sub.add_parser("pin-traduz")
    for c in ("origem", "destino", "pan", "bloco"):
        p.add_argument(c)
    p.add_argument("--formatos", default="44",
                   help="origem e destino: 4 (AES) ou 0 (3DES); padrao 44")
    p = sub.add_parser("pin-confere")
    p.add_argument("--lmk", required=True, help="LMK em hex (brinquedo)")
    p.add_argument("-n", type=int, default=10)
    p = sub.add_parser("pinv-confere")
    p.add_argument("--lmk", required=True, help="LMK em hex (brinquedo)")
    p.add_argument("-n", type=int, default=10)
    p.add_argument("--tabela", default=None,
                   help="bloco de tabela autorizada que o console devolveu; "
                        "confere que o MAC e o que o Python calcula")
    p.add_argument("--kcv", default=None,
                   help="com --tabela: o KCV da chave V1 da tabela")
    p = sub.add_parser("dukpt-confere")
    p.add_argument("--lmk", required=True, help="LMK em hex (brinquedo)")
    p.add_argument("-n", type=int, default=10)
    p = sub.add_parser("cvv-confere")
    p.add_argument("--lmk", required=True, help="LMK em hex (brinquedo)")
    p.add_argument("-n", type=int, default=10)
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
            bloco, kcv = h.gen(a.uso, a.modo, a.exp, a.alg)
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
        elif a.cmd == "rsa-verify":
            ok = h.rsa_verifica(int(a.n, 16), int(a.e, 16),
                                bytes.fromhex(a.digest), int(a.s, 16))
            print("assinatura confere" if ok else "assinatura NAO confere")
            return 0 if ok else 1
        elif a.cmd == "rsa-cavp":
            return rsa_cavp(h, bytes.fromhex(a.lmk) if a.lmk else None)
        elif a.cmd == "rsa-gen":
            bloco, n, e = h.rsa_gera(a.exp)
            print(bloco)
            print("n %0512X" % n, file=sys.stderr)
            print("e %08X" % e, file=sys.stderr)
        elif a.cmd == "rsa-confere":
            return rsa_confere(h, a.n)
        elif a.cmd == "rsa-sign":
            print("%0512X" % h.rsa_assina(a.bloco, bytes.fromhex(a.digest)))
        elif a.cmd == "ecdsa-verify":
            ok = h.ecdsa_verifica(int(a.qx, 16), int(a.qy, 16),
                                  bytes.fromhex(a.digest), int(a.r, 16), int(a.s, 16))
            print("assinatura confere" if ok else "assinatura NAO confere")
            return 0 if ok else 1
        elif a.cmd == "ecdsa-cavp":
            return ecdsa_cavp(h, bytes.fromhex(a.lmk) if a.lmk else None)
        elif a.cmd == "ecdsa-gen":
            bloco, qx, qy = h.ecdsa_gera(a.exp)
            print(bloco)
            print("Qx %064X" % qx, file=sys.stderr)
            print("Qy %064X" % qy, file=sys.stderr)
        elif a.cmd == "ecdsa-confere":
            return ecdsa_confere(h, a.n)
        elif a.cmd == "ecdsa-sign":
            print("%064X %064X" % h.ecdsa_assina(a.bloco, bytes.fromhex(a.digest)))
        elif a.cmd == "pkcs8-confere":
            return pkcs8_confere(h, bytes.fromhex(a.lmk), a.n)
        elif a.cmd == "tdes-confere":
            return tdes_confere(h, bytes.fromhex(a.lmk), a.n)
        elif a.cmd == "pin-traduz":
            print(h.pin_traduz(a.origem, a.destino, a.pan,
                               bytes.fromhex(a.bloco),
                               a.formatos).hex().upper())
        elif a.cmd == "pin-confere":
            return pin_confere(h, bytes.fromhex(a.lmk), a.n)
        elif a.cmd == "dukpt-confere":
            return dukpt_confere(h, bytes.fromhex(a.lmk), a.n)
        elif a.cmd == "cvv-confere":
            return cvv_confere(h, bytes.fromhex(a.lmk), a.n)
        elif a.cmd == "pinv-confere":
            return pinv_confere(h, bytes.fromhex(a.lmk), a.n, a.tabela, a.kcv)
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
