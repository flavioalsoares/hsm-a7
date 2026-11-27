#!/usr/bin/env python3
"""Teste de PC do ARQC e do ARPC (etapa 8.10).

    python3 host/test_emv.py

O que ele prova:

  1. `host/emv.py` acha os 18 casos de vectors/emv/arqc.rsp, de duas fontes
     (pyemv e jPOS): os KCVs da IMK, da MK e da chave de sessao quando a
     fonte os traz, o ARQC, e o ARPC metodo 1 e 2.
  2. `fw/src/emv.c`, compilado aqui com `gcc` junto com `des.c` e
     `mac_tdes.c`, acha os mesmos valores. O DES do C e o de des.c; o do
     Python e o da biblioteca `cryptography`: os dois lados nao dividem o
     motor.
  3. C e Python dao a mesma MK, a mesma chave de sessao, o mesmo ARQC e os
     mesmos ARPC em 500 casos ao acaso: PAN de 12 a 19 digitos, os dois
     esquemas, os dois preenchimentos, dados de 1 a 64 bytes, dado proprio
     de 0 a 8 bytes no ARPC 2.
  4. O C recusa PAN e PSN que nao sao digitos, PAN de 0 ou 20 digitos,
     preenchimento 3, mensagem vazia, esquema desconhecido e dado proprio de
     9 bytes.
  5. O autoteste do firmware (emv_selftest(), parte do KAT do 3DES) passa.

O que ele NAO prova: a politica do key store (uso E0, modo X, PAN de ate 16
digitos), a conferencia dupla e o comando A0 e o A2. Isso e do `tb_arqc`, com
o firmware real.
"""

import ctypes
import os
import random
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
sys.path.insert(0, AQUI)

import emv                 # noqa: E402
from des import kcv        # noqa: E402

falhas = 0


def check(nome, cond):
    global falhas
    if not cond:
        falhas += 1
        print("  FALHA:", nome)


def compila(d):
    so = os.path.join(d, "emv.so")
    src = os.path.join(RAIZ, "fw", "src")
    subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-Wno-unused-const-variable",
                    "-shared", "-fPIC", "-I", os.path.join(RAIZ, "fw", "include"),
                    os.path.join(src, "emv.c"), os.path.join(src, "des.c"),
                    os.path.join(src, "mac_tdes.c"), os.path.join(src, "wipe.c"),
                    "-o", so], check=True)
    return ctypes.CDLL(so)


def buf(n):
    return ctypes.create_string_buffer(n)


class C:
    def __init__(self, lib):
        self.lib = lib

    def mk(self, imk, pan, psn):
        out = buf(16)
        r = self.lib.emv_mk_opcao_a(imk, pan.encode(), len(pan), psn.encode(), out)
        return out.raw if r == 0 else None

    def csk(self, mk, r8):
        out = buf(16)
        return out.raw if self.lib.emv_csk(mk, r8, out) == 0 else None

    def chave(self, imk, pan, psn, atc, esq):
        out = buf(16)
        r = self.lib.emv_chave_ac(imk, pan.encode(), len(pan), psn.encode(), atc,
                                  esq, out)
        return out.raw if r == 0 else None

    def ac(self, k, dados, pad):
        out = buf(8)
        r = self.lib.emv_criptograma(k, dados, len(dados), pad, out)
        return out.raw if r == 0 else None

    def arpc1(self, k, arqc, arc):
        out = buf(8)
        return out.raw if self.lib.emv_arpc1(k, arqc, arc, out) == 0 else None

    def arpc2(self, k, arqc, csu, pad):
        out = buf(4)
        r = self.lib.emv_arpc2(k, arqc, csu, pad, len(pad), out)
        return out.raw if r == 0 else None


def confere_casos(c):
    H = bytes.fromhex
    casos = emv.le_rsp(os.path.join(RAIZ, "vectors", "emv", "arqc.rsp"))
    check("18 casos no .rsp", len(casos) == 18)
    fontes = {x["FONTE"].split()[0] for x in casos}
    check("duas fontes", fontes == {"pyemv", "jPOS"})
    for x in casos:
        nome = x["FONTE"]
        imk = H(x["IMK"])
        if "IMKKCV" in x:
            check(nome + " KCV da IMK", kcv(imk).hex().upper() == x["IMKKCV"])
        if "IMKKCV2" in x:
            check(nome + " KCV da IMK", kcv(imk)[:2].hex().upper() == x["IMKKCV2"])
        for lado, mk in (("py", emv.mk_opcao_a(imk, x["PAN"], x["PSN"])),
                         ("C", c.mk(imk, x["PAN"], x["PSN"]))):
            if "MKKCV2" in x:
                check(nome + " KCV da MK " + lado,
                      mk is not None and kcv(mk)[:2].hex().upper() == x["MKKCV2"])
            if x["ESQUEMA"] == "MK":
                k = mk
            else:
                r8 = H(x["R"]) if "R" in x else emv.r_do_atc(H(x["ATC"]))
                k = emv.csk(mk, r8) if lado == "py" else c.csk(mk, r8)
            if "SKKCV2" in x:
                check(nome + " KCV da sessao " + lado,
                      kcv(k)[:2].hex().upper() == x["SKKCV2"])
            if "ATC" in x:
                esq = 0 if x["ESQUEMA"] == "MK" else 1
                kk = (emv.chave_ac(imk, x["PAN"], x["PSN"], H(x["ATC"]), str(esq))
                      if lado == "py" else c.chave(imk, x["PAN"], x["PSN"], H(x["ATC"]), esq))
                check(nome + " chave do ATC " + lado, kk == k)
            pad = int(x["PAD"])
            a = (emv.criptograma(k, H(x["DADOS"]), pad) if lado == "py"
                 else c.ac(k, H(x["DADOS"]), pad))
            check(nome + " ARQC " + lado, a is not None and a.hex().upper() == x["ARQC"])
            if "ARPC1" in x:
                p = (emv.arpc1(k, a, H(x["ARC"])) if lado == "py"
                     else c.arpc1(k, a, H(x["ARC"])))
                check(nome + " ARPC1 " + lado, p.hex().upper() == x["ARPC1"])
            if "ARPC2" in x:
                p = (emv.arpc2(k, a, H(x["CSU"]), H(x["PAD_AUT"])) if lado == "py"
                     else c.arpc2(k, a, H(x["CSU"]), H(x["PAD_AUT"])))
                check(nome + " ARPC2 " + lado, p.hex().upper() == x["ARPC2"])


def ao_acaso(c, n=500):
    rnd = random.Random(810)
    for i in range(n):
        imk = bytes(rnd.getrandbits(8) for _ in range(16))
        pan = "999999" + "".join(rnd.choice("0123456789")
                                 for _ in range(rnd.randint(6, 13)))
        psn = "%02d" % rnd.randint(0, 99)
        atc = bytes(rnd.getrandbits(8) for _ in range(2))
        esq = rnd.randint(0, 1)
        pad = rnd.randint(1, 2)
        dados = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 64)))
        kp = emv.chave_ac(imk, pan, psn, atc, str(esq))
        kc = c.chave(imk, pan, psn, atc, esq)
        check("acaso %d chave" % i, kp == kc)
        check("acaso %d MK" % i, emv.mk_opcao_a(imk, pan, psn) == c.mk(imk, pan, psn))
        ap = emv.criptograma(kp, dados, pad)
        check("acaso %d ARQC" % i, ap == c.ac(kc, dados, pad))
        arc = bytes(rnd.getrandbits(8) for _ in range(2))
        check("acaso %d ARPC1" % i, emv.arpc1(kp, ap, arc) == c.arpc1(kc, ap, arc))
        csu = bytes(rnd.getrandbits(8) for _ in range(4))
        pa = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 8)))
        check("acaso %d ARPC2" % i, emv.arpc2(kp, ap, csu, pa) == c.arpc2(kc, ap, csu, pa))


def recusas(c):
    imk = bytes(range(16))
    check("PAN com letra", c.mk(imk, "99999912345678A0", "00") is None)
    check("PSN com letra", c.mk(imk, "9999991234567890", "0A") is None)
    check("PAN vazio", c.mk(imk, "", "00") is None)
    check("PAN de 20", c.mk(imk, "9" * 20, "00") is None)
    check("PAN de 19 aceito", c.mk(imk, "9" * 19, "00") is not None)
    k = c.chave(imk, "9999991234567890", "00", b"\x00\x01", 0)
    check("esquema 2", c.chave(imk, "9999991234567890", "00", b"\x00\x01", 2) is None)
    check("preenchimento 3", c.ac(k, b"abc", 3) is None)
    check("mensagem vazia", c.ac(k, b"", 1) is None)
    check("dado proprio de 9", c.arpc2(k, b"\0" * 8, b"\0" * 4, b"\0" * 9) is None)
    check("dado proprio de 8", c.arpc2(k, b"\0" * 8, b"\0" * 4, b"\0" * 8) is not None)


def main():
    with tempfile.TemporaryDirectory() as d:
        c = C(compila(d))
        confere_casos(c)
        ao_acaso(c)
        recusas(c)
        check("emv_selftest()", c.lib.emv_selftest() == 0)
    print("PASS" if falhas == 0 else "FAIL (%d)" % falhas)
    sys.exit(0 if falhas == 0 else 1)


if __name__ == "__main__":
    main()
