#!/usr/bin/env python3
"""Teste de PC do CVV, CVV2 e iCVV (etapa 8.6).

    python3 host/test_cvv.py

O que ele prova:

  1. `host/cvv.py` reproduz os 7 valores de terceiros de `vectors/cvv/cvv.rsp`,
     de tres fontes independentes (ver o MANIFEST para a procedencia). Onde a
     fonte traz o KCV da chave, ele confere com a chave lida do comentario.
  2. `fw/src/cvv.c`, compilado aqui com `gcc`, da o mesmo resultado que o
     Python: a montagem dos 16 bytes de entrada, para todo tamanho de PAN de
     12 a 19, e a extracao dos 3 digitos.
  3. A extracao em TODOS os formatos possiveis do resultado da cifra (de 0 a
     16 digitos decimais, em qualquer posicao). Os valores de terceiros nao
     cobrem o caso em que faltam decimais; ao acaso ele aparece em 1 bloco em
     18 113, e a conta exata dessa chance esta aqui.
  4. As recusas de forma: PAN curto ou longo, letra no PAN, na validade ou no
     codigo de servico, chave que nao e dupla.

O que ele NAO prova: a cifra (e o 3DES, que tem vetor do NIST e teste
proprio), o key store, o modo da chave e os comandos W0 e W2. Isso e do
`tb_cvv`, com o firmware real.
"""

import ctypes
import os
import random
import subprocess
import sys
import tempfile
from fractions import Fraction
from math import comb

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
sys.path.insert(0, AQUI)

import cvv   # noqa: E402
import des   # noqa: E402

falhas = 0


def check(nome, ok, detalhe=""):
    global falhas
    print("  %-4s %s%s" % ("ok" if ok else "ERRO", nome,
                           (" -- " + detalhe) if (detalhe and not ok) else ""))
    if not ok:
        falhas += 1


def le_vetores():
    casos, reg, fonte = [], {}, None
    with open(os.path.join(RAIZ, "vectors", "cvv", "cvv.rsp")) as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                if reg:
                    reg["fonte"] = fonte
                    casos.append(reg)
                    reg = {}
                continue
            if linha.startswith("#"):
                fonte = linha[1:].strip()
                continue
            k, v = [x.strip() for x in linha.split("=", 1)]
            reg[k] = v
    if reg:
        reg["fonte"] = fonte
        casos.append(reg)
    return casos


def terceiros():
    print("valores de terceiros (vectors/cvv/cvv.rsp)")
    casos = le_vetores()
    check("7 valores no arquivo", len(casos) == 7, str(len(casos)))
    for v in casos:
        k = bytes.fromhex(v["KEY"])
        if "KCV" in v:
            esperado = v["KCV"].split("/")
            metades = [k] if len(esperado) == 1 else [k[:8], k[8:]]
            calc = [des.kcv(m if len(m) == 16 else m + m).hex().upper()
                    for m in metades]
            check("%s: KCV da chave lida do comentario" % v["fonte"],
                  calc == esperado, "%s, fonte %s" % (calc, esperado))
        c = cvv.gera(k, v["PAN"], v["EXP"], v["SC"])
        check("%s: codigo %s -> %s" % (v["fonte"], v["SC"], v["CVV"]),
              c == v["CVV"], "calculado %s" % c)
        errado = "%03d" % ((int(v["CVV"]) + 1) % 1000)
        check("%s: um CVV errado nao confere" % v["fonte"],
              not cvv.confere(k, v["PAN"], v["EXP"], v["SC"], errado))


def recusas():
    print("recusas de forma")
    k = bytes(16)
    ruins = [("PAN de 11", ("99999901234", "2812", "101")),
             ("PAN de 20", ("99999901234567890123", "2812", "101")),
             ("letra no PAN", ("99999901234567A9", "2812", "101")),
             ("validade de 3", ("9999990123456789", "281", "101")),
             ("letra na validade", ("9999990123456789", "28A2", "101")),
             ("codigo de 4", ("9999990123456789", "2812", "1010")),
             ("letra no codigo", ("9999990123456789", "2812", "10A"))]
    for nome, args in ruins:
        try:
            cvv.gera(k, *args)
            check(nome + " recusado", False, "aceito")
        except cvv.CvvErro:
            check(nome + " recusado", True)
    for n in (8, 24):
        try:
            cvv.cifra(bytes(n), bytes(16))
            check("chave de %d bytes recusada" % n, False, "aceita")
        except cvv.CvvErro:
            check("chave de %d bytes recusada" % n, True)


def c_do_firmware():
    print("o C do firmware contra o Python")
    rnd = random.Random(86)
    with tempfile.TemporaryDirectory() as d:
        so = os.path.join(d, "cvv.so")
        subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-shared", "-fPIC",
                        "-I", os.path.join(RAIZ, "fw", "include"),
                        os.path.join(RAIZ, "fw", "src", "cvv.c"),
                        "-o", so], check=True)
        lib = ctypes.CDLL(so)

        def vals(s):
            return bytes(int(c) for c in s)

        # montagem da entrada, todo tamanho de PAN
        ok = True
        saida = ctypes.create_string_buffer(16)
        n_casos = 0
        for n in range(12, 20):
            for _ in range(200):
                pan = "999999" + "".join(rnd.choice("0123456789")
                                         for _ in range(n - 6))
                val = "".join(rnd.choice("0123456789") for _ in range(4))
                sc = rnd.choice(["101", "201", "000", "999"] +
                                ["".join(rnd.choice("0123456789")
                                         for _ in range(3))])
                r = lib.cvv_dados(pan.encode(), n, val.encode(), sc.encode(),
                                  saida)
                ok = ok and r == 0 and saida.raw == cvv.dados(pan, val, sc)
                n_casos += 1
        check("entrada: %d casos, PAN de 12 a 19" % n_casos, ok)

        ok = True
        for pan, val, sc in (("99999901234", "2812", "101"),
                             ("99999901234567890123", "2812", "101"),
                             ("99999901234567A9", "2812", "101"),
                             ("9999990123456789", "28A2", "101"),
                             ("9999990123456789", "2812", "10/")):
            r = lib.cvv_dados(pan.encode(), len(pan), val.encode(),
                              sc.encode(), saida)
            ok = ok and r == -1
        check("entrada: as mesmas recusas do Python (-1)", ok)

        # Extracao. Ao acaso quase nunca faltam decimais, entao os casos sao
        # construidos: toda quantidade de decimais, de 0 a 16, em posicoes
        # sorteadas.
        ok = True
        tres = ctypes.create_string_buffer(3)
        casos = 0
        for nd in range(17):
            for _ in range(300):
                pos = set(rnd.sample(range(16), nd))
                h = "".join(rnd.choice("0123456789") if i in pos
                            else rnd.choice("abcdef") for i in range(16))
                c = bytes.fromhex(h)
                lib.cvv_extrai(c, tres)
                ok = ok and tres.raw == vals(cvv.extrai(c))
                casos += 1
        for _ in range(5000):
            c = bytes(rnd.randrange(256) for _ in range(8))
            lib.cvv_extrai(c, tres)
            ok = ok and tres.raw == vals(cvv.extrai(c))
        check("extracao (%d construidos, de 0 a 16 decimais, e 5000 ao "
              "acaso)" % casos, ok)
        # casos a mao, para o leitor
        lib.cvv_extrai(bytes.fromhex("abcdefabcdefabcd"), tres)
        check("ABCDEF... da 012 (so letras)", tres.raw == vals("012"))
        lib.cvv_extrai(bytes.fromhex("f1eddddddddddd3d"), tres)
        check("F1ED...D3D da 135 (dois decimais, a primeira letra completa)",
              tres.raw == vals("135"))


def chance():
    print("a chance de faltar decimal")
    # Cada digito hexadecimal da cifra e decimal com chance 10/16. Faltam
    # decimais quando ha 0, 1 ou 2 entre os 16.
    p = sum(comb(16, k) * Fraction(10, 16) ** k * Fraction(6, 16) ** (16 - k)
            for k in range(3))
    check("P(menos de 3 decimais) = 1 em %d" % round(1 / p),
          round(1 / p) == 18113)


def main():
    terceiros()
    recusas()
    c_do_firmware()
    chance()
    print()
    if falhas:
        print("FALHOU: %d" % falhas)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
