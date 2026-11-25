#!/usr/bin/env python3
"""Teste de PC do retail MAC e do 3DES-CBC de dados (etapa 8.9a).

    python3 host/test_retail_mac.py

O que ele prova:

  1. `host/mac_tdes.py` reproduz os 6 valores de terceiros de
     `vectors/mac/retail_mac.rsp`, de duas fontes independentes (ver o
     MANIFEST), e um MAC com um bit trocado na mensagem muda.
  2. `host/mac_tdes.py` reproduz o 3DES-CBC dos vetores MMT do NIST
     (`vectors/tdes/TCBCMMT2.rsp` e `TCBCMMT3.rsp`), cifrar e decifrar.
  3. `fw/src/mac_tdes.c`, compilado aqui com `gcc` junto com `des.c`, da o
     mesmo MAC que o Python: os 6 valores, e 2000 casos ao acaso com mensagem
     de 1 a 160 bytes (o limite de dados da porta host), nos dois
     preenchimentos, com chave K = K' inclusive.
  4. As recusas: mensagem vazia, preenchimento 0 e 3, e (no Python) chave que
     nao e dupla e tamanho que nao e 4 nem 8.

O que ele NAO prova: o key store, o uso e o modo da chave, a dupla execucao e
os comandos M0, M2, C0 e C2. Isso e do `tb_mac3`, com o firmware real.
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

import mac_tdes   # noqa: E402

falhas = 0


def check(nome, ok, detalhe=""):
    global falhas
    print("  %-4s %s%s" % ("ok" if ok else "ERRO", nome,
                           (" -- " + detalhe) if (detalhe and not ok) else ""))
    if not ok:
        falhas += 1


def le_rsp(caminho):
    casos, reg, fonte = [], {}, None
    with open(caminho) as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("["):
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


def vetores():
    return le_rsp(os.path.join(RAIZ, "vectors", "mac", "retail_mac.rsp"))


def terceiros():
    print("valores de terceiros (vectors/mac/retail_mac.rsp)")
    casos = vetores()
    check("6 valores no arquivo", len(casos) == 6, str(len(casos)))
    for v in casos:
        k, m = bytes.fromhex(v["KEY"]), bytes.fromhex(v["MSG"])
        esperado = bytes.fromhex(v["MAC"])
        calc = mac_tdes.retail_mac(k, m, int(v["PAD"]), len(esperado))
        check("%s: PAD %s, %d bytes de mensagem, MAC de %d" % (
            v["fonte"], v["PAD"], len(m), len(esperado)), calc == esperado,
            "calculado %s" % calc.hex().upper())
        trocada = bytes([m[0] ^ 1]) + m[1:]
        check("%s: um bit trocado muda o MAC" % v["fonte"],
              mac_tdes.retail_mac(k, trocada, int(v["PAD"]),
                                  len(esperado)) != esperado)


def nist_cbc():
    print("3DES-CBC contra os MMT do NIST (vectors/tdes)")
    for nome, n_chaves in (("TCBCMMT2.rsp", 2), ("TCBCMMT3.rsp", 3)):
        casos = le_rsp(os.path.join(RAIZ, "vectors", "tdes", nome))
        ok, total = True, 0
        for v in casos:
            if "KEY1" not in v:
                continue
            k = bytes.fromhex(v["KEY1"] + v["KEY2"] + v["KEY3"])
            if n_chaves == 2:
                k = k[:16]
            iv = bytes.fromhex(v["IV"])
            p, c = bytes.fromhex(v["PLAINTEXT"]), bytes.fromhex(v["CIPHERTEXT"])
            ok &= mac_tdes.cbc(k, iv, p, True) == c
            ok &= mac_tdes.cbc(k, iv, c, False) == p
            total += 1
        check("%s: %d vetores, cifrar e decifrar" % (nome, total),
              ok and total > 0)


def recusas():
    print("recusas (Python)")
    ruins = [("mensagem vazia", (bytes(16), b"", 1, 8)),
             ("preenchimento 3", (bytes(16), b"x", 3, 8)),
             ("preenchimento 0", (bytes(16), b"x", 0, 8)),
             ("tamanho 5", (bytes(16), b"x", 1, 5)),
             ("chave de 24 bytes", (bytes(24), b"x", 1, 8)),
             ("chave de 8 bytes", (bytes(8), b"x", 1, 8))]
    for nome, args in ruins:
        try:
            mac_tdes.retail_mac(*args)
            check(nome + " recusado", False, "aceito")
        except mac_tdes.MacErro:
            check(nome + " recusado", True)


def c_do_firmware():
    print("o C do firmware contra o Python")
    rnd = random.Random(89)
    fw = os.path.join(RAIZ, "fw")
    with tempfile.TemporaryDirectory() as d:
        so = os.path.join(d, "mac_tdes.so")
        subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-shared",
                        "-fPIC", "-I", os.path.join(fw, "include"),
                        os.path.join(fw, "src", "mac_tdes.c"),
                        os.path.join(fw, "src", "des.c"),
                        os.path.join(fw, "src", "wipe.c"),
                        "-o", so], check=True)
        lib = ctypes.CDLL(so)
        saida = ctypes.create_string_buffer(8)

        def c_mac(k, m, metodo):
            r = lib.retail_mac(k, ctypes.c_uint8(metodo), m,
                               ctypes.c_uint32(len(m)), saida)
            return None if r != 0 else saida.raw

        ok = True
        for v in vetores():
            k, m = bytes.fromhex(v["KEY"]), bytes.fromhex(v["MSG"])
            esperado = bytes.fromhex(v["MAC"])
            calc = c_mac(k, m, int(v["PAD"]))
            ok &= calc is not None and calc[:len(esperado)] == esperado
        check("os 6 valores de terceiros", ok)

        ok, n_casos = True, 0
        for _ in range(2000):
            k = os.urandom(8)
            k = k + (k if rnd.random() < 0.05 else os.urandom(8))
            n = rnd.randint(1, 160)
            m = bytes(rnd.getrandbits(8) for _ in range(n))
            metodo = rnd.choice((1, 2))
            ok &= c_mac(k, m, metodo) == mac_tdes.retail_mac(k, m, metodo, 8)
            n_casos += 1
        check("%d casos ao acaso, 1 a 160 bytes, preenchimentos 1 e 2"
              % n_casos, ok)

        ok = True
        for n in range(1, 41):
            for metodo in (1, 2):
                k, m = os.urandom(16), os.urandom(n)
                ok &= c_mac(k, m, metodo) == mac_tdes.retail_mac(k, m, metodo)
        check("todo tamanho de 1 a 40 bytes (bordas de bloco)", ok)

        check("C recusa mensagem vazia",
              lib.retail_mac(bytes(16), ctypes.c_uint8(1), b"x",
                             ctypes.c_uint32(0), saida) == -1)
        for metodo in (0, 3):
            check("C recusa preenchimento %d" % metodo,
                  lib.retail_mac(bytes(16), ctypes.c_uint8(metodo), b"x",
                                 ctypes.c_uint32(1), saida) == -1)


def main():
    terceiros()
    nist_cbc()
    recusas()
    c_do_firmware()
    print()
    print("PASS" if falhas == 0 else "FAIL: %d" % falhas)
    return 0 if falhas == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
