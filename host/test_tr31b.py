#!/usr/bin/env python3
"""Teste de PC do key block X9.143 versao B, sob KBPK 3DES (etapa 8.7).

    python3 host/test_tr31b.py

O que ele prova:

  1. `host/tr31.py` abre os 3 blocos da versao B de terceiros que este
     projeto aceita (vectors/tr31/x9143_B_TDES.rsp) e acha a chave publicada,
     e recusa os outros 3 (DES simples e blocos opcionais).
  2. `fw/src/tr31.c`, compilado aqui com `gcc` (com des.c e cmac_tdes.c, e o
     AES do coprocessador trocado por um esboco que sempre falha), faz o
     mesmo nos 6 blocos.
  3. C e Python dao o MESMO bloco, caractere a caractere, com o mesmo
     enchimento: KBPK dupla e tripla, chave dupla e tripla, os modos e os
     usos. Cada lado abre o bloco do outro.
  4. Um bit trocado em qualquer caractere de um bloco e recusado pelo C.
  5. O autoteste do firmware (tr31b_selftest(), parte do KAT do 3DES) passa.
  6. As subchaves da derivacao: C igual ao Python, e KBEK diferente de KBAK.

O que ele NAO prova: a politica do key store (quais chaves uma KEK 3DES
transporta) e os comandos K4/K6. Isso e do `tb_kek3`, com o firmware real.
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

import tr31   # noqa: E402

falhas = 0

ESBOCO = r"""
/* Esboco do coprocessador AES: a versao B nao o usa, e o teste prova isso,
 * porque toda chamada daqui falha. */
#include <stdint.h>
int hsm_cfs_aes_key(const uint8_t *k) { (void)k; return -1; }
int hsm_cfs_aes_block(const uint8_t *a, uint8_t *b, int c)
{ (void)a; (void)b; (void)c; return -1; }
int hsm_cfs_wipe(void) { return -1; }
int aes_cbc(const uint8_t *iv, const uint8_t *a, uint8_t *b, uint32_t n, int c)
{ (void)iv; (void)a; (void)b; (void)n; (void)c; return -1; }
int cmac_aes256(const uint8_t *k, const uint8_t *m, uint32_t n, uint8_t *t)
{ (void)k; (void)m; (void)n; (void)t; return -1; }
int cmac_aes256_verifica(const uint8_t *k, const uint8_t *m, uint32_t n,
                         const uint8_t *t)
{ (void)k; (void)m; (void)n; (void)t; return 0; }
"""


def check(nome, ok, detalhe=""):
    global falhas
    print("  %-4s %s%s" % ("ok" if ok else "ERRO", nome,
                           (" -- " + detalhe) if (detalhe and not ok) else ""))
    if not ok:
        falhas += 1


def le_blocos():
    blocos = []
    with open(os.path.join(RAIZ, "vectors", "tr31", "x9143_B_TDES.rsp")) as f:
        for parte in f.read().split("\n\n"):
            d = dict(x.split(" = ", 1) for x in parte.splitlines() if " = " in x)
            if "KB" in d:
                blocos.append(d)
    return blocos


class Cab(ctypes.Structure):
    _fields_ = [("uso", ctypes.c_uint8 * 2), ("algoritmo", ctypes.c_uint8),
                ("modo", ctypes.c_uint8), ("versao_chave", ctypes.c_uint8 * 2),
                ("exportabilidade", ctypes.c_uint8)]


def compila(d):
    esboco = os.path.join(d, "esboco.c")
    with open(esboco, "w") as f:
        f.write(ESBOCO)
    so = os.path.join(d, "tr31b.so")
    src = os.path.join(RAIZ, "fw", "src")
    subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-Wno-unused-function",
                    "-Wno-unused-const-variable", "-shared", "-fPIC",
                    "-I", os.path.join(RAIZ, "fw", "include"),
                    os.path.join(src, "tr31.c"), os.path.join(src, "cmac_tdes.c"),
                    os.path.join(src, "des.c"), os.path.join(src, "wipe.c"),
                    esboco, "-o", so], check=True)
    return ctypes.CDLL(so)


def c_abre(lib, kbpk, kb):
    kbek = ctypes.create_string_buffer(24)
    kbak = ctypes.create_string_buffer(24)
    if lib.tr31b_deriva(kbpk, len(kbpk), kbek, kbak) != 0:
        return None
    cab = Cab()
    chave = ctypes.create_string_buffer(32)
    n = ctypes.c_uint8(0)
    r = lib.tr31b_desembrulha(kbek, kbak, len(kbpk), kb.encode(), len(kb),
                              ctypes.byref(cab), chave, ctypes.byref(n))
    return chave.raw[:n.value] if r == 0 else None


def c_embrulha(lib, kbpk, chave, uso, modo, exp_, ench):
    kbek = ctypes.create_string_buffer(24)
    kbak = ctypes.create_string_buffer(24)
    assert lib.tr31b_deriva(kbpk, len(kbpk), kbek, kbak) == 0
    cab = Cab()
    cab.uso[0], cab.uso[1] = ord(uso[0]), ord(uso[1])
    cab.algoritmo, cab.modo = ord("T"), ord(modo)
    cab.versao_chave[0] = cab.versao_chave[1] = ord("0")
    cab.exportabilidade = ord(exp_)
    saida = ctypes.create_string_buffer(200)
    n = ctypes.c_uint32(0)
    r = lib.tr31b_embrulha(kbek, kbak, len(kbpk), ctypes.byref(cab), chave,
                           len(chave), ench, len(ench), saida, ctypes.byref(n))
    return saida.raw[:n.value].decode() if r == 0 else None


def main():
    blocos = le_blocos()
    aceitos = {"1", "2", "3"}
    print("blocos de terceiros (vectors/tr31/x9143_B_TDES.rsp)")
    check("6 blocos no arquivo", len(blocos) == 6)
    for b in blocos:
        kbpk = bytes.fromhex(b["KBPK"])
        try:
            k, _ = tr31.desembrulha(kbpk, b["KB"])
            py = k.hex().upper()
        except tr31.Tr31Erro:
            py = None
        if b["COUNT"] in aceitos:
            check("bloco %s: Python acha a chave" % b["COUNT"], py == b["KEY"])
        else:
            check("bloco %s: Python recusa" % b["COUNT"], py is None)

    rnd = random.Random(87)
    with tempfile.TemporaryDirectory() as d:
        lib = compila(d)
        print("o C do firmware")
        for b in blocos:
            k = c_abre(lib, bytes.fromhex(b["KBPK"]), b["KB"])
            if b["COUNT"] in aceitos:
                check("bloco %s: o C acha a chave" % b["COUNT"],
                      k is not None and k.hex().upper() == b["KEY"])
            else:
                check("bloco %s: o C recusa" % b["COUNT"], k is None)

        check("tr31b_selftest() passa", lib.tr31b_selftest() == 0)

        # derivacao
        ok = True
        for n in (16, 24):
            for _ in range(20):
                kbpk = bytes(rnd.randrange(256) for _ in range(n))
                kbek = ctypes.create_string_buffer(24)
                kbak = ctypes.create_string_buffer(24)
                lib.tr31b_deriva(kbpk, n, kbek, kbak)
                e, a = tr31.deriva_subchaves_b(kbpk)
                ok = ok and kbek.raw[:n] == e and kbak.raw[:n] == a and e != a
        check("subchaves: C igual ao Python, KBEK != KBAK (40 KBPKs)", ok)
        for n in (8, 32):
            r = lib.tr31b_deriva(bytes(n), n, ctypes.create_string_buffer(24),
                                 ctypes.create_string_buffer(24))
            check("KBPK de %d bytes recusada" % n, r == -1)

        # C e Python, mesmo enchimento, mesmo bloco
        print("C e Python dao o mesmo bloco")
        ok = cruzado = True
        casos = 0
        for nk in (16, 24):
            for nc in (16, 24):
                for uso, modo in (("K0", "B"), ("K0", "E"), ("K0", "D"),
                                  ("P0", "E"), ("M3", "C"), ("D0", "N")):
                    kbpk = bytes(rnd.randrange(256) for _ in range(nk))
                    chave = bytes(rnd.randrange(256) for _ in range(nc))
                    ench = bytes(rnd.randrange(256) for _ in range(8))
                    exp_ = rnd.choice("ENS")
                    bc = c_embrulha(lib, kbpk, chave, uso, modo, exp_, ench)
                    bp = tr31.embrulha(kbpk, chave, uso, "T", modo, exp_,
                                       enchimento=ench, versao="B")
                    ok = ok and bc == bp
                    cruzado = cruzado and c_abre(lib, kbpk, bp) == chave and \
                        tr31.desembrulha(kbpk, bc)[0] == chave
                    casos += 1
        check("%d blocos iguais caractere a caractere" % casos, ok)
        check("cada lado abre o bloco do outro", cruzado)

        # Um bit trocado em cada caractere.
        print("adulteracao")
        kbpk = bytes(rnd.randrange(256) for _ in range(24))
        chave = bytes(rnd.randrange(256) for _ in range(24))
        b = tr31.embrulha(kbpk, chave, "K0", "T", "B", "E", versao="B")
        recusas = 0
        for i in range(len(b)):
            ruim = b[:i] + chr(ord(b[i]) ^ 1) + b[i + 1:]
            recusas += c_abre(lib, kbpk, ruim) is None
        check("um bit trocado nas %d posicoes: %d recusas" % (len(b), recusas),
              recusas == len(b))
        check("bloco D recusado como B",
              c_abre(lib, kbpk, "D" + b[1:]) is None)
        outra = bytes(rnd.randrange(256) for _ in range(24))
        check("outra KBPK recusa", c_abre(lib, outra, b) is None)
    print()
    if falhas:
        print("FALHOU: %d" % falhas)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
