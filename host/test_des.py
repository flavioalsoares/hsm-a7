#!/usr/bin/env python3
"""Testes do DES e do 3DES do lado do host, sem placa.

    python3 host/test_des.py

O que se prova aqui:

  1. OS VETORES DO NIST (vectors/tdes/, procedencia no MANIFEST). Os KATs
     da SP 800-20 exercitam cada permutacao, cada bit de chave e cada
     entrada das caixas S, em ECB e em CBC, cifrando e decifrando. Os MMT
     cobrem o 3DES de duas chaves e de tres, com varias mensagens.

  2. ACORDO COM UMA BIBLIOTECA INDEPENDENTE (`cryptography`), em chaves e
     dados ao acaso.

  3. PARIDADE E KCV.

O que NAO se prova aqui: o firmware. Quem prova e o KAT do firmware, com
os mesmos vetores, e os testes na simulacao e na placa.
"""

import os
import pathlib
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import des  # noqa: E402

VEC = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "tdes"
FALHAS = []


def check(nome, ok, detalhe=""):
    if ok:
        print("  ok    %s" % nome)
    else:
        print("  FALHA %s %s" % (nome, detalhe))
        FALHAS.append(nome)


def casos(arq):
    """[(modo, {campo: bytes})] de um .rsp do CAVP."""
    saida, modo, atual = [], None, {}
    for ln in (VEC / arq).read_text().splitlines():
        ln = ln.strip()
        if ln in ("[ENCRYPT]", "[DECRYPT]"):
            modo = ln.strip("[]")
            continue
        m = re.match(r"^(\w+) = (\w+)$", ln)
        if m and m[1] != "COUNT":
            atual[m[1]] = bytes.fromhex(m[2])
        elif not ln and atual:
            saida.append((modo, atual))
            atual = {}
    if atual:
        saida.append((modo, atual))
    return saida


def chave_de(c):
    if "KEYs" in c:
        return c["KEYs"] * 3
    return c["KEY1"] + c["KEY2"] + c["KEY3"]


def roda(arq):
    n, ok = 0, True
    for modo, c in casos(arq):
        k = chave_de(c)
        cifrar = modo == "ENCRYPT"
        entrada = c["PLAINTEXT"] if cifrar else c["CIPHERTEXT"]
        esperado = c["CIPHERTEXT"] if cifrar else c["PLAINTEXT"]
        if "IV" in c:
            r = des.tdes_cbc(k, c["IV"], entrada, cifrar)
        else:
            r = des.tdes_ecb(k, entrada, cifrar)
        ok = ok and (r == esperado)
        n += 1
    return n, ok


def main():
    print("vetores do NIST")
    total = 0
    for arq in sorted(p.name for p in VEC.glob("*.rsp")):
        n, ok = roda(arq)
        total += n
        check("%-18s %4d vetores" % (arq, n), ok and n > 0)
    print("  (%d vetores)" % total)

    print("contra a biblioteca cryptography")
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    ok = True
    for i in range(200):
        k = os.urandom(16 if i % 2 else 24)
        iv, d = os.urandom(8), os.urandom(8 * (1 + i % 5))
        ref = Cipher(TripleDES(k), modes.CBC(iv)).encryptor().update(d)
        if des.tdes_cbc(k, iv, d) != ref or des.tdes_cbc(k, iv, ref, False) != d:
            ok = False
    check("200 chaves ao acaso, duplas e triplas, CBC", ok)

    print("paridade e KCV")
    k = des.paridade_impar(os.urandom(24))
    check("paridade impar em todo byte", des.paridade_ok(k))
    check("chave sem paridade e detectada",
          not des.paridade_ok(bytes([k[0] ^ 1]) + k[1:]))
    check("a paridade nao muda a cifra",
          des.tdes_bloco(k, bytes(8))
          == des.tdes_bloco(bytes(b ^ 1 for b in k), bytes(8)))
    check("chave dupla = tripla com K3 = K1",
          des.tdes_bloco(k[:16], b"12345678")
          == des.tdes_bloco(k[:16] + k[:8], b"12345678"))
    check("KCV tem 3 bytes", len(des.kcv(k)) == 3)

    print()
    if FALHAS:
        print("FALHOU: %d" % len(FALHAS))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
