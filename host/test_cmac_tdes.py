#!/usr/bin/env python3
"""Teste de PC do CMAC-TDES (etapa 8.7).

    python3 host/test_cmac_tdes.py

O que ele prova:

  1. `fw/src/cmac_tdes.c`, compilado aqui com `gcc` junto com `des.c`, da a
     tag dos 192 vetores do NIST (vectors/cmac/CMACGenTDES2.rsp e
     CMACGenTDES3.rsp): chave dupla e tripla, mensagem vazia, incompleta e
     de blocos inteiros. Onde o vetor traz a tag truncada (Tlen 5 ou 7),
     compara os primeiros Tlen bytes, que e o que a norma define. O arquivo
     de chave dupla so tem tags truncadas; o de tripla tem 48 cheias.
  2. `host/tr31.py` (o CMAC da biblioteca `cryptography`) da as mesmas tags.
  3. A verificacao em C aceita a tag certa e recusa um bit trocado.
  4. Chave de 8 ou 32 bytes e recusada.

O que ele NAO prova: o uso do CMAC no key block (isso e de test_tr31.py e do
firmware real, no tb_kek3).
"""

import ctypes
import os
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
sys.path.insert(0, AQUI)

import tr31   # noqa: E402

falhas = 0


def check(nome, ok, detalhe=""):
    global falhas
    print("  %-4s %s%s" % ("ok" if ok else "ERRO", nome,
                           (" -- " + detalhe) if (detalhe and not ok) else ""))
    if not ok:
        falhas += 1


def le_rsp(nome):
    casos, reg = [], {}
    with open(os.path.join(RAIZ, "vectors", "cmac", nome)) as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or linha.startswith("["):
                if reg.get("Mac"):
                    casos.append(reg)
                    reg = {}
                continue
            if "=" in linha:
                k, v = [x.strip() for x in linha.split("=", 1)]
                reg[k] = v
    if reg.get("Mac"):
        casos.append(reg)
    return casos


def chave_de(v):
    k = bytes.fromhex(v["Key1"] + v["Key2"])
    if v["Klen"] == "3":
        k += bytes.fromhex(v["Key3"])
    elif v["Key3"] != v["Key1"]:
        raise SystemExit("vetor de 2 chaves com Key3 != Key1")
    return k


def main():
    with tempfile.TemporaryDirectory() as d:
        so = os.path.join(d, "cmac_tdes.so")
        src = os.path.join(RAIZ, "fw", "src")
        subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-shared", "-fPIC",
                        "-I", os.path.join(RAIZ, "fw", "include"),
                        os.path.join(src, "cmac_tdes.c"),
                        os.path.join(src, "des.c"),
                        os.path.join(src, "wipe.c"),
                        "-o", so], check=True)
        lib = ctypes.CDLL(so)
        tag = ctypes.create_string_buffer(8)

        # Tags cheias por arquivo, contadas no .rsp: o de duas chaves so traz
        # tags truncadas (Tlen 5 e 7). Os ultimos bytes da tag de chave
        # dupla sao cobertos pelos blocos versao B do psec (test_tr31.py),
        # cujo MAC de 8 bytes vem de KBPK dupla.
        cheios_esperados = {"CMACGenTDES2.rsp": 0, "CMACGenTDES3.rsp": 48}
        for arq in ("CMACGenTDES2.rsp", "CMACGenTDES3.rsp"):
            print(arq)
            casos = le_rsp(arq)
            check("96 vetores no arquivo", len(casos) == 96, str(len(casos)))
            ok_c = ok_py = True
            cheios = 0
            for v in casos:
                k = chave_de(v)
                mlen = int(v["Mlen"])
                msg = bytes.fromhex(v["Msg"])[:mlen]
                tlen = int(v["Tlen"])
                mac = bytes.fromhex(v["Mac"])
                r = lib.cmac_tdes(k, len(k), msg, mlen, tag)
                ok_c = ok_c and r == 0 and tag.raw[:tlen] == mac
                ok_py = ok_py and tr31.cmac_tdes(k, msg)[:tlen] == mac
                cheios += tlen == 8
            check("o C (cmac_tdes.c) da as tags", ok_c)
            check("o Python (cryptography) da as tags", ok_py)
            check("%d com a tag cheia de 8 bytes" % cheios,
                  cheios == cheios_esperados[arq])

        print("verificacao e recusas")
        v = [c for c in le_rsp("CMACGenTDES3.rsp") if c["Tlen"] == "8"][-1]
        k, msg = chave_de(v), bytes.fromhex(v["Msg"])[:int(v["Mlen"])]
        mac = bytes.fromhex(v["Mac"])
        check("tag certa confere", lib.cmac_tdes_verifica(k, 24, msg, len(msg),
                                                          mac) == 1)
        ruim = bytes([mac[0] ^ 1]) + mac[1:]
        check("um bit trocado na tag nao confere",
              lib.cmac_tdes_verifica(k, 24, msg, len(msg), ruim) == 0)
        ruim = mac[:7] + bytes([mac[7] ^ 0x80])
        check("o ultimo bit trocado nao confere",
              lib.cmac_tdes_verifica(k, 24, msg, len(msg), ruim) == 0)
        for n in (8, 32):
            check("chave de %d bytes recusada" % n,
                  lib.cmac_tdes(bytes(n), n, msg, len(msg), tag) == -1 and
                  tag.raw == bytes(8))
    print()
    if falhas:
        print("FALHOU: %d" % falhas)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
