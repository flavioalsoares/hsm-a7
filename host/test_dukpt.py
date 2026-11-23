#!/usr/bin/env python3
"""Teste de PC do DUKPT TDES (etapa 8.8a).

    python3 host/test_dukpt.py

O que ele prova:

  1. `host/dukpt.py` acha a IPEK, as 34 chaves de transacao e os 34 PIN
     blocks cifrados de vectors/dukpt/x924_1_tdes.rsp (X9.24-1:2009 A.4,
     sequencia inicial e a de rolagem do contador).
  2. `fw/src/dukpt.c`, compilado aqui com `gcc` junto com `des.c`, acha os
     mesmos valores. O DES do C e o de des.c; o do Python e o da biblioteca
     `cryptography`: os dois lados nao dividem o motor.
  3. C e Python dao a mesma IPEK e a mesma chave de PIN para 300 BDKs e KSNs
     ao acaso, com contadores de 1 a 10 bits 1.
  4. O C recusa o KSN de contador zero e o de 11 bits 1 ou mais, como o
     Python, e o contador que transborda os 21 bits nao muda a IPEK.
  5. O autoteste do firmware (dukpt_selftest(), parte do KAT do 3DES) passa.

O que ele NAO prova: a politica do key store (uso B0, modo X, chave de
zona) e os comandos P2 e I0. Isso e do `tb_dukpt`, com o firmware real.
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

import dukpt   # noqa: E402

falhas = 0


def check(nome, ok, detalhe=""):
    global falhas
    print("  %-4s %s%s" % ("ok" if ok else "ERRO", nome,
                           (" -- " + detalhe) if (detalhe and not ok) else ""))
    if not ok:
        falhas += 1


def le_rsp():
    cab, txs, atual = {}, [], {}
    with open(os.path.join(RAIZ, "vectors", "dukpt", "x924_1_tdes.rsp")) as f:
        for ln in f:
            ln = ln.strip()
            if " = " not in ln or ln.startswith("#"):
                continue
            k, v = ln.split(" = ", 1)
            if k in ("BDK", "IKSN", "IPEK", "PINBLOCK", "PAN"):
                cab[k] = bytes.fromhex(v)
            elif k != "COUNT":
                atual[k] = bytes.fromhex(v)
                if k == "EPB":
                    txs.append(atual)
                    atual = {}
    return cab, txs


def compila(d):
    so = os.path.join(d, "dukpt.so")
    src = os.path.join(RAIZ, "fw", "src")
    subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-Wno-unused-const-variable",
                    "-shared", "-fPIC", "-I", os.path.join(RAIZ, "fw", "include"),
                    os.path.join(src, "dukpt.c"), os.path.join(src, "des.c"),
                    os.path.join(src, "wipe.c"), "-o", so], check=True)
    return ctypes.CDLL(so)


def c_chama(lib, fn, bdk, ksn):
    saida = ctypes.create_string_buffer(16)
    r = getattr(lib, fn)(bdk, ksn, saida)
    return saida.raw if r == 0 else None


def ksn_ao_acaso(rnd, uns):
    base = bytes(rnd.randrange(256) for _ in range(10))
    bits = rnd.sample(range(21), uns)
    c = sum(1 << b for b in bits)
    v = (int.from_bytes(base, "big") & ~dukpt.CONTADOR_MASCARA) | c
    return v.to_bytes(10, "big")


def main():
    cab, txs = le_rsp()
    bdk = cab["BDK"]
    print("valores de terceiros (vectors/dukpt/x924_1_tdes.rsp)")
    check("34 transacoes no arquivo", len(txs) == 34, str(len(txs)))
    check("Python: IPEK", dukpt.ipek(bdk, cab["IKSN"]) == cab["IPEK"])
    ok_k = ok_e = True
    for t in txs:
        k = dukpt.chave_transacao(dukpt.ipek(bdk, t["KSN"]), t["KSN"])
        ok_k = ok_k and k == t["KEY"]
        ok_e = ok_e and dukpt.cifra_pin(bdk, t["KSN"], cab["PINBLOCK"]) == t["EPB"]
        ok_e = ok_e and dukpt.decifra_pin(bdk, t["KSN"], t["EPB"]) == cab["PINBLOCK"]
    check("Python: 34 chaves de transacao", ok_k)
    check("Python: 34 PIN blocks, cifra e decifra", ok_e)

    rnd = random.Random(88)
    with tempfile.TemporaryDirectory() as d:
        lib = compila(d)
        print("o C do firmware")
        check("C: IPEK", c_chama(lib, "dukpt_tdes_ipek", bdk, cab["IKSN"]) == cab["IPEK"])
        ok_k = ok_e = True
        for t in txs:
            ok_k = ok_k and c_chama(lib, "dukpt_tdes_chave_transacao", bdk,
                                    t["KSN"]) == t["KEY"]
            kp = c_chama(lib, "dukpt_tdes_chave_pin", bdk, t["KSN"])
            ok_e = ok_e and kp is not None and \
                dukpt._tdes(kp, cab["PINBLOCK"]) == t["EPB"]
        check("C: 34 chaves de transacao", ok_k)
        check("C: 34 chaves de PIN cifram o PIN block publicado", ok_e)
        check("dukpt_selftest() passa", lib.dukpt_selftest() == 0)

        print("C e Python, ao acaso")
        ok = True
        for i in range(300):
            b = bytes(rnd.randrange(256) for _ in range(16))
            ksn = ksn_ao_acaso(rnd, 1 + i % 10)
            ok = ok and c_chama(lib, "dukpt_tdes_ipek", b, ksn) == dukpt.ipek(b, ksn)
            ok = ok and c_chama(lib, "dukpt_tdes_chave_pin", b, ksn) == \
                dukpt.chave_pin(b, ksn)
        check("300 BDKs e KSNs (1 a 10 bits 1): IPEK e chave de PIN iguais", ok)

        print("KSN invalido")
        zero = ksn_ao_acaso(rnd, 1)
        zero = zero[:7] + bytes([zero[7] & 0xE0, 0, 0])
        onze = ksn_ao_acaso(rnd, 11)
        vinte1 = ksn_ao_acaso(rnd, 21)
        for nome, k in (("contador zero", zero), ("11 bits 1", onze),
                        ("21 bits 1", vinte1)):
            check("%s: C recusa, Python recusa" % nome,
                  lib.dukpt_ksn_valido(k) == 0 and not dukpt.ksn_valido(k) and
                  c_chama(lib, "dukpt_tdes_chave_pin", bdk, k) is None)
        dez = ksn_ao_acaso(rnd, 10)
        check("10 bits 1: aceito", lib.dukpt_ksn_valido(dez) == 1 and
              dukpt.ksn_valido(dez))
        # A IPEK so depende dos bits fora do contador.
        a = cab["IKSN"][:7] + bytes([cab["IKSN"][7] | 0x1F, 0xFF, 0xFF])
        check("IPEK ignora o contador",
              c_chama(lib, "dukpt_tdes_ipek", bdk, a) == cab["IPEK"])
    print()
    if falhas:
        print("FALHOU: %d" % falhas)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
