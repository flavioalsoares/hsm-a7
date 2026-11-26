#!/usr/bin/env python3
"""Teste de PC do DUKPT TDES (etapa 8.8a) e do DUKPT AES (etapa 8.8b).

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

  6. DUKPT AES: o motor AES-128 do firmware (`fw/src/aes128.c`) acha os 568
     vetores ECB*128 do CAVP, nas duas direcoes.
  7. `host/dukpt.py` e o C acham a chave inicial, as 30 chaves de transacao e
     as chaves de PIN AES-128 e AES-256 de vectors/dukpt/x924_3_aes*.rsp, e
     os 8 PIN blocks formato 4 publicados abrem sob a chave de PIN AES-128.
  8. C e Python dao a mesma chave de PIN para 400 casos ao acaso (BDK de 16
     e de 32 bytes, chave de trabalho de 16 e de 32), e o C recusa o KSN de
     contador zero e o de 17 bits 1. dukpt_aes_selftest() passa.

  9. MAC e dados (etapa 8.9b): o Python e o C acham os 63 valores de
     vectors/dukpt/dukpt_mac_dados.rsp, de duas fontes: o MAC de pedido e de
     resposta e os dados cifrados do DUKPT TDES; as chaves de MAC e de dados
     do DUKPT AES, e o CMAC e os dados cifrados. C e Python dao as mesmas
     chaves de uso, o mesmo CMAC e o mesmo AES-CBC em casos ao acaso, com
     chave de trabalho AES-128 e AES-256.

No PC, o coprocessador AES-256 e trocado pela OpenSSL (um arquivo C de
apoio, compilado aqui): o caminho AES-256 do C so e provado com o
coprocessador real no `tb_dukpt_aes`.

O que ele NAO prova: a politica do key store (uso B0, modo X, chave de
zona) e os comandos P2 e I0. Isso e do `tb_dukpt` e do `tb_dukpt_aes`, com
o firmware real.
"""

import ctypes
import glob
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


# O coprocessador, no PC: AES-256 ECB pela OpenSSL. So para este teste.
CFS_PC = r"""
#include <stdint.h>
#include <openssl/evp.h>
#include "hsm_cfs.h"
static uint8_t g_k[32];
int hsm_cfs_aes_key(const uint8_t k[32])
{ for (int i = 0; i < 32; i++) g_k[i] = k[i]; return 0; }
int hsm_cfs_aes_block(const uint8_t in[16], uint8_t out[16], int enc)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l;
    EVP_CipherInit_ex(c, EVP_aes_256_ecb(), 0, g_k, 0, enc);
    EVP_CIPHER_CTX_set_padding(c, 0);
    EVP_CipherUpdate(c, out, &l, in, 16);
    EVP_CIPHER_CTX_free(c);
    return 0;
}
int hsm_cfs_wipe(void) { for (int i = 0; i < 32; i++) g_k[i] = 0; return 0; }
"""


def compila(d):
    so = os.path.join(d, "dukpt.so")
    src = os.path.join(RAIZ, "fw", "src")
    cfs = os.path.join(d, "cfs_pc.c")
    with open(cfs, "w") as f:
        f.write(CFS_PC)
    subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-Wno-unused-const-variable",
                    "-shared", "-fPIC", "-I", os.path.join(RAIZ, "fw", "include"),
                    os.path.join(src, "dukpt.c"), os.path.join(src, "des.c"),
                    os.path.join(src, "aes128.c"), os.path.join(src, "wipe.c"),
                    os.path.join(src, "mac_tdes.c"),
                    cfs, "-lcrypto", "-o", so], check=True)
    lib = ctypes.CDLL(so)
    lib.aes128_ctx_comum.restype = ctypes.c_void_p
    return lib


def le_rsp_aes(nome):
    cab, txs, atual = {}, [], None
    with open(os.path.join(RAIZ, "vectors", "dukpt", nome)) as f:
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


def le_cavp_aes128():
    """(chave, claro, cifrado, cifrar) dos quatro ECB*128 do CAVP."""
    vs = []
    for arq in sorted(glob.glob(os.path.join(RAIZ, "vectors", "aes", "ECB*128.rsp"))):
        sec, cur = None, {}
        for ln in open(arq):
            ln = ln.strip()
            if ln in ("[ENCRYPT]", "[DECRYPT]"):
                sec = ln
            elif " = " in ln:
                k, v = ln.split(" = ")
                cur[k] = v
                if k == ("CIPHERTEXT" if sec == "[ENCRYPT]" else "PLAINTEXT"):
                    vs.append((bytes.fromhex(cur["KEY"]), bytes.fromhex(cur["PLAINTEXT"]),
                               bytes.fromhex(cur["CIPHERTEXT"]), sec == "[ENCRYPT]"))
    return vs


def c_aes(lib, fn, n_saida, *args):
    saida = ctypes.create_string_buffer(n_saida)
    r = getattr(lib, fn)(*args, saida)
    return saida.raw if r == 0 else None


def _aes_ecb(chave, bloco, cifrar):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(chave), modes.ECB())
    o = c.encryptor() if cifrar else c.decryptor()
    return o.update(bloco) + o.finalize()


def teste_aes(lib, rnd):
    print("DUKPT AES: o motor AES-128 do firmware")
    ctx = ctypes.c_void_p(lib.aes128_ctx_comum())
    vs = le_cavp_aes128()
    ok = 0
    for k, p, c, cifrar in vs:
        o = ctypes.create_string_buffer(16)
        lib.aes128_prepara(ctx, k)
        lib.aes128_bloco(ctx, c if not cifrar else p, o, 1 if cifrar else 0)
        ok += o.raw == (c if cifrar else p)
    lib.aes128_apaga(ctx)
    check("568 vetores ECB*128 do CAVP (%d de %d)" % (ok, len(vs)),
          len(vs) == 568 and ok == 568)
    check("contexto apagado", ctypes.string_at(ctx.value, 176) == bytes(176))

    print("DUKPT AES: valores de terceiros (vectors/dukpt/x924_3_aes*.rsp)")
    for nome, nb in (("x924_3_aes128.rsp", 16), ("x924_3_aes256.rsp", 32)):
        cab, txs = le_rsp_aes(nome)
        bdk = cab["BDK"]
        okp = okc = True
        n_pin = n_epb = 0
        okp = okp and dukpt.aes_ik(bdk, cab["IKID"]) == cab["IK"]
        okc = okc and c_aes(lib, "dukpt_aes_ik", nb, bdk, nb,
                            cab["IKID"] + bytes(4)) == cab["IK"]
        for t in txs:
            okp = okp and dukpt.aes_chave_transacao(cab["IK"], t["KSN"]) == t["KEY"]
            okc = okc and c_aes(lib, "dukpt_aes_chave_transacao", nb, bdk, nb,
                                t["KSN"]) == t["KEY"]
            for campo, nt in (("PIN128", 16), ("PIN256", 32)):
                if campo in t:
                    n_pin += 1
                    okp = okp and dukpt.aes_chave_pin(bdk, t["KSN"], nt) == t[campo]
                    kc = c_aes(lib, "dukpt_aes_chave_pin", nt, bdk, nb, t["KSN"], nt)
                    okc = okc and kc == t[campo]
            if "EPB" in t:
                n_epb += 1
                k = t["PIN128"]
                meio = bytes(a ^ b for a, b in zip(_aes_ecb(k, t["EPB"], False),
                                                    cab["PANFIELD"]))
                okp = okp and _aes_ecb(k, meio, False) == cab["PINFIELD"]
        check("%s: Python, IK, %d chaves de transacao, %d chaves de PIN, "
              "%d PIN blocks" % (nome, len(txs), n_pin, n_epb), okp)
        check("%s: C, os mesmos valores" % nome, okc)
    check("dukpt_aes_selftest() passa", lib.dukpt_aes_selftest() == 0)

    print("DUKPT AES: C e Python, ao acaso")
    ok = True
    for i in range(400):
        nb = (16, 32)[i % 2]
        nt = (16, 32)[(i // 2) % 2]
        b = bytes(rnd.randrange(256) for _ in range(nb))
        bits = rnd.sample(range(32), 1 + i % 16)
        cnt = sum(1 << x for x in bits)
        ksn = bytes(rnd.randrange(256) for _ in range(8)) + cnt.to_bytes(4, "big")
        ok = ok and c_aes(lib, "dukpt_aes_chave_pin", nt, b, nb, ksn, nt) == \
            dukpt.aes_chave_pin(b, ksn, nt)
        ok = ok and c_aes(lib, "dukpt_aes_ik", nb, b, nb, ksn) == dukpt.aes_ik(b, ksn[:8])
    check("400 casos (BDK 16/32 x trabalho 16/32, 1 a 16 bits 1): iguais", ok)

    print("DUKPT AES: KSN invalido")
    base = bytes(rnd.randrange(256) for _ in range(8))
    for nome, cnt in (("contador zero", 0), ("17 bits 1", (1 << 17) - 1)):
        ksn = base + cnt.to_bytes(4, "big")
        check("%s: C recusa, Python recusa" % nome,
              lib.dukpt_aes_ksn_valido(ksn) == 0 and not dukpt.aes_ksn_valido(ksn) and
              c_aes(lib, "dukpt_aes_chave_pin", 16, bytes(16), 16, ksn, 16) is None)
    ksn = base + ((1 << 16) - 1).to_bytes(4, "big")
    check("16 bits 1: aceito", lib.dukpt_aes_ksn_valido(ksn) == 1 and
          dukpt.aes_ksn_valido(ksn))
    check("trabalho de 24 bytes: recusado",
          c_aes(lib, "dukpt_aes_chave_pin", 32, bytes(16), 16, ksn, 24) is None)


def le_mac_dados():
    secoes, msg, atual, reg = {}, None, None, None
    with open(os.path.join(RAIZ, "vectors", "dukpt", "dukpt_mac_dados.rsp")) as f:
        for ln in f:
            ln = ln.strip()
            if ln.startswith("[") and ln.endswith("]"):
                atual = secoes.setdefault(ln[1:-1], [])
                continue
            if " = " not in ln or ln.startswith("#"):
                continue
            k, v = ln.split(" = ", 1)
            if k == "MSG":
                msg = bytes.fromhex(v)
            elif k == "COUNT":
                reg = {}
                atual.append(reg)
            else:
                reg[k] = bytes.fromhex(v)
    return msg, secoes


def teste_mac_dados(lib, rnd):
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    print("MAC e dados com DUKPT (etapa 8.9b)")
    msg, sec = le_mac_dados()
    check("63 valores, cinco secoes",
          sum(len(v) for v in sec.values()) == 63 and len(sec) == 5)
    check("a mensagem e a das duas fontes", msg == b"4012345678909D987")
    bdk = le_rsp()[0]["BDK"]
    p24 = msg + bytes(24 - len(msg))
    p32 = msg + bytes(32 - len(msg))
    U = (dukpt.MAC_PEDIDO, dukpt.MAC_RESPOSTA, dukpt.DADOS_PEDIDO,
         dukpt.DADOS_RESPOSTA)

    def c_chave_t(b, ksn, uso):
        out = ctypes.create_string_buffer(16)
        r = lib.dukpt_tdes_chave_uso(b, ksn, ctypes.c_uint8(uso), out)
        return out.raw if r == 0 else None

    def c_rmac(chave, m):
        out = ctypes.create_string_buffer(8)
        r = lib.retail_mac(chave, ctypes.c_uint8(1), m, ctypes.c_uint32(len(m)), out)
        return out.raw if r == 0 else None

    for fonte, regs, tam in (("openemv TDES", sec["openemv TDES"], 4),
                             ("moov-io TDES", sec["moov-io TDES"], 8)):
        okp = okc = True
        for t in regs:
            k = t["KSN"]
            okp &= dukpt.mac(bdk, k, U[0], msg, tam) == t["REQMAC"]
            okp &= dukpt.mac(bdk, k, U[1], msg, tam) == t["RESMAC"]
            okp &= dukpt.dados(bdk, k, U[2], bytes(8), p24, True) == t["REQDATA"]
            okc &= (c_rmac(c_chave_t(bdk, k, U[0]), msg) or b"")[:tam] == t["REQMAC"]
            okc &= (c_rmac(c_chave_t(bdk, k, U[1]), msg) or b"")[:tam] == t["RESMAC"]
            kd = c_chave_t(bdk, k, U[2])
            okc &= kd is not None and dukpt._tdes(kd, p24[:8]) == \
                dukpt.dados(bdk, k, U[2], bytes(8), p24[:8], True)
            okc &= kd == dukpt.chave_uso(bdk, k, U[2])
            if "RESDATA" in t:
                okp &= dukpt.dados(bdk, k, U[3], bytes(8), p24, True) == t["RESDATA"]
                okc &= c_chave_t(bdk, k, U[3]) == dukpt.chave_uso(bdk, k, U[3])
        check("%s: %d transacoes, Python" % (fonte, len(regs)), okp)
        check("%s: %d transacoes, C (chave de uso e retail MAC)" % (fonte, len(regs)), okc)

    def c_chave_a(b, ksn, uso, nt):
        out = ctypes.create_string_buffer(nt)
        r = lib.dukpt_aes_chave_uso(b, ctypes.c_uint32(len(b)), ksn,
                                    ctypes.c_uint8(uso), ctypes.c_uint32(nt), out)
        return out.raw if r == 0 else None

    def c_cmac(chave, m):
        out = ctypes.create_string_buffer(16)
        r = lib.dukpt_aes_cmac(chave, ctypes.c_uint32(len(chave)), m,
                               ctypes.c_uint32(len(m)), out)
        return out.raw if r == 0 else None

    def c_cbc(chave, iv, d, cifrar):
        out = ctypes.create_string_buffer(len(d))
        r = lib.dukpt_aes_cbc(chave, ctypes.c_uint32(len(chave)), iv, d, out,
                              ctypes.c_uint32(len(d)), cifrar)
        return out.raw if r == 0 else None

    for nome, arq in (("BDK128", "x924_3_aes128.rsp"), ("BDK256", "x924_3_aes256.rsp")):
        b = le_rsp_aes(arq)[0]["BDK"]
        ok = True
        for t in sec["openemv AES " + nome]:
            for campo, uso, nt in (("MACKEY128", U[0], 16), ("MACKEY256", U[0], 32),
                                   ("DATAKEY128", U[2], 16), ("DATAKEY256", U[2], 32)):
                if campo in t:
                    ok &= dukpt.aes_chave_uso(b, t["KSN"], uso, nt) == t[campo]
                    ok &= c_chave_a(b, t["KSN"], uso, nt) == t[campo]
        check("openemv AES %s: chaves de MAC e de dados, Python e C" % nome, ok)

    b = le_rsp_aes("x924_3_aes128.rsp")[0]["BDK"]
    okp = okc = True
    for t in sec["moov-io AES BDK128"]:
        k = t["KSN"]
        okp &= dukpt.aes_mac(b, k, U[0], 16, msg) == t["CMACREQ"]
        okp &= dukpt.aes_mac(b, k, U[1], 16, msg) == t["CMACRES"]
        okp &= dukpt.aes_dados(b, k, U[2], 16, bytes(16), p32, True) == t["REQDATA"]
        okp &= dukpt.aes_dados(b, k, U[3], 16, bytes(16), p32, True) == t["RESDATA"]
        okc &= c_cmac(c_chave_a(b, k, U[0], 16), msg) == t["CMACREQ"]
        okc &= c_cmac(c_chave_a(b, k, U[1], 16), msg) == t["CMACRES"]
        okc &= c_cbc(c_chave_a(b, k, U[2], 16), bytes(16), p32, 1) == t["REQDATA"]
        okc &= c_cbc(c_chave_a(b, k, U[3], 16), bytes(16), p32, 1) == t["RESDATA"]
        okc &= c_cbc(c_chave_a(b, k, U[2], 16), bytes(16), t["REQDATA"], 0) == p32
    check("moov-io AES: 8 transacoes, CMAC e dados, Python", okp)
    check("moov-io AES: 8 transacoes, CMAC e dados, C (motor AES-128)", okc)

    ok = True
    for i in range(200):
        bt = bytes(rnd.randrange(256) for _ in range(16))
        ksn = ksn_ao_acaso(rnd, 1 + i % 10)
        for uso in U:
            ok &= c_chave_t(bt, ksn, uso) == dukpt.chave_uso(bt, ksn, uso)
    check("200 BDKs TDES ao acaso: as quatro chaves de uso iguais", ok)
    ok = True
    for i in range(200):
        nb, nt = (16, 32)[i % 2], (16, 32)[(i // 2) % 2]
        ba = bytes(rnd.randrange(256) for _ in range(nb))
        bits = rnd.sample(range(32), 1 + i % 16)
        ksn = bytes(rnd.randrange(256) for _ in range(8)) + \
            sum(1 << x for x in bits).to_bytes(4, "big")
        uso = U[i % 4]
        kc = c_chave_a(ba, ksn, uso, nt)
        ok &= kc == dukpt.aes_chave_uso(ba, ksn, uso, nt)
        m = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 70)))
        c = CMAC(algorithms.AES(kc)); c.update(m)
        ok &= c_cmac(kc, m) == c.finalize()
        d = bytes(rnd.randrange(256) for _ in range(16 * rnd.randint(1, 6)))
        iv = bytes(rnd.randrange(256) for _ in range(16))
        e = Cipher(algorithms.AES(kc), modes.CBC(iv)).encryptor()
        cif = e.update(d) + e.finalize()
        ok &= c_cbc(kc, iv, d, 1) == cif and c_cbc(kc, iv, cif, 0) == d
    check("200 casos AES ao acaso (BDK e trabalho de 16 e 32): chave, CMAC e CBC iguais", ok)
    out = ctypes.create_string_buffer(16)
    check("uso 4: recusado",
          lib.dukpt_tdes_chave_uso(bdk, le_rsp()[1][0]["KSN"], ctypes.c_uint8(4), out) != 0)


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
        teste_aes(lib, rnd)
        print()
        teste_mac_dados(lib, rnd)
    print()
    if falhas:
        print("FALHOU: %d" % falhas)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
