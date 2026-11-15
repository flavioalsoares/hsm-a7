#!/usr/bin/env python3
"""Testes do PKCS#8 do firmware, no PC, sem placa.

    python3 host/test_pkcs8.py

Compila fw/src/pkcs8.c com `gcc` e o confronta com a biblioteca
`cryptography`, que e a implementacao independente:

  1. O QUE O FIRMWARE MONTA, A BIBLIOTECA ABRE. Chave RSA-2048 e chave
     P-256 no formato interno viram DER; a biblioteca carrega o DER e
     devolve os mesmos numeros. O `d` do RSA, que o firmware calcula, tem
     de fechar e*d = 1 mod (p-1) e mod (q-1).

  2. O QUE A BIBLIOTECA MONTA, O FIRMWARE ABRE. DER gerado pela biblioteca
     vira o formato interno, campo a campo. Na curva, com e sem a chave
     publica.

  3. O DER E CANONICO: o que o firmware monta e, byte a byte, o que a
     biblioteca monta para a mesma chave.

  4. RECUSAS. DER truncado, com lixo no fim, com um byte trocado em cada
     posicao da estrutura, chave de outro tamanho, outra curva, comprimento
     em forma longa sem necessidade.

O que NAO se prova aqui: o caminho no equipamento (key block, comandos).
Quem prova e a simulacao e a placa.
"""

import ctypes
import os
import pathlib
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

RAIZ = pathlib.Path(__file__).resolve().parent.parent
FALHAS = []


def check(nome, ok, detalhe=""):
    if ok:
        print("  ok    %s" % nome)
    else:
        print("  FALHA %s %s" % (nome, detalhe))
        FALHAS.append(nome)


def der_de(chave):
    return chave.private_bytes(serialization.Encoding.DER,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())


def interna_rsa(k):
    n = k.private_numbers()
    b = lambda v: v.to_bytes(128, "big")
    return (n.public_numbers.e.to_bytes(4, "big") + b(n.p) + b(n.q)
            + b(n.dmp1) + b(n.dmq1) + b(n.iqmp))


def interna_ec(k):
    n = k.private_numbers()
    b = lambda v: v.to_bytes(32, "big")
    return b(n.private_value) + b(n.public_numbers.x) + b(n.public_numbers.y)


def main():
    with tempfile.TemporaryDirectory() as d:
        so = os.path.join(d, "pkcs8.so")
        subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-std=c99", "-shared", "-fPIC",
                        "-I", str(RAIZ / "fw" / "include"),
                        str(RAIZ / "fw" / "src" / "pkcs8.c"),
                        str(RAIZ / "fw" / "src" / "wipe.c"), "-o", so],
                       check=True)
        lib = ctypes.CDLL(so)
        return testes(lib)


def testes(lib):
    buf = ctypes.create_string_buffer(1400)
    n_out = ctypes.c_uint32(0)

    def rsa_monta(interna, n):
        r = lib.pkcs8_rsa_monta(interna, n, buf, 1222, ctypes.byref(n_out))
        return buf.raw[:n_out.value] if r == 0 else None

    def rsa_le(der):
        saida = ctypes.create_string_buffer(644)
        return saida.raw if lib.pkcs8_rsa_le(der, len(der), saida) == 0 else None

    def ec_monta(interna):
        r = lib.pkcs8_ec_monta(interna, buf, 138, ctypes.byref(n_out))
        return buf.raw[:n_out.value] if r == 0 else None

    def ec_le(der):
        saida = ctypes.create_string_buffer(96)
        tem = ctypes.c_int(0)
        if lib.pkcs8_ec_le(der, len(der), saida, ctypes.byref(tem)) != 0:
            return None, 0
        return saida.raw, tem.value

    print("RSA-2048")
    ok_abre = ok_d = ok_canon = ok_le = True
    maior = 0
    chaves = [rsa.generate_private_key(65537, 2048) for _ in range(6)]
    for k in chaves:
        nums = k.private_numbers()
        interna = interna_rsa(k)
        n = nums.public_numbers.n.to_bytes(256, "big")
        der = rsa_monta(interna, n)
        if der is None:
            ok_abre = False
            continue
        maior = max(maior, len(der))
        k2 = serialization.load_der_private_key(der, None).private_numbers()
        if (k2.p, k2.q, k2.dmp1, k2.dmq1, k2.iqmp, k2.public_numbers.n,
                k2.public_numbers.e) != (nums.p, nums.q, nums.dmp1, nums.dmq1,
                                         nums.iqmp, nums.public_numbers.n,
                                         nums.public_numbers.e):
            ok_abre = False
        if (65537 * k2.d) % (nums.p - 1) != 1 or (65537 * k2.d) % (nums.q - 1) != 1:
            ok_d = False
        # A biblioteca usa d mod lcm; o firmware, d mod (p-1)(q-1). Os dois
        # valem. O DER so e identico quando os dois d coincidem; por isso a
        # comparacao canonica troca o d da biblioteca pelo do firmware.
        ref = rsa.RSAPrivateNumbers(nums.p, nums.q, k2.d, nums.dmp1, nums.dmq1,
                                    nums.iqmp, nums.public_numbers).private_key(
                                        unsafe_skip_rsa_key_validation=True)
        if der_de(ref) != der:
            ok_canon = False
        if rsa_le(der_de(k)) != interna or rsa_le(der) != interna:
            ok_le = False
    check("o que o firmware monta, a biblioteca abre", ok_abre)
    check("o d calculado fecha com e", ok_d)
    check("o DER do firmware e o canonico, byte a byte", ok_canon)
    check("o que a biblioteca monta, o firmware abre", ok_le)
    check("o DER cabe no teto (%d de 1222 bytes)" % maior, 0 < maior <= 1222)

    k = chaves[0]
    der = der_de(k)
    check("truncado", all(rsa_le(der[:i]) is None
                          for i in (0, 1, 4, 30, len(der) - 1)))
    check("lixo no fim", rsa_le(der + b"\x00") is None)
    # Um byte trocado em cada posicao da ESTRUTURA (etiquetas, comprimentos,
    # versoes, OID). Trocar um byte de valor de inteiro da outra chave, que
    # o leitor nao tem como recusar.
    estrutura = list(range(0, 26)) + [26, 27, 28, 29, 30, 31, 32]
    ruins = 0
    for i in estrutura:
        m = bytearray(der)
        m[i] ^= 0x01
        if rsa_le(bytes(m)) is not None:
            ruins += 1
    check("byte de estrutura trocado e recusado (%d posicoes)" % len(estrutura),
          ruins == 0, "%d aceitos" % ruins)
    check("chave de 1024 bits recusada",
          rsa_le(der_de(rsa.generate_private_key(65537, 1024))) is None)
    check("chave de 3072 bits recusada",
          rsa_le(der_de(rsa.generate_private_key(65537, 3072))) is None)
    check("chave de curva no leitor de RSA",
          rsa_le(der_de(ec.generate_private_key(ec.SECP256R1()))) is None)
    check("e = 3 aceito",
          rsa_le(der_de(rsa.generate_private_key(3, 2048))) is not None)
    # comprimento em forma longa sem necessidade: 30 82 LL LL e valido; a
    # versao "02 01 00" reescrita como "02 81 01 00" nao e DER.
    i = der.index(b"\x02\x01\x00")
    nao_der = der[:i] + b"\x02\x81\x01\x00" + der[i + 3:]
    nao_der = nao_der[:2] + (int.from_bytes(nao_der[2:4], "big") + 1).to_bytes(2, "big") + nao_der[4:]
    check("comprimento em forma longa sem necessidade", rsa_le(nao_der) is None)
    interna = interna_rsa(k)
    n = k.private_numbers().public_numbers.n.to_bytes(256, "big")
    n_errado = (int.from_bytes(n, "big") - 2 ** 1030).to_bytes(256, "big")
    check("n que nao e p*q: nada sai",
          rsa_monta(interna, n_errado) is None)

    print("curva P-256")
    ok_abre = ok_canon = ok_le = ok_sem = True
    for _ in range(50):
        k = ec.generate_private_key(ec.SECP256R1())
        interna = interna_ec(k)
        der = ec_monta(interna)
        if der is None or interna_ec(serialization.load_der_private_key(der, None)) != interna:
            ok_abre = False
        if der != der_de(k):
            ok_canon = False
        if ec_le(der_de(k)) != (interna, 1):
            ok_le = False
        # sem a chave publica: so d, e o firmware avisa que falta Q
        d = interna[:32]
        sem = (bytes.fromhex("3041020100301306072A8648CE3D020106082A8648CE3D030107"
                             "0427302502010104 20".replace(" ", "")) + d)
        if ec_le(sem) != (d + bytes(64), 0):
            ok_sem = False
    check("o que o firmware monta, a biblioteca abre", ok_abre)
    check("o DER do firmware e o canonico, byte a byte (%d bytes)" % len(der),
          ok_canon)
    check("o que a biblioteca monta, o firmware abre", ok_le)
    check("sem chave publica: aceito, e avisa que falta Q", ok_sem)
    der = der_de(k)
    check("truncado", all(ec_le(der[:i])[0] is None
                          for i in (0, 5, 30, 70, len(der) - 1)))
    check("lixo no fim", ec_le(der + b"\x00")[0] is None)
    ruins = 0
    # 0..35: cabecalhos, versoes e OIDs, ate o comprimento de d. 36..67 e o
    # valor de d. 68..73: a etiqueta [1], o BIT STRING, o 00 e o 04.
    assert der[34:36] == b"\x04\x20" and der[68:74] == bytes.fromhex("a14403420004")
    estrutura = list(range(0, 36)) + [68, 69, 70, 71, 72, 73]
    for i in estrutura:
        m = bytearray(der)
        m[i] ^= 0x01
        if ec_le(bytes(m))[0] is not None:
            ruins += 1
    check("byte de estrutura trocado e recusado (%d posicoes)" % len(estrutura),
          ruins == 0, "%d aceitos" % ruins)
    check("outra curva (P-384) recusada",
          ec_le(der_de(ec.generate_private_key(ec.SECP384R1())))[0] is None)
    check("chave RSA no leitor de curva", ec_le(der_de(chaves[0]))[0] is None)

    print()
    if FALHAS:
        print("FALHOU: %d" % len(FALHAS))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
