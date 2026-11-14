#!/usr/bin/env python3
"""Testes do PIN block ISO 9564-1 formato 4 do lado do host, sem placa.

    python3 host/test_pinblock.py

O que se prova aqui:

  1. OS VALORES DE TERCEIROS. O campo do PIN, o campo do PAN e um bloco
     cifrado completo, de vectors/pinblock/. Sao os unicos numeros deste
     teste que nao vieram deste projeto. Procedencia em
     vectors/MANIFEST.txt: fonte secundaria, e a chave e AES-128.

  2. IDA E VOLTA com AES-256, a chave que o equipamento usa, para todo
     tamanho de PIN e de PAN.

  3. QUE O PAN AMARRA O BLOCO. Abrir com outro PAN tem de falhar no
     formato.

  4. QUE O FORMATO E CONFERIDO. Controle, tamanho, digito e enchimento
     errados sao recusados.

  5. QUE O ALEATORIO MUDA O BLOCO. O mesmo PIN cifrado duas vezes da dois
     blocos diferentes.

  6. QUE O C DO FIRMWARE CONCORDA NO FORMATO. fw/src/pinblock.c, que nao
     tem chave nem cifra, e compilado aqui com `gcc` e comparado com o
     Python: o campo do PAN para todo tamanho, e a conferencia do campo do
     PIN para campos validos e para campos com um nibble trocado.

O que NAO se prova aqui: a cifra no firmware. Quem prova isso e o
`tb_pin`, que roda o C de verdade no processador.
"""

import ctypes
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pinblock  # noqa: E402

RAIZ = pathlib.Path(__file__).resolve().parent.parent
VETOR = RAIZ / "vectors" / "pinblock" / "iso9564_f4.rsp"

FALHAS = []


def check(nome, ok, detalhe=""):
    if ok:
        print("  ok    %s" % nome)
    else:
        print("  FALHA %s %s" % (nome, detalhe))
        FALHAS.append(nome)


def recusa(nome, fn):
    """Passa se `fn` levantar PinErro. Aceitar em silencio e a falha."""
    try:
        fn()
    except pinblock.PinErro:
        print("  ok    %s -- recusado" % nome)
        return
    except Exception as e:                      # noqa: BLE001
        print("  FALHA %s -- excecao errada: %r" % (nome, e))
        FALHAS.append(nome)
        return
    print("  FALHA %s -- aceito" % nome)
    FALHAS.append(nome)


def le_vetor():
    secoes, atual = {}, None
    for ln in VETOR.read_text().splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("["):
            atual = secoes.setdefault(ln.strip("[]"), {})
            continue
        k, v = [t.strip() for t in ln.split("=", 1)]
        atual[k] = v
    return secoes


def c_do_firmware():
    with tempfile.TemporaryDirectory() as d:
        so = os.path.join(d, "pinblock.so")
        subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-shared", "-fPIC",
                        "-I", str(RAIZ / "fw" / "include"),
                        str(RAIZ / "fw" / "src" / "pinblock.c"), "-o", so],
                       check=True)
        lib = ctypes.CDLL(so)
        campo = ctypes.create_string_buffer(16)

        ok = True
        for n in range(1, pinblock.PAN_MAX + 1):
            for _ in range(20):
                pan = "".join(str(b % 10) for b in os.urandom(n))
                r = lib.pinblock_campo_pan(pan.encode(), n, campo)
                if r != 0 or campo.raw != pinblock.campo_pan(pan):
                    ok = False
        check("campo do PAN, todo tamanho", ok)
        check("PAN vazio, longo e com letra recusados",
              lib.pinblock_campo_pan(b"", 0, campo) == -1
              and lib.pinblock_campo_pan(b"1" * 20, 20, campo) == -1
              and lib.pinblock_campo_pan(b"40000A", 6, campo) == -1)

        def py_valido(c):
            try:
                pinblock.le_campo_pin(c)
                return 1
            except pinblock.PinErro:
                return 0

        ok, validos, invalidos = True, 0, 0
        for np in range(pinblock.PIN_MIN, pinblock.PIN_MAX + 1):
            pin = "".join(str(b % 10) for b in os.urandom(np))
            bom = pinblock.campo_pin(pin)
            if lib.pinblock_campo_valido(bom) != 1:
                ok = False
            validos += 1
            # cada um dos 16 nibbles da metade fixa, com os 15 outros valores
            for pos in range(16):
                for delta in range(1, 16):
                    c = bytearray(bom)
                    c[pos // 2] ^= delta << (4 if pos % 2 == 0 else 0)
                    c = bytes(c)
                    esperado = py_valido(c)
                    if lib.pinblock_campo_valido(c) != esperado:
                        ok = False
                    validos += esperado
                    invalidos += 1 - esperado
        # campos ao acaso: quase todos invalidos
        for _ in range(20000):
            c = os.urandom(16)
            if lib.pinblock_campo_valido(c) != py_valido(c):
                ok = False
        check("campo do PIN: C e Python concordam (%d validos, %d invalidos)"
              % (validos, invalidos), ok)


def main():
    v = le_vetor()

    print("valores de terceiros")
    s = v["campo do PIN"]
    check("campo do PIN",
          pinblock.campo_pin(s["PIN"])[:8].hex().upper() == s["PINFIELD"])
    s = v["campo do PAN"]
    check("campo do PAN",
          pinblock.campo_pan(s["PAN"]).hex().upper() == s["PANFIELD"])
    s = v["AES-128"]
    chave = bytes.fromhex(s["KEY"])
    bloco = pinblock.cifra(chave, s["PIN"], s["PAN"], bytes.fromhex(s["RND"]))
    check("bloco cifrado", bloco.hex().upper() == s["BLOCK"])
    check("bloco decifrado",
          pinblock.decifra(chave, bytes.fromhex(s["BLOCK"]), s["PAN"])
          == s["PIN"])

    print("ida e volta, AES-256")
    k = os.urandom(32)
    ok = True
    for np in range(pinblock.PIN_MIN, pinblock.PIN_MAX + 1):
        for na in range(1, pinblock.PAN_MAX + 1):
            pin = "".join(str(d % 10) for d in os.urandom(np))
            pan = "".join(str(d % 10) for d in os.urandom(na))
            if pinblock.decifra(k, pinblock.cifra(k, pin, pan), pan) != pin:
                ok = False
    check("todo tamanho de PIN e de PAN", ok)
    check("o aleatorio muda o bloco",
          pinblock.cifra(k, "1234", "4000001234567899")
          != pinblock.cifra(k, "1234", "4000001234567899"))

    print("o PAN amarra o bloco")
    b = pinblock.cifra(k, "1234", "4000001234567899")
    recusa("outro PAN", lambda: pinblock.decifra(k, b, "4000001234567898"))
    recusa("outra chave",
           lambda: pinblock.decifra(os.urandom(32), b, "4000001234567899"))

    print("formato")
    rnd = bytes(8)
    for nome, nib in (("controle 0", "041234AAAAAAAAAA"),
                      ("tamanho 3", "43123AAAAAAAAAAA"),
                      ("tamanho 13", "4D1234567890123A"),
                      ("digito A no PIN", "44123AAAAAAAAAAA"),
                      ("enchimento F", "441234FFFFFFFFFF"),
                      ("enchimento com um 0", "441234AAAAAAAAA0")):
        recusa(nome, lambda n=nib: pinblock.le_campo_pin(
            bytes.fromhex(n) + rnd))
    check("PIN de 12 digitos",
          pinblock.le_campo_pin(bytes.fromhex("4C123456789012AA") + rnd)
          == "123456789012")
    for nome, pin in (("PIN de 3", "123"), ("PIN de 13", "1" * 13),
                      ("PIN com letra", "12A4")):
        recusa(nome, lambda p=pin: pinblock.campo_pin(p))
    for nome, pan in (("PAN vazio", ""), ("PAN de 20", "1" * 20),
                      ("PAN com letra", "40000A")):
        recusa(nome, lambda p=pan: pinblock.campo_pan(p))
    check("PAN curto: zeros a esquerda",
          pinblock.campo_pan("123").hex().upper()
          == "0000000000123" + "0" * 19)

    print("o C do firmware")
    c_do_firmware()

    print()
    if FALHAS:
        print("FALHOU: %d" % len(FALHAS))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
