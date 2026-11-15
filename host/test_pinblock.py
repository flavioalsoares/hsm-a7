#!/usr/bin/env python3
"""Testes do PIN block ISO 9564-1, formatos 4 e 0, do lado do host, sem placa.

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

  7. O FORMATO 0. Os valores de terceiros do bloco em claro; ida e volta
     com 3DES de chave dupla e tripla; e o C do firmware contra o Python:
     o campo do PAN, a conferencia do campo e as duas conversoes entre a
     forma do formato 0 e a do formato 4.

  8. O QUE O VEREDITO DO FORMATO 0 REVELA. O PAN entra por XOR sobre os
     digitos do PIN, e vem do host. O teste faz o papel do atacante, que
     so ve "bem formado" ou "malformado", e mede o que ele aprende. E a
     conta que sustenta o texto do manual; nao e defeito a consertar.

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
VETOR_0 = RAIZ / "vectors" / "pinblock" / "iso9564_f0.rsp"

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


def le_vetor_0():
    """{secao: [registro, ...]} do arquivo do formato 0."""
    secoes, lista, atual = {}, None, None
    for ln in VETOR_0.read_text().splitlines():
        ln = ln.strip()
        if ln.startswith("#"):
            continue
        if not ln:
            atual = None
            continue
        if ln.startswith("["):
            lista = secoes.setdefault(ln.strip("[]"), [])
            continue
        if atual is None:
            atual = {}
            lista.append(atual)
        k, v = [t.strip() for t in ln.split("=", 1)]
        atual[k] = v
    return secoes


def formato_0():
    v = le_vetor_0()
    print("formato 0: valores de terceiros")
    check("bloco em claro, montar (%d)" % len(v["montar"]),
          len(v["montar"]) == 2 and all(
              pinblock.claro0(r["PIN"], r["PAN"]).hex().upper() == r["CLEAR"]
              for r in v["montar"]))
    check("bloco em claro, ler (%d)" % len(v["ler"]),
          len(v["ler"]) == 4 and all(
              pinblock.le_claro0(bytes.fromhex(r["CLEAR"]), r["PAN"])
              == r["PIN"] for r in v["ler"]))
    assert len(v["malformado"]) == 5
    for r in v["malformado"]:
        recusa(r["ERRO"].split(":")[0], lambda r=r: pinblock.le_claro0(
            bytes.fromhex(r["CLEAR"]), r["PAN"]))

    print("formato 0: ida e volta, 3DES")
    import des
    for nk in (16, 24):
        k = des.paridade_impar(os.urandom(nk))
        ok = True
        for np in range(pinblock.PIN_MIN, pinblock.PIN_MAX + 1):
            for na in range(pinblock.PAN0_MIN, pinblock.PAN_MAX + 1):
                pin = "".join(str(d % 10) for d in os.urandom(np))
                pan = "".join(str(d % 10) for d in os.urandom(na))
                b = pinblock.cifra0(k, pin, pan)
                if len(b) != 8 or pinblock.decifra0(k, b, pan) != pin:
                    ok = False
        check("chave de %d bytes, todo tamanho de PIN e de PAN" % nk, ok)
    check("sem aleatorio: o mesmo bloco duas vezes",
          pinblock.cifra0(k, "1234", "9999991234567899")
          == pinblock.cifra0(k, "1234", "9999991234567899"))
    recusa("outra chave", lambda: pinblock.decifra0(
        des.paridade_impar(os.urandom(16)),
        pinblock.cifra0(k, "1234", "9999991234567899"), "9999991234567899"))
    for nome, pan in (("PAN de 12", "9" * 12), ("PAN de 20", "9" * 20),
                      ("PAN com letra", "999999123456A")):
        recusa(nome, lambda p=pan: pinblock.campo_pan0(p))
    check("o digito verificador nao entra",
          pinblock.campo_pan0("9999991234567890")
          == pinblock.campo_pan0("9999991234567895"))

    print("formato 0: o C do firmware")
    with tempfile.TemporaryDirectory() as d:
        so = os.path.join(d, "pinblock.so")
        subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-shared", "-fPIC",
                        "-I", str(RAIZ / "fw" / "include"),
                        str(RAIZ / "fw" / "src" / "pinblock.c"), "-o", so],
                       check=True)
        lib = ctypes.CDLL(so)
        lib.pinblock_f4_para_f0.restype = None
        c8 = ctypes.create_string_buffer(8)
        c16 = ctypes.create_string_buffer(16)

        ok = True
        for n in range(pinblock.PAN0_MIN, pinblock.PAN_MAX + 1):
            for _ in range(20):
                pan = "".join(str(b % 10) for b in os.urandom(n))
                if lib.pinblock_campo_pan0(pan.encode(), n, c8) != 0 \
                        or c8.raw != pinblock.campo_pan0(pan):
                    ok = False
        check("campo do PAN, de 13 a 19 digitos", ok)
        check("PAN de 12, de 20 e com letra recusados",
              lib.pinblock_campo_pan0(b"9" * 12, 12, c8) == -1
              and lib.pinblock_campo_pan0(b"9" * 20, 20, c8) == -1
              and lib.pinblock_campo_pan0(b"999999123456A", 13, c8) == -1)

        zero_pan = "0" * 13             # campo do PAN zero: claro = campo

        def py_valido0(c):
            try:
                return pinblock.le_claro0(c, zero_pan)
            except pinblock.PinErro:
                return None

        def confere(c):
            """O C concorda com o Python no veredito, e, se o campo e
            valido, na conversao para a forma do formato 4 e de volta."""
            pin = py_valido0(c)
            r = lib.pinblock_f0_para_f4(c, c16)
            if r != (1 if pin is not None else 0):
                return False
            if pin is None:
                return True
            if c16.raw != pinblock.campo_pin(pin, bytes(8)):
                return False
            lib.pinblock_f4_para_f0(pinblock.campo_pin(pin), c8)
            return c8.raw == c

        ok, validos, invalidos = True, 0, 0
        for np in range(pinblock.PIN_MIN, pinblock.PIN_MAX + 1):
            pin = "".join(str(b % 10) for b in os.urandom(np))
            bom = pinblock.campo_pin0(pin)
            for pos in range(16):
                for delta in range(16):
                    c = bytearray(bom)
                    c[pos // 2] ^= delta << (4 if pos % 2 == 0 else 0)
                    c = bytes(c)
                    if not confere(c):
                        ok = False
                    if py_valido0(c) is None:
                        invalidos += 1
                    else:
                        validos += 1
        for _ in range(20000):
            if not confere(os.urandom(8)):
                ok = False
        check("campo do PIN e conversoes: C e Python concordam "
              "(%d validos, %d invalidos)" % (validos, invalidos), ok)
        for r in v["ler"]:
            claro = bytes(x ^ y for x, y in zip(
                bytes.fromhex(r["CLEAR"]), pinblock.campo_pan0(r["PAN"])))
            if lib.pinblock_f0_para_f4(claro, c16) != 1 or \
                    pinblock.le_campo_pin(c16.raw) != r["PIN"]:
                ok = False
        check("os valores de terceiros, pelo C", ok)


def vazamento_formato_0():
    """O atacante tem um PIN block formato 0 e um servico que responde
    "bem formado" ou "malformado" para o bloco aberto com o PAN que ELE
    informa. Aqui o servico e o le_claro0(); no equipamento e o erro 14 do
    P0. Ele troca um digito do PAN por vez e anota as respostas."""
    import des
    print("formato 0: o que o veredito revela")
    k = des.paridade_impar(os.urandom(16))

    def oraculo(bloco, pan):
        try:
            pinblock.decifra0(k, bloco, pan)
            return True
        except pinblock.PinErro:
            return False

    def assinatura(pin, pan):
        """As respostas do servico para todo PAN com UM digito trocado,
        nos 12 digitos que entram no bloco."""
        bloco = pinblock.cifra0(k, pin, pan)
        resp = []
        for pos in range(len(pan) - 13, len(pan) - 1):
            for d in "0123456789":
                if d != pan[pos]:
                    resp.append(oraculo(bloco, pan[:pos] + d + pan[pos + 1:]))
        return tuple(resp)

    # 1. O tamanho do PIN sai sempre: trocar o digito do PAN por (d XOR 1)
    #    mantem valido um digito de PIN, e estraga um enchimento.
    ok = True
    pan = "9999990123456789"
    for np in range(pinblock.PIN_MIN, pinblock.PIN_MAX + 1):
        pin = "".join(str(b % 10) for b in os.urandom(np))
        bloco = pinblock.cifra0(k, pin, pan)
        achado = 2
        for j in range(12):                     # nibbles 4 a 15 do bloco
            pos = len(pan) - 13 + j
            d = str(int(pan[pos]) ^ 1)
            if oraculo(bloco, pan[:pos] + d + pan[pos + 1:]):
                achado = 3 + j
        if achado != np:
            ok = False
    check("o tamanho do PIN, para todo tamanho de 4 a 12", ok)

    # 2. Os dois primeiros digitos nao aparecem: o campo do PAN e zero ali.
    check("os dois primeiros digitos nao mudam as respostas",
          len({assinatura("%02d34" % i, pan) for i in range(100)}) == 1)

    # 3. O terceiro digito: quantos valores o atacante ainda nao separa,
    #    conforme o digito do PAN que esta na mesma posicao.
    tabela = {}
    for a in range(10):
        pan_a = "999" + str(a) + "000000000000"      # o 4o digito e o que
        classes = {}                                 # cai sob o 3o do PIN
        for p in range(10):
            classes.setdefault(assinatura("00%d0" % p, pan_a), []).append(p)
        tabela[a] = sorted(classes.values())
    for a in range(10):
        print("        digito do PAN %d: o atacante separa %s"
              % (a, " ".join("{" + "".join(map(str, c)) + "}"
                             for c in tabela[a])))
    media = sum(len(c) * len(c) for a in tabela for c in tabela[a]) / 100.0
    print("        candidatos que sobram, em media: %.2f de 10" % media)
    check("o veredito separa valores do digito (e o ataque publicado)",
          all(len(tabela[a]) > 1 for a in range(10)))
    check("o ultimo bit do digito nunca sai",
          all(p ^ 1 in c for a in tabela for c in tabela[a] for p in c))


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

    formato_0()
    vazamento_formato_0()

    print()
    if FALHAS:
        print("FALHOU: %d" % len(FALHAS))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
