#!/usr/bin/env python3
"""Teste de PC da verificacao de PIN: metodo do offset e PVV (etapa 8.5).

    python3 host/test_pinverif.py

O que ele prova:

  1. `host/pinverif.py` reproduz os 24 valores de terceiros de
     `vectors/pinverif/psec_pin.rsp` (ver o MANIFEST para a procedencia).
  2. `fw/src/pinverif.c`, compilado aqui com `gcc`, da o mesmo resultado que
     o Python: decimalizacao, offset nos dois sentidos, montagem do dado do
     PVV e extracao do PVV. Entradas ao acaso, e os casos de borda que os
     valores de terceiros nao cobrem.
  3. A extracao do PVV em TODOS os formatos possiveis do resultado da cifra
     (de 0 a 16 digitos decimais, em qualquer posicao).
  4. O MAC da tabela muda com a tabela e com a LMK.

O que ele NAO prova: a cifra (e o 3DES, que tem vetor do NIST e teste
proprio), o key store, os comandos e a recusa de tabela sem MAC. Isso e do
`tb_pinv`, com o firmware real.

A conta do ataque de decimalizacao (Bond e Zielinski, 2003) NAO e refeita
aqui: os numeros do manual sao os do relatorio, citado la.
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

import des            # noqa: E402
import pinverif as pv  # noqa: E402

falhas = 0


def check(nome, ok, detalhe=""):
    global falhas
    print("  %-4s %s%s" % ("ok" if ok else "ERRO", nome,
                           (" -- " + detalhe) if (detalhe and not ok) else ""))
    if not ok:
        falhas += 1


def le_vetores():
    """{secao: [dict]}, e a chave."""
    secoes, chave, sec, reg = {}, None, None, {}
    with open(os.path.join(RAIZ, "vectors", "pinverif", "psec_pin.rsp")) as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#"):
                if reg:
                    secoes[sec].append(reg)
                    reg = {}
                continue
            if linha.startswith("["):
                sec = linha.strip("[]")
                secoes[sec] = []
                continue
            k, v = [x.strip() for x in linha.split("=", 1)]
            if k == "KEY":
                chave = bytes.fromhex(v)
            else:
                reg[k] = v
    if reg:
        secoes[sec].append(reg)
    return chave, secoes


def dados_do(v):
    o, n = int(v["OFS"]), int(v["LEN"])
    return bytes.fromhex(v["PAN"][o:o + n][:16].ljust(16, v["PAD"]))


def terceiros():
    print("valores de terceiros")
    chave, s = le_vetores()
    check("24 valores lidos",
          [len(s[k]) for k in ("offset -> PIN", "PIN -> offset", "PVV")]
          == [10, 10, 4])
    check("offset -> PIN (10)",
          all(pv.pin_do_offset(chave, v["TABLE"], dados_do(v), v["OFFSET"])
              == v["PIN"] for v in s["offset -> PIN"]))
    check("PIN -> offset (10)",
          all(pv.offset_gera(chave, v["TABLE"], dados_do(v), v["PIN"])
              == v["OFFSET"] for v in s["PIN -> offset"]))
    check("os dois sentidos fecham",
          all(pv.offset_confere(chave, v["TABLE"], dados_do(v), v["PIN"],
                                v["OFFSET"]) for v in s["PIN -> offset"]))
    check("PVV (4)",
          all(pv.pvv_gera(chave, v["PAN"], v["INDEX"], v["PIN"]) == v["PVV"]
              for v in s["PVV"]))
    return chave


def c_do_firmware():
    print("o C do firmware contra o Python")
    rnd = random.Random(85)
    with tempfile.TemporaryDirectory() as d:
        so = os.path.join(d, "pinverif.so")
        subprocess.run(["gcc", "-O2", "-Wall", "-Werror", "-shared", "-fPIC",
                        "-I", os.path.join(RAIZ, "fw", "include"),
                        os.path.join(RAIZ, "fw", "src", "pinverif.c"),
                        "-o", so], check=True)
        lib = ctypes.CDLL(so)

        def vals(s):
            return bytes(int(c) for c in s)

        # forma da tabela
        ok = lib.pinv_tabela_forma(b"0123456789012345") == 1
        for ruim in (b"012345678901234A", b"/123456789012345",
                     b":123456789012345", b"01234567890123 5"):
            ok = ok and lib.pinv_tabela_forma(ruim) == 0
        check("forma da tabela", ok)

        # decimalizacao, com tabelas e blocos ao acaso
        ok = True
        nat = ctypes.create_string_buffer(16)
        for _ in range(2000):
            tab = "".join(rnd.choice("0123456789") for _ in range(16))
            c = bytes(rnd.randrange(256) for _ in range(8))
            lib.pinv_decimaliza(c, tab.encode(), nat)
            ok = ok and nat.raw == vals(pv.decimaliza(c, tab))
        check("decimalizacao (2000 ao acaso)", ok)

        # offset: todos os pares de digitos, e PINs de 4 a 12
        ok = True
        off = ctypes.create_string_buffer(12)
        for p in range(10):
            for n_ in range(10):
                lib.pinv_offset(bytes([p]), bytes([n_]), 1, off)
                o = off.raw[0]
                ok = ok and o == (p - n_) % 10
                ok = ok and lib.pinv_offset_confere(bytes([p]), bytes([n_]),
                                                    bytes([o]), 1) == 1
                for x in range(10):
                    if x != o:
                        ok = ok and lib.pinv_offset_confere(
                            bytes([p]), bytes([n_]), bytes([x]), 1) == 0
        check("offset: os 100 pares de digitos, e os 900 offsets errados", ok)

        ok = True
        for _ in range(2000):
            n = rnd.randrange(4, 13)
            pin = bytes(rnd.randrange(10) for _ in range(n))
            natv = bytes(rnd.randrange(10) for _ in range(n))
            lib.pinv_offset(pin, natv, n, off)
            esperado = bytes((a - b) % 10 for a, b in zip(pin, natv))
            ok = ok and off.raw[:n] == esperado
            ok = ok and lib.pinv_offset_confere(pin, natv, esperado, n) == 1
            k = rnd.randrange(n)
            ruim = bytearray(esperado)
            ruim[k] = (ruim[k] + rnd.randrange(1, 10)) % 10
            ok = ok and lib.pinv_offset_confere(pin, natv, bytes(ruim), n) == 0
        check("offset: 2000 PINs de 4 a 12, certo e com um digito errado", ok)

        # TSP do PVV
        ok = True
        tsp = ctypes.create_string_buffer(8)
        for _ in range(2000):
            na = rnd.randrange(12, 20)
            pan = "".join(rnd.choice("0123456789") for _ in range(na))
            ind = rnd.randrange(10)
            pin = "".join(rnd.choice("0123456789") for _ in range(4))
            r = lib.pinv_pvv_tsp(pan.encode(), na, ind, vals(pin), tsp)
            ok = ok and r == 0 and tsp.raw == pv.pvv_tsp(pan, str(ind), pin)
        ok = ok and lib.pinv_pvv_tsp(b"99999901234", 11, 1, vals("1234"), tsp) == -1
        ok = ok and lib.pinv_pvv_tsp(b"9999990123456789012A", 20, 1,
                                     vals("1234"), tsp) == -1
        ok = ok and lib.pinv_pvv_tsp(b"99999901234A", 12, 1, vals("1234"), tsp) == -1
        ok = ok and lib.pinv_pvv_tsp(b"999999012345", 12, 10, vals("1234"), tsp) == -1
        check("PVV: o dado de entrada (2000 ao acaso, e 4 recusas)", ok)

        # Extracao do PVV. Ao acaso quase nunca faltam decimais: a chance de
        # um bloco ter menos de 4 e de 1 em 2214. Entao os
        # casos sao construidos: toda quantidade de decimais, de 0 a 16, em
        # posicoes sorteadas.
        ok = True
        saida = ctypes.create_string_buffer(4)
        casos = 0
        for nd in range(17):
            for _ in range(300):
                pos = set(rnd.sample(range(16), nd))
                h = "".join(rnd.choice("0123456789") if i in pos
                            else rnd.choice("abcdef") for i in range(16))
                c = bytes.fromhex(h)
                lib.pinv_pvv_extrai(c, saida)
                ok = ok and saida.raw == vals(pv.pvv_extrai(c))
                casos += 1
        for _ in range(5000):
            c = bytes(rnd.randrange(256) for _ in range(8))
            lib.pinv_pvv_extrai(c, saida)
            ok = ok and saida.raw == vals(pv.pvv_extrai(c))
        check("PVV: extracao (%d construidos, de 0 a 16 decimais, e 5000 "
              "ao acaso)" % casos, ok)
        # um caso a mao, para o leitor: so letras
        lib.pinv_pvv_extrai(bytes.fromhex("abcdefabcdefabcd"), saida)
        check("PVV: ABCD... da 0123", saida.raw == vals("0123"))
        lib.pinv_pvv_extrai(bytes.fromhex("f1e2ddddddddddd3"), saida)
        check("PVV: F1E2D...D3 da 1235", saida.raw == vals("1235"))


def ponta_a_ponta(chave):
    """O metodo inteiro em Python, com chave dupla e tripla."""
    print("ida e volta em Python")
    rnd = random.Random(86)
    ok = True
    for _ in range(300):
        k = des.paridade_impar(bytes(rnd.randrange(256)
                                     for _ in range(rnd.choice((16, 24)))))
        n = rnd.randrange(4, 13)
        pin = "".join(rnd.choice("0123456789") for _ in range(n))
        tab = "".join(rnd.choice("0123456789") for _ in range(16))
        dv = bytes(rnd.randrange(256) for _ in range(8))
        off = pv.offset_gera(k, tab, dv, pin)
        ok = ok and pv.pin_do_offset(k, tab, dv, off) == pin
        ok = ok and pv.offset_confere(k, tab, dv, pin, off)
        ok = ok and not pv.offset_confere(k, tab, dv, pin, off[:-1] + str(
            (int(off[-1]) + 1) % 10))
        if n > 4:
            ok = ok and not pv.offset_confere(k, tab, dv, pin, off[:-1])
        pan = "999999" + "".join(rnd.choice("0123456789")
                                 for _ in range(rnd.randrange(6, 14)))
        ind = str(rnd.randrange(10))
        pvv = pv.pvv_gera(k, pan, ind, pin)
        ok = ok and len(pvv) == 4 and pvv.isdigit()
        ok = ok and pv.pvv_confere(k, pan, ind, pin, pvv)
        # o digito verificador do PAN nao entra no PVV
        outro = pan[:-1] + str((int(pan[-1]) + 1) % 10)
        ok = ok and pv.pvv_gera(k, outro, ind, pin) == pvv
        # so os 4 primeiros digitos do PIN entram
        ok = ok and pv.pvv_gera(k, pan, ind, pin[:4]) == pvv
    check("300 voltas: offset e PVV, chave dupla e tripla", ok)

    # O exemplo numerico do manual, secao 35.
    k = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    dv = bytes.fromhex("9999990123456789")
    c = des.tdes_bloco(k, dv)
    nat = pv.decimaliza(c, pv.TABELA_PADRAO)
    off = pv.offset_gera(k, pv.TABELA_PADRAO, dv, "48213")
    print("    exemplo do manual: cifrado %s, natural %s, PIN 48213, "
          "offset %s" % (c.hex().upper(), nat, off))
    pan = "9999990123456789"
    t = pv.pvv_tsp(pan, "1", "48213")
    c2 = des.tdes_bloco(k, t)
    print("    exemplo do manual: TSP %s, cifrado %s, PVV %s"
          % (t.hex().upper(), c2.hex().upper(), pv.pvv_extrai(c2)))


def tabela():
    print("tabela autorizada")
    lmk = bytes(range(32))
    kcv = bytes.fromhex("08D7B4")
    a = pv.tabela_autoriza(lmk, pv.TABELA_PADRAO, kcv)
    check("o bloco tem a tabela e 16 caracteres de MAC",
          len(a) == 32 and a[:16] == pv.TABELA_PADRAO)
    check("outra tabela, outro MAC",
          pv.tabela_autoriza(lmk, "0123456789012346", kcv)[16:] != a[16:])
    check("outra chave de verificacao (outro KCV), outro MAC",
          pv.tabela_autoriza(lmk, pv.TABELA_PADRAO,
                             bytes.fromhex("08D7B5"))[16:] != a[16:])
    check("outra LMK, outro MAC",
          pv.tabela_autoriza(bytes(31) + b"\x01", pv.TABELA_PADRAO, kcv)[16:]
          != a[16:])
    import tr31
    kbek, kbak = tr31.deriva_subchaves(lmk)
    k = pv.tabela_chave(lmk)
    check("a chave do MAC nao e a KBEK nem a KBAK do key block",
          len(k) == 32 and k != kbek and k != kbak)


def main():
    chave = terceiros()
    c_do_firmware()
    ponta_a_ponta(chave)
    tabela()
    print()
    if falhas:
        print("FALHOU: %d" % falhas)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
