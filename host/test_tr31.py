#!/usr/bin/env python3
"""Testes do key block X9.143 do lado do host, sem placa.

    python3 host/test_tr31.py

O que se prova aqui:

  1. O VETOR. Desembrulhar um key block versao D produzido por uma
     implementacao independente devolve a chave certa. E o unico numero
     deste modulo que nao veio deste projeto -- procedencia em
     vectors/MANIFEST.txt, e ela NAO e do CAVP.

  2. IDA E VOLTA. Embrulhar e desembrulhar devolve a chave. Cobre a
     direcao que nao tem KAT possivel, porque o enchimento e aleatorio
     por norma e embrulhar nao e deterministico.

  3. QUE O MAC SERVE PARA ALGUMA COISA. Um bit trocado em QUALQUER
     posicao do bloco -- cabecalho, corpo ou MAC -- tem de recusar. Este
     e o teste que vale mais que os outros dois juntos: uma
     implementacao que "esqueceu" de incluir o cabecalho no MAC passa no
     vetor e na ida-e-volta, e falha so aqui.

  4. QUE AS DUAS SUBCHAVES SAO DIFERENTES. Se KBEK e KBAK coincidissem,
     tudo acima continuaria passando -- e um oraculo de MAC seria um
     oraculo de cifragem de graca.

O que NAO se prova aqui: acordo com o firmware. Quem prova isso e o
`tb_tr31_block`, que roda o C de verdade. Ver doc/fase3-notas.md.
"""

import os
import pathlib
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tr31  # noqa: E402

RAIZ = pathlib.Path(__file__).resolve().parent.parent
VETOR = RAIZ / "vectors" / "tr31" / "x9143_D_AES256.rsp"

FALHAS = []


def check(nome, ok, detalhe=""):
    if ok:
        print("  ok    %s" % nome)
    else:
        print("  FALHA %s %s" % (nome, detalhe))
        FALHAS.append(nome)


def recusa(nome, fn):
    """Passa se `fn` levantar Tr31Erro. Aceitar em silencio e a falha."""
    try:
        fn()
    except tr31.Tr31Erro:
        print("  ok    %s -- recusado" % nome)
        return
    except Exception as e:                      # noqa: BLE001
        check(nome, False, "levantou %r, esperado Tr31Erro" % e)
        return
    check(nome, False, "ACEITOU")


def le_vetor():
    if not VETOR.exists():
        sys.exit("ERRO: %s nao existe -- rode scripts/fetch-vectors.sh" % VETOR)
    campos = {}
    for linha in VETOR.read_text().splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or linha.startswith("["):
            continue
        if "=" not in linha:
            continue
        k, v = (x.strip() for x in linha.split("=", 1))
        campos[k.upper()] = v
    return (
        bytes.fromhex(campos["KBPK"]),
        bytes.fromhex(campos["KEY"]),
        campos["KB"],
    )


# ---------------------------------------------------------------------
def test_vetor():
    print("== vetor conhecido (fonte de terceiros, NAO do CAVP)")
    kbpk, chave, kb = le_vetor()
    try:
        obtida, cab = tr31.desembrulha(kbpk, kb)
    except tr31.Tr31Erro as e:
        # Nao deixar estourar: quando o vetor reprova, o resto da suite e
        # que diz ONDE -- e uma pilha de excecao esconde justamente isso.
        check("chave desembrulhada confere", False, str(e))
        return
    check("chave desembrulhada confere", obtida == chave, obtida.hex().upper())
    check("cabecalho lido", cab["uso"] == "P0" and cab["algoritmo"] == "A",
          repr(cab))
    check("comprimento declarado bate", cab["comprimento"] == len(kb))


def test_derivacao():
    print("== derivacao de KBEK e KBAK")
    kbpk, _, _ = le_vetor()
    kbek, kbak = tr31.deriva_subchaves(kbpk)
    check("KBEK tem 32 bytes", len(kbek) == 32, str(len(kbek)))
    check("KBAK tem 32 bytes", len(kbak) == 32, str(len(kbak)))
    check("KBEK != KBAK", kbek != kbak)
    check("nenhuma das duas e a KBPK", kbek != kbpk and kbak != kbpk)
    check("deterministica", tr31.deriva_subchaves(kbpk) == (kbek, kbak))

    # Duas metades de 16 bytes vindas de contadores diferentes. Se o
    # contador fosse ignorado, as duas metades seriam iguais -- e a chave
    # de 256 bits teria 128 bits de entropia.
    check("metades da KBEK diferem", kbek[:16] != kbek[16:])
    check("metades da KBAK diferem", kbak[:16] != kbak[16:])

    recusa("KBPK de 20 bytes", lambda: tr31.deriva_subchaves(b"\x00" * 20))


def test_ida_e_volta():
    print("== ida e volta")
    kbpk = os.urandom(32)
    for n in (16, 24, 32):
        chave = os.urandom(n)
        bloco = tr31.embrulha(kbpk, chave)
        obtida, cab = tr31.desembrulha(kbpk, bloco)
        check("chave de %d bytes volta inteira" % n, obtida == chave)
        check("campo de comprimento bate (%d bytes)" % n,
              cab["comprimento"] == len(bloco))
        check("bloco e multiplo de 16 caracteres (%d bytes)" % n,
              len(bloco) % 16 == 0, str(len(bloco)))

    # Enchimento aleatorio: o MESMO par (chave, KBPK) tem de dar blocos
    # diferentes. Um enchimento constante nao seria erro de correcao, e
    # seria um vazamento -- dois blocos identicos denunciam que a mesma
    # chave foi exportada duas vezes.
    chave = os.urandom(32)
    b1 = tr31.embrulha(kbpk, chave)
    b2 = tr31.embrulha(kbpk, chave)
    check("dois embrulhos da mesma chave diferem", b1 != b2)

    # 16 e 24 bytes de chave dao o MESMO tamanho de bloco: o enchimento
    # esconde a diferenca. E o motivo de ele existir.
    n16 = len(tr31.embrulha(kbpk, os.urandom(16)))
    n24 = len(tr31.embrulha(kbpk, os.urandom(24)))
    check("chave de 16 e de 24 bytes dao blocos do mesmo tamanho",
          n16 == n24, "%d vs %d" % (n16, n24))


def test_kbpk_errada():
    print("== KBPK errada")
    kbpk, _, kb = le_vetor()
    outra = bytes(b ^ 0x01 for b in kbpk)
    recusa("um bit trocado na KBPK", lambda: tr31.desembrulha(outra, kb))


def test_bit_trocado():
    print("== um bit trocado em qualquer lugar do bloco")
    kbpk, _, kb = le_vetor()

    # TODAS as posicoes. E caro (112 posicoes x 8 bits), e e o teste que
    # justifica o formato inteiro: se alguma passar, existe uma regiao do
    # bloco que nao esta autenticada.
    aceitos = []
    for i in range(len(kb)):
        for bit in range(8):
            c = chr(ord(kb[i]) ^ (1 << bit))
            adulterado = kb[:i] + c + kb[i + 1:]
            if adulterado == kb:
                continue
            try:
                tr31.desembrulha(kbpk, adulterado)
                aceitos.append((i, bit))
            except tr31.Tr31Erro:
                pass
            except Exception:                    # noqa: BLE001
                pass
    check("nenhuma das %d posicoes passou" % len(kb), not aceitos, str(aceitos[:5]))


def test_malformados():
    print("== blocos malformados")
    kbpk, _, kb = le_vetor()

    recusa("vazio", lambda: tr31.desembrulha(kbpk, ""))
    recusa("so o cabecalho", lambda: tr31.desembrulha(kbpk, kb[:16]))
    recusa("truncado no meio", lambda: tr31.desembrulha(kbpk, kb[:-2]))
    recusa("numero impar de caracteres", lambda: tr31.desembrulha(kbpk, kb + "0"))
    recusa("versao B", lambda: tr31.desembrulha(kbpk, "B" + kb[1:]))
    recusa("comprimento nao decimal",
           lambda: tr31.desembrulha(kbpk, kb[:1] + "X112" + kb[5:]))

    # Hexadecimal minusculo: a norma escreve maiusculo, e o firmware
    # recusa. Se o host aceitasse, existiriam duas grafias do "mesmo"
    # bloco com MACs diferentes.
    minusculo = kb[:16] + kb[16:].lower()
    recusa("corpo em hexadecimal minusculo",
           lambda: tr31.desembrulha(kbpk, minusculo))

    # Blocos opcionais: o campo diz que existem, o parser nao os
    # implementa. Ignorar seria aceitar um campo que nao se entendeu.
    recusa("blocos opcionais anunciados",
           lambda: tr31.desembrulha(kbpk, kb[:12] + "01" + kb[14:]))

    recusa("chave de comprimento zero",
           lambda: tr31.embrulha(kbpk, b""))
    recusa("algoritmo 3DES",
           lambda: tr31.embrulha(kbpk, os.urandom(16), algoritmo=tr31.ALG_3DES))
    recusa("modo de uso invalido",
           lambda: tr31.embrulha(kbpk, os.urandom(16), modo="Z"))
    recusa("exportabilidade invalida",
           lambda: tr31.embrulha(kbpk, os.urandom(16), exportabilidade="X"))


def test_cabecalho_no_mac():
    print("== o cabecalho esta mesmo dentro do MAC")
    kbpk = os.urandom(32)
    chave = os.urandom(32)

    # Dois blocos que so diferem no cabecalho, com o MESMO enchimento.
    # Se o cabecalho nao entrasse no MAC, o MAC dos dois seria igual --
    # e trocar a exportabilidade de 'N' para 'E' seria edicao de texto.
    ench = os.urandom(14)
    a = tr31.embrulha(kbpk, chave, exportabilidade=tr31.EXP_NAO, enchimento=ench)
    b = tr31.embrulha(kbpk, chave, exportabilidade=tr31.EXP_SIM, enchimento=ench)
    check("MAC muda quando a exportabilidade muda", a[-32:] != b[-32:])
    check("corpo cifrado tambem muda (o MAC e o IV)", a[16:-32] != b[16:-32])

    # O ataque literal: pegar o bloco 'N' e reescrever o byte para 'E'.
    forjado = a[:11] + tr31.EXP_SIM + a[12:]
    recusa("bloco com exportabilidade reescrita a mao",
           lambda: tr31.desembrulha(kbpk, forjado))


def main():
    print("== key block ANSI X9.143 / TR-31 versao D -- lado do host")
    try:
        tr31.cmac_aes(b"\x00" * 16, b"")
    except tr31.Tr31Erro as e:
        print(e)
        return 1

    test_vetor()
    test_derivacao()
    test_ida_e_volta()
    test_kbpk_errada()
    test_bit_trocado()
    test_malformados()
    test_cabecalho_no_mac()

    print()
    if FALHAS:
        print("FALHOU: %d verificacao(oes)" % len(FALHAS))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
