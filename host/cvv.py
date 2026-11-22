#!/usr/bin/env python3
"""CVV, CVV2 e iCVV (fase 8, etapa 8.6).

A segunda implementacao, em Python, do que `fw/src/cvv.c` e `fw/src/keystore.c`
fazem. As duas existem para discordar quando alguem ler o metodo errado.
Mexer numa exige mexer na outra.

    D    = PAN . validade (4) . codigo de servico (3), completado com '0'
           ate 32 digitos, lido como 16 bytes
    X    = DES_A(D[0..7]) xor D[8..15]          A = metade esquerda da CVK
    C    = 3DES_AB(X)                           a CVK inteira, dupla
    CVV  = os 3 primeiros digitos decimais de C; se faltar, as letras de C,
           na ordem, com A->0 ... F->5

O mesmo metodo da os tres codigos; so muda o codigo de servico: o da tarja
(CVV), 000 (CVV2, impresso no verso) e 999 (iCVV, no chip).

⚠ Este arquivo calcula com chave em claro. Serve para TESTE: um host de
verdade nunca tem a chave de verificacao de cartao.
"""

import des

CVV2 = "000"
ICVV = "999"


class CvvErro(ValueError):
    pass


def _digitos(s, nome, minimo, maximo):
    if not (minimo <= len(s) <= maximo) or not s.isdigit() or not s.isascii():
        raise CvvErro("%s: de %d a %d digitos" % (nome, minimo, maximo))


def dados(pan, validade, servico):
    """Os 16 bytes de entrada."""
    _digitos(pan, "PAN", 12, 19)
    _digitos(validade, "validade", 4, 4)
    _digitos(servico, "codigo de servico", 3, 3)
    return bytes.fromhex((pan + validade + servico).ljust(32, "0"))


def extrai(cifrado):
    h = cifrado.hex()
    dec = [c for c in h if c.isdigit()]
    let = [str(int(c, 16) - 10) for c in h if not c.isdigit()]
    return "".join((dec + let)[:3])


def cifra(cvk, d):
    """C, os 8 bytes de onde o CVV sai. `cvk`: 16 bytes."""
    if len(cvk) != 16:
        raise CvvErro("CVK: 3DES de comprimento duplo, 16 bytes")
    x = des.des_bloco(cvk[:8], d[:8])
    x = bytes(a ^ b for a, b in zip(x, d[8:]))
    return des.tdes_bloco(cvk, x)


def gera(cvk, pan, validade, servico):
    return extrai(cifra(cvk, dados(pan, validade, servico)))


def confere(cvk, pan, validade, servico, cvv):
    _digitos(cvv, "CVV", 3, 3)
    return gera(cvk, pan, validade, servico) == cvv
