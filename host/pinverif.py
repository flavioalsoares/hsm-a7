#!/usr/bin/env python3
"""Verificacao de PIN: metodo do offset e PVV (fase 8, etapa 8.5).

A segunda implementacao, em Python, do que `fw/src/pinverif.c` e
`fw/src/keystore.c` fazem. As duas existem para discordar quando alguem ler
o metodo errado. Mexer numa exige mexer na outra.

METODO DO OFFSET

    dados de validacao   16 digitos hexadecimais, que o emissor tira do PAN
    C       = 3DES_PVK(dados)                          16 digitos hex
    natural = tabela aplicada a cada digito de C       16 digitos decimais
    PIN     = natural + offset      digito a digito, modulo 10
    offset  = PIN - natural

    So os `n` primeiros digitos contam; `n` e o tamanho do PIN.

PVV

    TSP = 11 digitos do PAN (os da direita, sem o verificador)
          . indice da chave . 4 primeiros digitos do PIN
    C   = 3DES_PVK(TSP)
    PVV = os 4 primeiros digitos decimais de C; se faltar, as letras de C,
          na ordem, com A->0 ... F->5.

TABELA AUTORIZADA

    A tabela de decimalizacao e o parametro do ataque de Bond e Zielinski
    (2003). O equipamento so aceita tabela com MAC valido, e o MAC so sai
    do console, com dual control. O MAC amarra a tabela a UMA chave de
    verificacao, pelo KCV dela:

        K   = KDF(LMK, "HSM-A7 DECTAB")     SP 800-108, contador, CMAC-AES
        MAC = 8 primeiros bytes de CMAC_K(tabela . KCV da chave V1)
        bloco = tabela (16 digitos) . MAC (16 hex)

⚠ Este arquivo calcula com chave em claro. Serve para TESTE: um host de
verdade nunca tem a chave de verificacao nem a LMK.
"""

import des

TABELA_PADRAO = "0123456789012345"
ROTULO = b"HSM-A7 DECTAB"


class PinvErro(ValueError):
    pass


def _digitos(s, nome, minimo, maximo):
    if not (minimo <= len(s) <= maximo) or not s.isdigit() or not s.isascii():
        raise PinvErro("%s: de %d a %d digitos" % (nome, minimo, maximo))


def decimaliza(cifrado, tabela):
    """bytes de 8 -> string de 16 digitos decimais."""
    _digitos(tabela, "tabela", 16, 16)
    return "".join(tabela[int(c, 16)] for c in cifrado.hex())


def natural(pvk, tabela, dados):
    """O PIN natural inteiro, 16 digitos. `dados`: 8 bytes."""
    if len(dados) != 8:
        raise PinvErro("dados de validacao: 8 bytes")
    return decimaliza(des.tdes_bloco(pvk, dados), tabela)


def offset_gera(pvk, tabela, dados, pin):
    _digitos(pin, "PIN", 4, 12)
    nat = natural(pvk, tabela, dados)
    return "".join(str((int(p) - int(n)) % 10) for p, n in zip(pin, nat))


def pin_do_offset(pvk, tabela, dados, offset):
    _digitos(offset, "offset", 4, 12)
    nat = natural(pvk, tabela, dados)
    return "".join(str((int(o) + int(n)) % 10) for o, n in zip(offset, nat))


def offset_confere(pvk, tabela, dados, pin, offset):
    _digitos(pin, "PIN", 4, 12)
    _digitos(offset, "offset", 4, 12)
    return len(pin) == len(offset) and \
        pin_do_offset(pvk, tabela, dados, offset) == pin


def pvv_tsp(pan, indice, pin):
    _digitos(pan, "PAN", 12, 19)
    _digitos(indice, "indice", 1, 1)
    _digitos(pin, "PIN", 4, 12)
    return bytes.fromhex(pan[-12:-1] + indice + pin[:4])


def pvv_extrai(cifrado):
    h = cifrado.hex()
    dec = [c for c in h if c.isdigit()]
    let = [str(int(c, 16) - 10) for c in h if not c.isdigit()]
    return "".join((dec + let)[:4])


def pvv_gera(pvk, pan, indice, pin):
    return pvv_extrai(des.tdes_bloco(pvk, pvv_tsp(pan, indice, pin)))


def pvv_confere(pvk, pan, indice, pin, pvv):
    _digitos(pvv, "PVV", 4, 4)
    return pvv_gera(pvk, pan, indice, pin) == pvv


# ----------------------------------------------------------------------
# Tabela autorizada
# ----------------------------------------------------------------------

def _cmac(chave, msg):
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    c = CMAC(algorithms.AES(chave))
    c.update(msg)
    return c.finalize()


def tabela_chave(lmk):
    """A chave de MAC das tabelas: SP 800-108 em modo contador, PRF = CMAC,
    256 bits. Bloco i: [i] . rotulo . 00 . [0100]."""
    return b"".join(_cmac(lmk, bytes([i]) + ROTULO + b"\x00\x01\x00")
                    for i in (1, 2))


def tabela_autoriza(lmk, tabela, kcv):
    """O bloco que o host manda no V0/V2: tabela . MAC em hex, 32
    caracteres. `kcv`: os 3 bytes do KCV da chave de verificacao V1."""
    _digitos(tabela, "tabela", 16, 16)
    if len(kcv) != 3:
        raise PinvErro("KCV: 3 bytes")
    mac = _cmac(tabela_chave(lmk), tabela.encode() + bytes(kcv))[:8]
    return tabela + mac.hex().upper()
