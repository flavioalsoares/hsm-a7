"""ARQC e ARPC do EMV, 3DES (etapa 8.10). O lado do emissor, em Python.

As contas, sem politica, como em `fw/src/emv.c`:

    IMK  --Opcao A-->  MK do cartao  --CSK (ATC)-->  chave de sessao
                                         |
                            CVN 10: a MK direto
    ARQC  = retail MAC (ISO/IEC 9797-1 alg. 3) da chave, sobre os dados
    ARPC1 = 3DES da chave sobre ARQC XOR (ARC || 000000000000)    8 bytes
    ARPC2 = retail MAC da chave sobre ARQC || CSU || dado proprio  4 bytes

A chave do ARPC e a mesma que conferiu o ARQC (EMV Book 2, A1.2): a MK no
esquema MK, a chave de sessao no CSK.

Fontes publicas: EMV Book 2, anexo A1 (Opcao A, A1.4.1; chave de sessao
comum, A1.3; ARPC, A1.2). Os valores de teste estao em vectors/emv/arqc.rsp,
de duas fontes de terceiros.

Este modulo tambem faz o papel do CHIP de teste (`gera_arqc`): nos testes,
o "cartao" e um programa no PC com uma MK derivada de uma IMK de teste e um
PAN 999999... O HSM nao gera ARQC.
"""

from des import tdes_bloco, paridade_impar
from mac_tdes import retail_mac

ESQ_MK = "0"    # CVN 10: o criptograma sai da MK do cartao
ESQ_CSK = "1"   # chave de sessao comum do EMV, R = ATC || 000000000000


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def mk_opcao_a(imk, pan, psn="00"):
    """MK do cartao pela Opcao A: os 16 digitos da direita de PAN || PSN
    (completados com zeros a esquerda), cifrados sob a IMK, e o mesmo bloco
    invertido. Paridade impar."""
    if not (pan.isdigit() and psn.isdigit() and len(psn) == 2):
        raise ValueError("PAN e PSN sao digitos; PSN tem 2")
    y = bytes.fromhex((pan + psn)[-16:].rjust(16, "0"))
    return paridade_impar(tdes_bloco(imk, y) +
                          tdes_bloco(imk, _xor(y, b"\xff" * 8)))


def csk(mk, r):
    """Chave de sessao comum: R com F0 e com 0F no terceiro byte, cifrados
    sob a MK. Para o ARQC, R = ATC || 000000000000."""
    if len(r) != 8:
        raise ValueError("R tem 8 bytes")
    esq = r[:2] + b"\xf0" + r[3:]
    dir_ = r[:2] + b"\x0f" + r[3:]
    return paridade_impar(tdes_bloco(mk, esq) + tdes_bloco(mk, dir_))


def r_do_atc(atc):
    if len(atc) != 2:
        raise ValueError("ATC tem 2 bytes")
    return atc + b"\x00" * 6


def chave_ac(imk, pan, psn, atc, esquema):
    """A chave que calcula o ARQC e o ARPC."""
    mk = mk_opcao_a(imk, pan, psn)
    if esquema == ESQ_MK:
        return mk
    if esquema == ESQ_CSK:
        return csk(mk, r_do_atc(atc))
    raise ValueError("esquema")


def criptograma(chave, dados, pad):
    """ARQC, TC ou AAC: retail MAC de 8 bytes, preenchimento 1 (zeros) ou
    2 (80 e zeros)."""
    if pad not in (1, 2):
        raise ValueError("preenchimento")
    return retail_mac(chave, dados, pad, 8)


def arpc1(chave, arqc, arc):
    if len(arqc) != 8 or len(arc) != 2:
        raise ValueError("ARQC 8 bytes, ARC 2")
    return tdes_bloco(chave, _xor(arqc, arc + b"\x00" * 6))


def arpc2(chave, arqc, csu, pad_aut=b""):
    if len(arqc) != 8 or len(csu) != 4 or len(pad_aut) > 8:
        raise ValueError("ARQC 8 bytes, CSU 4, dado proprio ate 8")
    return retail_mac(chave, arqc + csu + pad_aut, 2, 4)


# ------------------------------------------------------------ o chip de teste
def gera_arqc(imk, pan, psn, atc, esquema, dados, pad):
    """O papel do CARTAO, so para os testes: o chip tem a MK e calcula o ARQC.
    No mundo real a MK nunca sai do chip, e a IMK nunca sai do emissor."""
    return criptograma(chave_ac(imk, pan, psn, atc, esquema), dados, pad)


def le_rsp(caminho):
    """Os casos de vectors/emv/arqc.rsp, como dicionarios de strings."""
    casos, atual = [], None
    for linha in open(caminho, encoding="utf-8"):
        linha = linha.rstrip("\n")
        if linha.startswith("["):
            atual = {"FONTE": linha[1:-1]}
            casos.append(atual)
        elif " = " in linha and atual is not None:
            k, v = linha.split(" = ", 1)
            atual[k] = v
        elif linha.endswith(" =") and atual is not None:
            atual[linha[:-2]] = ""
    return casos
