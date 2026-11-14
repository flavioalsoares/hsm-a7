#!/usr/bin/env python3
"""DES e 3DES (TDEA) em Python, do lado do host.

O algoritmo esta escrito duas vezes: aqui e em fw/src/des.c. As duas
implementacoes sao conferidas contra os vetores oficiais do NIST
(vectors/tdes/), e uma contra a outra.

    DES    bloco de 64 bits, chave de 64 bits com 8 de paridade (56 uteis),
           16 rodadas de uma rede de Feistel. FIPS 46-3.
    3DES   C = E_K3( D_K2( E_K1(P) ) ). SP 800-67.
           chave tripla:  K1, K2, K3 diferentes (24 bytes)
           chave dupla:   K3 = K1               (16 bytes)

⚠ Legado. O DES simples esta quebrado por busca exaustiva desde 1998, e
o 3DES nao e mais aceito pelo NIST para cifrar dados novos. Eles estao
aqui porque a rede de pagamento ainda os usa. Ver o manual, Parte VII.

As tabelas sao as da FIPS 46-3, com bits numerados de 1 (o mais alto) em
diante. Quem garante que foram copiadas certo sao os KATs da SP 800-20,
feitos para exercitar cada entrada de cada tabela.
"""

# Permutacao inicial e a inversa dela.
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
# Expansao de 32 para 48 bits, e a permutacao P no fim da funcao f.
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
# Escalonamento de chave: PC-1 tira a paridade (64 -> 56), PC-2 escolhe os
# 48 bits de cada rodada, e ROT diz quanto cada metade gira por rodada.
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
ROT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
# As oito caixas S: 6 bits entram, 4 saem. Linha = bits 1 e 6; coluna = 2 a 5.
S = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]

BLOCO = 8


class DesErro(ValueError):
    """Chave ou dado de tamanho errado."""


def _permuta(v, tabela, n_entrada):
    """Bit i da saida = bit tabela[i] da entrada, contando de 1 pelo alto."""
    r = 0
    for pos in tabela:
        r = (r << 1) | ((v >> (n_entrada - pos)) & 1)
    return r


def subchaves(chave):
    """As 16 subchaves de 48 bits de uma chave DES de 8 bytes."""
    if len(chave) != 8:
        raise DesErro("chave DES: 8 bytes")
    cd = _permuta(int.from_bytes(chave, "big"), PC1, 64)
    c, d = cd >> 28, cd & 0xFFFFFFF
    ks = []
    for r in ROT:
        c = ((c << r) | (c >> (28 - r))) & 0xFFFFFFF
        d = ((d << r) | (d >> (28 - r))) & 0xFFFFFFF
        ks.append(_permuta((c << 28) | d, PC2, 56))
    return ks


def _f(r, k):
    """A funcao de rodada: expande, mistura a subchave, passa nas caixas S."""
    x = _permuta(r, E, 32) ^ k
    saida = 0
    for i in range(8):
        seis = (x >> (42 - 6 * i)) & 0x3F
        linha = ((seis >> 4) & 2) | (seis & 1)
        coluna = (seis >> 1) & 0xF
        saida = (saida << 4) | S[i][linha][coluna]
    return _permuta(saida, P, 32)


def _bloco(ks, bloco):
    v = _permuta(int.from_bytes(bloco, "big"), IP, 64)
    esq, dir_ = v >> 32, v & 0xFFFFFFFF
    for k in ks:
        esq, dir_ = dir_, esq ^ _f(dir_, k)
    # As metades saem trocadas da ultima rodada.
    return _permuta((dir_ << 32) | esq, FP, 64).to_bytes(8, "big")


def des_bloco(chave, bloco, cifrar=True):
    """Um bloco de DES simples. Decifrar e cifrar com as subchaves ao
    contrario: e a propriedade da rede de Feistel."""
    if len(bloco) != BLOCO:
        raise DesErro("bloco DES: 8 bytes")
    ks = subchaves(chave)
    return _bloco(ks if cifrar else ks[::-1], bloco)


def _tres(chave):
    if len(chave) == 16:
        return chave[:8], chave[8:], chave[:8]
    if len(chave) == 24:
        return chave[:8], chave[8:16], chave[16:]
    raise DesErro("chave 3DES: 16 ou 24 bytes")


def tdes_bloco(chave, bloco, cifrar=True):
    """Um bloco de 3DES: cifra-decifra-cifra (EDE)."""
    k1, k2, k3 = _tres(chave)
    if cifrar:
        return des_bloco(k3, des_bloco(k2, des_bloco(k1, bloco), False))
    return des_bloco(k1, des_bloco(k2, des_bloco(k3, bloco, False)), False)


def tdes_ecb(chave, dados, cifrar=True):
    if len(dados) % BLOCO:
        raise DesErro("dados: multiplo de 8 bytes")
    return b"".join(tdes_bloco(chave, dados[i:i + 8], cifrar)
                    for i in range(0, len(dados), 8))


def tdes_cbc(chave, iv, dados, cifrar=True):
    if len(dados) % BLOCO or len(iv) != BLOCO:
        raise DesErro("dados: multiplo de 8 bytes; IV: 8 bytes")
    saida, ant = [], iv
    for i in range(0, len(dados), 8):
        b = dados[i:i + 8]
        if cifrar:
            ant = tdes_bloco(chave, bytes(x ^ y for x, y in zip(b, ant)))
            saida.append(ant)
        else:
            saida.append(bytes(x ^ y for x, y in
                               zip(tdes_bloco(chave, b, False), ant)))
            ant = b
    return b"".join(saida)


def paridade_impar(chave):
    """A chave com o bit baixo de cada byte ajustado para paridade impar."""
    return bytes((b & 0xFE) | ((bin(b >> 1).count("1") + 1) & 1)
                 for b in chave)


def paridade_ok(chave):
    return all(bin(b).count("1") & 1 for b in chave)


def kcv(chave):
    """KCV de uma chave 3DES: os 3 primeiros bytes de cifrar 8 zeros."""
    return tdes_bloco(chave, bytes(8))[:3]
