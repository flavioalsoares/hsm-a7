#!/usr/bin/env python3
"""Cutoffs dos health tests da SP 800-90B, calculados.

Este arquivo existe para que os numeros em rtl/crypto/hsm_health.v tenham
PROCEDENCIA. A regra do projeto e nao escrever vetor nem constante "de
memoria" (CLAUDE.md); tabela de norma lembrada de cabeca e a mesma coisa
com outro nome, e um cutoff errado nao aparece em teste nenhum -- ele so
aparece em campo, ou desligando um HSM saudavel, ou deixando passar
entropia degradada.

Rodar:  python3 scripts/health-cutoffs.py

  RCT (secao 4.4.1)
      C = 1 + ceil(-log2(alpha) / H)

  APT (secao 4.4.2)
      W = 1024 para fonte binaria
      C = menor inteiro tal que P(X >= C) <= alpha, X ~ Binomial(W, 2^-H)

  alpha = 2^-20, a taxa de falso positivo que a norma adota.

SOBRE H, E ISTO E O PONTO IMPORTANTE
------------------------------------
H e a min-entropia por amostra bruta. O projeto adota H = 0,5 bit como
HIPOTESE, nao como medida. Uma validacao 90B de verdade ESTIMA H a partir
de 1.000.000 de amostras brutas coletadas do hardware real, pelo track
nao-IID da norma (ferramenta ea_non_iid do NIST).

Enquanto H for chute, os cutoffs sao chute. E por isso que o CFS tem o
registrador de retrato (TRNG_SNAP): ele e o caminho para coletar as
amostras e um dia trocar a hipotese por um numero medido.

A tabela abaixo mostra como os cutoffs se movem com H -- util para ver o
tamanho do erro que uma hipotese errada introduz.
"""

from decimal import Decimal, getcontext
from math import ceil, comb

ALPHA_EXP = 20                      # alpha = 2^-20
W_BINARIO = 1024                    # SP 800-90B 4.4.2, fonte binaria

getcontext().prec = 80


def rct_cutoff(h: float) -> int:
    """SP 800-90B 4.4.1."""
    return 1 + ceil(ALPHA_EXP / h)


def apt_cutoff(h: float, w: int = W_BINARIO) -> int:
    """Menor C com P(X >= C) <= alpha, X ~ Bin(w, 2^-h).

    Somado da cauda para baixo com Decimal: em ponto flutuante comum os
    termos extremos somem por underflow e o cutoff sai deslocado.
    """
    p = Decimal(2) ** Decimal(-h)
    q = Decimal(1) - p
    limite = Decimal(1) / Decimal(2 ** ALPHA_EXP)

    cauda = Decimal(0)
    for k in range(w, -1, -1):
        cauda += Decimal(comb(w, k)) * (p ** k) * (q ** (w - k))
        if cauda > limite:
            return k + 1        # k ja estourou; o cutoff e o anterior
    return 0


if __name__ == "__main__":
    print(f"SP 800-90B secao 4.4 -- alpha = 2^-{ALPHA_EXP}, APT W = {W_BINARIO}")
    print()
    print(f"{'H (bit/amostra)':>16} | {'RCT C':>6} | {'APT C':>6}")
    print("-" * 34)
    for h in (0.25, 0.5, 0.75, 1.0):
        marca = "   <- adotado no projeto" if h == 0.5 else ""
        print(f"{h:>16} | {rct_cutoff(h):>6} | {apt_cutoff(h):>6}{marca}")
    print()
    print("Os valores de H = 0,5 sao os defaults de rtl/crypto/hsm_health.v.")
