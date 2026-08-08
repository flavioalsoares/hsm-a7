#!/usr/bin/env python3
"""Estatísticas de sanidade sobre um arquivo de bytes aleatórios.

Reimplementa as cinco medidas do `ent` de John Walker, para o critério de
aceitação da fase 2 não depender de um pacote instalado na máquina.

    python3 scripts/entstat.py random.bin

---------------------------------------------------------------------
ISTO NÃO VALIDA UM RNG. LEIA ANTES DE CONCLUIR QUALQUER COISA.

Estes números detectam *lixo óbvio*: gerador travado, viés grosseiro,
período curto, bytes repetidos, saída que na verdade é um contador. É
peneira grossa, e serve para isso.

O que eles **não** fazem: um contador de 32 bits cifrado com AES passa em
todos eles com louvor, e um DRBG semeado com quatro bits de entropia
também. Nenhuma estatística sobre a SAÍDA detecta entropia insuficiente na
SEMENTE — é por isso que a SP 800-90B estima entropia sobre a amostra
BRUTA da fonte, e não sobre o que sai do DRBG.

Ou seja: passar aqui é necessário e está longe de ser suficiente. A parte
que importa de verdade são os health tests sobre a fonte
(`rtl/crypto/hsm_health.v`) e, um dia, a estimativa de H sobre o retrato de
amostras brutas.
"""
import math
import pathlib
import sys


def estatisticas(dados: bytes) -> dict:
    n = len(dados)
    if n == 0:
        raise SystemExit("arquivo vazio")

    cont = [0] * 256
    for b in dados:
        cont[b] += 1

    # Entropia de Shannon, bits por byte. Ideal: 8,0
    ent = 0.0
    for c in cont:
        if c:
            p = c / n
            ent -= p * math.log2(p)

    # Qui-quadrado sobre a distribuição dos 256 valores.
    esperado = n / 256.0
    chi2 = sum((c - esperado) ** 2 / esperado for c in cont)

    # Média aritmética. Ideal: 127,5
    media = sum(b * c for b, c in enumerate(cont)) / n

    # Monte Carlo para pi: pares de 3 bytes viram coordenadas num quadrado.
    # Converge para pi se os bytes forem independentes.
    dentro = 0
    total = 0
    for i in range(0, (n // 6) * 6, 6):
        x = int.from_bytes(dados[i:i + 3], "big") / 16777215.0
        y = int.from_bytes(dados[i + 3:i + 6], "big") / 16777215.0
        if x * x + y * y <= 1.0:
            dentro += 1
        total += 1
    pi = (4.0 * dentro / total) if total else float("nan")

    # Correlação serial: cada byte contra o seguinte. Ideal: 0
    if n > 1:
        t1 = sum(dados[i] * dados[i + 1] for i in range(n - 1)) + dados[-1] * dados[0]
        t2 = sum(dados)
        t3 = sum(b * b for b in dados)
        num = n * t1 - t2 * t2
        den = n * t3 - t2 * t2
        scc = (num / den) if den else float("nan")
    else:
        scc = float("nan")

    return {
        "n": n,
        "entropia": ent,
        "chi2": chi2,
        "media": media,
        "pi": pi,
        "scc": scc,
    }


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"uso: {sys.argv[0]} <arquivo>")

    dados = pathlib.Path(sys.argv[1]).read_bytes()
    r = estatisticas(dados)

    # Faixas de sanidade. Não são critérios estatísticos rigorosos: são
    # limites largos que só um gerador visivelmente quebrado ultrapassa.
    #
    # O qui-quadrado com 255 graus de liberdade tem média 255 e desvio
    # ~22,6. A faixa abaixo é generosa de propósito -- apertá-la produziria
    # reprovações aleatórias, e um teste que reprova por acaso ensina a
    # ignorar teste.
    limites = [
        ("entropia (bits/byte)", r["entropia"], 7.99, 8.01, "%.6f"),
        ("qui-quadrado (gl=255)", r["chi2"], 180.0, 340.0, "%.2f"),
        ("media aritmetica", r["media"], 127.0, 128.0, "%.4f"),
        ("Monte Carlo pi", r["pi"], 3.10, 3.18, "%.6f"),
        ("correlacao serial", r["scc"], -0.01, 0.01, "%.6f"),
    ]

    print(f"amostra: {r['n']} bytes")
    print()
    falhas = 0
    for nome, valor, lo, hi, fmt in limites:
        ok = lo <= valor <= hi
        if not ok:
            falhas += 1
        print(f"  {nome:24s} {fmt % valor:>12s}   "
              f"[{fmt % lo} .. {fmt % hi}]  {'ok' if ok else 'FORA'}")

    print()
    if r["n"] < 1048576:
        print(f"AVISO: {r['n']} bytes e pouco. O criterio da fase pede 1 MB --")
        print("       com amostra pequena o qui-quadrado oscila muito.")
        print()

    if falhas:
        print(f"REPROVOU em {falhas} medida(s).")
        return 1

    print("Sanidade: OK.")
    print()
    print("Isto NAO valida o gerador -- ver o cabecalho deste arquivo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
