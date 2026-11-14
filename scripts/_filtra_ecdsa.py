#!/usr/bin/env python3
"""Filtra um arquivo de vetores de ECDSA do CAVP para a curva P-256 e,
onde ha hash, para o SHA-256.

Nada e calculado nem reescrito aqui: as linhas que ficam sao copiadas
literalmente do arquivo de origem, cujo zip tem o SHA-256 no MANIFEST.
Ficam o cabecalho de comentarios e as secoes [P-256] e [P-256,SHA-256].

Uso: _filtra_ecdsa.py <arquivo de origem> <saida>
"""
import re
import sys
import pathlib

src = pathlib.Path(sys.argv[1]).read_text()
saida, fica, cabecalho, secoes = [], False, True, 0

for linha in src.splitlines(keepends=True):
    if cabecalho and (linha.startswith("#") or not linha.strip()):
        saida.append(linha)
        continue
    cabecalho = False
    m = re.match(r"^\[([PKB]-\d+)(?:,(SHA-[\d/]+))?\]", linha)
    if m:
        fica = m.group(1) == "P-256" and m.group(2) in (None, "SHA-256")
        secoes += fica
    if fica:
        saida.append(linha)

if secoes != 1:
    sys.exit(f"{sys.argv[1]}: esperava 1 secao do P-256, achei {secoes}")

pathlib.Path(sys.argv[2]).write_text("".join(saida))
