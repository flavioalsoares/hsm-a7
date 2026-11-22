#!/usr/bin/env python3
"""Extrai os valores conhecidos de key block X9.143 versao B (KBPK 3DES) do
arquivo de testes do `psec`, e escreve um .rsp no estilo dos demais vetores.

Nada e calculado aqui. Os tres campos de cada registro sao copiados
literalmente das tuplas do arquivo de origem, cujo SHA-256 esta no MANIFEST.
A extracao falha se nao achar exatamente 6 blocos da versao B.

Os 6 vao todos para o arquivo, inclusive os que este projeto recusa (chave
de DES simples, blocos opcionais). Quem le o arquivo decide: o teste exige
a chave nos aceitos e a recusa nos outros.

Uso: _extrai_tr31b.py <test_tr31.py de origem> <saida .rsp>
"""
import pathlib
import re
import sys

ESPERADOS = 6

src = pathlib.Path(sys.argv[1]).read_text(errors="replace")

# A tupla e ("<kbpk hex>", "<chave hex>", "<key block>"). Os blocos da
# versao B sao os que comecam com 'B' seguido do comprimento.
achados = re.findall(
    r'\(\s*"([0-9A-Fa-f]+)"\s*,\s*"([0-9A-Fa-f]+)"\s*,\s*"(B[0-9]{4}[0-9A-Za-z]+)"\s*\)',
    src)
if len(achados) != ESPERADOS:
    sys.exit(f"esperava {ESPERADOS} blocos da versao B, achei {len(achados)}")

linhas = [
    "# ANSI X9.143 / TR-31 versao B (KBPK 3DES) -- valores conhecidos de",
    "# terceiros, copiados do arquivo de testes do `psec`.",
    "#",
    "# NAO E VETOR DO CAVP. Ver vectors/MANIFEST.txt para a procedencia e",
    "# para o que estes valores cobrem e o que eles NAO cobrem.",
    "#",
    "# KBPK  chave que protege o key block (3DES, 16 ou 24 bytes)",
    "# KEY   chave em claro que esta dentro do bloco",
    "# KB    o key block, em ASCII",
    "",
]
for i, (kbpk, chave, kb) in enumerate(achados):
    linhas += [f"COUNT = {i}", f"KBPK = {kbpk.upper()}",
               f"KEY = {chave.upper()}", f"KB = {kb}", ""]
pathlib.Path(sys.argv[2]).write_text("\n".join(linhas))
print(f"    {sys.argv[2]}: {len(achados)} blocos")
