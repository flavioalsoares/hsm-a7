#!/usr/bin/env python3
"""Extrai o vetor conhecido de key block X9.143 versao D do arquivo de
testes do `psec`, e escreve um .rsp no estilo dos demais vetores.

Nada e calculado aqui. Os tres campos sao copiados literalmente da
tupla do arquivo de origem, cujo SHA-256 esta no MANIFEST.

Uso: _extrai_tr31.py <test_tr31.py de origem> <saida .rsp>
"""
import re
import sys
import pathlib

src = pathlib.Path(sys.argv[1]).read_text(errors="replace")

# A tupla e ("<kbpk hex>", "<chave hex>", "<key block>") e o bloco da
# versao D e o unico cujo terceiro campo comeca com 'D'.
achados = re.findall(
    r'\(\s*"([0-9A-Fa-f]+)"\s*,\s*"([0-9A-Fa-f]+)"\s*,\s*"(D[0-9A-Za-z]+)"\s*\)', src
)
if len(achados) != 1:
    sys.exit(f"esperava 1 vetor da versao D, achei {len(achados)}")

kbpk, chave, kb = achados[0]

pathlib.Path(sys.argv[2]).write_text(
    "# ANSI X9.143 / TR-31 versao D -- valor conhecido de terceiros.\n"
    "#\n"
    "# NAO E VETOR DO CAVP. Ver vectors/MANIFEST.txt para a procedencia e\n"
    "# para o que este vetor cobre e o que ele NAO cobre.\n"
    "#\n"
    "# KBPK  chave que protege o key block (AES-256)\n"
    "# KEY   chave em claro que esta dentro do bloco\n"
    "# KB    o key block, em ASCII\n"
    "\n"
    "[AES-256 KBPK]\n\n"
    f"COUNT = 0\n"
    f"KBPK = {kbpk}\n"
    f"KEY = {chave}\n"
    f"KB = {kb}\n"
)
print(f"    {sys.argv[2]}: 1 vetor")
