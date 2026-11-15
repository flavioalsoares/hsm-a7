#!/usr/bin/env python3
"""Extrai os valores conhecidos de verificacao de PIN (offset e PVV) do
arquivo de testes do `psec`, e escreve um .rsp no estilo dos demais vetores.

Nada e calculado aqui. Os campos sao copiados literalmente do arquivo de
origem, cujo SHA-256 esta no MANIFEST. O script falha se o arquivo nao tiver
exatamente a quantidade esperada de valores em cada funcao de teste, ou se a
chave do teste mudar.

Uso: _extrai_pinverif.py <test_pin.py de origem> <saida>
"""
import re
import sys
import pathlib

src = pathlib.Path(sys.argv[1]).read_text(errors="replace")
CHAVE = "0123456789ABCDEFFEDCBA9876543210"


def trecho(nome):
    """O bloco `parametrize` logo antes de `def <nome>`, e o corpo dela."""
    fim = src.index(f"def {nome}(")
    ini = src.rindex("@pytest.mark.parametrize", 0, fim)
    corpo = src[fim:src.find("\n\n\n", fim)]
    if f'bytes.fromhex("{CHAVE}")' not in corpo:
        sys.exit(f"{nome}: a chave do teste de origem mudou")
    return src[ini:fim]


def linhas(padrao, nome, quantos):
    achados = re.findall(padrao, trecho(nome))
    if len(achados) != quantos:
        sys.exit(f"{nome}: esperava {quantos} valores, achei {len(achados)}")
    return achados


S = r'"([0-9A-Fa-f]*)"'
N = r'(\d+)'
sete = (r'\(\s*' + S + r'\s*,\s*' + S + r'\s*,\s*' + S + r'\s*,\s*' + N +
        r'\s*,\s*' + N + r'\s*,\s*' + S + r'\s*,\s*' + S + r'\s*\)')
quatro = (r'\(\s*' + S + r'\s*,\s*' + S + r'\s*,\s*' + S + r'\s*,\s*' + S +
          r'\s*\)')

do_offset = linhas(sete, "test_generate_ibm3624_pin", 10)
do_pin = linhas(sete, "test_generate_ibm3624_offset", 10)
pvv = linhas(quatro, "test_generate_visa_pvv", 4)

out = [
    "# Verificacao de PIN, offset e PVV -- valores conhecidos de terceiros.",
    "#",
    "# NAO E VETOR OFICIAL. Ver vectors/MANIFEST.txt para a procedencia e",
    "# para o que estes valores cobrem e o que NAO cobrem.",
    "#",
    "# KEY     a chave de verificacao, 3DES de comprimento duplo",
    "# TABLE   a tabela de decimalizacao",
    "# PAN     a origem dos dados de validacao: OFS e o primeiro caractere,",
    "#         LEN e quantos, PAD completa ate 16",
    "# OFFSET  o offset; PIN  o PIN; INDEX  o indice da chave do PVV",
    "",
    f"KEY = {CHAVE}",
    "",
    "[offset -> PIN]",
    "",
]
for tab, off, pan, o, n, pad, pin in do_offset:
    out += [f"TABLE = {tab}", f"OFFSET = {off}", f"PAN = {pan}", f"OFS = {o}",
            f"LEN = {n}", f"PAD = {pad}", f"PIN = {pin}", ""]
out += ["[PIN -> offset]", ""]
for tab, pin, pan, o, n, pad, off in do_pin:
    out += [f"TABLE = {tab}", f"PIN = {pin}", f"PAN = {pan}", f"OFS = {o}",
            f"LEN = {n}", f"PAD = {pad}", f"OFFSET = {off}", ""]
out += ["[PVV]", ""]
for ind, pin, pan, v in pvv:
    out += [f"INDEX = {ind}", f"PIN = {pin}", f"PAN = {pan}", f"PVV = {v}", ""]

pathlib.Path(sys.argv[2]).write_text("\n".join(out))
print(f"    {sys.argv[2]}: {len(do_offset) + len(do_pin) + len(pvv)} valores")
