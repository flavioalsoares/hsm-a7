#!/usr/bin/env python3
"""Extrai os valores conhecidos de PIN block ISO 9564 formato 4 do arquivo
de testes do `psec`, e escreve um .rsp no estilo dos demais vetores.

Nada e calculado aqui. Os campos sao copiados literalmente do arquivo de
origem, cujo SHA-256 esta no MANIFEST. O script falha se o arquivo nao
tiver exatamente os valores esperados em cada funcao de teste.

Uso: _extrai_pinblock.py <test_pinblock.py de origem> <saida .rsp>
"""
import re
import sys
import pathlib

src = pathlib.Path(sys.argv[1]).read_text(errors="replace")


def trecho(nome):
    """O bloco `parametrize` logo antes de `def <nome>`."""
    fim = src.index(f"def {nome}(")
    ini = src.rindex("@pytest.mark.parametrize", 0, fim)
    return src[ini:fim]


def um(padrao, texto, o_que):
    achados = re.findall(padrao, texto)
    if len(achados) != 1:
        sys.exit(f"esperava 1 {o_que}, achei {len(achados)}")
    return achados[0]


pin_c = um(r'\(\s*"(\d+)"\s*,\s*"([0-9A-F]{16})"\s*\)',
           trecho("test_encode_pin_field_iso_4"), "campo de PIN")
pan_c = um(r'\(\s*"(\d+)"\s*,\s*"([0-9A-F]{32})"\s*\)',
           trecho("test_encode_pan_field_iso_4"), "campo de PAN")
t = trecho("test_encipher_pinblock_iso_4_det")
cif = um(r'bytes\.fromhex\("([0-9A-Fa-f]+)"\)\s*,\s*"(\d+)"\s*,\s*"(\d+)"\s*,'
         r'\s*"([0-9A-F]{32})"', t, "bloco cifrado")
# O teste de origem fixa os 8 bytes aleatorios em FF.
i = src.index("def test_encipher_pinblock_iso_4_det(")
if 'bytes.fromhex("FF") * n' not in src[i:i + 400]:
    sys.exit("o teste de origem nao fixa mais o aleatorio em FF")

pathlib.Path(sys.argv[2]).write_text(
    "# PIN block ISO 9564-1 formato 4 -- valores conhecidos de terceiros.\n"
    "#\n"
    "# NAO E VETOR OFICIAL. Ver vectors/MANIFEST.txt para a procedencia e\n"
    "# para o que estes valores cobrem e o que NAO cobrem.\n"
    "#\n"
    "# PINFIELD  os 8 primeiros bytes do campo do PIN (os outros 8 sao\n"
    "#           aleatorios)\n"
    "# PANFIELD  o campo do PAN, 16 bytes\n"
    "# RND       os 8 bytes aleatorios do campo do PIN\n"
    "# BLOCK     o PIN block cifrado\n"
    "\n"
    "[campo do PIN]\n\n"
    f"PIN = {pin_c[0]}\n"
    f"PINFIELD = {pin_c[1]}\n"
    "\n"
    "[campo do PAN]\n\n"
    f"PAN = {pan_c[0]}\n"
    f"PANFIELD = {pan_c[1]}\n"
    "\n"
    "[AES-128]\n\n"
    f"KEY = {cif[0].upper()}\n"
    f"PIN = {cif[1]}\n"
    f"PAN = {cif[2]}\n"
    "RND = FFFFFFFFFFFFFFFF\n"
    f"BLOCK = {cif[3]}\n"
)
print(f"    {sys.argv[2]}: 3 valores")
