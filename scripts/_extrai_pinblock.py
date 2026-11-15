#!/usr/bin/env python3
"""Extrai os valores conhecidos de PIN block ISO 9564, formatos 4 e 0, do
arquivo de testes do `psec`, e escreve um .rsp de cada formato, no estilo dos
demais vetores.

Nada e calculado aqui. Os campos sao copiados literalmente do arquivo de
origem, cujo SHA-256 esta no MANIFEST. O script falha se o arquivo nao
tiver exatamente os valores esperados em cada funcao de teste.

Uso: _extrai_pinblock.py <test_pinblock.py de origem> <saida do formato 4>
                         [<saida do formato 0>]
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

if len(sys.argv) > 3:
    # Formato 0: o bloco EM CLARO (campo do PIN XOR campo do PAN). A cifra
    # e o 3DES, que tem vetor do NIST.
    monta = re.findall(r'\(\s*"(\d+)"\s*,\s*"(\d+)"\s*,\s*"([0-9A-F]{16})"\s*\)',
                       trecho("test_encode_pinblock_iso_0"))
    le = re.findall(r'\(\s*"(\d+)"\s*,\s*bytes\.fromhex\("([0-9A-F]{16})"\)'
                    r'\s*,\s*"(\d+)"\s*\)',
                    trecho("test_decode_pinblock_iso_0"))
    ruins = re.findall(r'\(\s*bytes\.fromhex\("([0-9A-F]{16})"\)\s*,\s*"(\d{13,})"'
                       r'\s*,\s*"([^"]+)"\s*\)',
                       trecho("test_decode_pinblock_iso_0_exception"))
    if (len(monta), len(le), len(ruins)) != (2, 4, 5):
        sys.exit("formato 0: esperava 2, 4 e 5 valores, achei %d, %d e %d"
                 % (len(monta), len(le), len(ruins)))
    t = ("# PIN block ISO 9564-1 formato 0 -- valores conhecidos de terceiros.\n"
         "#\n"
         "# NAO E VETOR OFICIAL. Ver vectors/MANIFEST.txt para a procedencia e\n"
         "# para o que estes valores cobrem e o que NAO cobrem.\n"
         "#\n"
         "# CLEAR  o bloco em claro, 8 bytes: campo do PIN XOR campo do PAN\n"
         "\n[montar]\n\n")
    for pin, pan, bloco in monta:
        t += f"PIN = {pin}\nPAN = {pan}\nCLEAR = {bloco}\n\n"
    t += "[ler]\n\n"
    for pin, bloco, pan in le:
        t += f"PIN = {pin}\nPAN = {pan}\nCLEAR = {bloco}\n\n"
    t += "[malformado]\n\n"
    for bloco, pan, erro in ruins:
        t += f"PAN = {pan}\nCLEAR = {bloco}\nERRO = {erro}\n\n"
    pathlib.Path(sys.argv[3]).write_text(t)
    print(f"    {sys.argv[3]}: {len(monta) + len(le) + len(ruins)} valores")
