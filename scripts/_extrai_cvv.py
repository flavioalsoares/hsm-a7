#!/usr/bin/env python3
"""Extrai os valores conhecidos de CVV (CVV, CVV2 e iCVV) de tres fontes de
terceiros, e escreve um .rsp no estilo dos demais vetores.

Nada e calculado aqui. Os campos sao copiados literalmente dos arquivos de
origem, cujos SHA-256 estao no MANIFEST. O script falha se alguma fonte nao
tiver exatamente a quantidade esperada de valores.

A unica interpretacao: no jPOS a chave esta cifrada sob a LMK de teste da
biblioteca, e o valor em claro vem num comentario do tipo "Clear key value:
4 times 12345678". O script repete o grupo o numero de vezes escrito, e copia
o KCV da declaracao. `host/test_cvv.py` confere o KCV contra a chave: se a
leitura do comentario estiver errada, o teste falha.

Uso: _extrai_cvv.py <diretorio com os arquivos baixados> <saida>
"""
import re
import sys
import pathlib

d = pathlib.Path(sys.argv[1])


def le(nome):
    return (d / nome).read_text(errors="replace")


def um(padrao, texto, onde):
    achados = re.findall(padrao, texto, re.S)
    if len(achados) != 1:
        sys.exit(f"{onde}: esperava 1, achei {len(achados)}")
    return achados[0]


H = r'([0-9A-Fa-f]+)'
N = r'(\d+)'
casos = []   # (fonte, chave, kcv ou "", pan, validade, codigo, cvv)

# ---- psec: o teste ------------------------------------------------------
t = le("psec_test_cvv.py")
corpo = t[t.index("def test_generate_cvv()"):]
chave = um(r'cvk = "' + H + '"', corpo, "psec teste, chave")
pan, val, sc = um(r'generate_cvv\(bytes\.fromhex\(cvk\), "' + N + r'", "' + N +
                  r'", "' + N + r'"\)', corpo, "psec teste, entrada")
cvv = um(r'assert card_cvv == "' + N + '"', corpo, "psec teste, cvv")
casos.append(("psec, tests/test_cvv.py", chave, "", pan, val, sc, cvv))

# ---- psec: o exemplo da documentacao da funcao ---------------------------
t = le("psec_cvv.py")
chave = um(r'>>> cvk = bytes\.fromhex\("' + H + r'"\)', t, "psec doc, chave")
pan, val, sc, cvv = um(r'generate_cvv\(cvk, "' + N + r'", "' + N + r'", "' +
                       N + r'"\)\s*\n\s*\'' + N + r"'", t, "psec doc, entrada")
casos.append(("psec, psec/cvv.py (exemplo)", chave, "", pan, val, sc, cvv))

# ---- jPOS ----------------------------------------------------------------
t = le("jpos_JCESecurityModuleTest.java")


def chave_jpos(nome):
    vezes, grupo, kcv = um(
        r'Clear key value: (\d+) times ([0-9A-Fa-f]+)\s*\*/\s*static SecureDESKey '
        + nome + r' = new SecureDESKey\([^;]*?"([0-9A-Fa-f]{6})"\);',
        t, "jPOS, chave " + nome)
    return grupo * int(vezes), kcv


k, kk = chave_jpos("cvk")
ka, kka = chave_jpos("cvkA")
kb, kkb = chave_jpos("cvkB")
for nome, chave, kcv, args in (
        ("testCalculateCVDImpl1", k, kk, r'cvk, null'),
        ("testCalculateCVDImpl2", ka + kb, kka + "/" + kkb, r'cvkA, cvkB')):
    ini = t.index("public void " + nome + "(")
    corpo = t[ini:t.index("@Test", ini)]
    pan = um(r'accountNo = "' + N + '"', corpo, nome + ", PAN")
    val = um(r'expDate = "' + N + '"', corpo, nome + ", validade")
    sc = um(r'serviceCode = "' + N + '"', corpo, nome + ", codigo")
    cvv = um(r'expected = "' + N + '"', corpo, nome + ", cvv")
    um(r'calculateCVD\(accountNo, ' + args + r', expDate, serviceCode\)',
       corpo, nome + ", chaves")
    casos.append(("jPOS, " + nome, chave, kcv, pan, val, sc, cvv))

# ---- jmeter-iso8583 -------------------------------------------------------
b = le("jm_ISO8583TestBase.java")
chave = um(r'DEFAULT_3DES_KEY = "' + H + '"', b, "jmeter, chave")
t = le("jm_CalculateCVVFunctionTest.java")
corpo = t[t.index("public void shouldCalculateCVV()"):]
corpo = corpo[:corpo.index("@Test")]
pan = um(r'pan = new CompoundVariable\("' + N + r'"\)', corpo, "jmeter, PAN")
val = um(r'exp = new CompoundVariable\("' + N + r'"\)', corpo, "jmeter, validade")
um(r'cvk = new CompoundVariable\(DEFAULT_3DES_KEY\)', corpo, "jmeter, chave")
codigos = re.findall(r'setParameters\(Arrays\.asList\(cvk, pan, exp, new '
                     r'CompoundVariable\("' + N + r'"\)', corpo)
cvvs = re.findall(r'assertEquals\("' + N + r'", instance\.execute', corpo)
if len(codigos) != 3 or len(cvvs) != 3:
    sys.exit(f"jmeter: esperava 3 e 3, achei {len(codigos)} e {len(cvvs)}")
for sc, cvv in zip(codigos, cvvs):
    casos.append(("jmeter-iso8583, shouldCalculateCVV", chave, "", pan, val,
                  sc, cvv))

if len(casos) != 7:
    sys.exit(f"esperava 7 valores, achei {len(casos)}")

out = [
    "# CVV, CVV2 e iCVV -- valores conhecidos de terceiros, de tres fontes.",
    "#",
    "# NAO E VETOR OFICIAL. Ver vectors/MANIFEST.txt para a procedencia e",
    "# para o que estes valores cobrem e o que NAO cobrem.",
    "#",
    "# KEY  a chave de verificacao de cartao, 3DES de comprimento duplo",
    "#      (CVK A . CVK B)",
    "# KCV  o KCV copiado da fonte, quando ela traz; A/B quando sao duas",
    "# PAN  o numero da fonte (padrao de teste, nao e cartao)",
    "# EXP  a validade, como a fonte a escreve; SC  o codigo de servico",
    "",
]
for fonte, chave, kcv, pan, val, sc, cvv in casos:
    out += [f"# {fonte}", f"KEY = {chave.upper()}"]
    if kcv:
        out.append(f"KCV = {kcv.upper()}")
    out += [f"PAN = {pan}", f"EXP = {val}", f"SC = {sc}", f"CVV = {cvv}", ""]

pathlib.Path(sys.argv[2]).write_text("\n".join(out))
print(f"    {sys.argv[2]}: {len(casos)} valores")
