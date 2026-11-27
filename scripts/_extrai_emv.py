#!/usr/bin/env python3
"""Extrai os valores de ARQC e de ARPC (etapa 8.10), 3DES, de duas fontes de
terceiros, e escreve um .rsp no estilo dos demais vetores.

Nada e calculado aqui. Os campos sao copiados literalmente dos arquivos de
origem, cujos SHA-256 estao no MANIFEST. A unica montagem e a dos dados da
transacao do jPOS, que o teste dele tambem faz: a concatenacao, na ordem de
getDataNoPad(), dos campos de EMVTxnData. A extracao falha se algum valor
faltar.

  pyemv (Python, MIT), tests/test_ac_hsm.py, test_kd_hsm.py, test_cvn_hsm.py:
    chave do cartao pela Opcao A, chave de sessao comum (CSK) com um R dado,
    ARQC com preenchimento EMV (0x80) e Visa (zeros), ARPC metodo 1 e 2; e os
    criptogramas CVN 10 (MK direto) e CVN 18 (CSK com o ATC) sobre os campos
    de uma transacao.
  jPOS (Java), JCESecurityModuleTest.java:
    IMK "4 times 12345678" (o comentario; o KCV do construtor o confere),
    PAN 1234567890123456, PSN 00, ATC 3456, ARQC VSDC (MK direto) e EMV_CSKD
    (CSK), preenchimento 00 e 80, ARPC metodo 1 e 2. Os casos MCHIP (derivacao
    de sessao propria de uma bandeira) e Opcao B ficam fora do escopo.

Os casos de ARPC metodo 1 do pyemv que usam a MK com um ARQC da CSK nao
entram: a EMV Book 2 (A1.2.1) usa a chave de sessao, e o jPOS e o
test_derive_common_sk do proprio pyemv tambem. O ARQC deles entra.

Uso: _extrai_emv.py <diretorio com os arquivos baixados> <saida>
"""
import pathlib
import re
import sys

d = pathlib.Path(sys.argv[1])
saida = pathlib.Path(sys.argv[2])


def falha(msg):
    raise SystemExit("extrai_emv: " + msg)


def corpo_py(texto, nome):
    m = re.search(r"^def " + nome + r"\(.*?(?=^def |\Z)", texto, re.M | re.S)
    if not m:
        falha("teste %s nao achado" % nome)
    return m.group(0)


def hexvar(corpo, var):
    m = re.search(r"\b" + var + r"\s*=\s*bytes\.fromhex\(\"([0-9A-Fa-f]*)\"\)", corpo)
    if not m:
        falha("%s nao achado" % var)
    return m.group(1).upper()


def strvar(corpo, var):
    m = re.search(r"\b" + var + r"\s*=\s*\"([0-9]+)\"", corpo)
    if not m:
        falha("%s nao achado" % var)
    return m.group(1)


def assert_hex(corpo, expr):
    m = re.search(re.escape(expr) + r"\.hex\(\)\.upper\(\)\s*==\s*\"([0-9A-F]+)\"", corpo)
    if not m:
        falha("assert de %s nao achado" % expr)
    return m.group(1)


reg = []

# --------------------------------------------------------------------- pyemv
ac = (d / "test_ac_hsm.py").read_text()
kd = (d / "test_kd_hsm.py").read_text()
cvn = (d / "test_cvn_hsm.py").read_text()

PYEMV = [
    # arquivo, teste, arpc metodo 1 entra?
    (ac, "test_ac_hsm.py", "test_generate_ac_emv_arpc1", False),
    (ac, "test_ac_hsm.py", "test_generate_ac_visa_aprc1", False),
    (ac, "test_ac_hsm.py", "test_generate_ac_visa_aprc1_no_padding_required", False),
    (ac, "test_ac_hsm.py", "test_generate_arpc2", None),
    (ac, "test_ac_hsm.py", "test_generate_arpc2_no_prop_auth_data", None),
    (kd, "test_kd_hsm.py", "test_derive_common_sk", True),
]
for texto, arq, nome, m1 in PYEMV:
    c = corpo_py(texto, nome)
    if "derive_icc_mk_a(" not in c or "derive_common_sk(" not in c:
        falha("%s nao e Opcao A com CSK" % nome)
    r = {"FONTE": "pyemv %s %s" % (arq, nome), "ESQUEMA": "CSK"}
    r["IMK"] = hexvar(c, "iss_mk")
    r["IMKKCV2"] = assert_hex(c, "tools.key_check_digits(iss_mk, 2)")
    r["PAN"] = strvar(c, "pan")
    r["PSN"] = strvar(c, "psn")
    r["MKKCV2"] = assert_hex(c, "tools.key_check_digits(icc_mk, 2)")
    r["R"] = hexvar(c, "r")
    r["SKKCV2"] = assert_hex(c, "tools.key_check_digits(sk_ac, 2)")
    r["DADOS"] = hexvar(c, "cipher_text")
    pad = re.search(r"generate_ac\(sk_ac, cipher_text(?:, ac\.PaddingType\.(\w+))?\)", c)
    if not pad:
        falha("generate_ac em %s" % nome)
    r["PAD"] = {None: "2", "EMV": "2", "VISA": "1"}[pad.group(1)]
    r["ARQC"] = assert_hex(c, "arqc")
    if m1 is True:
        if "generate_arpc_1(sk_ac, arqc, arpc_rc)" not in c:
            falha("arpc 1 com a chave de sessao em %s" % nome)
        r["ARC"] = hexvar(c, "arpc_rc")
        r["ARPC1"] = assert_hex(c, "arpc")
    elif m1 is None:
        if "generate_arpc_2(sk_ac, arqc, csu" not in c:
            falha("arpc 2 em %s" % nome)
        r["CSU"] = hexvar(c, "csu")
        r["PAD_AUT"] = (hexvar(c, "prop_auth_data")
                        if "prop_auth_data =" in c else "")
        r["ARPC2"] = assert_hex(c, "arpc")
    reg.append(r)

# CVN 10 e CVN 18: os campos da transacao, na ordem dos argumentos
TAGS = ["tag_9f02", "tag_9f03", "tag_9f1a", "tag_95", "tag_5f2a", "tag_9a",
        "tag_9c", "tag_9f37", "tag_82"]
for nome, esquema, extra, pad in (("test_visa_cvn10", "MK", "cvr", "1"),
                                  ("test_visa_cvn18", "CSK", "tag_9f10", "2")):
    c = corpo_py(cvn, nome)
    r = {"FONTE": "pyemv test_cvn_hsm.py %s" % nome, "ESQUEMA": esquema}
    r["IMK"] = hexvar(c, "iss_mk_ac")
    # o teste e parametrizado: PAN e PSN vem do decorador
    dec = re.search(r"\(b\"(\d+)\", b\"(\d+)\"", cvn[cvn.rfind("@pytest", 0, cvn.find("def " + nome)):cvn.find("def " + nome)])
    if not dec:
        falha("PAN de %s" % nome)
    r["PAN"], r["PSN"] = dec.group(1), dec.group(2)
    r["MKKCV2"] = re.search(r"key_check_digits\(cvn\d+\.icc_mk_ac\)\.hex\(\)\.upper\(\) == \"([0-9A-F]+)\"", c).group(1)
    r["ATC"] = hexvar(c, "atc")
    campos = "".join(hexvar(c, t) for t in TAGS) + r["ATC"] + hexvar(c, extra)
    if "tag_9f36=atc" not in c:
        falha("ATC fora dos campos em %s" % nome)
    r["DADOS"] = campos
    r["PAD"] = pad
    r["ARQC"] = assert_hex(c, "arqc")
    if esquema == "CSK":
        r["SKKCV2"] = re.search(r"_derive_sk_ac_common\(atc\)\)\.hex\(\)\.upper\(\)\s*==\s*\"([0-9A-F]+)\"", c).group(1)
        r["CSU"] = hexvar(c, "csu")
        r["PAD_AUT"] = ""
        r["ARPC2"] = assert_hex(c, "arpc")
    else:
        r["ARC"] = hexvar(c, "arpc_rc")
        r["ARPC1"] = assert_hex(c, "arpc")
    reg.append(r)

# ---------------------------------------------------------------------- jPOS
j = (d / "JCESecurityModuleTest.java").read_text()
m = re.search(r"Clear key value: 4 times 12345678\s*\*/\s*static SecureDESKey imkac = new "
              r"SecureDESKey\([^,]+,[^,]+,\"([0-9A-F]+)\", \"([0-9A-F]+)\"\)", j)
if not m:
    falha("imkac do jPOS")
IMK_J = "12345678" * 4
IMK_J_KCV = m.group(2)


def jconst(nome):
    m = re.search(r"static final String " + nome + r" = \"(\d+)\";", j)
    if not m:
        falha(nome)
    return m.group(1)


PAN_J, PSN_J = jconst("accountNoA"), jconst("accountNoA_CSN")
dm = dict(re.findall(r"dm\.put\(\"(\w+)\",\s*ISOUtil\.hex2byte\(\"([0-9A-F]+)\"\)\);", j))
ordem = re.findall(r"data = ISOUtil\.concat\(data, dm\.get\(\"(\w+)\"\) \);", j)
if len(ordem) != 11 or any(k not in dm for k in ordem):
    falha("EMVTxnData do jPOS")
DADOS_J = "".join(dm[k] for k in ordem)
ATC_J = dm["ATC"]


def jmetodo(nome):
    m = re.search(r"public void " + nome + r"\(\) throws Throwable \{(.*?)\n    \}", j, re.S)
    if not m:
        falha("teste %s do jPOS" % nome)
    return m.group(1)


def jhex(corpo, var):
    m = re.search(r"byte\[\] " + var + r"\s*=\s*ISOUtil\.hex2byte\(\"([0-9A-F]+)\"\);", corpo)
    if not m:
        falha("%s no jPOS" % var)
    return m.group(1)


def jbase(nome, c):
    if "MKDMethod.OPTION_A" not in c or "accountNoA, accountNoA_CSN" not in c:
        falha("%s nao e Opcao A com accountNoA" % nome)
    esq = "MK" if "SKDMethod.VSDC" in c else ("CSK" if "SKDMethod.EMV_CSKD" in c else None)
    if esq is None:
        falha("esquema de %s" % nome)
    return {"FONTE": "jPOS JCESecurityModuleTest.java %s" % nome, "ESQUEMA": esq,
            "IMK": IMK_J, "IMKKCV": IMK_J_KCV, "PAN": PAN_J, "PSN": PSN_J,
            "ATC": ATC_J}


for nome in ("testVerifyARQCImpl_VSDC_P00", "testVerifyARQCImpl_VSDC_P80",
             "testVerifyARQCImpl_CSKD_P00", "testVerifyARQCImpl_CSKD_P80"):
    c = jmetodo(nome)
    r = jbase(nome, c)
    r["DADOS"] = DADOS_J
    r["PAD"] = "1" if "getDataNoPad()" in c else "2"
    r["ARQC"] = jhex(c, "arqc")
    reg.append(r)

for nome in ("testVerifyARQCGenerateARPCImpl_VSDC_P00_M1",
             "testVerifyARQCGenerateARPCImpl_VSDC_P80_M1",
             "testVerifyARQCGenerateARPCImpl_CSKD_P00_M1",
             "testVerifyARQCGenerateARPCImpl_CSKD_P80_M1",
             "testVerifyARQCGenerateARPCImpl_CSKD_P00_M2",
             "testVerifyARQCGenerateARPCImpl_CSKD_P80_M2"):
    c = jmetodo(nome)
    r = jbase(nome, c)
    r["DADOS"] = DADOS_J
    r["PAD"] = "1" if "getDataNoPad()" in c else "2"
    r["ARQC"] = jhex(c, "arqc")
    if "ARPCMethod.METHOD_1" in c:
        r["ARC"] = jhex(c, "arc")
        r["ARPC1"] = jhex(c, "arpc")
    else:
        r["CSU"] = jhex(c, "csu")
        r["PAD_AUT"] = ""
        r["ARPC2"] = jhex(c, "arpc")
    reg.append(r)

# ---------------------------------------------------------------------- saida
ORDEM = ["ESQUEMA", "IMK", "IMKKCV", "IMKKCV2", "PAN", "PSN", "MKKCV2", "ATC", "R",
         "SKKCV2", "PAD", "DADOS", "ARQC", "ARC", "ARPC1", "CSU", "PAD_AUT", "ARPC2"]
L = ["# ARQC e ARPC, 3DES, chave do cartao pela Opcao A (etapa 8.10).",
     "# Valores de terceiros, de duas fontes: pyemv e jPOS. Ver vectors/MANIFEST.txt.",
     "# ESQUEMA MK: o criptograma sai da chave do cartao (CVN 10). CSK: da chave de",
     "# sessao comum, com R = ATC || 000000000000, ou o R dado.",
     "# PAD 1: zeros ate o bloco (ISO 9797-1 metodo 1); 2: 80 e zeros (metodo 2).",
     "# KCV2: os 2 primeiros bytes do KCV, como o pyemv confere.", ""]
for r in reg:
    L.append("[%s]" % r["FONTE"])
    for k in ORDEM:
        if k in r:
            L.append("%s = %s" % (k, r[k]))
    L.append("")
saida.parent.mkdir(parents=True, exist_ok=True)
saida.write_text("\n".join(L))
print("%d casos -> %s" % (len(reg), saida))
