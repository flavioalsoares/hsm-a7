#!/usr/bin/env python3
"""Extrai os valores de MAC e de dados do DUKPT (etapa 8.9b), TDES e AES, de
duas fontes de terceiros, e escreve um .rsp no estilo dos demais vetores.

Nada e calculado aqui. Os campos sao copiados literalmente dos arquivos de
origem, cujos SHA-256 estao no MANIFEST. A extracao falha se algum vetor
faltar ou tiver o tamanho errado.

  openemv/dukpt (os mesmos arquivos e o mesmo commit da 8.8):
    TDES (X9.24-1:2009 A.4.2 e A.4.3): o MAC de pedido e o de resposta, de 4
      bytes, e os dados de pedido cifrados, para as 34 transacoes. Os CMACs
      do arquivo nao entram: estao marcados la como "hand crafted".
    AES (suplemento da X9.24-3:2017): as chaves de MAC (uso 2000, "MAC
      generation") e de dados (uso 3000, "data encryption") das 8 primeiras
      transacoes; AES-128 com a BDK AES-128, e AES-128 e AES-256 com a BDK
      AES-256.
  moov-io/dukpt:
    TDES: 5 transacoes do anexo A.4, com o MAC de pedido e o de resposta de 8
      bytes e os dados de pedido e de resposta cifrados.
    AES: 8 transacoes da BDK AES-128 do suplemento, com o CMAC de pedido (uso
      2000) e de resposta (2001), e os dados de pedido (3000) e de resposta
      (3001) cifrados, todos com chave de trabalho AES-128.

A mensagem e a mesma nas duas fontes, "4012345678909D987"; o script exige
isso. Os dados vao completados com zeros ate o bloco (a fonte o faz antes de
cifrar), com IV zero.

Uso: _extrai_dukpt_mac.py <diretorio com os arquivos baixados> <saida>
"""
import pathlib
import re
import sys

d = pathlib.Path(sys.argv[1])
MSG = "4012345678909D987"


def c_src(nome):
    t = (d / nome).read_text(errors="replace")
    return re.sub(r"//[^\n]*", "", t)


def vetor(src, nome):
    m = re.search(r"static (?:const )?uint8_t " + re.escape(nome) +
                  r"\s*\[\]\s*(\[[^\]]*\])?\s*=\s*\{(.*?)\};", src, re.S)
    if not m:
        sys.exit(f"vetor {nome} nao achado")
    linhas = re.findall(r"\{([^{}]*)\}", m.group(2)) if m.group(1) else [m.group(2)]
    return [bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", l))
            for l in linhas]


def exige_msg(src, onde):
    m = re.findall(r'static const char txn_data\[\] = "([^"]*)";', src)
    if m != [MSG]:
        sys.exit(f"{onde}: mensagem inesperada {m}")


def colunas(src, ksn_v, campos, tam, onde):
    ks = vetor(src, ksn_v)
    cols = {c: vetor(src, v) for c, v in campos.items()}
    if not ks or any(len(v) != len(ks) for v in cols.values()):
        sys.exit(f"{onde}: listas de tamanhos diferentes")
    saida = []
    for j, k in enumerate(ks):
        reg = [f"KSN = {k.hex().upper()}"]
        for c, v in cols.items():
            if len(v[j]) != tam[c]:
                sys.exit(f"{onde}: {c} de tamanho errado")
            reg.append(f"{c} = {v[j].hex().upper()}")
        saida.append(reg)
    return saida


linhas = [
    "# DUKPT, MAC e dados (etapa 8.9b) -- valores de terceiros, de duas fontes:",
    "# openemv/dukpt e moov-io/dukpt.",
    "#",
    "# NAO E VETOR DO CAVP. Ver vectors/MANIFEST.txt para a procedencia e",
    "# para o que estes valores cobrem e o que NAO cobrem. As BDKs sao as de",
    "# x924_1_tdes.rsp e x924_3_aes*.rsp.",
    "#",
    "# MSG      a mensagem, em hex (\"4012345678909D987\"), das duas fontes",
    "# REQMAC   MAC de pedido; RESMAC  MAC de resposta (TDES: retail MAC sob a",
    "#          variante; 4 bytes no openemv, 8 no moov-io)",
    "# REQDATA  os dados de pedido cifrados; RESDATA  os de resposta",
    "# MACKEY128/256, DATAKEY128/256  as chaves de trabalho AES (usos 2000 e 3000)",
    "# CMACREQ, CMACRES  o CMAC de pedido (2000) e de resposta (2001)",
    "",
    f"MSG = {MSG.encode().hex().upper()}",
    "",
]
total = 0


def secao(nome, regs):
    global total
    linhas.extend([f"[{nome}]", ""])
    for reg in regs:
        linhas.append(f"COUNT = {total}")
        linhas.extend(reg)
        linhas.append("")
        total += 1


# ---- openemv, TDES --------------------------------------------------------
s = c_src("openemv_dukpt_tdes_test.c")
exige_msg(s, "openemv TDES")
tam = {"REQMAC": 4, "RESMAC": 4, "REQDATA": 24}
regs = colunas(s, "ksn_verify", {"REQMAC": "mac_request_verify",
                                 "RESMAC": "mac_response_verify",
                                 "REQDATA": "txn_request_verify"}, tam, "openemv A.4.2")
regs += colunas(s, "ksn_verify2", {"REQMAC": "mac_request_verify2",
                                   "RESMAC": "mac_response_verify2",
                                   "REQDATA": "txn_request_verify2"}, tam, "openemv A.4.3")
if len(regs) != 34:
    sys.exit(f"openemv TDES: esperava 34, achei {len(regs)}")
secao("openemv TDES", regs)

# ---- openemv, AES ---------------------------------------------------------
s = c_src("openemv_dukpt_aes128_test.c")
exige_msg(s, "openemv AES-128")
regs = colunas(s, "ksn_verify", {"MACKEY128": "cmac_aes128_key_verify",
                                 "DATAKEY128": "data_aes128_key_verify"},
               {"MACKEY128": 16, "DATAKEY128": 16}, "openemv AES-128")
if len(regs) != 8:
    sys.exit("openemv AES-128: esperava 8")
secao("openemv AES BDK128", regs)
s = c_src("openemv_dukpt_aes256_test.c")
exige_msg(s, "openemv AES-256")
regs = colunas(s, "ksn_verify", {"MACKEY128": "cmac_aes128_key_verify",
                                 "MACKEY256": "cmac_aes256_key_verify",
                                 "DATAKEY128": "data_aes128_key_verify",
                                 "DATAKEY256": "data_aes256_key_verify"},
               {"MACKEY128": 16, "MACKEY256": 32, "DATAKEY128": 16,
                "DATAKEY256": 32}, "openemv AES-256")
if len(regs) != 8:
    sys.exit("openemv AES-256: esperava 8")
secao("openemv AES BDK256", regs)

# ---- moov-io, TDES --------------------------------------------------------
t = (d / "moov_des_test.go").read_text(errors="replace")
if re.findall(r'data := "([^"]*)"', t) != [MSG]:
    sys.exit("moov TDES: mensagem inesperada")
H = r'pkg\.HexDecode\("([0-9A-F]+)"\)'
itens = re.findall(r"Ksn:\s*" + H + r",\s*CurrentKey:\s*" + H + r",\s*PinEnc:\s*" + H +
                   r",\s*DataReqEnc:\s*" + H + r",\s*DataResEnc:\s*" + H +
                   r",\s*RequestMac:\s*" + H + r",\s*ResponseMac:\s*" + H, t)
if len(itens) != 5:
    sys.exit(f"moov TDES: esperava 5, achei {len(itens)}")
regs = []
for ksn, _k, _p, dreq, dres, mreq, mres in itens:
    if (len(ksn), len(dreq), len(dres), len(mreq), len(mres)) != (20, 48, 48, 16, 16):
        sys.exit("moov TDES: tamanho errado")
    regs.append([f"KSN = {ksn}", f"REQMAC = {mreq}", f"RESMAC = {mres}",
                 f"REQDATA = {dreq}", f"RESDATA = {dres}"])
secao("moov-io TDES", regs)

# ---- moov-io, AES ---------------------------------------------------------
t = (d / "moov_aes_test.go").read_text(errors="replace")
if re.findall(r'macData := "([^"]*)"', t) != [MSG]:
    sys.exit("moov AES: mensagem inesperada")
Q = r'"([0-9A-F]+)"'
itens = re.findall(r"Ksn:\s*" + Q + r",\s*CurrentKey:\s*" + Q + r",\s*CMACRequest:\s*" + Q +
                   r",\s*CMACResponse:\s*" + Q + r",\s*HMACRequest:\s*" + Q +
                   r",\s*HMACResponse:\s*" + Q + r",\s*DataRequest:\s*" + Q +
                   r",\s*DataResponse:\s*" + Q, t)
if len(itens) != 8:
    sys.exit(f"moov AES: esperava 8, achei {len(itens)}")
regs = []
for ksn, _k, creq, cres, _hq, _hr, dreq, dres in itens:
    if (len(ksn), len(creq), len(cres), len(dreq), len(dres)) != (24, 32, 32, 64, 64):
        sys.exit("moov AES: tamanho errado")
    regs.append([f"KSN = {ksn}", f"CMACREQ = {creq}", f"CMACRES = {cres}",
                 f"REQDATA = {dreq}", f"RESDATA = {dres}"])
secao("moov-io AES BDK128", regs)

pathlib.Path(sys.argv[2]).write_text("\n".join(linhas))
print(f"    {sys.argv[2]}: {total} transacoes")
