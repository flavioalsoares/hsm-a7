#!/usr/bin/env python3
"""Extrai os valores do DUKPT TDES (ANSI X9.24-1:2009, anexo A.4) do arquivo
de testes do projeto `openemv/dukpt`, e escreve um .rsp no estilo dos demais
vetores.

Nada e calculado aqui. Cada valor e copiado literalmente de um vetor C do
arquivo de origem, cujo SHA-256 esta no MANIFEST. A extracao falha se algum
vetor faltar ou tiver o tamanho errado.

O arquivo de origem tambem traz MACs e CMACs. Os CMACs estao marcados la
como "hand crafted" (feitos pelo autor, nao da norma), e os MACs sao da
etapa 8.9: nenhum dos dois entra aqui.

Uso: _extrai_dukpt_tdes.py <dukpt_tdes_test.c de origem> <saida .rsp>
"""
import pathlib
import re
import sys

src = pathlib.Path(sys.argv[1]).read_text(errors="replace")


def vetor(nome):
    """Bytes de `static const uint8_t nome[] = { ... };` ou de uma matriz
    `nome[][N] = { {...}, {...} };`. Devolve uma lista de linhas (bytes)."""
    m = re.search(r"static const uint8_t " + re.escape(nome) +
                  r"\s*\[\]\s*(\[[^\]]*\])?\s*=\s*\{(.*?)\};", src, re.S)
    if not m:
        sys.exit(f"vetor {nome} nao achado")
    corpo = m.group(2)
    if m.group(1):
        linhas = re.findall(r"\{([^{}]*)\}", corpo)
    else:
        linhas = [corpo]
    return [bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", l))
            for l in linhas]


def um(nome, n):
    v = vetor(nome)
    if len(v) != 1 or len(v[0]) != n:
        sys.exit(f"{nome}: esperava {n} bytes")
    return v[0].hex().upper()


bdk = um("bdk", 16)
iksn = um("iksn", 10)
ik = um("ik_verify", 16)
pb = um("pinblock", 8)
pan = um("pan", 7)

linhas = [
    "# DUKPT TDES (ANSI X9.24-1:2009, anexo A.4) -- valores de terceiros,",
    "# copiados do arquivo de testes do projeto `openemv/dukpt`, que os",
    "# transcreve da norma.",
    "#",
    "# NAO E VETOR DO CAVP. Ver vectors/MANIFEST.txt para a procedencia e",
    "# para o que estes valores cobrem e o que eles NAO cobrem.",
    "#",
    "# BDK      chave base de derivacao",
    "# IKSN     KSN inicial; IPEK = chave inicial do terminal",
    "# PINBLOCK o PIN block formato 0 em claro (PIN 1234 e o PAN do anexo)",
    "# PAN      o PAN do anexo, em BCD com F no fim (padrao de teste, nao e cartao)",
    "# KSN      um KSN de transacao; KEY a chave de transacao (sem variante);",
    "#          EPB o PIN block cifrado sob a variante de PIN dessa chave",
    "",
    f"BDK = {bdk}", f"IKSN = {iksn}", f"IPEK = {ik}",
    f"PINBLOCK = {pb}", f"PAN = {pan}", "",
]
total = 0
for seq, (k, t, e) in (("A.4.2", ("ksn_verify", "txn_key_verify",
                                    "encrypted_pinblock_verify")),
                       ("A.4.3", ("ksn_verify2", "txn_key_verify2",
                                  "encrypted_pinblock_verify2"))):
    ks, ts, es = vetor(k), vetor(t), vetor(e)
    if not (len(ks) == len(ts) == len(es)) or not ks:
        sys.exit(f"{seq}: listas de tamanhos diferentes")
    linhas.append(f"[{seq}]")
    linhas.append("")
    for a, b, c in zip(ks, ts, es):
        if (len(a), len(b), len(c)) != (10, 16, 8):
            sys.exit(f"{seq}: tamanho errado")
        linhas += [f"COUNT = {total}", f"KSN = {a.hex().upper()}",
                   f"KEY = {b.hex().upper()}", f"EPB = {c.hex().upper()}", ""]
        total += 1
pathlib.Path(sys.argv[2]).write_text("\n".join(linhas))
print(f"    {sys.argv[2]}: {total} transacoes")
