#!/usr/bin/env python3
"""Extrai os valores do DUKPT AES (suplemento de vetores de teste da ANSI
X9.24-3:2017), com BDK AES-128 ou AES-256, do arquivo de testes do projeto `openemv/dukpt`,
e escreve um .rsp no estilo dos demais vetores.

Nada e calculado aqui. Cada valor e copiado literalmente de um vetor C do
arquivo de origem, cujo SHA-256 esta no MANIFEST. Linhas comentadas no
arquivo de origem (`//`) NAO entram: o autor tirou de proposito o contador
0x1FFFF, que tem mais de 16 bits 1. A extracao falha se algum vetor faltar
ou tiver o tamanho errado.

Entram a chave inicial, as chaves de transacao, as chaves de PIN (AES-128 e,
com BDK AES-256, tambem AES-256) e, quando o arquivo os traz, os PIN blocks
formato 4 cifrados e os campos do PIN e do PAN. As chaves de MAC e de dados
ficam de fora: sao da etapa 8.9.

Uso: _extrai_dukpt_aes.py <dukpt_aesNNN_test.c de origem> <saida .rsp> <128|256>
"""
import pathlib
import re
import sys

src = pathlib.Path(sys.argv[1]).read_text(errors="replace")
# Tira comentarios de linha antes de qualquer busca.
src = re.sub(r"//[^\n]*", "", src)


def vetor(nome):
    m = re.search(r"static const uint8_t " + re.escape(nome) +
                  r"\s*\[\]\s*(\[[^\]]*\])?\s*=\s*\{(.*?)\};", src, re.S)
    if not m:
        sys.exit(f"vetor {nome} nao achado")
    linhas = re.findall(r"\{([^{}]*)\}", m.group(2)) if m.group(1) else [m.group(2)]
    return [bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", l))
            for l in linhas]


def um(nome, n):
    v = vetor(nome)
    if len(v) != 1 or len(v[0]) != n:
        sys.exit(f"{nome}: esperava {n} bytes")
    return v[0].hex().upper()


BITS = int(sys.argv[3])
if BITS not in (128, 256):
    sys.exit("tamanho da BDK: 128 ou 256")
NB = BITS // 8

linhas = [
    f"# DUKPT AES, BDK AES-{BITS} (suplemento de vetores da ANSI X9.24-3:2017) --",
    "# valores de terceiros, copiados do arquivo de testes do projeto",
    "# `openemv/dukpt`, que os transcreve do suplemento.",
    "#",
    "# NAO E VETOR DO CAVP. Ver vectors/MANIFEST.txt para a procedencia e",
    "# para o que estes valores cobrem e o que eles NAO cobrem.",
    "#",
    f"# BDK      chave base de derivacao, AES-{BITS}",
    "# IKID     identificador da chave inicial (8 bytes); IK a chave inicial",
    "# KSN      IKID (8) || contador de transacao (4)",
    f"# KEY      a chave de transacao (chave de derivacao), AES-{BITS}",
    "# PIN128   a chave de PIN AES-128 da transacao (so nas 8 primeiras)",
    "# PIN256   a chave de PIN AES-256 (so com BDK AES-256, nas 8 primeiras)",
    "# EPB      o PIN block formato 4 cifrado sob PIN128 (so com BDK AES-128)",
    "# PINFIELD e PANFIELD: os campos em claro do formato 4 desses EPB",
    "",
    f"BDK = {um('bdk', NB)}", f"IKID = {um('ikid', 8)}",
    f"IK = {um('ik_verify', NB)}",
]
tem_epb = BITS == 128
if tem_epb:
    linhas += [f"PINFIELD = {um('pinfield', 16)}", f"PANFIELD = {um('panfield', 16)}"]
linhas.append("")
total = 0
primeiras = {"KEY": "txn_key_verify", "PIN128": "pin_key_aes128_verify"}
if BITS == 256:
    primeiras["PIN256"] = "pin_key_aes256_verify"
if tem_epb:
    primeiras["EPB"] = "encrypted_pinblock_verify"
tam = {"KEY": NB, "PIN128": 16, "PIN256": 32, "EPB": 16}
for nome, ksn_v, campos in (("primeiras 8", "ksn_verify", primeiras),
                            ("bordas 1FFFE a 20001", "ksn_verify2",
                             {"KEY": "txn_key_verify2"}),
                            ("ultimas 4", "ksn_verify3", {"KEY": "txn_key_verify3"})):
    ks = vetor(ksn_v)
    cols = {c: vetor(v) for c, v in campos.items()}
    if not ks or any(len(v) != len(ks) for v in cols.values()):
        sys.exit(f"{nome}: listas de tamanhos diferentes")
    linhas += [f"[{nome}]", ""]
    for j, k in enumerate(ks):
        if len(k) != 12:
            sys.exit(f"{nome}: KSN de tamanho errado")
        linhas += [f"COUNT = {total}", f"KSN = {k.hex().upper()}"]
        for c, v in cols.items():
            if len(v[j]) != tam[c]:
                sys.exit(f"{nome}: {c} de tamanho errado")
            linhas.append(f"{c} = {v[j].hex().upper()}")
        linhas.append("")
        total += 1
pathlib.Path(sys.argv[2]).write_text("\n".join(linhas))
print(f"    {sys.argv[2]}: {total} transacoes")
