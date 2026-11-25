#!/usr/bin/env python3
"""Extrai os valores conhecidos de retail MAC (ISO/IEC 9797-1, algoritmo 3; a
ANSI X9.19) de duas fontes de terceiros, e escreve um .rsp no estilo dos
demais vetores. Etapa 8.9a.

Nada e calculado aqui. Os campos sao copiados literalmente dos arquivos de
origem, cujos SHA-256 estao no MANIFEST. O script falha se alguma fonte nao
tiver exatamente a quantidade esperada de valores.

As duas interpretacoes, e quem as confere:

  psec (tests/test_mac.py): a funcao recebe `key1` e `key2` de 16 bytes, em
  ASCII (b"AAAAAAAAAAAAAAAA", b"BBBBBBBBBBBBBBBB"), e usa cada uma como 3DES.
  Com as duas metades iguais, o 3DES e o DES simples daquela metade: K =
  4141414141414141 e K' = 4242424242424242. O script exige as metades iguais e
  escreve KEY = K . K', a chave dupla como este equipamento a guarda. Os
  casos com o preenchimento 3 nao entram: este equipamento faz so o 1 e o 2.
  Os casos com tamanho None repetem os de tamanho 8 e tambem nao entram.

  RustCrypto retail-mac (README.md): K e K' vem concatenados, como aqui. O
  crate preenche com zeros (`pad_with_zeros`, src/block_api.rs): preenchimento
  1. O exemplo e o da ISO/IEC 9797-1:2011, secao B.4.

`host/test_retail_mac.py` confere os valores contra uma conta independente, a
da biblioteca `cryptography`: se uma leitura estiver errada, o teste falha.

Uso: _extrai_retail_mac.py <diretorio com os arquivos baixados> <saida>
"""
import re
import sys
import pathlib

d = pathlib.Path(sys.argv[1])


def le(nome):
    return (d / nome).read_text(errors="replace")


def todos(padrao, texto, n, onde):
    achados = re.findall(padrao, texto, re.S)
    if len(achados) != n:
        sys.exit(f"{onde}: esperava {n}, achei {len(achados)}")
    return achados


def um(padrao, texto, onde):
    return todos(padrao, texto, 1, onde)[0]


casos = []   # (fonte, chave hex, dados hex, preenchimento, mac hex)

# ---- psec ----------------------------------------------------------------
t = le("psec_test_mac.py")
corpo = t[t.index("def test_generate_retail_mac_exception"):
          t.index("def test_generate_cbc_mac_exception")]
k1, k2, dados = um(r'mac\.generate_retail_mac\(\s*b"([A-Z]+)", b"([A-Z]+)", '
                   r'b"([^"]*)", padding, length', corpo, "psec, chamada")
for k in (k1, k2):
    if len(k) != 16 or k[:8] != k[8:]:
        sys.exit("psec: a chave nao tem as duas metades iguais")
chave = (k1[:8] + k2[:8]).encode().hex().upper()
linhas = todos(r'\((\d), (\d|None), "([0-9A-F]+)"\)', corpo, 9, "psec, casos")
for pad, tam, mac in linhas:
    if pad == "3" or tam == "None":
        continue
    if len(mac) != 2 * int(tam):
        sys.exit("psec: MAC com tamanho diferente do declarado")
    casos.append(("psec, tests/test_mac.py", chave,
                  dados.encode().hex().upper(), pad, mac))
if len(casos) != 4:
    sys.exit(f"psec: esperava 4 casos, achei {len(casos)}")

# ---- RustCrypto retail-mac ------------------------------------------------
t = le("rustcrypto_retail_mac_README.md")
chave = um(r'let key = hex!\("([0-9A-F]+)"\);', t, "rust, chave").upper()
msgs = todos(r'mac2?\.update\(b"([^"]*)"\);', t, 2, "rust, mensagens")
macs = todos(r'let correct2? = hex!\("([0-9A-F]+)"\);', t, 2, "rust, MACs")
for m, mac in zip(msgs, macs):
    casos.append(("RustCrypto retail-mac, README.md (ISO/IEC 9797-1:2011 B.4)",
                  chave, m.encode().hex().upper(), "1", mac.upper()))

saida = ["# Retail MAC (ISO/IEC 9797-1, algoritmo 3; ANSI X9.19) -- valores",
         "# conhecidos de terceiros, de duas fontes.",
         "#",
         "# NAO E VETOR OFICIAL. Ver vectors/MANIFEST.txt para a procedencia e",
         "# para o que estes valores cobrem e o que NAO cobrem.",
         "#",
         "# KEY  a chave dupla K . K' (DES de K na cadeia, K' so no fim)",
         "# MSG  a mensagem, em hex; PAD  o preenchimento da ISO 9797-1 (1 ou 2)",
         "# MAC  o MAC, com o tamanho da fonte (4 ou 8 bytes)",
         ""]
for fonte, chave, msg, pad, mac in casos:
    saida += ["# " + fonte, "KEY = " + chave, "MSG = " + msg, "PAD = " + pad,
              "MAC = " + mac, ""]
pathlib.Path(sys.argv[2]).write_text("\n".join(saida))
print(f"{len(casos)} valores")
