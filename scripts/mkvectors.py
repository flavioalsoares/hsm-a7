#!/usr/bin/env python3
"""Converte os .rsp do NIST em arquivos hex para $readmemh nos testbenches.

    ./scripts/mkvectors.py            -> build/vectors/*.hex

Por que existe: parsear .rsp dentro de um testbench Verilog seria frágil e
ilegível. A conversão é aritmeticamente trivial (hex para hex, sem
transformação) e fica auditável aqui, num único lugar.

O que ele NÃO faz: nenhum valor é calculado. Chave, entrada e saída
esperada são copiados literalmente do arquivo do NIST. A única coisa
derivada é o preenchimento (padding) das mensagens de SHA — e isso é
deliberado, porque o sha256_core opera sobre blocos de 512 bits e não
implementa padding; quem faz isso é o firmware. Testar o core sem o padding
mistura duas responsabilidades.

Saída em build/, que está no .gitignore: é derivado de vectors/.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VEC = ROOT / "vectors"
OUT = ROOT / "build" / "vectors"


def parse_rsp(path):
    """Agrupa os registros de um .rsp do NIST por seção.

    Os dois formatos que aparecem aqui separam registros de formas
    diferentes: o AESAVS abre cada um com `COUNT =`, o SHAVS com `Len =`.
    Em vez de tratar cada caso, a regra é geral: **repetir uma chave que já
    está no registro corrente inicia um registro novo**. Funciona para os
    dois e para os próximos.

    `[ENCRYPT]` é seção; `[L = 32]` é parâmetro do arquivo e não separa
    grupos. Registros que apareçam antes de qualquer seção vão para "".
    """
    grupos = {}
    secao = ""
    atual = None

    def novo():
        nonlocal atual
        atual = {}
        grupos.setdefault(secao, []).append(atual)

    for linha in path.read_text(errors="replace").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue

        if linha.startswith("[") and linha.endswith("]"):
            corpo = linha[1:-1].strip()
            if "=" not in corpo:          # seção de verdade: [ENCRYPT]
                secao = corpo.upper()
                grupos.setdefault(secao, [])
                atual = None
            continue                      # [L = 32] e afins: ignorar

        if "=" in linha:
            chave, valor = (x.strip() for x in linha.split("=", 1))
            chave = chave.upper()
            if atual is None or chave in atual:
                novo()
            atual[chave] = valor

    return grupos


def escreve(nome, valores, nibbles):
    """Um valor hex por linha, largura fixa, para $readmemh."""
    OUT.mkdir(parents=True, exist_ok=True)
    p = OUT / f"{nome}.hex"
    with p.open("w") as f:
        for v in valores:
            v = v.strip().lower()
            if len(v) != nibbles:
                raise SystemExit(
                    f"{nome}: esperado {nibbles} nibbles, recebido {len(v)}: {v!r}")
            f.write(v + "\n")
    return p


def aes(modo):
    """modo: 'ECB' ou 'CBC'. Junta os quatro tipos de vetor do AESAVS."""
    arquivos = sorted((VEC / "aes").glob(f"{modo}*256.rsp"))
    if not arquivos:
        raise SystemExit(f"vetores de AES {modo} não encontrados em {VEC/'aes'}")

    enc = {"key": [], "iv": [], "in": [], "out": []}
    dec = {"key": [], "iv": [], "in": [], "out": []}

    for arq in arquivos:
        grupos = parse_rsp(arq)
        for v in grupos.get("ENCRYPT", []):
            enc["key"].append(v["KEY"])
            enc["in"].append(v["PLAINTEXT"])
            enc["out"].append(v["CIPHERTEXT"])
            if modo == "CBC":
                enc["iv"].append(v["IV"])
        for v in grupos.get("DECRYPT", []):
            dec["key"].append(v["KEY"])
            dec["in"].append(v["CIPHERTEXT"])
            dec["out"].append(v["PLAINTEXT"])
            if modo == "CBC":
                dec["iv"].append(v["IV"])

    base = f"aes_{modo.lower()}256"
    for direcao, d in (("enc", enc), ("dec", dec)):
        escreve(f"{base}_{direcao}_key", d["key"], 64)
        escreve(f"{base}_{direcao}_in", d["in"], 32)
        escreve(f"{base}_{direcao}_out", d["out"], 32)
        if modo == "CBC":
            escreve(f"{base}_{direcao}_iv", d["iv"], 32)
        print(f"  {base}_{direcao}: {len(d['key'])} vetores "
              f"({', '.join(a.name for a in arquivos)})")

    return len(enc["key"]), len(dec["key"])


def sha256_padded():
    """Mensagens de SHA-256, já preenchidas e fatiadas em blocos de 512 bits.

    O padding (bit 1, zeros, comprimento em 64 bits big-endian) é da norma
    FIPS 180-4 e é responsabilidade de quem chama o core, não do core.
    """
    arq = VEC / "sha" / "SHA256ShortMsg.rsp"
    if not arq.exists():
        raise SystemExit(f"não encontrado: {arq}")

    grupos = parse_rsp(arq)
    itens = grupos.get("", [])            # SHAVS não tem seção nomeada

    blocos, digests, nblocos = [], [], []
    for v in itens:
        n = int(v["LEN"])                      # comprimento em BITS
        msg = bytes.fromhex(v["MSG"]) if n else b""
        msg = msg[: n // 8]

        pad = msg + b"\x80"
        while (len(pad) + 8) % 64:
            pad += b"\x00"
        pad += n.to_bytes(8, "big")

        nb = len(pad) // 64
        nblocos.append(f"{nb:08x}")
        for i in range(nb):
            blocos.append(pad[i * 64:(i + 1) * 64].hex())
        digests.append(v["MD"])

    escreve("sha256_blocks", blocos, 128)
    escreve("sha256_nblocks", nblocos, 8)
    escreve("sha256_digest", digests, 64)
    print(f"  sha256: {len(digests)} mensagens, {len(blocos)} blocos "
          f"({arq.name})")
    return len(digests)


def main():
    if not VEC.exists():
        raise SystemExit("vectors/ ausente — rode ./scripts/fetch-vectors.sh")
    print("=== gerando vetores para simulacao em build/vectors/")
    n_ecb, _ = aes("ECB")
    n_cbc, _ = aes("CBC")
    n_sha = sha256_padded()

    # As contagens saem daqui em vez de serem repetidas no testbench: um
    # numero desatualizado la faria o teste rodar sobre lixo silenciosamente.
    counts = OUT / "counts.vh"
    counts.write_text(
        "// Gerado por scripts/mkvectors.py -- nao editar\n"
        f"`define N_AES_ECB {n_ecb}\n"
        f"`define N_AES_CBC {n_cbc}\n"
        f"`define N_SHA256  {n_sha}\n"
    )
    print(f"  counts.vh: ECB={n_ecb} CBC={n_cbc} SHA={n_sha}")
    print(f"=== ok -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
