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

import hashlib
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


def rsa():
    """RSA: produtos de Montgomery e o KAT do SigGen15.

    O KAT e do CAVP: S^e mod n tem de dar o EM de PKCS#1 v1.5. Os produtos sao
    conta de inteiros do Python sobre o n do mesmo arquivo. a, b e o esperado
    nao sao vetores de autoridade, e sim a referencia do testbench.
    """
    texto = (VEC / "rsa" / "SigGen15_186-3.rsp").read_text()
    texto = texto.split("[mod = 3072]")[0]
    n = int(re.search(r"^n = (\w+)", texto, re.M)[1], 16)
    e = int(re.search(r"^e = (\w+)", texto, re.M)[1], 16)
    prefixo = bytes.fromhex("3031300d060960864801650304020105000420")

    def limbs(x):
        return [(x >> (16 * i)) & 0xFFFF for i in range(128)]

    def n0p(m):
        return (-pow(m, -1, 1 << 16)) % (1 << 16)

    def pseudo(semente, m):
        h, x = semente.encode(), 0
        for _ in range(9):
            h = hashlib.sha256(h).digest()
            x = (x << 256) | int.from_bytes(h, "big")
        return x % m

    modulos = [(128, n), (64, (n >> 1024) | 1), (2, (n >> 2016) | 1),
               (1, (n >> 2032) | 1)]
    produtos, cfg = [], []
    for L, m in modulos:
        R = 1 << (16 * L)
        casos = [(0, 1), (1, 1), (1, m - 1), (m - 1, m - 1), (R % m, R % m)]
        casos += [(pseudo(f"a{L}{i}", m), pseudo(f"b{L}{i}", m)) for i in range(6)]
        for a, b in casos:
            esperado = a * b * pow(R, -1, m) % m
            produtos += limbs(m) + limbs(a) + limbs(b) + limbs(esperado)
            cfg += [L, n0p(m)]
    escreve("rsa_mont", ["%04x" % x for x in produtos], 4)
    escreve("rsa_mont_cfg", ["%04x" % x for x in cfg], 4)

    kat = limbs(n) + limbs((1 << 4096) % n)
    total = 0
    for v in re.finditer(r"SHAAlg = SHA256\nMsg = (\w+)\nS = (\w+)", texto):
        t = prefixo + hashlib.sha256(bytes.fromhex(v[1])).digest()
        em = int.from_bytes(b"\0\1" + b"\xff" * (253 - len(t)) + b"\0" + t, "big")
        s = int(v[2], 16)
        if pow(s, e, n) != em:
            raise SystemExit("SigGen15: vetor nao fecha em Python")
        kat += limbs(s) + limbs(em)
        total += 1
    escreve("rsa_kat", ["%04x" % x for x in kat], 4)

    # Pedido do R4: o segundo vetor, porque o POST usa o primeiro.
    v = list(re.finditer(r"SHAAlg = SHA256\nMsg = (\w+)\nS = (\w+)", texto))[1]
    r4 = (n.to_bytes(256, "big") + e.to_bytes(4, "big") +
          hashlib.sha256(bytes.fromhex(v[1])).digest() + bytes.fromhex(v[2]))
    escreve("rsa_r4", ["%02x" % x for x in r4], 2)
    rsa_r2(prefixo)
    return len(cfg) // 2, total, n0p(n), e


def rsa_r2(prefixo):
    """R2: a primeira chave de 2048 bits do KeyGen do CAVP (p, q e d oficiais),
    embrulhada sob a LMK que o tb_rsa monta na cerimonia.

    A assinatura esperada e conta do Python sobre essa chave -- PKCS#1 v1.5 e
    deterministico, mas o CAVP nao publica assinatura para esta chave. O que e
    oficial e a chave; a conta, o tb confere tambem pela verificacao com e.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import tr31

    texto = (VEC / "rsa" / "KeyGen_RandomProbablyPrime3_3.rsp").read_text()
    texto = texto.split("[mod = 2048]")[1].split("[mod =")[0]
    m = re.search(r"e = (\w+)\s+p = (\w+)\s+q = (\w+)\s+n = (\w+)\s+d = (\w+)", texto)
    e, p, q, n, d = (int(x, 16) for x in m.groups())
    if p * q != n or pow(pow(7, e, n), d, n) != 7:
        raise SystemExit("KeyGen: chave do CAVP nao fecha em Python")
    chave = (e.to_bytes(4, "big") + p.to_bytes(128, "big") + q.to_bytes(128, "big")
             + (d % (p - 1)).to_bytes(128, "big") + (d % (q - 1)).to_bytes(128, "big")
             + pow(q, -1, p).to_bytes(128, "big"))

    # A LMK do tb_rsa: os tres componentes de la, por XOR.
    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    ench = bytes(range(16))          # fixo: o .hex tem de ser reprodutivel
    bloco = tr31.embrulha(lmk, chave, uso="S0", algoritmo="R", modo="S",
                          exportabilidade="E", enchimento=ench)
    aes = tr31.embrulha(lmk, bytes(range(32)), uso="D0", algoritmo="A",
                        modo="B", exportabilidade="E", enchimento=ench)

    digest = hashlib.sha256(b"hsm-a7 fase 7: R2").digest()
    t = prefixo + digest
    em = int.from_bytes(b"\0\1" + b"\xff" * (253 - len(t)) + b"\0" + t, "big")
    sig = pow(em, d, n)
    if pow(sig, e, n) != em:
        raise SystemExit("R2: assinatura de referencia nao verifica")

    escreve("rsa_r2_bloco", ["%02x" % ord(c) for c in bloco], 2)
    escreve("rsa_r2_aes", ["%02x" % ord(c) for c in aes], 2)
    escreve("rsa_r2", ["%02x" % x for x in digest + sig.to_bytes(256, "big")], 2)
    return len(bloco), len(aes)


def main():
    if not VEC.exists():
        raise SystemExit("vectors/ ausente — rode ./scripts/fetch-vectors.sh")
    print("=== gerando vetores para simulacao em build/vectors/")
    n_ecb, _ = aes("ECB")
    n_cbc, _ = aes("CBC")
    n_sha = sha256_padded()
    n_rsa_mont, n_rsa_kat, rsa_n0p, rsa_e = rsa()

    # As contagens saem daqui em vez de serem repetidas no testbench: um
    # numero desatualizado la faria o teste rodar sobre lixo silenciosamente.
    counts = OUT / "counts.vh"
    counts.write_text(
        "// Gerado por scripts/mkvectors.py -- nao editar\n"
        f"`define N_AES_ECB {n_ecb}\n"
        f"`define N_AES_CBC {n_cbc}\n"
        f"`define N_SHA256  {n_sha}\n"
        f"`define N_RSA_MONT {n_rsa_mont}\n"
        f"`define N_RSA_KAT  {n_rsa_kat}\n"
        f"`define RSA_N0P   16'h{rsa_n0p:04x}\n"
        f"`define RSA_E     32'h{rsa_e:08x}\n"
    )
    print(f"  counts.vh: ECB={n_ecb} CBC={n_cbc} SHA={n_sha}")
    print(f"=== ok -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
