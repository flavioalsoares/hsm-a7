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


def ecdsa():
    """Vetores do tb_ecdsa, todos do CAVP (vectors/ecdsa/), copiados.

    E4: o SEGUNDO vetor "P" do SigVer -- nenhum SigVer e usado no autoteste
    do firmware, que usa o SigGen --, o primeiro "F (3 - S changed)" e a
    primeira chave "F (2 - Point not on curve)" do PKV.
    E2: a chave do SEGUNDO vetor do SigGen (o primeiro e o do autoteste),
    embrulhada sob a LMK do tb. O digest e o da mensagem do vetor.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import tr31

    def casos(nome):
        saida, atual = [], {}
        for linha in (VEC / "ecdsa" / nome).read_text().splitlines():
            m = re.match(r"^(\w+) = (.*)$", linha.strip())
            if m:
                atual[m[1]] = m[2].strip()
            elif atual:
                saida.append(atual)
                atual = {}
        if atual:
            saida.append(atual)
        return [c for c in saida if "Qx" in c]

    def b32(c, *nomes):
        return b"".join(bytes.fromhex(c[n].zfill(64)) for n in nomes)

    def e4(c):
        digest = hashlib.sha256(bytes.fromhex(c["Msg"])).digest()
        return b32(c, "Qx", "Qy") + digest + b32(c, "R", "S")

    ver = casos("SigVer_P256.rsp")
    p = [c for c in ver if c["Result"].startswith("P")][1]
    f = next(c for c in ver if c["Result"].startswith("F (3"))
    k = next(c for c in casos("PKV_P256.rsp")
             if c["Result"].startswith("F (2") and len(c["Qx"]) <= 64)
    escreve("ecdsa_e4_p", ["%02x" % x for x in e4(p)], 2)
    escreve("ecdsa_e4_f", ["%02x" % x for x in e4(f)], 2)
    escreve("ecdsa_e4_pkv", ["%02x" % x for x in
                             b32(k, "Qx", "Qy") + bytes(31) + b"\x01" + bytes(63) + b"\x01"], 2)

    g = casos("SigGen_P256.txt")[1]
    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    import pkcs8
    der = pkcs8.ec_der(int(g["d"], 16))
    bloco = tr31.embrulha(lmk, der, uso="S0", algoritmo="E",
                          modo="S", exportabilidade="E", enchimento=bytes(range(16)))
    if len(bloco) != 336:
        raise SystemExit("ECDSA: key block de %d caracteres" % len(bloco))
    digest = hashlib.sha256(bytes.fromhex(g["Msg"])).digest()
    escreve("ecdsa_e2_bloco", ["%02x" % ord(c) for c in bloco], 2)
    escreve("ecdsa_e2", ["%02x" % x for x in digest + b32(g, "Qx", "Qy")], 2)


def pin():
    """Vetores do tb_pin: duas chaves de PIN (P0) sob a LMK do tb, a chave de
    destino tambem como chave de dados (D0), e um PIN block formato 4 feito
    pelo host/pinblock.py sob a chave de origem.

    A chave de destino embrulhada como D0 e so para o testbench: com ela o
    C2 abre o bloco traduzido, e o tb confere o campo do PIN. So quem tem a
    LMK consegue fazer esse bloco.

    O PAN e inventado (prefixo 999999). Nenhum PAN real, nunca.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import pinblock
    import tr31

    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    ko = hashlib.sha256(b"tb_pin: chave de origem").digest()
    kd = hashlib.sha256(b"tb_pin: chave de destino").digest()
    ench = bytes(range(16))

    def bloco(chave, uso):
        b = tr31.embrulha(lmk, chave, uso=uso, modo="B", exportabilidade="E",
                          enchimento=ench)
        if len(b) != 144:
            raise SystemExit("PIN: key block de %d caracteres" % len(b))
        return ["%02x" % ord(c) for c in b]

    escreve("pin_ko", bloco(ko, "P0"), 2)
    escreve("pin_kd", bloco(kd, "P0"), 2)
    escreve("pin_kd_d0", bloco(kd, "D0"), 2)

    pin_, pan = "48213", "9999990123456789"
    rnd = bytes(range(0xA1, 0xA9))
    campo = pinblock.campo_pin(pin_, rnd)
    pb = pinblock.cifra(ko, pin_, pan, rnd)
    if pinblock.decifra(ko, pb, pan) != pin_:
        raise SystemExit("PIN: ida e volta falhou no Python")
    # PAN em ASCII (16) . PIN block (16) . campo do PAN (16) . campo do PIN (16)
    dados = pan.encode() + pb + pinblock.campo_pan(pan) + campo
    escreve("pin_dados", ["%02x" % x for x in dados], 2)

    # ---- tb_pin0: formato 0, com chaves 3DES de PIN ---------------------
    # O formato 0 nao tem aleatorio: o bloco de saida e previsivel, e o tb
    # o compara inteiro com o que o Python calcula aqui.
    import des
    ko3 = des.paridade_impar(hashlib.sha256(b"tb_pin0: origem").digest()[:16])
    kd3 = des.paridade_impar(hashlib.sha256(b"tb_pin0: destino").digest()[:24])

    def bloco3(chave):
        b = tr31.embrulha(lmk, chave, uso="P0", algoritmo="T", modo="B",
                          exportabilidade="E", enchimento=ench)
        if len(b) != 112:
            raise SystemExit("PIN: key block 3DES de %d caracteres" % len(b))
        return ["%02x" % ord(c) for c in b]

    escreve("pin0_ko", bloco3(ko3), 2)
    escreve("pin0_kd", bloco3(kd3), 2)
    entrada0 = pinblock.cifra0(ko3, pin_, pan)
    saida0 = pinblock.cifra0(kd3, pin_, pan)
    if pinblock.decifra0(kd3, saida0, pan) != pin_ or entrada0 == saida0:
        raise SystemExit("PIN: formato 0 falhou no Python")
    # PIN block sob a origem (8) . PIN block esperado sob o destino (8)
    escreve("pin0_dados", ["%02x" % x for x in entrada0 + saida0], 2)

    # ---- tb_pinv: verificacao de PIN, offset e PVV (etapa 8.5) ----------
    # O PIN block e o do formato 0 acima, sob ko3. As chaves de verificacao
    # sao 3DES; o offset, o PVV e o MAC da tabela saem do host/pinverif.py.
    import pinverif
    v1 = des.paridade_impar(hashlib.sha256(b"tb_pinv: offset").digest()[:16])
    v2 = des.paridade_impar(hashlib.sha256(b"tb_pinv: pvv").digest()[:24])

    def bloco_v(chave, uso, modo):
        b = tr31.embrulha(lmk, chave, uso=uso, algoritmo="T", modo=modo,
                          exportabilidade="E", enchimento=ench)
        if len(b) != 112:
            raise SystemExit("PINV: key block de %d caracteres" % len(b))
        return ["%02x" % ord(c) for c in b]

    escreve("pinv_v1", bloco_v(v1, "V1", "C"), 2)
    escreve("pinv_v1v", bloco_v(v1, "V1", "V"), 2)      # so verifica
    escreve("pinv_v2", bloco_v(v2, "V2", "C"), 2)
    tab = pinverif.TABELA_PADRAO
    tab_b = pinverif.tabela_autoriza(lmk, tab, des.kcv(v1))
    dv = bytes.fromhex(pan)                 # dados de validacao: o PAN, BCD
    off = pinverif.offset_gera(v1, tab, dv, pin_)
    pvv = pinverif.pvv_gera(v2, pan, "1", pin_)
    if not pinverif.offset_confere(v1, tab, dv, pin_, off) or len(off) != 5:
        raise SystemExit("PINV: offset falhou no Python")
    # O MAC da mesma tabela, autorizada para a chave do PVV (outro KCV): o
    # tb_pinv o usa com a chave do offset e espera 17.
    tab_o = pinverif.tabela_autoriza(lmk, tab, des.kcv(v2))
    # tabela (16 ASCII) . MAC (8) . dados de validacao (8) . offset (5 ASCII)
    # . PVV (4 ASCII) . KCV de v1 (3) . KCV de v2 (3) . MAC para v2 (8)
    escreve("pinv_dados", ["%02x" % x for x in
                           tab.encode() + bytes.fromhex(tab_b[16:]) + dv
                           + off.encode() + pvv.encode() + des.kcv(v1)
                           + des.kcv(v2) + bytes.fromhex(tab_o[16:])], 2)


def tdes():
    """Vetores do tb_tdes: chaves 3DES conhecidas, embrulhadas sob a LMK do tb
    pelo host/tr31.py, e o KCV de cada uma calculado pelo host/des.py. O
    des.py e conferido contra os vetores do CAVP em host/test_des.py.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import des
    import tr31

    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    k3 = des.paridade_impar(hashlib.sha256(b"tb_tdes: chave tripla").digest()[:24])
    k2 = des.paridade_impar(hashlib.sha256(b"tb_tdes: chave dupla").digest()[:16])
    ench = bytes(range(16))

    def bloco(chave, uso):
        b = tr31.embrulha(lmk, chave, uso=uso, algoritmo="T", modo="B",
                          exportabilidade="E", enchimento=ench)
        if len(b) != 112:
            raise SystemExit("TDES: key block de %d caracteres" % len(b))
        return ["%02x" % ord(c) for c in b]

    escreve("tdes_k3", bloco(k3, "P0"), 2)
    escreve("tdes_k2", bloco(k2, "P0"), 2)
    escreve("tdes_k2_d0", bloco(k2, "D0"), 2)
    # KCV em ASCII hex, como o K2 devolve: o da tripla e o da dupla.
    kcvs = (des.kcv(k3).hex().upper() + des.kcv(k2).hex().upper()).encode()
    escreve("tdes_kcv", ["%02x" % x for x in kcvs], 2)


def cvv():
    """Vetores do tb_cvv (etapa 8.6). Chaves embrulhadas sob a LMK do tb pelo
    host/tr31.py, e os casos que o tb pede ao W0 e ao W2.

    Os quatro primeiros casos sao valores de TERCEIROS, lidos aqui de
    vectors/cvv/cvv.rsp (ver o MANIFEST) e nao recalculados: a chave da
    fonte vai para dentro de um key block, e o tb exige do firmware o CVV que
    a fonte publicou. Os PANs sao os das fontes, padroes de teste publicados.
    Os dois ultimos sao deste projeto, com PAN inventado (prefixo 999999) de
    19 e de 12 digitos, que as fontes nao cobrem; o CVV sai do host/cvv.py.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import cvv as cvvpy
    import des
    import tr31

    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    ench = bytes(range(16))

    def bloco(chave, uso="C0", modo="C"):
        b = tr31.embrulha(lmk, chave, uso=uso, algoritmo="T", modo=modo,
                          exportabilidade="E", enchimento=ench)
        if len(b) != 112:
            raise SystemExit("CVV: key block de %d caracteres" % len(b))
        return ["%02x" % ord(c) for c in b]

    # os valores de terceiros, do arquivo fixado por hash
    reg, terc = {}, []
    for linha in (VEC / "cvv" / "cvv.rsp").read_text().splitlines() + [""]:
        linha = linha.strip()
        if not linha:
            if reg:
                terc.append(reg)
                reg = {}
        elif not linha.startswith("#"):
            k, v = [x.strip() for x in linha.split("=", 1)]
            reg[k] = v
    psec = [v for v in terc if v["SC"] == "111"]
    jm = [v for v in terc if v["PAN"] == "4444333322221111"]
    if len(psec) != 1 or len(jm) != 3:
        raise SystemExit("CVV: vectors/cvv/cvv.rsp nao tem os casos esperados")
    k_psec = bytes.fromhex(psec[0]["KEY"])
    k_jm = bytes.fromhex(jm[0]["KEY"])

    kp = des.paridade_impar(hashlib.sha256(b"tb_cvv: chave").digest()[:16])
    k3 = des.paridade_impar(hashlib.sha256(b"tb_cvv: tripla").digest()[:24])
    escreve("cvv_k1", bloco(k_psec), 2)
    escreve("cvv_k2", bloco(k_jm), 2)
    escreve("cvv_kp", bloco(kp), 2)
    escreve("cvv_kv", bloco(kp, modo="V"), 2)          # so verifica
    escreve("cvv_kg", bloco(kp, modo="G"), 2)          # so gera
    escreve("cvv_kt", bloco(k3), 2)                    # tripla: recusada
    escreve("cvv_pvk", bloco(kp, uso="V2"), 2)         # outro uso: recusada

    pan19 = "999999" + "0123456789012"
    pan12 = "999999012345"
    casos = [(v["PAN"], v["EXP"], v["SC"], v["CVV"]) for v in psec + jm]
    casos += [(pan19, "2812", "201", cvvpy.gera(kp, pan19, "2812", "201")),
              (pan12, "2812", "000", cvvpy.gera(kp, pan12, "2812", "000"))]
    for c in casos[:4]:
        k = k_psec if c[2] == "111" else k_jm
        if cvvpy.gera(k, *c[:3]) != c[3]:
            raise SystemExit("CVV: o Python nao reproduz %s" % (c,))
    # registro de 31 bytes ASCII: tamanho do PAN (2) . PAN (19, completado
    # com espaco) . validade (4) . codigo de servico (3) . CVV (3)
    dados = b"".join(("%02d" % len(p) + p.ljust(19) + e + sc + c).encode()
                     for p, e, sc, c in casos)
    if len(dados) != 31 * 6:
        raise SystemExit("CVV: registro com tamanho errado")
    escreve("cvv_casos", ["%02x" % x for x in dados], 2)


def kek3():
    """Vetores do tb_kek3 (etapa 8.7): KEK 3DES e key block versao B.

    Os blocos versao B sao valores de TERCEIROS, lidos de
    vectors/tr31/x9143_B_TDES.rsp (ver o MANIFEST), copiados como estao. O
    firmware tem de abrir os aceitos (1, 2, 3) e achar a chave publicada --
    conferida pelo KCV, que o tb recebe aqui calculado com o host/des.py -- e
    recusar o 0 (DES simples) e o 4 (blocos opcionais).

    A KBPK do bloco 3 entra no equipamento por COMPONENTES, no console: dois
    de 16 bytes cujo XOR e ela. As KBPKs dos blocos 1 (dupla) e 2 (tripla)
    vem embrulhadas sob a LMK do tb, como K0.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import des
    import tr31

    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    ench = bytes(range(16))

    def sob_lmk(chave, uso, alg, modo, tam):
        b = tr31.embrulha(lmk, chave, uso=uso, algoritmo=alg, modo=modo,
                          exportabilidade="E", enchimento=ench)
        if len(b) != tam:
            raise SystemExit("KEK3: bloco de %d caracteres" % len(b))
        return ["%02x" % ord(c) for c in b]

    blocos = {}
    for parte in (VEC / "tr31" / "x9143_B_TDES.rsp").read_text().split("\n\n"):
        d = dict(x.split(" = ", 1) for x in parte.splitlines() if " = " in x)
        if "KB" in d:
            blocos[int(d["COUNT"])] = d
    if len(blocos) != 6:
        raise SystemExit("KEK3: esperava 6 blocos versao B")
    for i in (1, 2, 3):
        b = blocos[i]
        if tr31.desembrulha(bytes.fromhex(b["KBPK"]), b["KB"])[0] != \
                bytes.fromhex(b["KEY"]):
            raise SystemExit("KEK3: o bloco %d nao abre no Python" % i)

    kbpk1 = bytes.fromhex(blocos[1]["KBPK"])      # dupla
    kbpk2 = bytes.fromhex(blocos[2]["KBPK"])      # tripla
    kbpk3 = bytes.fromhex(blocos[3]["KBPK"])      # dupla, vai por componentes
    if (len(kbpk1), len(kbpk2), len(kbpk3)) != (16, 24, 16):
        raise SystemExit("KEK3: KBPKs de tamanho inesperado")

    escreve("kek3_k2", sob_lmk(kbpk1, "K0", "T", "B", 112), 2)
    escreve("kek3_k3", sob_lmk(kbpk2, "K0", "T", "B", 112), 2)
    aes = hashlib.sha256(b"tb_kek3: aes").digest()
    t3 = des.paridade_impar(hashlib.sha256(b"tb_kek3: tripla").digest()[:24])
    escreve("kek3_aes", sob_lmk(aes, "D0", "A", "B", 144), 2)
    escreve("kek3_t3", sob_lmk(t3, "D0", "T", "B", 112), 2)

    # Os blocos B 0 a 4, cada um em 104 bytes: o tamanho vai no tb.
    reg = []
    for i in range(5):
        kb = blocos[i]["KB"]
        if len(kb) > 104:
            raise SystemExit("KEK3: bloco %d com %d caracteres" % (i, len(kb)))
        reg += ["%02x" % ord(c) for c in kb.ljust(104, "0")]
    escreve("kek3_blocos", reg, 2)

    comp0 = hashlib.sha256(b"tb_kek3: componente 0").digest()[:16]
    comp1 = bytes(a ^ b for a, b in zip(comp0, kbpk3))
    escreve("kek3_comp", ["%02x" % x for x in comp0 + comp1], 2)

    # KCVs (3DES), 3 bytes cada: chave dos blocos 1 e 2, chave do bloco 3,
    # KBPK do bloco 3 (a KEK montada), componente 0, componente 1, t3.
    kcvs = b"".join(des.kcv(k) for k in (
        bytes.fromhex(blocos[1]["KEY"]), bytes.fromhex(blocos[3]["KEY"]),
        kbpk3, comp0, comp1, t3))
    if bytes.fromhex(blocos[1]["KEY"]) != bytes.fromhex(blocos[2]["KEY"]):
        raise SystemExit("KEK3: os blocos 1 e 2 deviam ter a mesma chave")
    escreve("kek3_kcv", ["%02x" % x for x in kcvs], 2)


def dukpt_tb():
    """Vetores do tb_dukpt (etapa 8.8a): DUKPT TDES pelo P2 e pelo I0.

    A BDK, o KSN, o PIN block cifrado e a IPEK sao valores de TERCEIROS, de
    vectors/dukpt/x924_1_tdes.rsp (X9.24-1:2009 A.4; ver o MANIFEST). A
    transacao e a de KSN ...EFF800 (contador 0FF800, 9 bits 1). O PAN e o do anexo.

    O que e conta do Python (host/dukpt.py, host/pinblock.py, host/des.py):
    o PIN block de saida sob a chave de zona (formato 0, deterministico: o
    tb o compara inteiro), o KCV da IPEK e o cabecalho do bloco do I0, e o
    bloco adulterado que o Python confirma que nao abre como formato 0.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import des
    import dukpt
    import pinblock
    import tr31

    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    ench = bytes(range(16))

    def sob_lmk(chave, uso, modo):
        b = tr31.embrulha(lmk, chave, uso=uso, algoritmo="T", modo=modo,
                          exportabilidade="E", enchimento=ench)
        if len(b) != 112:
            raise SystemExit("DUKPT: bloco de %d caracteres" % len(b))
        return b

    txt = (VEC / "dukpt" / "x924_1_tdes.rsp").read_text()
    cab = dict(re.findall(r"^(BDK|IKSN|IPEK|PINBLOCK|PAN) = ([0-9A-F]+)$", txt, re.M))
    txs = re.findall(r"^KSN = ([0-9A-F]{20})\nKEY = [0-9A-F]{32}\nEPB = ([0-9A-F]{16})$",
                     txt, re.M)
    t = [x for x in txs if x[0] == "FFFF9876543210EFF800"]
    if len(cab) != 5 or len(t) != 1:
        raise SystemExit("DUKPT: arquivo de vetores inesperado")
    bdk = bytes.fromhex(cab["BDK"])
    ksn, epb = bytes.fromhex(t[0][0]), bytes.fromhex(t[0][1])
    pan = cab["PAN"].rstrip("F")
    if pinblock.le_claro0(dukpt.decifra_pin(bdk, ksn, epb), pan) != "1234":
        raise SystemExit("DUKPT: o PIN block do anexo nao abre no Python")
    if dukpt.ipek(bdk, ksn).hex().upper() != cab["IPEK"]:
        raise SystemExit("DUKPT: a IPEK do anexo nao confere no Python")

    zona = des.paridade_impar(hashlib.sha256(b"tb_dukpt: zona").digest()[:16])
    kek = des.paridade_impar(hashlib.sha256(b"tb_dukpt: kek").digest()[:16])
    esperado = des.tdes_bloco(zona, pinblock.claro0("1234", pan))
    # Um bit trocado no PIN block que o Python confirma que nao abre.
    ruim = None
    for i in range(64):
        x = bytearray(epb)
        x[i // 8] ^= 0x80 >> (i % 8)
        try:
            pinblock.le_claro0(dukpt.decifra_pin(bdk, ksn, bytes(x)), pan)
        except pinblock.PinErro:
            ruim = bytes(x)
            break
    if ruim is None:
        raise SystemExit("DUKPT: nenhum bit trocado da formato invalido")
    ipek = bytes.fromhex(cab["IPEK"])
    cab_i0 = tr31.embrulha(kek, ipek, uso="B1", algoritmo="T", modo="X",
                           exportabilidade="N", versao="B")[:16]

    texto = (sob_lmk(bdk, "B0", "X") + sob_lmk(bdk, "B0", "B")
             + sob_lmk(zona, "P0", "E") + sob_lmk(kek, "K0", "E"))
    escreve("dukpt_blocos", ["%02x" % ord(c) for c in texto], 2)
    if len(pan) != 13:
        raise SystemExit("DUKPT: o PAN do anexo devia ter 13 digitos")
    pedido = (ksn.hex().upper() + pan + epb.hex().upper() + ruim.hex().upper()
              + esperado.hex().upper() + des.kcv(ipek).hex().upper() + cab_i0)
    # 20 + 13 + 16 + 16 + 16 + 6 + 16 = 103 caracteres
    escreve("dukpt_dados", ["%02x" % ord(c) for c in pedido], 2)


def dukpt_aes_tb():
    """Vetores do tb_dukpt_aes (etapa 8.8b): DUKPT AES pelo P2 e pelo I0.

    As BDKs AES-128 e AES-256, o KSN, a chave inicial (IK), o PIN block
    cifrado sob a chave de PIN AES-128 e o PAN sao valores de TERCEIROS, de
    vectors/dukpt/x924_3_aes128.rsp e x924_3_aes256.rsp (o suplemento da
    X9.24-3; ver o MANIFEST). A transacao e a de contador 7 (3 bits 1).

    O que e conta do Python (host/dukpt.py, host/pinblock.py, host/des.py):
    o PIN block sob a chave de PIN AES-256 (os valores publicados nao trazem
    um), com 8 bytes aleatorios fixos; o PIN block de saida sob a chave de
    zona 3DES (formato 0, deterministico: o tb o compara inteiro); o KCV da
    IK e o cabecalho do bloco do I0.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import des
    import dukpt
    import pinblock
    import tr31
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    ench = bytes(range(16))

    def sob_lmk(chave, uso, alg, modo, n):
        b = tr31.embrulha(lmk, chave, uso=uso, algoritmo=alg, modo=modo,
                          exportabilidade="E", enchimento=ench)
        if len(b) != n:
            raise SystemExit("DUKPT AES: bloco de %d caracteres" % len(b))
        return b

    def le(nome):
        txt = (VEC / "dukpt" / nome).read_text()
        cab = dict(re.findall(r"^(BDK|IKID|IK|PINFIELD|PANFIELD) = ([0-9A-F]+)$", txt, re.M))
        m = re.search(r"^KSN = 123456789012345600000007\n((?:[A-Z0-9]+ = [0-9A-F]+\n)+)",
                      txt, re.M)
        if not m or len(cab) < 3:
            raise SystemExit("DUKPT AES: %s inesperado" % nome)
        t = dict(re.findall(r"^([A-Z0-9]+) = ([0-9A-F]+)$", m.group(1), re.M))
        return ({k: bytes.fromhex(v) for k, v in cab.items()},
                {k: bytes.fromhex(v) for k, v in t.items()})

    c128, t128 = le("x924_3_aes128.rsp")
    c256, t256 = le("x924_3_aes256.rsp")
    ksn = bytes.fromhex("123456789012345600000007")
    pan = "4111111111111111"
    if pinblock.campo_pan(pan) != c128["PANFIELD"]:
        raise SystemExit("DUKPT AES: o PAN publicado nao e 4111111111111111")
    pin = pinblock.le_campo_pin(c128["PINFIELD"])
    if pin != "1234":
        raise SystemExit("DUKPT AES: o PIN publicado nao e 1234")
    k128 = dukpt.aes_chave_pin(c128["BDK"], ksn, 16)
    k256 = dukpt.aes_chave_pin(c256["BDK"], ksn, 32)
    if k128 != t128["PIN128"] or k256 != t256["PIN256"]:
        raise SystemExit("DUKPT AES: chaves de PIN nao conferem no Python")
    epb128 = t128["EPB"]
    if pinblock.decifra(k128, epb128, pan) != pin:
        raise SystemExit("DUKPT AES: o PIN block publicado nao abre no Python")
    epb256 = pinblock.cifra(k256, pin, pan, aleatorio=bytes(range(0xA0, 0xA8)))
    if dukpt.aes_ik(c128["BDK"], ksn[:8]) != c128["IK"]:
        raise SystemExit("DUKPT AES: a IK publicada nao confere no Python")

    zona = des.paridade_impar(hashlib.sha256(b"tb_dukpt_aes: zona").digest()[:16])
    kek3 = des.paridade_impar(hashlib.sha256(b"tb_dukpt_aes: kek3").digest()[:16])
    keka = hashlib.sha256(b"tb_dukpt_aes: keka").digest()
    dados128 = hashlib.sha256(b"tb_dukpt_aes: d0").digest()[:16]
    esperado = des.tdes_bloco(zona, pinblock.claro0(pin, pan))
    e = Cipher(algorithms.AES(c128["IK"]), modes.ECB()).encryptor()
    kcv_ik = (e.update(bytes(16)) + e.finalize())[:3]
    cab_i0 = tr31.embrulha(keka, c128["IK"], uso="B1", algoritmo="A", modo="X",
                           exportabilidade="N")[:16]
    if cab_i0 != "D0112B1AX00N0000":
        raise SystemExit("DUKPT AES: cabecalho do I0 inesperado: %s" % cab_i0)

    t112 = (sob_lmk(c128["BDK"], "B0", "A", "X", 112)     # 0: BDK AES-128
            + sob_lmk(zona, "P0", "T", "E", 112)          # 1: zona 3DES
            + sob_lmk(kek3, "K0", "T", "E", 112)          # 2: KEK 3DES
            + sob_lmk(dados128, "D0", "A", "B", 112))     # 3: AES-128 de dados
    t144 = (sob_lmk(c256["BDK"], "B0", "A", "X", 144)     # 0: BDK AES-256
            + sob_lmk(keka, "K0", "A", "E", 144))         # 1: KEK AES-256
    escreve("dukpt_aes_b112", ["%02x" % ord(c) for c in t112], 2)
    escreve("dukpt_aes_b144", ["%02x" % ord(c) for c in t144], 2)
    pedido = (ksn.hex().upper() + pan + epb128.hex().upper() + epb256.hex().upper()
              + esperado.hex().upper() + kcv_ik.hex().upper() + cab_i0)
    # 24 + 16 + 32 + 32 + 16 + 6 + 16 = 142 caracteres
    if len(pedido) != 142:
        raise SystemExit("DUKPT AES: dados de %d caracteres" % len(pedido))
    escreve("dukpt_aes_dados", ["%02x" % ord(c) for c in pedido], 2)


def mac3_tb():
    """Vetores do tb_mac3 (etapa 8.9a): dados e MAC com chave 3DES, pelos C0, C2,
    M0 e M2.

    Os valores de retail MAC sao de TERCEIROS (vectors/mac/retail_mac.rsp, duas
    fontes; ver o MANIFEST): o da ISO/IEC 9797-1:2011 B.4 pelo RustCrypto
    (preenchimento 1, MAC de 8 bytes) e o do psec (preenchimento 2, MAC de 4
    bytes). O 3DES-CBC e do NIST (vectors/tdes/TCBCMMT3.rsp, chave tripla): o
    vetor de mais blocos que cabe na porta host.

    So a chave tripla de MAC, que o tb usa para uma recusa, e conta do Python.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import mac_tdes
    import tr31

    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    ench = bytes(range(16))

    def sob_lmk(chave, uso, modo):
        b = tr31.embrulha(lmk, chave, uso=uso, algoritmo="T", modo=modo,
                          exportabilidade="E", enchimento=ench)
        if len(b) != 112:
            raise SystemExit("tb_mac3: bloco de %d caracteres" % len(b))
        return b

    regs, reg, fonte = [], {}, ""
    for ln in (VEC / "mac" / "retail_mac.rsp").read_text().splitlines():
        ln = ln.strip()
        if not ln:
            if reg:
                reg["fonte"] = fonte
                regs.append(reg)
                reg = {}
            continue
        if ln.startswith("#"):
            fonte = ln
            continue
        k, v = [x.strip() for x in ln.split("=", 1)]
        reg[k] = v
    if reg:
        reg["fonte"] = fonte
        regs.append(reg)
    rust = [r for r in regs if "RustCrypto" in r["fonte"] and len(r["MSG"]) == 48]
    psec = [r for r in regs if "psec" in r["fonte"] and r["PAD"] == "2"
            and len(r["MAC"]) == 8]
    if len(rust) != 1 or len(psec) != 1:
        raise SystemExit("tb_mac3: valores de retail MAC inesperados")
    rust, psec = rust[0], psec[0]
    for r in (rust, psec):
        m = bytes.fromhex(r["MAC"])
        if mac_tdes.retail_mac(bytes.fromhex(r["KEY"]), bytes.fromhex(r["MSG"]),
                               int(r["PAD"]), len(m)) != m:
            raise SystemExit("tb_mac3: o Python nao reproduz %s" % r["fonte"])

    melhor = None
    for bloco in (VEC / "tdes" / "TCBCMMT3.rsp").read_text().split("\n\n"):
        d = dict(re.findall(r"^(\w+) = (\w+)$", bloco, re.M))
        if "KEY1" not in d or len(d["PLAINTEXT"]) > 2 * 64:
            continue
        if melhor is None or len(d["PLAINTEXT"]) > len(melhor["PLAINTEXT"]):
            melhor = d
    if melhor is None:
        raise SystemExit("tb_mac3: nenhum vetor CBC do NIST")
    kc = bytes.fromhex(melhor["KEY1"] + melhor["KEY2"] + melhor["KEY3"])
    iv = bytes.fromhex(melhor["IV"])
    claro = bytes.fromhex(melhor["PLAINTEXT"])
    cifrado = bytes.fromhex(melhor["CIPHERTEXT"])
    if mac_tdes.cbc(kc, iv, claro, True) != cifrado:
        raise SystemExit("tb_mac3: o Python nao reproduz o vetor do NIST")

    tripla = hashlib.sha256(b"tb_mac3: tripla").digest()[:24]
    t112 = (sob_lmk(bytes.fromhex(rust["KEY"]), "M3", "C")   # 0: RustCrypto, gera e verifica
            + sob_lmk(bytes.fromhex(psec["KEY"]), "M3", "V")  # 1: psec, so verifica
            + sob_lmk(kc, "D0", "B")                          # 2: NIST, cifra e decifra
            + sob_lmk(tripla, "M3", "C")                      # 3: MAC com chave tripla
            + sob_lmk(kc, "D0", "E"))                         # 4: NIST, so cifra
    escreve("mac3_b112", ["%02x" % ord(c) for c in t112], 2)
    n = len(claro)
    pedido = (rust["MSG"] + rust["MAC"] + psec["MSG"] + psec["MAC"] + iv.hex().upper()
              + claro.hex().upper() + cifrado.hex().upper())
    # 48 + 16 + 22 + 8 + 16 + 2n + 2n caracteres
    if len(pedido) != 110 + 4 * n:
        raise SystemExit("tb_mac3: dados de %d caracteres" % len(pedido))
    escreve("mac3_dados", ["%02x" % ord(c) for c in pedido], 2)
    escreve("mac3_n", ["%02x" % n], 2)


def dukpt_mac_tb():
    """Vetores do tb_dukpt_mac (etapa 8.9b): M4, M6, C4 e C6.

    Tudo de TERCEIROS (vectors/dukpt/dukpt_mac_dados.rsp, duas fontes; ver o
    MANIFEST): a BDK do anexo A.4 e a BDK AES-128 do suplemento, a primeira
    transacao de cada (KSN ...E00001 e ...00000001). TDES: o MAC de pedido de
    4 bytes e os dados de pedido do openemv; o MAC de resposta de 8 bytes e os
    dados de resposta do moov-io. AES: o CMAC e os dados de pedido e de
    resposta do moov-io. A chave de zona e conta do Python, so para uma
    recusa.
    """
    sys.path.insert(0, str(ROOT / "host"))
    import des
    import tr31

    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    ench = bytes(range(16))

    def sob_lmk(chave, uso, alg, modo):
        b = tr31.embrulha(lmk, chave, uso=uso, algoritmo=alg, modo=modo,
                          exportabilidade="E", enchimento=ench)
        if len(b) != 112:
            raise SystemExit("tb_dukpt_mac: bloco de %d caracteres" % len(b))
        return b

    txt = (VEC / "dukpt" / "dukpt_mac_dados.rsp").read_text()
    msg = bytes.fromhex(re.search(r"^MSG = ([0-9A-F]+)$", txt, re.M).group(1))
    sec = {}
    for nome, corpo in re.findall(r"^\[([^\]]+)\]\n(.*?)(?=^\[|\Z)", txt, re.M | re.S):
        regs = []
        for bloco in corpo.strip().split("\n\n"):
            regs.append(dict(re.findall(r"^(\w+) = ([0-9A-F]+)$", bloco, re.M)))
        sec[nome] = regs
    ot, mt, ma = sec["openemv TDES"][0], sec["moov-io TDES"][0], sec["moov-io AES BDK128"][0]
    if not (ot["KSN"] == mt["KSN"] == "FFFF9876543210E00001" and
            ma["KSN"] == "123456789012345600000001" and msg == b"4012345678909D987"):
        raise SystemExit("tb_dukpt_mac: transacoes inesperadas")
    bdk_t = bytes.fromhex(re.search(r"^BDK = ([0-9A-F]+)$",
                                    (VEC / "dukpt" / "x924_1_tdes.rsp").read_text(), re.M).group(1))
    bdk_a = bytes.fromhex(re.search(r"^BDK = ([0-9A-F]+)$",
                                    (VEC / "dukpt" / "x924_3_aes128.rsp").read_text(), re.M).group(1))
    zona = des.paridade_impar(hashlib.sha256(b"tb_dukpt_mac: zona").digest()[:16])
    t112 = (sob_lmk(bdk_t, "B0", "T", "X")       # 0: BDK do anexo A.4
            + sob_lmk(bdk_a, "B0", "A", "X")     # 1: BDK AES-128 do suplemento
            + sob_lmk(zona, "P0", "T", "E"))     # 2: chave de zona (recusa)
    escreve("dukpt_mac_b112", ["%02x" % ord(c) for c in t112], 2)
    p24 = msg + bytes(24 - len(msg))
    p32 = msg + bytes(32 - len(msg))
    pedido = (ot["KSN"] + ot["REQMAC"] + mt["RESMAC"] + ot["REQDATA"] + mt["RESDATA"]
              + msg.hex().upper() + p24.hex().upper()
              + ma["KSN"] + ma["CMACREQ"] + ma["CMACRES"] + ma["REQDATA"] + ma["RESDATA"]
              + p32.hex().upper())
    # 20 + 8 + 16 + 48 + 48 + 34 + 48 + 24 + 32 + 32 + 64 + 64 + 64 = 502
    if len(pedido) != 502:
        raise SystemExit("tb_dukpt_mac: dados de %d caracteres" % len(pedido))
    escreve("dukpt_mac_dados", ["%02x" % ord(c) for c in pedido], 2)


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
    import pkcs8
    chave = pkcs8.rsa_der(p, q, e, d)       # PKCS#8, com o d oficial do CAVP

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


def arqc_tb():
    """Vetores do tb_arqc (etapa 8.10): A0 e A2.

    Tudo de TERCEIROS (vectors/emv/arqc.rsp, duas fontes; ver o MANIFEST):
    do jPOS, a IMK "4 times 12345678", o ARQC VSDC (MK, preenchimento 00) com
    o ARPC metodo 1 e o EMV_CSKD (preenchimento 80) com o ARPC metodo 2; do
    pyemv, a IMK do CVN 10 e do CVN 18, os dois ARQCs e os ARPCs, e os dois
    primeiros bytes do KCV da MK do cartao (BAB0). O KCV inteiro da MK e a
    KEK de transporte sao conta do Python (host/emv.py, conferido contra as
    duas fontes pelo host/test_emv.py).
    """
    sys.path.insert(0, str(ROOT / "host"))
    import des
    import emv
    import tr31

    lmk = bytes(((0x10 + i) ^ (0x5A ^ ((i * 7) & 0xFF)) ^ ((0xC3 + i) & 0xFF)) & 0xFF
                for i in range(32))
    ench = bytes(range(16))

    def sob_lmk(chave, uso, modo):
        b = tr31.embrulha(lmk, chave, uso=uso, algoritmo="T", modo=modo,
                          exportabilidade="E", enchimento=ench)
        if len(b) != 112:
            raise SystemExit("tb_arqc: bloco de %d caracteres" % len(b))
        return b

    casos = {c["FONTE"].split()[-1]: c
             for c in emv.le_rsp(str(VEC / "emv" / "arqc.rsp"))}
    j1 = casos["testVerifyARQCGenerateARPCImpl_VSDC_P00_M1"]
    j2 = casos["testVerifyARQCGenerateARPCImpl_CSKD_P80_M2"]
    p10 = casos["test_visa_cvn10"]
    p18 = casos["test_visa_cvn18"]
    if not (j1["IMK"] == j2["IMK"] and j1["DADOS"] == j2["DADOS"] and
            j1["PAN"] == j2["PAN"] and j1["ATC"] == j2["ATC"] and
            p10["IMK"] == p18["IMK"] and p10["PAN"] == p18["PAN"] and
            p10["ATC"] == p18["ATC"] and p10["PSN"] == p18["PSN"] and
            j1["ESQUEMA"] == "MK" and j1["PAD"] == "1" and
            j2["ESQUEMA"] == "CSK" and j2["PAD"] == "2" and j2["PAD_AUT"] == "" and
            p10["ESQUEMA"] == "MK" and p10["PAD"] == "1" and
            p18["ESQUEMA"] == "CSK" and p18["PAD"] == "2" and p18["PAD_AUT"] == "" and
            len(j1["PAN"]) == 16 and len(p10["PAN"]) == 16):
        raise SystemExit("tb_arqc: casos inesperados")
    imk_j = bytes.fromhex(j1["IMK"])
    imk_p = bytes.fromhex(p10["IMK"])
    kek = des.paridade_impar(hashlib.sha256(b"tb_arqc: kek").digest()[:16])
    t112 = (sob_lmk(imk_j, "E0", "X")       # 0: IMK do jPOS
            + sob_lmk(imk_p, "E0", "X")     # 1: IMK do pyemv
            + sob_lmk(kek, "K0", "E"))      # 2: KEK 3DES, para o A2
    escreve("arqc_b112", ["%02x" % ord(c) for c in t112], 2)
    mk = emv.mk_opcao_a(imk_p, p10["PAN"], p10["PSN"])
    mk_kcv = des.kcv(mk).hex().upper()
    if mk_kcv[:4] != p10["MKKCV2"]:
        raise SystemExit("tb_arqc: KCV da MK nao e o publicado")
    partes = [
        (0, j1["ATC"]), (4, j1["ARQC"]), (20, j1["ARC"]), (24, j1["ARPC1"]),
        (40, j2["ARQC"]), (56, j2["CSU"]), (64, j2["ARPC2"]), (72, j1["DADOS"]),
        (150, p10["ATC"]), (154, p10["ARQC"]), (170, p10["ARC"]),
        (174, p10["ARPC1"]), (190, p10["DADOS"]), (264, p18["ARQC"]),
        (280, p18["CSU"]), (288, p18["ARPC2"]), (296, p18["DADOS"]),
        (376, j1["PAN"]), (392, j1["PSN"]), (394, p10["PAN"]), (410, p10["PSN"]),
        (412, p10["MKKCV2"]), (416, mk_kcv)]
    pedido = ""
    for de, txt in partes:
        if len(pedido) != de:
            raise SystemExit("tb_arqc: campo em %d, esperado %d" % (len(pedido), de))
        pedido += txt
    if len(pedido) != 422:
        raise SystemExit("tb_arqc: dados de %d caracteres" % len(pedido))
    escreve("arqc_dados", ["%02x" % ord(c) for c in pedido], 2)


def main():
    if not VEC.exists():
        raise SystemExit("vectors/ ausente — rode ./scripts/fetch-vectors.sh")
    print("=== gerando vetores para simulacao em build/vectors/")
    n_ecb, _ = aes("ECB")
    n_cbc, _ = aes("CBC")
    n_sha = sha256_padded()
    n_rsa_mont, n_rsa_kat, rsa_n0p, rsa_e = rsa()
    ecdsa()
    pin()
    tdes()
    cvv()
    kek3()
    dukpt_tb()
    dukpt_aes_tb()
    mac3_tb()
    dukpt_mac_tb()
    arqc_tb()

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
