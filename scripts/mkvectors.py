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
