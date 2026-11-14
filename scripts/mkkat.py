#!/usr/bin/env python3
"""Gera fw/include/kat_vectors.h a partir dos vetores oficiais em vectors/.

Por que existe: o POST precisa dos vetores EMBUTIDOS no firmware, e a regra
inviolável nº 5 do CLAUDE.md só vale se a procedência for verificável. Um
vetor digitado à mão no meio de um .c não é auditável por ninguém -- e um
vetor errado faz o POST reprovar hardware bom, ou pior, aprovar hardware
ruim.

Aqui nada é calculado. Chave, entrada e resultado esperado são copiados
literalmente dos arquivos do NIST e do IETF. A única exceção é o
comprimento das mensagens SHA, que vem do campo `Len` do próprio .rsp.

Quantos vetores: poucos, de propósito. A IMEM tem 16 KB e o POST roda a
cada boot. A cobertura exaustiva (1620 vetores de AES, 65 de SHA, 480 de
DRBG) fica na simulação, onde é barata; o POST prova que o caminho
CPU->coprocessador está íntegro AGORA, neste boot, neste silício.

Uso:  python3 scripts/mkkat.py
"""
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VEC = ROOT / "vectors"
SAIDA = ROOT / "fw" / "include" / "kat_vectors.h"


# ---------------------------------------------------------------------
def hexbytes(s):
    s = s.strip().replace(" ", "")
    if s == "":
        return b""
    return bytes.fromhex(s)


def carr(nome, dados):
    """Um array C, 12 bytes por linha."""
    if len(dados) == 0:
        return f"static const uint8_t {nome}[1] = {{ 0x00 }};  /* vazio */"
    linhas = []
    for i in range(0, len(dados), 12):
        pedaco = dados[i:i + 12]
        linhas.append("    " + " ".join(f"0x{b:02X}," for b in pedaco))
    corpo = "\n".join(linhas)
    return f"static const uint8_t {nome}[{len(dados)}] = {{\n{corpo}\n}};"


# ---------------------------------------------------------------------
def rsp_registros(path, sep):
    """Registros de um .rsp, separados quando a chave `sep` reaparece."""
    regs = []
    atual = None
    for linha in path.read_text(errors="replace").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or linha.startswith("["):
            continue
        if "=" not in linha:
            continue
        chave, valor = (x.strip() for x in linha.split("=", 1))
        if chave.upper() == sep.upper():
            atual = {}
            regs.append(atual)
        if atual is not None:
            atual.setdefault(chave.upper(), []).append(valor)
    return regs


# ---------------------------------------------------------------------
def aes_vetores():
    """Um vetor de cifra e um de decifra, do AESAVS ECB-256.

    Escolhidos do GFSbox (chave zero, texto escolhido) e do KeySbox (chave
    escolhida, texto zero): os dois pegam classes de erro diferentes na
    expansão de chave.
    """
    out = []
    for arq, secao in (("ECBGFSbox256.rsp", "ENCRYPT"),
                       ("ECBKeySbox256.rsp", "DECRYPT")):
        p = VEC / "aes" / arq
        if not p.exists():
            sys.exit(f"ERRO: {p} nao existe -- rode scripts/fetch-vectors.sh")
        texto = p.read_text(errors="replace")
        # corta na seção pedida
        i = texto.upper().find(f"[{secao}]")
        if i < 0:
            sys.exit(f"ERRO: secao [{secao}] nao encontrada em {arq}")
        bloco = texto[i:]
        reg = {}
        for linha in bloco.splitlines()[1:]:
            linha = linha.strip()
            if linha.startswith("[") and "COUNT" in reg:
                break
            if "=" not in linha:
                continue
            k, v = (x.strip() for x in linha.split("=", 1))
            k = k.upper()
            if k in reg:
                break
            reg[k] = v
        falta = {"KEY", "PLAINTEXT", "CIPHERTEXT"} - set(reg)
        if falta:
            sys.exit(f"ERRO: {arq}/{secao} sem {falta}")
        out.append({
            "arquivo": f"{arq} [{secao}] COUNT={reg.get('COUNT','?')}",
            "key": hexbytes(reg["KEY"]),
            "pt": hexbytes(reg["PLAINTEXT"]),
            "ct": hexbytes(reg["CIPHERTEXT"]),
            "cifra": secao == "ENCRYPT",
        })
    return out


def sha_vetores(n=2):
    """Mensagens curtas do SHAVS. A de comprimento 0 entra sempre: ela é a
    que pega padding errado no caso degenerado."""
    p = VEC / "sha" / "SHA256ShortMsg.rsp"
    if not p.exists():
        sys.exit(f"ERRO: {p} nao existe")
    regs = rsp_registros(p, "Len")
    escolhidos = []
    for r in regs:
        comp = int(r["LEN"][0])
        if comp % 8 != 0:
            continue                      # so mensagens em bytes inteiros
        escolhidos.append({
            "bits": comp,
            "msg": hexbytes(r["MSG"][0])[: comp // 8],
            "md": hexbytes(r["MD"][0]),
        })
        if len(escolhidos) >= n:
            break
    if len(escolhidos) < n:
        sys.exit("ERRO: vetores SHA insuficientes")
    return escolhidos


def hmac_vetores(casos=(1, 2, 6)):
    """Casos do RFC 4231. O caso 6 usa chave MAIOR que o bloco, que é o
    ramo mais esquecido de qualquer HMAC caseiro."""
    p = VEC / "hmac" / "rfc4231.txt"
    if not p.exists():
        sys.exit(f"ERRO: {p} nao existe")
    texto = p.read_text(errors="replace")

    # Corpo de cada "4.x.  Test Case N", ate o proximo
    blocos = {}
    partes = re.split(r"^\s*4\.\d+\.\s+Test Case (\d+)\s*$", texto, flags=re.M)
    for i in range(1, len(partes), 2):
        blocos[int(partes[i])] = partes[i + 1]

    def campo(bloco, rotulo):
        """Valor hex de um rotulo, juntando linhas de continuacao."""
        m = re.search(rf"^\s*{re.escape(rotulo)}\s*=\s*(.*)$", bloco, flags=re.M)
        if not m:
            return None
        pedacos = [m.group(1)]
        inicio = bloco.index(m.group(0)) + len(m.group(0))
        for linha in bloco[inicio:].splitlines()[1:]:
            if "=" in linha or not linha.strip():
                break
            pedacos.append(linha)
        junto = " ".join(pedacos)
        junto = re.sub(r"\(.*?\)", " ", junto)       # tira ("Hi There"), (20 bytes)
        return "".join(re.findall(r"[0-9a-fA-F]{2,}", junto))

    out = []
    for n in casos:
        if n not in blocos:
            sys.exit(f"ERRO: Test Case {n} nao encontrado no RFC 4231")
        b = blocos[n]
        k = campo(b, "Key")
        d = campo(b, "Data")
        m = campo(b, "HMAC-SHA-256")
        if not k or m is None:
            sys.exit(f"ERRO: Test Case {n} incompleto")
        mac = hexbytes(m)
        if len(mac) != 32:
            sys.exit(f"ERRO: Test Case {n}: HMAC-SHA-256 com {len(mac)} bytes")
        out.append({
            "caso": n,
            "key": hexbytes(k),
            "data": hexbytes(d or ""),
            "mac": mac,
        })
    return out


def cmac_vetores(n=3):
    """CMAC-AES-256 do CAVP (CMACGenAES256.rsp).

    ⚠ O arquivo do CAVS 11.0 só traz tags TRUNCADAS -- Tlen 5 e 10, nenhuma
    de 16 bytes. Truncar é o comportamento normatizado (SP 800-38B §6.2: a
    tag são os Tlen bytes mais à esquerda do CMAC completo), então o KAT
    compara os primeiros Tlen bytes. É KAT legítimo, mas registre-se: ele
    NÃO verifica os últimos 6 bytes da tag. Um erro que afete só o fim do
    último bloco passaria -- e não há vetor público de tag cheia para
    fechar isso.

    Escolhe comprimentos de mensagem DIFERENTES, cobrindo os três caminhos
    que o algoritmo tem:

        Mlen = 0          mensagem vazia -- usa K2, e é o caso que mais
                          falha em implementação caseira
        Mlen % 16 == 0    alinhada ao bloco -- usa K1
        Mlen % 16 != 0    precisa de padding -- usa K2

    Um vetor só, de qualquer tamanho, não distingue K1 de K2. Uma
    implementação que use sempre o mesmo subkey passa em metade dos casos.
    """
    p = VEC / "cmac" / "CMACGenAES256.rsp"
    if not p.exists():
        sys.exit(f"ERRO: {p} nao existe -- rode scripts/fetch-vectors.sh")

    regs = []
    atual = None
    for linha in p.read_text(errors="replace").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or linha.startswith("["):
            continue
        if "=" not in linha:
            continue
        k, v = (x.strip() for x in linha.split("=", 1))
        k = k.upper()
        if k == "COUNT":
            atual = {}
            regs.append(atual)
            continue
        if atual is not None:
            atual[k] = v

    quero = ["vazia", "alinhada", "padding"]
    achados = {}
    for r in regs:
        if "MAC" not in r or "MLEN" not in r or "TLEN" not in r:
            continue
        # a mais longa das duas disponiveis, para maximizar o que e conferido
        if int(r["TLEN"]) != 10:
            continue
        mlen = int(r["MLEN"])
        if mlen == 0:
            classe = "vazia"
        elif mlen % 16 == 0:
            classe = "alinhada"
        else:
            classe = "padding"
        if classe in achados:
            continue
        msg = b"" if mlen == 0 else hexbytes(r["MSG"])[:mlen]
        if len(msg) != mlen:
            continue
        mac = hexbytes(r["MAC"])
        if len(mac) != int(r["TLEN"]):
            continue
        achados[classe] = {
            "classe": classe,
            "mlen": mlen,
            "key": hexbytes(r["KEY"]),
            "msg": msg,
            "mac": mac,
        }
        if len(achados) == len(quero):
            break

    faltando = [c for c in quero if c not in achados]
    if faltando:
        sys.exit(f"ERRO: nao achei vetor CMAC para {faltando}")
    return [achados[c] for c in quero][:n]


def drbg_vetores(n=3):
    """CTR_DRBG AES-256 use df, sem resemeadura (CAVP).

    Estrutura de cada registro:
        EntropyInput, Nonce, PersonalizationString,
        AdditionalInput (duas vezes), ReturnedBits

    Fluxo do teste: instancia, gera uma vez DESCARTANDO, gera de novo --
    a segunda saída é ReturnedBits. Gerar só uma vez dá outro resultado, e
    é o erro clássico de quem lê o .rsp sem ler a especificação do teste.

    Escolhe registros de seções diferentes (com e sem personalização, com e
    sem dado adicional) para o POST exercitar os quatro caminhos.
    """
    p = VEC / "drbg" / "CTR_DRBG_AES256.rsp"
    if not p.exists():
        sys.exit(f"ERRO: {p} nao existe")

    regs = []
    atual = None
    for linha in p.read_text(errors="replace").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or linha.startswith("["):
            continue
        if "=" not in linha:
            continue
        k, v = (x.strip() for x in linha.split("=", 1))
        k = k.upper()
        if k == "COUNT":
            atual = {"ADDITIONALINPUT": []}
            regs.append(atual)
            continue
        if atual is None:
            continue
        if k == "ADDITIONALINPUT":
            atual["ADDITIONALINPUT"].append(v)
        else:
            atual[k] = v

    # um de cada combinação (personalização x dado adicional)
    vistos = {}
    for r in regs:
        if "RETURNEDBITS" not in r or len(r["ADDITIONALINPUT"]) < 2:
            continue
        chave = (bool(r.get("PERSONALIZATIONSTRING", "")),
                 bool(r["ADDITIONALINPUT"][0]))
        if chave in vistos:
            continue
        vistos[chave] = {
            "pers_flag": chave[0],
            "addl_flag": chave[1],
            "entropia": hexbytes(r["ENTROPYINPUT"]),
            "nonce": hexbytes(r.get("NONCE", "")),
            "pers": hexbytes(r.get("PERSONALIZATIONSTRING", "")),
            "addl1": hexbytes(r["ADDITIONALINPUT"][0]),
            "addl2": hexbytes(r["ADDITIONALINPUT"][1]),
            "esperado": hexbytes(r["RETURNEDBITS"]),
        }
        if len(vistos) >= n:
            break

    if len(vistos) < n:
        sys.exit(f"ERRO: so achei {len(vistos)} combinacoes de DRBG, queria {n}")
    return list(vistos.values())


def tr31_vetor():
    """O unico valor conhecido de key block X9.143 versao D.

    ⚠ PROCEDENCIA DIFERENTE DE TODOS OS OUTROS DESTE ARQUIVO. Nao e do
    CAVP e nao ha como ser: o CAVP valida ALGORITMO, e X9.143 e FORMATO.
    A norma que traz o exemplo e paga. Este vem do arquivo de testes de
    uma biblioteca de terceiros, fixado por commit e por hash --
    vectors/MANIFEST.txt explica o que ele vale e o que nao vale.

    Cobre DESEMBRULHAR. Embrulhar nao tem KAT possivel: o enchimento do
    corpo e aleatorio por norma, entao a operacao nao e deterministica.
    """
    p = VEC / "tr31" / "x9143_D_AES256.rsp"
    if not p.exists():
        sys.exit(f"ERRO: {p} nao existe -- rode scripts/fetch-vectors.sh")

    reg = {}
    for linha in p.read_text(errors="replace").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or linha.startswith("["):
            continue
        if "=" not in linha:
            continue
        k, v = (x.strip() for x in linha.split("=", 1))
        reg[k.upper()] = v

    falta = {"KBPK", "KEY", "KB"} - set(reg)
    if falta:
        sys.exit(f"ERRO: {p} sem {falta}")

    kbpk = hexbytes(reg["KBPK"])
    if len(kbpk) != 32:
        sys.exit(f"ERRO: KBPK com {len(kbpk)} bytes; o firmware so faz AES-256")

    kb = reg["KB"]
    if not kb.startswith("D"):
        sys.exit(f"ERRO: key block de versao {kb[0]!r}; este projeto so faz a D")
    if int(kb[1:5]) != len(kb):
        sys.exit(f"ERRO: campo de comprimento {kb[1:5]} != {len(kb)} caracteres")

    return {
        "kbpk": kbpk,
        "key": hexbytes(reg["KEY"]),
        "kb": kb.encode("ascii"),
    }


# ---------------------------------------------------------------------
def rsa_vetor():
    """Primeiro vetor SHA-256 de 2048 bits do SigGen15.

    Do arquivo vem n, e, Msg e S. O digest e o EM saem deles por PKCS#1 v1.5,
    e S^e mod n tem de fechar aqui antes de ir para o firmware.
    """
    texto = (VEC / "rsa" / "SigGen15_186-3.rsp").read_text()
    texto = texto.split("[mod = 3072]")[0]
    n = re.search(r"^n = (\w+)", texto, re.M)[1]
    e = int(re.search(r"^e = (\w+)", texto, re.M)[1], 16)
    v = re.search(r"SHAAlg = SHA256\nMsg = (\w+)\nS = (\w+)", texto)
    digest = hashlib.sha256(bytes.fromhex(v[1])).digest()
    t = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    em = b"\0\1" + b"\xff" * (253 - len(t)) + b"\0" + t
    if pow(int(v[2], 16), e, int(n, 16)) != int.from_bytes(em, "big"):
        raise SystemExit("SigGen15: vetor nao fecha")
    return {"n": bytes.fromhex(n), "e": e, "s": bytes.fromhex(v[2]),
            "em": em, "digest": digest,
            "chave": rsa_chave_crt(int(n, 16), e,
                                   int(re.search(r"^d = (\w+)", (VEC / "rsa" / "SigGen15_186-3.txt").read_text().split("[mod = 3072]")[0], re.M)[1], 16),
                                   int.from_bytes(em, "big"), int(v[2], 16))}


def rsa_chave_crt(n, e, d, em, s):
    """A chave do vetor no layout do key block: e(4) p q dp dq qinv.

    O arquivo do CAVP traz n, e e d, e a assinatura do firmware e por CRT,
    que precisa de p e q. Eles saem de (n, e, d) pelo metodo classico: e*d - 1
    e multiplo da ordem do grupo, e uma raiz quadrada nao trivial de 1 modulo n
    entrega um fator. Nada aqui e escolhido: p*q tem de ser o n do vetor, e a
    assinatura por CRT do EM tem de ser o S do vetor, ou o script para.
    """
    import math
    k = e * d - 1
    t = 0
    while k % 2 == 0:
        k //= 2
        t += 1
    p = None
    for g in range(2, 200):
        x = pow(g, k, n)
        for _ in range(t):
            y = x * x % n
            if y == 1 and x not in (1, n - 1):
                p = math.gcd(x - 1, n)
                break
            x = y
        if p:
            break
    if not p:
        raise SystemExit("SigGen15: nao fatorou n")
    q = n // p
    if p < q:
        p, q = q, p
    dp, dq, qinv = d % (p - 1), d % (q - 1), pow(q, -1, p)
    sp, sq = pow(em, dp, p), pow(em, dq, q)
    if p * q != n or (sq + q * ((qinv * (sp - sq)) % p)) != s:
        raise SystemExit("SigGen15: a chave em CRT nao reproduz o vetor")
    return e.to_bytes(4, "big") + b"".join(
        v.to_bytes(128, "big") for v in (p, q, dp, dq, qinv))


def ecdsa_vetor():
    """Primeiro vetor [P-256,SHA-256] do SigGen.txt: d, Q, k, R, S e o digest
    da mensagem. Serve ao KAT de assinatura (com k fixo) e ao de verificacao."""
    texto = (VEC / "ecdsa" / "SigGen_P256.txt").read_text()
    c = {}
    for m in re.finditer(r"^(\w+) = (\w+)", texto, re.M):
        if m[1] in c:
            break
        c[m[1]] = m[2]
    b = lambda nome: bytes.fromhex(c[nome].zfill(64))
    return {"d": b("d"), "q": b("Qx") + b("Qy"), "k": b("k"),
            "rs": b("R") + b("S"),
            "digest": hashlib.sha256(bytes.fromhex(c["Msg"])).digest()}


def main():
    aes = aes_vetores()
    sha = sha_vetores()
    hmac = hmac_vetores()
    cmac = cmac_vetores()
    drbg = drbg_vetores()
    tr31 = tr31_vetor()
    rsa = rsa_vetor()
    ec = ecdsa_vetor()

    L = []
    L.append("/* fw/include/kat_vectors.h -- GERADO, nao editar")
    L.append(" *")
    L.append(" * Produzido por scripts/mkkat.py a partir de vectors/.")
    L.append(" * Procedencia dos arquivos: vectors/MANIFEST.txt.")
    L.append(" *")
    L.append(" * Editar este arquivo a mao quebra a unica garantia que ele tem:")
    L.append(" * a de que os numeros vieram do NIST e do IETF, e nao da memoria")
    L.append(" * de quem escreveu o codigo.")
    L.append(" */")
    L.append("#ifndef KAT_VECTORS_H")
    L.append("#define KAT_VECTORS_H")
    L.append("")
    L.append("#include <stdint.h>")
    L.append("")

    L.append("/* ---- AES-256 ECB (NIST CAVP / AESAVS) ---- */")
    for i, v in enumerate(aes):
        L.append(f"/* {v['arquivo']} */")
        L.append(carr(f"kat_aes{i}_key", v["key"]))
        L.append(carr(f"kat_aes{i}_in", v["pt"] if v["cifra"] else v["ct"]))
        L.append(carr(f"kat_aes{i}_out", v["ct"] if v["cifra"] else v["pt"]))
        L.append(f"#define KAT_AES{i}_CIFRA {1 if v['cifra'] else 0}")
        L.append("")
    L.append(f"#define KAT_AES_N {len(aes)}")
    L.append("")

    L.append("/* ---- SHA-256 (NIST CAVP / SHAVS ShortMsg) ---- */")
    for i, v in enumerate(sha):
        L.append(f"/* Len = {v['bits']} bits */")
        L.append(carr(f"kat_sha{i}_msg", v["msg"]))
        L.append(f"#define KAT_SHA{i}_LEN {len(v['msg'])}u")
        L.append(carr(f"kat_sha{i}_md", v["md"]))
        L.append("")
    L.append(f"#define KAT_SHA_N {len(sha)}")
    L.append("")

    L.append("/* ---- HMAC-SHA-256 (IETF RFC 4231) ---- */")
    for i, v in enumerate(hmac):
        L.append(f"/* Test Case {v['caso']}: chave {len(v['key'])} bytes,"
                 f" dado {len(v['data'])} bytes */")
        L.append(carr(f"kat_hmac{i}_key", v["key"]))
        L.append(f"#define KAT_HMAC{i}_KEYLEN {len(v['key'])}u")
        L.append(carr(f"kat_hmac{i}_data", v["data"]))
        L.append(f"#define KAT_HMAC{i}_DATALEN {len(v['data'])}u")
        L.append(carr(f"kat_hmac{i}_mac", v["mac"]))
        L.append("")
    L.append(f"#define KAT_HMAC_N {len(hmac)}")
    L.append("")

    L.append("/* ---- CMAC-AES-256 (NIST CAVP / CMACVS) ----")
    L.append(" *")
    L.append(" * Tres classes, porque o algoritmo tem tres caminhos e um")
    L.append(" * vetor so nao distingue K1 de K2.")
    L.append(" *")
    L.append(" * TAGS TRUNCADAS: o arquivo do CAVS 11.0 nao tem tag de 16")
    L.append(" * bytes. Comparar os primeiros TAGLEN bytes e o que a norma")
    L.append(" * define (SP 800-38B 6.2), mas nao confere o resto da tag. */")
    for i, v in enumerate(cmac):
        L.append(f"/* {v['classe']}: Mlen = {v['mlen']}, Tlen = {len(v['mac'])} */")
        L.append(carr(f"kat_cmac{i}_key", v["key"]))
        L.append(carr(f"kat_cmac{i}_msg", v["msg"]))
        L.append(f"#define KAT_CMAC{i}_MSGLEN {len(v['msg'])}u")
        L.append(carr(f"kat_cmac{i}_mac", v["mac"]))
        L.append(f"#define KAT_CMAC{i}_TAGLEN {len(v['mac'])}u")
        L.append("")
    L.append(f"#define KAT_CMAC_N {len(cmac)}")
    L.append("")

    L.append("/* ---- CTR_DRBG AES-256 use df (NIST CAVP / SP 800-90A) ----")
    L.append(" *")
    L.append(" * Fluxo do teste, e ele NAO e obvio a partir do .rsp:")
    L.append(" *   instantiate(entropia, nonce, personalizacao)")
    L.append(" *   generate(addl1)  -> DESCARTA")
    L.append(" *   generate(addl2)  -> compara com esperado")
    L.append(" *")
    L.append(" * Gerar uma vez so produz outro resultado. */")
    for i, v in enumerate(drbg):
        L.append(f"/* personalizacao={'sim' if v['pers_flag'] else 'nao'},"
                 f" dado adicional={'sim' if v['addl_flag'] else 'nao'} */")
        for campo in ("entropia", "nonce", "pers", "addl1", "addl2", "esperado"):
            L.append(carr(f"kat_drbg{i}_{campo}", v[campo]))
            L.append(f"#define KAT_DRBG{i}_{campo.upper()}_N {len(v[campo])}u")
        L.append("")
    L.append(f"#define KAT_DRBG_N {len(drbg)}")
    L.append("")
    L.append("/* ---- key block ANSI X9.143 versao D ----")
    L.append(" *")
    L.append(" * ATENCAO: este NAO e vetor do CAVP. E um valor conhecido de")
    L.append(" * TERCEIROS -- o CAVP valida algoritmo, e X9.143 e formato, e a")
    L.append(" * norma que traz o exemplo e paga. Procedencia completa em")
    L.append(" * vectors/MANIFEST.txt.")
    L.append(" *")
    L.append(" * Cobre DESEMBRULHAR. Embrulhar nao tem KAT possivel: o")
    L.append(" * enchimento e aleatorio por norma. */")
    L.append(f"#define KAT_RSA_E 0x{rsa['e']:08x}u")
    L.append(carr("kat_rsa_n", rsa["n"]))
    L.append(carr("kat_rsa_s", rsa["s"]))
    L.append(carr("kat_rsa_digest", rsa["digest"]))
    L.append("/* A chave do mesmo vetor, em CRT: p e q saem de n, e, d em")
    L.append(" * scripts/mkkat.py. KAT de assinatura, no primeiro uso. */")
    L.append(carr("kat_rsa_chave", rsa["chave"]))
    L.append("")
    L.append("/* ---- ECDSA P-256 com SHA-256, CAVP (FIPS 186-4), SigGen ---- */")
    L.append(carr("kat_ec_d", ec["d"]))
    L.append(carr("kat_ec_q", ec["q"]))
    L.append(carr("kat_ec_k", ec["k"]))
    L.append(carr("kat_ec_digest", ec["digest"]))
    L.append(carr("kat_ec_rs", ec["rs"]))
    L.append("")
    L.append(carr("kat_tr31_kbpk", tr31["kbpk"]))
    L.append(carr("kat_tr31_key", tr31["key"]))
    L.append(f"#define KAT_TR31_KEY_LEN {len(tr31['key'])}u")
    L.append(carr("kat_tr31_kb", tr31["kb"]))
    L.append(f"#define KAT_TR31_KB_LEN {len(tr31['kb'])}u")
    L.append("")
    L.append("#endif /* KAT_VECTORS_H */")

    SAIDA.write_text("\n".join(L) + "\n")
    mr_vetores()

    print(f"-> {SAIDA.relative_to(ROOT)}")
    print(f"   AES  {len(aes)} vetores")
    print(f"   SHA  {len(sha)} vetores")
    print(f"   HMAC {len(hmac)} vetores (casos {[v['caso'] for v in hmac]})")
    print(f"   CMAC {len(cmac)} vetores ({[v['classe'] for v in cmac]})")
    print(f"   DRBG {len(drbg)} vetores")
    print(f"   TR31 1 vetor ({len(tr31['kb'])} caracteres) -- fonte de terceiros")
    print(f"   {SAIDA.stat().st_size} bytes")


def mr_vetores():
    """fw/include/kat_mr.h: candidatos do KAT de primalidade do CAVP
    (KeyGen_186-3_RandomProbablyPrime3_3_KAT.txt), copiados literalmente.

    So o firmware de TESTE inclui este header (make HSM_TESTE_MR=1): o
    Miller-Rabin custa uma exponenciacao de 1024 bits por rodada, caro
    demais para o POST. Tres casos: o p de um resultado P (primo), o p de
    um F no passo 4.7 e o q de um F no passo 5.8 (compostos)."""
    texto = (VEC / "rsa" / "KeyGen_186-3_RandomProbablyPrime3_3_KAT.txt"
             ).read_text(encoding="latin-1")
    texto = texto.split("[mod = 2048]")[1].split("[mod =")[0]
    ents = re.findall(r"prandom = (\w+)\s+qrandom = (\w+)\s+Result = (.*)", texto)
    primo = next(p for p, q, r in ents if r.startswith("P"))
    comp1 = next(p for p, q, r in ents if r.startswith("F (Step 4.7"))
    comp2 = next(q for p, q, r in ents
                 if r.startswith("F (Step 5.8") and int(q, 16) & 1)
    casos = [(primo, 1, "P: p provavelmente primo"),
             (comp1, 0, "F, passo 4.7: p composto"),
             (comp2, 0, "F, passo 5.8: q composto")]
    L = ["/* fw/include/kat_mr.h -- GERADO por scripts/mkkat.py, nao editar",
         " *",
         " * KAT de primalidade do CAVP (FIPS 186-3, primos provaveis). So o",
         " * firmware de teste (make HSM_TESTE_MR=1) inclui este arquivo.",
         " */",
         "#ifndef KAT_MR_H", "#define KAT_MR_H", "", "#include <stdint.h>", ""]
    for i, (w, esperado, nome) in enumerate(casos):
        b = bytes.fromhex(w)
        if len(b) != 128 or not (b[0] & 0x80) or not (b[-1] & 1):
            raise SystemExit(f"kat_mr: candidato {i} fora do formato")
        L.append(f"/* {nome} */")
        L.append(carr(f"kat_mr{i}", b))
        L.append(f"#define KAT_MR{i}_PRIMO {esperado}")
        L.append("")
    L.append(f"#define KAT_MR_N {len(casos)}")
    L.append("")
    L.append("#endif")
    (ROOT / "fw" / "include" / "kat_mr.h").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
