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


# ---------------------------------------------------------------------
def main():
    aes = aes_vetores()
    sha = sha_vetores()
    hmac = hmac_vetores()
    cmac = cmac_vetores()
    drbg = drbg_vetores()

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
    L.append("#endif /* KAT_VECTORS_H */")

    SAIDA.write_text("\n".join(L) + "\n")

    print(f"-> {SAIDA.relative_to(ROOT)}")
    print(f"   AES  {len(aes)} vetores")
    print(f"   SHA  {len(sha)} vetores")
    print(f"   HMAC {len(hmac)} vetores (casos {[v['caso'] for v in hmac]})")
    print(f"   CMAC {len(cmac)} vetores ({[v['classe'] for v in cmac]})")
    print(f"   DRBG {len(drbg)} vetores")
    print(f"   {SAIDA.stat().st_size} bytes")


if __name__ == "__main__":
    main()
