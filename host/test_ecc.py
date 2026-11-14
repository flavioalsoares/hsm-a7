#!/usr/bin/env python3
"""ECDSA P-256 do firmware contra os vetores do CAVP, no PC.

Compila fw/src/ecc.c -- o mesmo arquivo do firmware -- com o modelo do
coprocessador de fw/teste/ecc_nativo.c, e confere:

  KeyPair   Q = d * G                                    10 vetores
  PKV       validacao da chave publica                   aceita e recusa
  SigGen    assinatura com o k do vetor: r e s exatos    15 vetores
  SigVer    verificacao: aceita e recusa                 15 vetores

Mais casos que os vetores nao trazem, com valores esperados calculados
aqui em Python com inteiros (NAO sao vetores oficiais; sao propriedades):

  - os caminhos de excecao da soma final da verificacao (P1 = P2,
    P1 = -P2, u1 = 0);
  - r e s fora de [1, n-1];
  - geracao e assinatura com k sorteado, conferidas pela biblioteca
    `cryptography`, se ela estiver instalada.

O que este teste NAO prova: que o C fala certo com o hardware. Isso e do
testbench tb_ecdsa. Precisa de gcc.

    python3 host/test_ecc.py
"""
import hashlib
import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
VEC = ROOT / "vectors" / "ecdsa"

# Parametros da curva, para as contas de conferencia (SP 800-186, 3.2.1.3).
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def soma(p1, p2):
    """Soma de pontos afins; None e o ponto no infinito."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def mult(k, p):
    r = None
    while k:
        if k & 1:
            r = soma(r, p)
        p = soma(p, p)
        k >>= 1
    return r


def h32(v):
    return f"{v:064x}"


def blocos(nome):
    """Os casos de um arquivo do CAVP, como dicionarios."""
    casos, atual = [], {}
    for linha in (VEC / nome).read_text().splitlines():
        m = re.match(r"^(\w+) = (.*)$", linha.strip())
        if m:
            atual[m.group(1)] = m.group(2).strip()
        elif atual:
            casos.append(atual)
            atual = {}
    if atual:
        casos.append(atual)
    return [c for c in casos if len(c) > 1]


class Nativo:
    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()
        exe = os.path.join(self.dir.name, "ecc_nativo")
        fontes = ["fw/teste/ecc_nativo.c", "fw/src/ecc.c", "fw/src/mont.c",
                  "fw/src/bn.c"]
        subprocess.run(
            ["gcc", "-O1", "-Wall", "-Wextra", "-Werror", "-std=c99",
             "-I", str(ROOT / "fw" / "include"), "-o", exe]
            + [str(ROOT / f) for f in fontes], check=True)
        self.p = subprocess.Popen([exe], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)

    def __call__(self, *campos):
        self.p.stdin.write(" ".join(campos) + "\n")
        self.p.stdin.flush()
        resp = self.p.stdout.readline().split("#")[0].split()
        return int(resp[0]), (resp[1] if len(resp) > 1 else "")


erros = 0


def confere(cond, texto):
    global erros
    if not cond:
        erros += 1
        print("  FALHOU:", texto)


def main():
    nat = Nativo()

    # Os parametros escritos aqui, antes de servirem de referencia.
    assert (GY * GY - (GX**3 - 3 * GX + B)) % P == 0
    assert mult(N, (GX, GY)) is None

    casos = blocos("KeyPair_P256.rsp")
    for c in casos:
        r, q = nat("pub", c["d"].zfill(64))
        confere(r == 0 and q == c["Qx"].zfill(64) + c["Qy"].zfill(64),
                f"KeyPair d={c['d'][:16]}")
    print(f"KeyPair  {len(casos)} vetores")

    # PKV pela verificacao: chave recusada devolve -1, antes de olhar a
    # assinatura. Chave aceita com assinatura qualquer devolve 0.
    casos = blocos("PKV_P256.rsp")
    for c in casos:
        qx, qy = c["Qx"], c["Qy"]
        aceita = c["Result"].startswith("P")
        if len(qx) > 64 or len(qy) > 64:
            # Coordenada que nem cabe em 256 bits: o comando recusa pelo
            # tamanho do campo, antes do ECDSA.
            confere(not aceita, "PKV: coordenada longa marcada como valida")
            continue
        r, _ = nat("ver", qx.zfill(64) + qy.zfill(64), h32(1), h32(1) + h32(1))
        confere(r == (0 if aceita else -1), f"PKV Qx={qx[:16]} {c['Result']}")
    print(f"PKV      {len(casos)} vetores")

    casos = blocos("SigGen_P256.txt")
    for c in casos:
        dig = hashlib.sha256(bytes.fromhex(c["Msg"])).hexdigest()
        r, sig = nat("sigk", c["d"].zfill(64), dig, c["k"].zfill(64))
        confere(r == 0 and sig == c["R"].zfill(64) + c["S"].zfill(64),
                f"SigGen d={c['d'][:16]}")
        # A mesma assinatura, pela verificacao.
        r, _ = nat("ver", c["Qx"].zfill(64) + c["Qy"].zfill(64), dig,
                   c["R"].zfill(64) + c["S"].zfill(64))
        confere(r == 1, f"SigGen, verificacao d={c['d'][:16]}")
    print(f"SigGen   {len(casos)} vetores")

    casos = blocos("SigVer_P256.rsp")
    for c in casos:
        dig = hashlib.sha256(bytes.fromhex(c["Msg"])).hexdigest()
        r, _ = nat("ver", c["Qx"].zfill(64) + c["Qy"].zfill(64), dig,
                   c["R"].zfill(64) + c["S"].zfill(64))
        confere(r == (1 if c["Result"].startswith("P") else 0),
                f"SigVer Qx={c['Qx'][:16]} {c['Result']}")
    print(f"SigVer   {len(casos)} vetores")

    # --- propriedades, com contas em Python ---------------------------
    g = (GX, GY)
    k = secrets.randbelow(N - 1) + 1
    r_ = mult(k, g)[0] % N

    # P1 = P2: Q = G, e = r, s = 2r/k. u1 = u2 = k/2, a soma e uma dobra.
    s_ = 2 * r_ * pow(k, -1, N) % N
    v, _ = nat("ver", h32(GX) + h32(GY), h32(r_), h32(r_) + h32(s_))
    confere(v == 1, "P1 = P2 (dobra) devia valer")

    # P1 = -P2: Q = -G, e = r. A soma e o infinito: invalida.
    v, _ = nat("ver", h32(GX) + h32(P - GY), h32(r_), h32(r_) + h32(s_))
    confere(v == 0, "P1 = -P2 (infinito) devia ser invalida")

    # u1 = 0: digest zero e digest n. Assinatura valida sobre e = 0.
    d = secrets.randbelow(N - 1) + 1
    q = mult(d, g)
    s_ = pow(k, -1, N) * (0 + r_ * d) % N
    for e in (0, N):
        v, _ = nat("ver", h32(q[0]) + h32(q[1]), h32(e), h32(r_) + h32(s_))
        confere(v == 1, f"u1 = 0 com e = {'n' if e else '0'} devia valer")

    # Escalares de borda na verificacao. Quem monta a assinatura escolhe
    # u1 e u2; com R = u1*G + u2*Q, r = x(R), s = r/u2 e e = u1*s, a
    # assinatura (r, s) sobre e e valida.
    for t in (1, 2, N - 1, N - 2, N - 3):
        for u1, u2 in ((t, secrets.randbelow(N - 1) + 1),
                       (secrets.randbelow(N - 1) + 1, t), (t, t)):
            ponto = soma(mult(u1, g), mult(u2, q))
            if ponto is None:
                continue
            rr = ponto[0] % N
            ss = rr * pow(u2, -1, N) % N
            ee = u1 * ss % N
            v, _ = nat("ver", h32(q[0]) + h32(q[1]), h32(ee), h32(rr) + h32(ss))
            confere(v == 1, f"verificacao com u1={u1:x} u2={u2:x}")
            v, _ = nat("ver", h32(q[0]) + h32(q[1]), h32(ee ^ 1), h32(rr) + h32(ss))
            confere(v == 0, f"verificacao adulterada com u1={u1:x} u2={u2:x}")

    # r e s fora do intervalo: invalida, nao erro.
    for rr, ss in ((0, s_), (r_, 0), (N, s_), (r_, N), (2**256 - 1, s_)):
        v, _ = nat("ver", h32(q[0]) + h32(q[1]), h32(5), h32(rr) + h32(ss))
        confere(v == 0, "r ou s fora de [1, n-1] devia ser invalida")

    # Escalares nas bordas, contra a multiplicacao em Python.
    for dd in (1, 2, 3, 4, N - 1, N - 2, N - 3, N - 4, (N - 1) // 2, (N + 1) // 2, 2**255,
               2**256 - N, 2**256 - N - 1, 2**256 - N + 1):
        r, saida = nat("pub", h32(dd))
        esperado = mult(dd, g)
        confere(r == 0 and saida == h32(esperado[0]) + h32(esperado[1]),
                f"d de borda {dd:x}")
    for dd in (0, N, N + 1, 2**256 - 1):
        r, _ = nat("pub", h32(dd))
        confere(r == -1, f"d invalido {dd:x} devia ser recusado")

    # Escalares e pontos ao acaso, contra o Python.
    for _ in range(40):
        dd = secrets.randbelow(N - 1) + 1
        r, saida = nat("pub", h32(dd))
        esperado = mult(dd, g)
        confere(r == 0 and saida == h32(esperado[0]) + h32(esperado[1]),
                f"d ao acaso {dd:x}")
    print("bordas e casos de excecao")

    # Geracao e assinatura com k sorteado: confere com outra biblioteca.
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        print("`cryptography` nao instalada: sem a conferencia cruzada")
    else:
        for _ in range(20):
            r, chave = nat("gen")
            confere(r == 0, "gen")
            dd = int(chave[:64], 16)
            esperado = mult(dd, g)
            confere(chave[64:] == h32(esperado[0]) + h32(esperado[1]),
                    "gen: Q != d*G")
            dig = secrets.token_bytes(32)
            r, sig = nat("sign", chave, dig.hex())
            confere(r == 0, "sign")
            pub = ec.EllipticCurvePublicNumbers(
                esperado[0], esperado[1], ec.SECP256R1()).public_key()
            der = utils.encode_dss_signature(int(sig[:64], 16),
                                             int(sig[64:], 16))
            alg = ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            try:
                pub.verify(der, dig, alg)
            except InvalidSignature:
                confere(False, "assinatura do firmware recusada pela biblioteca")
            # E o caminho inverso: a biblioteca assina, o firmware verifica.
            priv = ec.derive_private_key(dd, ec.SECP256R1())
            r2, s2 = utils.decode_dss_signature(priv.sign(dig, alg))
            v, _ = nat("ver", chave[64:], dig.hex(), h32(r2) + h32(s2))
            confere(v == 1, "assinatura da biblioteca recusada pelo firmware")
            v, _ = nat("ver", chave[64:], dig.hex(), h32(r2) + h32(s2 ^ 1))
            confere(v == 0, "assinatura adulterada aceita")
        # Chave publica que nao e a da chave privada: a assinatura nao sai.
        r, chave = nat("gen")
        ruim = chave[:64] + h32(GX) + h32(GY)
        r, _ = nat("sign", ruim, secrets.token_hex(32))
        confere(r == -2, "assinatura com Q errado devia dar -2")
        print("geracao e assinatura, conferidas pela `cryptography`")

    if erros:
        print(f"FAIL: {erros} erro(s)")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
