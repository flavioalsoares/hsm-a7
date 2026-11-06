#!/usr/bin/env python3
"""puf.py -- mede o RO-PUF e calcula as metricas (fase 6).

So funciona com build/puf/hsm_puf.bit na placa. Ver doc/puf-experimento.md.

  puf.py ler -n 100 -o a.csv       le n varreduras
  puf.py termica -o t.csv          sobe a carga e amostra a cada 5 C
  puf.py analisa a.csv             metricas de uma ou mais medidas
  puf.py deriva base.csv t.csv     BER contra a referencia, por nivel de carga
  puf.py compara a.csv b.csv       bits diferentes entre duas referencias
  puf.py corretor --ber 2          dimensiona o BCH e conta a entropia que sobra

Cada linha do CSV: carga, temperatura em C, e as 64 contagens. O hardware so
conta: formar bits e escolher pares acontece aqui, sobre a mesma medida.
"""
import argparse
import csv
import math
import sys
import time

import serial

from hsmtool import default_port

N = 64
POR_COLUNA = 16
LIMITE_C = 70.0
RECUSADO = 0xFFFFFF


def celsius(cod):
    return cod * 503.975 / 4096 - 273.15


class Puf:
    def __init__(self, porta):
        self.s = serial.Serial(porta, 115200, timeout=2)
        self.s.reset_input_buffer()
        self.s.write(b"V")
        if self._le(4) != b"PUF1":
            raise SystemExit("sem resposta: o bitstream do PUF esta na placa?")

    def _le(self, n):
        d = self.s.read(n)
        if len(d) != n:
            raise SystemExit("resposta curta: %d de %d bytes" % (len(d), n))
        return d

    def temp(self):
        self.s.write(b"T")
        r = self._le(4)
        return celsius(int.from_bytes(r[1:3], "big")), r[3]

    def vccint(self):
        self.s.write(b"U")
        r = self._le(4)
        return int.from_bytes(r[1:3], "big") * 3 / 4096

    def carga(self, nivel):
        self.s.write(b"C" + bytes([nivel]))
        return self._le(4)[1]

    def varre(self):
        self.s.write(b"S")
        cab = self._le(4)
        if cab[:1] != b"S" or cab[3] != N:
            raise SystemExit("cabecalho invalido: %s" % cab.hex())
        d = self._le(3 * N)
        fim = self._le(4)
        if fim[:1] != b"E":
            raise SystemExit("fim invalido: %s" % fim.hex())
        contas = [int.from_bytes(d[i:i + 3], "big") for i in range(0, 3 * N, 3)]
        if RECUSADO in contas:
            raise SystemExit("varredura recusada pelo limite de temperatura")
        return celsius(int.from_bytes(cab[1:3], "big")), contas


def grava(w, nivel, temp, contas):
    w.writerow([nivel, "%.2f" % temp] + contas)


def cmd_ler(a):
    p = Puf(a.porta or default_port())
    with open(a.saida, "w", newline="") as f:
        w = csv.writer(f)
        for i in range(a.n):
            t, c = p.varre()
            grava(w, a.carga, t, c)
            if i % 100 == 0:
                print("%5d  %.1f C" % (i, t), flush=True)
    return 0


def cmd_termica(a):
    """Cada nivel de carga fica ate a temperatura parar de subir."""
    p = Puf(a.porta or default_port())
    with open(a.saida, "w", newline="") as f:
        w = csv.writer(f)
        try:
            for nivel in range(0, 9):
                p.carga(nivel)
                anterior, parado = -100.0, 0
                while parado < 3:
                    time.sleep(a.espera)
                    t, estado = p.temp()
                    if t >= LIMITE_C - 2 or estado & 2:
                        print("limite: %.1f C, VCCINT %.3f V" % (t, p.vccint()))
                        return 0
                    parado = parado + 1 if t - anterior < 0.3 else 0
                    anterior = t
                for _ in range(a.n):
                    t, c = p.varre()
                    grava(w, nivel, t, c)
                print("carga %d: %.1f C, VCCINT %.3f V" % (nivel, t, p.vccint()),
                      flush=True)
        finally:
            p.carga(0)
    return 0


# ---- metricas ------------------------------------------------------------

def carrega(nome):
    with open(nome, newline="") as f:
        return [(int(r[0]), float(r[1]), [int(x) for x in r[2:]])
                for r in csv.reader(f)]


def pares_vizinhos():
    """Vizinhos na coluna, sem repetir anel: um bit por par."""
    return [(i, i + 1) for i in range(0, N, 2)]


def pares_cadeia():
    """Vizinhos em cadeia: mais bits, mas nao independentes."""
    return [(i, i + 1) for i in range(N - 1) if (i + 1) % POR_COLUNA]


def pares_colunas():
    """Mesma linha em colunas diferentes: longe no die."""
    return [(i, i + POR_COLUNA) for i in range(N - POR_COLUNA)]


PAREAMENTOS = {"vizinhos": pares_vizinhos, "cadeia": pares_cadeia,
               "colunas": pares_colunas}


def bits(contas, pares):
    return [1 if contas[i] > contas[j] else 0 for i, j in pares]


def referencia(medidas, pares):
    n = len(medidas)
    soma = [0] * len(pares)
    for _, _, c in medidas:
        for k, b in enumerate(bits(c, pares)):
            soma[k] += b
    return [1 if 2 * s > n else 0 for s in soma], soma


def ber(medidas, pares, ref):
    tot = 0
    for _, _, c in medidas:
        tot += sum(a != b for a, b in zip(bits(c, pares), ref))
    return tot / (len(medidas) * len(pares))


def h2(p):
    return 0.0 if p in (0.0, 1.0) else -p * math.log2(p) - (1 - p) * math.log2(1 - p)


def binom_cauda(n, p, t):
    """P(mais de t erros em n bits)."""
    return 1 - sum(math.comb(n, k) * p**k * (1 - p)**(n - k) for k in range(t + 1))


def cmd_analisa(a):
    m = []
    for nome in a.arquivos:
        m += carrega(nome)
    temps = [x[1] for x in m]
    print("%d varreduras, %.1f a %.1f C" % (len(m), min(temps), max(temps)))

    media = [sum(x[2][i] for x in m) / len(m) for i in range(N)]
    mhz = [c / 1000 for c in media]        # janela de 1 ms
    print("frequencia: %.2f a %.2f MHz, media %.2f"
          % (min(mhz), max(mhz), sum(mhz) / N))
    for col in range(N // POR_COLUNA):
        v = mhz[col * POR_COLUNA:(col + 1) * POR_COLUNA]
        print("  coluna %d: media %.3f MHz, desvio %.3f"
              % (col, sum(v) / len(v),
                 math.sqrt(sum((x - sum(v) / len(v))**2 for x in v) / len(v))))
    ruido = [math.sqrt(sum((x[2][i] - media[i])**2 for x in m) / len(m))
             for i in range(N)]
    print("ruido por anel: %.1f contagens, ou %.4f%%"
          % (sum(ruido) / N, 100 * sum(ruido) / sum(media)))

    # Pares entre colunas: se todos os bits de uma fronteira saem iguais, o que
    # se mede e o gradiente do die, que seria igual em todos os chips.
    ref, _ = referencia(m, pares_colunas())
    for col in range(N // POR_COLUNA - 1):
        v = ref[col * POR_COLUNA:(col + 1) * POR_COLUNA]
        print("  coluna %d contra %d: %2d de %d bits em 1"
              % (col, col + 1, sum(v), len(v)))

    # Proxy de unicidade: cada coluna faz papel de um chip. Nao e medida
    # entre chips, e o ideal seria 50%.
    ref, _ = referencia(m, pares_cadeia())
    por = POR_COLUNA - 1
    cols = [ref[c * por:(c + 1) * por] for c in range(N // POR_COLUNA)]
    ds = [sum(x != y for x, y in zip(cols[i], cols[j])) / por
          for i in range(len(cols)) for j in range(i + 1, len(cols))]
    print("proxy de unicidade entre colunas: %.1f%% (%.1f a %.1f)"
          % (100 * sum(ds) / len(ds), 100 * min(ds), 100 * max(ds)))

    for nome, f in PAREAMENTOS.items():
        pares = f()
        ref, soma = referencia(m, pares)
        n = len(m)
        instaveis = sum(0 < s < n for s in soma)
        print("%-9s %2d bits: BER %.3f%%, instaveis %d (%.1f%%), uniformidade %.1f%%"
              % (nome, len(pares), 100 * ber(m, pares, ref), instaveis,
                 100 * instaveis / len(pares), 100 * sum(ref) / len(ref)))
    return 0


def cmd_deriva(a):
    """BER contra a referencia fria, por nivel de carga."""
    base = carrega(a.base)
    quente = carrega(a.medida)
    print("referencia: %d varreduras, %.1f C"
          % (len(base), sum(x[1] for x in base) / len(base)))
    pares = pares_vizinhos()
    ref, _ = referencia(base, pares)
    cadeia = pares_cadeia()
    ref_c, _ = referencia(base, cadeia)
    for nivel in sorted({x[0] for x in quente}):
        m = [x for x in quente if x[0] == nivel]
        t = sum(x[1] for x in m) / len(m)
        mhz = sum(sum(x[2]) for x in m) / len(m) / N / 1000
        print("carga %d: %.1f C, %.2f MHz, BER vizinhos %.2f%%, cadeia %.2f%%"
              % (nivel, t, mhz, 100 * ber(m, pares, ref),
                 100 * ber(m, cadeia, ref_c)))
    return 0


def cmd_compara(a):
    """Distancia entre as respostas de referencia de duas medidas."""
    m1, m2 = carrega(a.a), carrega(a.b)
    for nome, f in PAREAMENTOS.items():
        pares = f()
        r1, _ = referencia(m1, pares)
        r2, _ = referencia(m2, pares)
        d = sum(x != y for x, y in zip(r1, r2))
        print("%-9s %2d de %2d bits diferentes (%.1f%%)"
              % (nome, d, len(pares), 100 * d / len(pares)))
    return 0


def bch_k(t, m=8):
    """k do BCH binario primitivo de comprimento 2^m - 1 que corrige t erros:
    n menos o tamanho da uniao das classes ciclotomicas de 1, 3 ... 2t-1."""
    n = (1 << m) - 1
    raizes = set()
    for i in range(1, 2 * t, 2):
        x = i
        while x not in raizes:
            raizes.add(x)
            x = 2 * x % n
    return n - len(raizes)


def cmd_corretor(a):
    """Dimensiona BCH(255, k, t) para um BER e conta o que sobra de entropia.
    O helper publica n - k bits sobre a resposta."""
    n = 255
    p = a.ber / 100
    h = h2(a.uniformidade / 100)
    print("BER %.2f%%, uniformidade %.1f%%: %.3f bit de entropia por bit"
          % (a.ber, a.uniformidade, h))
    print("erros esperados em %d bits: %.1f" % (n, n * p))
    for t in range(1, 64):
        k = bch_k(t)
        if k <= 0:
            print("nenhum BCH(255) corrige isso")
            return 1
        falha = binom_cauda(n, p, t)
        if falha <= a.falha:
            sobra = n * h - (n - k)
            print("BCH(255, %d, %d): falha %.1e por reconstrucao" % (k, t, falha))
            print("publicados %d bits de paridade; sobram %.0f bits de chave"
                  % (n - k, max(sobra, 0.0)))
            return 0
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--porta")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("ler")
    s.add_argument("-n", type=int, default=100)
    s.add_argument("--carga", type=int, default=0)
    s.add_argument("-o", "--saida", required=True)
    s.set_defaults(f=cmd_ler)
    s = sub.add_parser("termica")
    s.add_argument("-n", type=int, default=100)
    s.add_argument("--espera", type=float, default=20.0)
    s.add_argument("-o", "--saida", required=True)
    s.set_defaults(f=cmd_termica)
    s = sub.add_parser("analisa")
    s.add_argument("arquivos", nargs="+")
    s.set_defaults(f=cmd_analisa)
    s = sub.add_parser("deriva")
    s.add_argument("base")
    s.add_argument("medida")
    s.set_defaults(f=cmd_deriva)
    s = sub.add_parser("compara")
    s.add_argument("a")
    s.add_argument("b")
    s.set_defaults(f=cmd_compara)
    s = sub.add_parser("corretor")
    s.add_argument("--ber", type=float, required=True, help="em %%")
    s.add_argument("--uniformidade", type=float, default=50.0, help="em %%")
    s.add_argument("--falha", type=float, default=1e-6)
    s.set_defaults(f=cmd_corretor)
    a = ap.parse_args()
    return a.f(a)


if __name__ == "__main__":
    sys.exit(main())
