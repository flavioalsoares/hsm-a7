#!/usr/bin/env python3
"""Regressao na PLACA: todos os testes de bancada, um veredito.

    python3 host/regressao.py --lmk <LMK em hex>
    python3 host/regressao.py --lmk <LMK em hex> --rapido

Roda, pela serial, os comandos de teste que ja existem no hsmtool.py e no
hsmhost.py, e confere o resultado de cada um. A placa roda em tempo real:
o que leva horas na simulacao leva minutos aqui.

QUANDO USAR (decisao do usuario, 2026-11-14; ver CLAUDE.md):

  - mudanca so de firmware: o testbench novo e os que cobrem o codigo
    alterado passam na simulacao, a placa e gravada, e ESTE script e a
    regressao do resto;
  - mudanca de RTL, e fim de fase: a suite completa na simulacao vem
    antes, e este script roda depois.

O QUE ELE NAO COBRE, e so a simulacao cobre:

  - falhas provocadas: fonte de entropia travada, tensao fora da faixa,
    perda de lock, flash corrompida, POST reprovado;
  - sinais internos: tempo constante do multiplicador, apagamento das
    memorias do coprocessador;
  - o que pede os dois botoes: cerimonia, ZEROIZE, e a recusa "antes da
    cerimonia". O script exige a placa ja em OPERATIONAL.

⚠ PRECISA DA LMK, para o Python abrir os key blocks e conferir as contas.
E a LMK de desenvolvimento desta placa. Um host de verdade nunca a tem.

⚠ O `post` zera a BRAM e restaura da flash. O script grava registros no
log de auditoria. Nao apaga chave nenhuma.

⚠ Com a ponte TCP rodando, a serial esta ocupada: pare a ponte antes.
"""

import argparse
import os
import subprocess
import sys
import time

AQUI = os.path.dirname(os.path.abspath(__file__))


def roda(args, prazo):
    """(codigo de saida, saida inteira) de um comando do host."""
    try:
        p = subprocess.run([sys.executable] + args, cwd=AQUI, timeout=prazo,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        return -1, (e.stdout or "") + "\n(passou do prazo de %d s)" % prazo


def main(argv=None):
    ap = argparse.ArgumentParser(description="regressao na placa")
    ap.add_argument("--lmk", required=True,
                    help="LMK em hex (a de desenvolvimento desta placa)")
    ap.add_argument("--rapido", action="store_true",
                    help="menos voltas em cada teste")
    ap.add_argument("--porta", default=None, help="porta serial")
    a = ap.parse_args(argv)

    porta = ["--port", a.porta] if a.porta else []
    porta_h = ["--porta", a.porta] if a.porta else []
    tool = ["hsmtool.py"] + porta
    host = ["hsmhost.py", "--serial"] + porta_h
    n = (lambda cheio, curto: str(curto if a.rapido else cheio))

    # (nome, comando, prazo em s, textos que a saida TEM de conter)
    passos = [
        ("ping", tool + ["ping"], 20, ["PONG"]),
        ("estado OPERATIONAL", tool + ["version"], 20, ["OPERATIONAL"]),
        ("firmware gravado = fw/elf.bin", tool + ["build"], 30, ["CONFERE"]),
        ("POST", tool + ["post"], 60, ["POST: OK"]),
        ("sensores, antes", tool + ["env"], 20,
         ["agora       : nada", "retido      : nada"]),
        ("porta host", host + ["diag"], 20, ["OPERATIONAL"]),
        ("chaves simetricas (K0 K2 K4 K6 C0 C2 M0 M2)",
         host + ["confere", "--lmk", a.lmk, "-n", n(50, 5)], 900,
         ["voltas conferidas"]),
        ("chaves 3DES e KEK 3DES (K0 T2/T3, K2, K4, K6, versao B)",
         host + ["tdes-confere", "--lmk", a.lmk, "-n", n(10, 2)], 600,
         ["voltas conferidas"]),
        ("traducao de PIN (P0), formatos 4 e 0",
         host + ["pin-confere", "--lmk", a.lmk, "-n", n(50, 9)], 900,
         ["voltas conferidas"]),
        ("verificacao de PIN (V0 V2 V4 V6), offset e PVV",
         host + ["pinv-confere", "--lmk", a.lmk, "-n", n(24, 6)], 900,
         ["voltas conferidas"]),
        ("CVV, CVV2 e iCVV (W0 W2)",
         host + ["cvv-confere", "--lmk", a.lmk, "-n", n(16, 4)], 900,
         ["voltas conferidas"]),
        ("DUKPT TDES (P2 I0), anexo A.4 e terminais",
         host + ["dukpt-confere", "--lmk", a.lmk, "-n", n(10, 3)], 900,
         ["anexo A.4", "voltas conferidas"]),
        ("ECDSA, vetores do CAVP (E4, E2)",
         host + ["ecdsa-cavp", "--lmk", a.lmk], 300,
         ["do CAVP conferidos", "E2 2: assinatura com a chave do CAVP confere"]),
        ("ECDSA, pares gerados (E0 E2 E4)",
         host + ["ecdsa-confere", "-n", n(10, 2)], 600,
         ["3 assinaturas conferidas"]),
        ("RSA, vetores do CAVP (R4, R2)",
         host + ["rsa-cavp", "--lmk", a.lmk], 300,
         ["10 vetores do CAVP conferidos",
          "R2 2: assinatura com a chave do CAVP confere"]),
        ("RSA, pares gerados (R0 R2 R4)",
         host + ["rsa-confere", "-n", n(3, 1)], 900,
         ["3 assinaturas conferidas"]),
        ("PKCS#8 nos dois sentidos (R0 R2 R4 E0 E2 E4)",
         host + ["pkcs8-confere", "--lmk", a.lmk, "-n", n(3, 1)], 900,
         ["voltas conferidas"]),
        ("log de auditoria", tool + ["audit"], 300, ["proximo seq"]),
        # O erro grave (dupla execucao discordou) fica retido ate o boot:
        # se algum teste acima o provocou, aparece aqui.
        ("sensores e erro grave, depois", tool + ["env"], 20,
         ["agora       : nada", "retido      : nada"]),
        ("POST, depois", tool + ["post"], 60, ["POST: OK"]),
    ]

    falhas = []
    t_total = time.time()
    for nome, cmd, prazo, exige in passos:
        t0 = time.time()
        rc, saida = roda(cmd, prazo)
        faltou = [e for e in exige if e not in saida]
        ok = (rc == 0) and not faltou
        print("  %-5s %-46s %6.1f s" % ("ok" if ok else "FALHA", nome,
                                         time.time() - t0), flush=True)
        if not ok:
            falhas.append(nome)
            print("        codigo de saida %d" % rc)
            for e in faltou:
                print("        faltou na saida: %r" % e)
            for linha in saida.strip().splitlines()[-12:]:
                print("        | " + linha)
            # Sem comunicacao ou fora de OPERATIONAL, o resto nao diz nada.
            if nome in ("ping", "estado OPERATIONAL"):
                print("        (parei aqui: sem isso o resto nao roda)")
                break

    print()
    print("tempo total: %.0f s" % (time.time() - t_total))
    if falhas:
        print("FALHOU: %d passo(s): %s" % (len(falhas), ", ".join(falhas)))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
