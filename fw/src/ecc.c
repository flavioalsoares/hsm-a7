/* fw/src/ecc.c -- ECDSA sobre a curva P-256. Ver fw/include/ecc.h.
 *
 * FRONTEIRA: dentro. A verificacao so ve dados publicos; a assinatura e a
 * geracao tratam a chave privada d e o numero secreto k em claro, DENTRO
 * da fronteira. Este modulo nao guarda nada entre chamadas, e apaga o
 * rascunho e o coprocessador ao terminar.
 *
 * Divisao de trabalho: toda multiplicacao modular e do coprocessador de
 * Montgomery, com 256 bits (16 limbs). Em C ficam soma, subtracao e
 * comparacao. Os elementos do corpo ficam em C, na representacao de
 * Montgomery, e vao ao core a cada produto.
 *
 * Multiplicacao de ponto: escada de Montgomery em coordenadas (X, Y) com Z
 * comum (Rivain, "Fast and Regular Algorithms for Scalar Multiplication
 * over Elliptic Curves", 2011, algoritmo 9). TEMPO CONSTANTE: todo bit do
 * escalar custa as mesmas operacoes; o bit so escolhe QUAL dos dois pontos
 * ocupa cada papel.
 *
 * PROCEDENCIA. As funcoes de ponto (dobra_jacobiano, aplica_z,
 * dobra_inicial, soma_coz, soma_coz_conj, escada_ponto) seguem, formula a
 * formula, as da biblioteca micro-ecc (github.com/kmackay/micro-ecc),
 * reescritas para este coprocessador. O aviso dela vai abaixo, como a
 * licenca exige. Ver THIRD-PARTY.md.
 *
 *   Copyright (c) 2014, Kenneth MacKay. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "ecc.h"
#include "mont.h"
#include "hsm_cfs.h"
#include "drbg.h"
#include "wipe.h"

#define W      8u                    /* palavras de 32 bits em 256 bits */
#define LIMBS  16u

/* Um numero de 256 bits, a palavra menos significativa primeiro. */
typedef uint32_t fe_t[W];

/* Parametros da curva P-256 (FIPS 186-4, D.1.2.3; SP 800-186, 3.2.1.3).
 * y^2 = x^3 - 3x + b sobre o corpo de p elementos; G tem ordem n. */
static const fe_t c_p = {
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu
};
static const fe_t c_n = {
    0xFC632551u, 0xF3B9CAC2u, 0xA7179E84u, 0xBCE6FAADu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0xFFFFFFFFu
};
static const fe_t c_b = {
    0x27D2604Bu, 0x3BCE3C3Eu, 0xCC53B0F6u, 0x651D06B0u,
    0x769886BCu, 0xB3EBBD55u, 0xAA3A93E7u, 0x5AC635D8u
};
static const fe_t c_gx = {
    0xD898C296u, 0xF4A13945u, 0x2DEB33A0u, 0x77037D81u,
    0x63A440F2u, 0xF8BCE6E5u, 0xE12C4247u, 0x6B17D1F2u
};
static const fe_t c_gy = {
    0x37BF51F5u, 0xCBB64068u, 0x6B315ECEu, 0x2BCE3357u,
    0x7C0F9E16u, 0x8EE7EB4Au, 0xFE1A7F9Bu, 0x4FE342E2u
};

/* Rascunho. Estatico para nao pesar na pilha; apagado no fim de toda
 * funcao publica.
 *
 * FRONTEIRA: dentro. Enquanto uma assinatura roda, contem k, d e os pontos
 * intermediarios de k * G. */
static fe_t g_rx[2], g_ry[2];        /* os dois pontos da escada */
static fe_t g_px, g_py;              /* o ponto de entrada, em Montgomery */
static fe_t g_t4, g_t5, g_t6, g_t7;  /* temporarios das formulas */
static fe_t g_z;
static fe_t g_k0, g_k1;              /* escalar regularizado */
static fe_t g_a, g_b;                /* rascunho de soma e subtracao */
static fe_t g_um;                    /* 1 em Montgomery, modulo p */
static fe_t g_d, g_k, g_e, g_r, g_s; /* contas da assinatura */
static fe_t g_x1, g_y1;
static int  g_erro;                  /* o coprocessador nao respondeu */

/* ---------------------------------------------------------------------
 * Numeros de 256 bits. Nenhuma funcao daqui desvia pelo valor.
 * ------------------------------------------------------------------- */

static void fe_copia(fe_t r, const fe_t a)
{
    uint32_t i;

    for (i = 0u; i < W; i++) {
        r[i] = a[i];
    }
}

static void fe_de_be(fe_t r, const uint8_t *b)
{
    uint32_t i;

    for (i = 0u; i < W; i++) {
        const uint8_t *p = &b[4u * (W - 1u - i)];
        r[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | p[3];
    }
}

static void fe_para_be(uint8_t *b, const fe_t a)
{
    uint32_t i;

    for (i = 0u; i < W; i++) {
        uint8_t *p = &b[4u * (W - 1u - i)];
        p[0] = (uint8_t)(a[i] >> 24);
        p[1] = (uint8_t)(a[i] >> 16);
        p[2] = (uint8_t)(a[i] >> 8);
        p[3] = (uint8_t)a[i];
    }
}

/* r = a + b; devolve o vai-um. */
static uint32_t soma_bruta(fe_t r, const fe_t a, const fe_t b)
{
    uint32_t i, vai = 0u, s, v;

    for (i = 0u; i < W; i++) {
        s   = a[i] + vai;
        v   = (uint32_t)(s < vai);
        s  += b[i];
        v  += (uint32_t)(s < b[i]);
        r[i] = s;
        vai  = v;
    }
    return vai;
}

/* r = a - b; devolve o emprestimo. */
static uint32_t sub_bruta(fe_t r, const fe_t a, const fe_t b)
{
    uint32_t i, emp = 0u, d, e;

    for (i = 0u; i < W; i++) {
        d   = a[i] - emp;
        e   = (uint32_t)(a[i] < emp);
        e  += (uint32_t)(d < b[i]);
        r[i] = d - b[i];
        emp  = e;
    }
    return emp;
}

/* r = mascara ? a : b, com mascara 0 ou 0xFFFFFFFF. */
static void fe_escolhe(fe_t r, const fe_t a, const fe_t b, uint32_t mascara)
{
    uint32_t i;

    for (i = 0u; i < W; i++) {
        r[i] = (a[i] & mascara) | (b[i] & ~mascara);
    }
}

/* r = (a + b) mod m, com a, b < m. Calcula a + b - m sempre e escolhe por
 * mascara. */
static void fe_soma(fe_t r, const fe_t a, const fe_t b, const fe_t m)
{
    uint32_t vai, emp;

    vai = soma_bruta(g_a, a, b);
    emp = sub_bruta(g_b, g_a, m);
    /* Fica com a soma sem subtrair se ela era menor que m: emprestimo sem
     * vai-um. */
    fe_escolhe(r, g_a, g_b, 0u - (emp & (vai ^ 1u)));
}

/* r = (a - b) mod m, com a, b < m. */
static void fe_sub(fe_t r, const fe_t a, const fe_t b, const fe_t m)
{
    uint32_t emp;

    emp = sub_bruta(g_a, a, b);
    (void)soma_bruta(g_b, g_a, m);
    fe_escolhe(r, g_b, g_a, 0u - emp);
}

/* 1 se a == 0. */
static uint32_t fe_zero(const fe_t a)
{
    uint32_t i, acc = 0u;

    for (i = 0u; i < W; i++) {
        acc |= a[i];
    }
    return (uint32_t)(acc == 0u);
}

/* 1 se a == b. */
static uint32_t fe_igual(const fe_t a, const fe_t b)
{
    uint32_t i, acc = 0u;

    for (i = 0u; i < W; i++) {
        acc |= a[i] ^ b[i];
    }
    return (uint32_t)(acc == 0u);
}

/* 1 se a < b. */
static uint32_t fe_menor(const fe_t a, const fe_t b)
{
    return sub_bruta(g_a, a, b);
}

/* ---------------------------------------------------------------------
 * O coprocessador. Operandos em R_BASE e R_ACC, resultado em R_T. R_R2 e
 * R_UM sao do mont_prepara(); R_X e R_Y, da mont_escada().
 * ------------------------------------------------------------------- */

/* Programa o modulo m no core. */
static void modulo(const fe_t m)
{
    uint8_t mb[EC_BYTES], x[EC_BYTES];

    fe_para_be(mb, m);
    if (mont_prepara(mb, EC_BYTES, x) != 0) {
        g_erro = 1;
    }
}

static void produto(fe_t r, unsigned a, unsigned b)
{
    if (hsm_cfs_rsa_mont(R_T, a, b, LIMBS) != 0) {
        g_erro = 1;
    }
    hsm_cfs_rsa_le_w(J_REG(R_T), r, W);
}

/* r = a * b * R^-1: o produto de dois elementos em Montgomery. */
static void f_mul(fe_t r, const fe_t a, const fe_t b)
{
    hsm_cfs_rsa_escreve_w(J_REG(R_BASE), a, W);
    hsm_cfs_rsa_escreve_w(J_REG(R_ACC), b, W);
    produto(r, R_BASE, R_ACC);
}

static void f_quad(fe_t r, const fe_t a)
{
    hsm_cfs_rsa_escreve_w(J_REG(R_BASE), a, W);
    produto(r, R_BASE, R_BASE);
}

/* r = a * R: entra na representacao de Montgomery. */
static void para_mont(fe_t r, const fe_t a)
{
    hsm_cfs_rsa_escreve_w(J_REG(R_BASE), a, W);
    produto(r, R_BASE, R_R2);
}

/* r = a * R^-1: sai da representacao de Montgomery. */
static void de_mont(fe_t r, const fe_t a)
{
    hsm_cfs_rsa_escreve_w(J_REG(R_BASE), a, W);
    produto(r, R_BASE, R_UM);
}

/* R_X = a^(m - 2) * R = (1/a) em Montgomery, com `a` em forma normal e m o
 * modulo programado (primo): pequeno teorema de Fermat. O expoente e
 * publico, mas a base pode ser k: vai pela escada, em tempo constante. */
static void inverso_no_core(const fe_t a, const fe_t m)
{
    uint8_t e[EC_BYTES];

    fe_para_be(e, m);
    e[EC_BYTES - 1u] = (uint8_t)(e[EC_BYTES - 1u] - 2u);   /* m e impar e > 2 */
    hsm_cfs_rsa_escreve_w(J_REG(R_BASE), a, W);
    if (mont_escada(e, EC_BYTES) != 0) {
        g_erro = 1;
    }
}

/* r = 1/a modulo p, as duas pontas em Montgomery. */
static void f_inv(fe_t r, const fe_t a)
{
    de_mont(r, a);
    inverso_no_core(r, c_p);
    hsm_cfs_rsa_le_w(J_REG(R_X), r, W);
}

/* ---------------------------------------------------------------------
 * Pontos. Tudo modulo p, em Montgomery.
 * ------------------------------------------------------------------- */

/* Dobra o ponto jacobiano (X1, Y1, Z1), no lugar. Curva com a = -3. */
static void dobra_jacobiano(fe_t X1, fe_t Y1, fe_t Z1)
{
    uint32_t vai, impar;

    f_quad(g_t4, Y1);                    /* t4 = y1^2 */
    f_mul(g_t5, X1, g_t4);               /* t5 = x1*y1^2 = A */
    f_quad(g_t4, g_t4);                  /* t4 = y1^4 */
    f_mul(Y1, Y1, Z1);                   /* Y1 = y1*z1 = z3 */
    f_quad(Z1, Z1);                      /* Z1 = z1^2 */

    fe_soma(X1, X1, Z1, c_p);            /* X1 = x1 + z1^2 */
    fe_soma(Z1, Z1, Z1, c_p);            /* Z1 = 2*z1^2 */
    fe_sub(Z1, X1, Z1, c_p);             /* Z1 = x1 - z1^2 */
    f_mul(X1, X1, Z1);                   /* X1 = x1^2 - z1^4 */

    fe_soma(Z1, X1, X1, c_p);            /* Z1 = 2*(x1^2 - z1^4) */
    fe_soma(X1, X1, Z1, c_p);            /* X1 = 3*(x1^2 - z1^4) */

    /* X1 = X1 / 2: se impar, soma p (que e impar) antes de deslocar. */
    impar = 0u - (X1[0] & 1u);
    {
        uint32_t i;
        for (i = 0u; i < W; i++) {
            g_b[i] = c_p[i] & impar;
        }
        vai = soma_bruta(X1, X1, g_b);
        for (i = 0u; i < W - 1u; i++) {
            X1[i] = (X1[i] >> 1) | (X1[i + 1u] << 31);
        }
        X1[W - 1u] = (X1[W - 1u] >> 1) | (vai << 31);
    }                                    /* X1 = 3/2*(x1^2 - z1^4) = B */

    f_quad(Z1, X1);                      /* Z1 = B^2 */
    fe_sub(Z1, Z1, g_t5, c_p);           /* Z1 = B^2 - A */
    fe_sub(Z1, Z1, g_t5, c_p);           /* Z1 = B^2 - 2A = x3 */
    fe_sub(g_t5, g_t5, Z1, c_p);         /* t5 = A - x3 */
    f_mul(X1, X1, g_t5);                 /* X1 = B*(A - x3) */
    fe_sub(g_t4, X1, g_t4, c_p);         /* t4 = B*(A - x3) - y1^4 = y3 */

    fe_copia(X1, Z1);
    fe_copia(Z1, Y1);
    fe_copia(Y1, g_t4);
}

/* (X1, Y1) -> (X1 * z^2, Y1 * z^3). */
static void aplica_z(fe_t X1, fe_t Y1, const fe_t z)
{
    f_quad(g_t4, z);                     /* z^2 */
    f_mul(X1, X1, g_t4);
    f_mul(g_t4, g_t4, z);                /* z^3 */
    f_mul(Y1, Y1, g_t4);
}

/* Entra P = (X1, Y1) afim. Sai (X1, Y1) = 2P e (X2, Y2) = P, com o mesmo
 * Z. */
static void dobra_inicial(fe_t X1, fe_t Y1, fe_t X2, fe_t Y2)
{
    fe_copia(X2, X1);
    fe_copia(Y2, Y1);
    fe_copia(g_z, g_um);
    dobra_jacobiano(X1, Y1, g_z);
    aplica_z(X2, Y2, g_z);
}

/* Entram P = (X1, Y1) e Q = (X2, Y2) com o mesmo Z. Saem P' = (X1, Y1),
 * que e P com o Z novo, e P + Q = (X2, Y2). */
static void soma_coz(fe_t X1, fe_t Y1, fe_t X2, fe_t Y2)
{
    fe_sub(g_t5, X2, X1, c_p);           /* t5 = x2 - x1 */
    f_quad(g_t5, g_t5);                  /* t5 = (x2 - x1)^2 = A */
    f_mul(X1, X1, g_t5);                 /* X1 = x1*A = B */
    f_mul(X2, X2, g_t5);                 /* X2 = x2*A = C */
    fe_sub(Y2, Y2, Y1, c_p);             /* Y2 = y2 - y1 */
    f_quad(g_t5, Y2);                    /* t5 = (y2 - y1)^2 = D */

    fe_sub(g_t5, g_t5, X1, c_p);         /* t5 = D - B */
    fe_sub(g_t5, g_t5, X2, c_p);         /* t5 = D - B - C = x3 */
    fe_sub(X2, X2, X1, c_p);             /* X2 = C - B */
    f_mul(Y1, Y1, X2);                   /* Y1 = y1*(C - B) */
    fe_sub(X2, X1, g_t5, c_p);           /* X2 = B - x3 */
    f_mul(Y2, Y2, X2);                   /* Y2 = (y2 - y1)*(B - x3) */
    fe_sub(Y2, Y2, Y1, c_p);             /* Y2 = y3 */

    fe_copia(X2, g_t5);
}

/* Entram P = (X1, Y1) e Q = (X2, Y2) com o mesmo Z. Saem P - Q = (X1, Y1)
 * e P + Q = (X2, Y2), com o mesmo Z novo. */
static void soma_coz_conj(fe_t X1, fe_t Y1, fe_t X2, fe_t Y2)
{
    fe_sub(g_t5, X2, X1, c_p);           /* t5 = x2 - x1 */
    f_quad(g_t5, g_t5);                  /* t5 = (x2 - x1)^2 = A */
    f_mul(X1, X1, g_t5);                 /* X1 = x1*A = B */
    f_mul(X2, X2, g_t5);                 /* X2 = x2*A = C */
    fe_soma(g_t5, Y2, Y1, c_p);          /* t5 = y2 + y1 */
    fe_sub(Y2, Y2, Y1, c_p);             /* Y2 = y2 - y1 */

    fe_sub(g_t6, X2, X1, c_p);           /* t6 = C - B */
    f_mul(Y1, Y1, g_t6);                 /* Y1 = y1*(C - B) = E */
    fe_soma(g_t6, X1, X2, c_p);          /* t6 = B + C */
    f_quad(X2, Y2);                      /* X2 = (y2 - y1)^2 = D */
    fe_sub(X2, X2, g_t6, c_p);           /* X2 = D - (B + C) = x3 */

    fe_sub(g_t7, X1, X2, c_p);           /* t7 = B - x3 */
    f_mul(Y2, Y2, g_t7);                 /* Y2 = (y2 - y1)*(B - x3) */
    fe_sub(Y2, Y2, Y1, c_p);             /* Y2 = y3 */

    f_quad(g_t7, g_t5);                  /* t7 = (y2 + y1)^2 = F */
    fe_sub(g_t7, g_t7, g_t6, c_p);       /* t7 = F - (B + C) = x3' */
    fe_sub(g_t6, g_t7, X1, c_p);         /* t6 = x3' - B */
    f_mul(g_t6, g_t6, g_t5);             /* t6 = (y2 + y1)*(x3' - B) */
    fe_sub(Y1, g_t6, Y1, c_p);           /* Y1 = y3' */

    fe_copia(X1, g_t7);
}

/* A escada: (rx, ry) = k * (g_px, g_py), tudo afim e em Montgomery. O
 * modulo p ja esta programado. O ponto tem ordem n, e k esta em
 * [2, n-3]: fora disso um ponto intermediario seria o infinito, que estas
 * formulas nao representam. Quem cuida das bordas e ponto_mult().
 *
 * O escalar percorrido e k + n ou k + 2n, o que tiver 257 bits: o
 * resultado e o mesmo, e o bit mais alto, sempre 1, e consumido pela
 * dobra inicial. Assim a escada tem 256 passos para todo k. */
static void escada_ponto(fe_t rx, fe_t ry, const fe_t k)
{
    uint32_t vai, bit, nb;
    int      i;

    vai = soma_bruta(g_k0, k, c_n);
    (void)soma_bruta(g_k1, g_k0, c_n);
    fe_escolhe(g_k0, g_k0, g_k1, 0u - vai);

    fe_copia(g_rx[1], g_px);
    fe_copia(g_ry[1], g_py);
    dobra_inicial(g_rx[1], g_ry[1], g_rx[0], g_ry[0]);

    for (i = 255; i > 0; i--) {
        bit = (g_k0[(uint32_t)i >> 5] >> ((uint32_t)i & 31u)) & 1u;
        nb  = bit ^ 1u;
        soma_coz_conj(g_rx[1u - nb], g_ry[1u - nb], g_rx[nb], g_ry[nb]);
        soma_coz(g_rx[nb], g_ry[nb], g_rx[1u - nb], g_ry[1u - nb]);
    }
    nb = (g_k0[0] & 1u) ^ 1u;
    soma_coz_conj(g_rx[1u - nb], g_ry[1u - nb], g_rx[nb], g_ry[nb]);

    /* 1/Z final, recuperado do ponto de entrada. */
    fe_sub(g_z, g_rx[1], g_rx[0], c_p);          /* X1 - X0 */
    f_mul(g_z, g_z, g_ry[1u - nb]);              /* Yb*(X1 - X0) */
    f_mul(g_z, g_z, g_px);                       /* xP*Yb*(X1 - X0) */
    f_inv(g_z, g_z);
    f_mul(g_z, g_z, g_py);                       /* yP / (xP*Yb*(X1 - X0)) */
    f_mul(g_z, g_z, g_rx[1u - nb]);              /* Xb*yP / (...) */

    soma_coz(g_rx[nb], g_ry[nb], g_rx[1u - nb], g_ry[1u - nb]);
    aplica_z(g_rx[0], g_ry[0], g_z);

    fe_copia(rx, g_rx[0]);
    fe_copia(ry, g_ry[0]);
}

/* (rx, ry) = k * (g_px, g_py), para todo k em [1, n-1].
 *
 * A escada nao serve para k = 1, n-1 e n-2. Esses saem de P e de 2P:
 * 1*P = P, (n-1)*P = -P e (n-2)*P = -2P. O desvio revela so que k e um
 * desses tres valores, o que para um k secreto, sorteado, tem chance de
 * 3 em 2^256. Para a verificacao, onde quem monta a assinatura escolhe os
 * escalares, e este desvio que da a resposta certa. */
static void ponto_mult(fe_t rx, fe_t ry, const fe_t k)
{
    fe_t     m;
    uint32_t i, baixo, nega;

    /* m = n - k. Se m e 1 ou 2, k e n-1 ou n-2. */
    (void)sub_bruta(m, c_n, k);
    nega = 0u;
    for (i = 1u, baixo = 0u; i < W; i++) {
        baixo |= m[i];
    }
    if ((baixo == 0u) && ((m[0] == 1u) || (m[0] == 2u))) {
        nega = 1u;                       /* k = n-1 ou n-2: usa n - k */
    } else {
        fe_copia(m, k);
    }
    for (i = 1u, baixo = 0u; i < W; i++) {
        baixo |= m[i];
    }
    if ((baixo == 0u) && (m[0] == 1u)) {
        fe_copia(rx, g_px);
        fe_copia(ry, g_py);
    } else {
        escada_ponto(rx, ry, m);
    }
    if (nega != 0u) {
        for (i = 0u; i < W; i++) {
            m[i] = 0u;
        }
        fe_sub(ry, m, ry, c_p);          /* -P = (x, p - y) */
    }
    wipe(m, sizeof m);
}

/* Programa p e deixa 1 em Montgomery em g_um. */
static void modulo_p(void)
{
    modulo(c_p);
    produto(g_um, R_UM, R_R2);
}

/* Poe o ponto afim (x, y), em forma normal, em (g_px, g_py). */
static void carrega_ponto(const fe_t x, const fe_t y)
{
    para_mont(g_px, x);
    para_mont(g_py, y);
}

/* 1 se (g_px, g_py) satisfaz y^2 = x^3 - 3x + b. */
static uint32_t na_curva(void)
{
    f_quad(g_t4, g_px);                          /* x^2 */
    f_mul(g_t4, g_t4, g_px);                     /* x^3 */
    fe_soma(g_t5, g_px, g_px, c_p);
    fe_soma(g_t5, g_t5, g_px, c_p);              /* 3x */
    fe_sub(g_t4, g_t4, g_t5, c_p);
    para_mont(g_t5, c_b);
    fe_soma(g_t4, g_t4, g_t5, c_p);              /* x^3 - 3x + b */
    f_quad(g_t5, g_py);
    return fe_igual(g_t4, g_t5);
}

/* ---------------------------------------------------------------------
 * ECDSA
 * ------------------------------------------------------------------- */

static void limpa(void)
{
    wipe(g_rx, sizeof g_rx);
    wipe(g_ry, sizeof g_ry);
    wipe(g_px, sizeof g_px);
    wipe(g_py, sizeof g_py);
    wipe(g_t4, sizeof g_t4);
    wipe(g_t5, sizeof g_t5);
    wipe(g_t6, sizeof g_t6);
    wipe(g_t7, sizeof g_t7);
    wipe(g_z, sizeof g_z);
    wipe(g_k0, sizeof g_k0);
    wipe(g_k1, sizeof g_k1);
    wipe(g_a, sizeof g_a);
    wipe(g_b, sizeof g_b);
    wipe(g_d, sizeof g_d);
    wipe(g_k, sizeof g_k);
    wipe(g_e, sizeof g_e);
    wipe(g_r, sizeof g_r);
    wipe(g_s, sizeof g_s);
    wipe(g_x1, sizeof g_x1);
    wipe(g_y1, sizeof g_y1);
    (void)hsm_cfs_wipe();
}

/* 1 se 1 <= a < n. */
static uint32_t escalar_valido(const fe_t a)
{
    return (fe_zero(a) ^ 1u) & fe_menor(a, c_n);
}

/* e = digest como inteiro, reduzido modulo n. O digest tem 256 bits e
 * n > 2^255: uma subtracao basta. */
static void digest_para_e(fe_t e, const uint8_t digest[EC_BYTES])
{
    fe_de_be(e, digest);
    (void)sub_bruta(g_b, e, c_n);
    fe_escolhe(e, e, g_b, 0u - fe_menor(e, c_n));
}

/* Um escalar em [1, n-1], do DRBG: c de 256 bits, recusado se c > n - 2;
 * o escalar e c + 1 (FIPS 186-5, A.2.2 e A.3.2). */
static int sorteia_escalar(fe_t k)
{
    uint8_t  b[EC_BYTES];
    uint32_t i, tentativa, vai;
    int      r = -1;

    for (tentativa = 0u; tentativa < 16u; tentativa++) {
        if (drbg_dispositivo_bytes(b, EC_BYTES) != 0) {
            break;
        }
        fe_de_be(k, b);
        /* k = c + 1; recusa se passou de n - 1, ou se c era 2^256 - 1. */
        vai = 1u;
        for (i = 0u; i < W; i++) {
            k[i] += vai;
            vai   = (uint32_t)(k[i] < vai);
        }
        if ((vai == 0u) && (fe_menor(k, c_n) != 0u)) {
            r = 0;
            break;
        }
    }
    wipe(b, sizeof b);
    return r;
}

/* (r, s) em g_r e g_s, com d em g_d, k em g_k e e em g_e. 0, ou -1 se r
 * ou s deram zero. */
static int assina_interno(void)
{
    /* r = (x de k*G) mod n. */
    modulo_p();
    carrega_ponto(c_gx, c_gy);
    ponto_mult(g_x1, g_y1, g_k);
    de_mont(g_r, g_x1);
    (void)sub_bruta(g_b, g_r, c_n);
    fe_escolhe(g_r, g_r, g_b, 0u - fe_menor(g_r, c_n));

    /* s = k^-1 * (e + r*d) mod n. */
    modulo(c_n);
    para_mont(g_s, g_r);                             /* r*R */
    hsm_cfs_rsa_escreve_w(J_REG(R_BASE), g_s, W);
    hsm_cfs_rsa_escreve_w(J_REG(R_ACC), g_d, W);
    produto(g_s, R_BASE, R_ACC);                     /* r*d */
    fe_soma(g_s, g_s, g_e, c_n);                     /* e + r*d */
    inverso_no_core(g_k, c_n);                       /* R_X = (1/k)*R */
    hsm_cfs_rsa_escreve_w(J_REG(R_BASE), g_s, W);
    produto(g_s, R_BASE, R_X);

    if ((g_erro != 0) || (fe_zero(g_r) != 0u) || (fe_zero(g_s) != 0u)) {
        return -1;
    }
    return 0;
}

int ecdsa_assina_k(const uint8_t d[EC_BYTES], const uint8_t digest[EC_BYTES],
                   const uint8_t k[EC_BYTES], uint8_t sig[EC_SIG])
{
    int r = -1;

    g_erro = 0;
    fe_de_be(g_d, d);
    fe_de_be(g_k, k);
    digest_para_e(g_e, digest);
    if ((escalar_valido(g_d) != 0u) && (escalar_valido(g_k) != 0u) &&
        (assina_interno() == 0)) {
        fe_para_be(&sig[0], g_r);
        fe_para_be(&sig[EC_BYTES], g_s);
        r = 0;
    }
    limpa();
    return r;
}

int ecdsa_verifica(const uint8_t q[EC_PUB], const uint8_t digest[EC_BYTES],
                   const uint8_t sig[EC_SIG])
{
    /* So dados publicos: os temporarios podem ficar na pilha, e os desvios
     * pelo valor nao vazam nada. */
    fe_t     qx, qy, u1, u2, x2, y2;
    uint32_t tem_p1;
    int      r = -1;

    g_erro = 0;
    fe_de_be(qx, &q[0]);
    fe_de_be(qy, &q[EC_BYTES]);
    fe_de_be(g_r, &sig[0]);
    fe_de_be(g_s, &sig[EC_BYTES]);
    digest_para_e(g_e, digest);

    /* A chave publica: coordenadas no corpo e ponto na curva. A curva tem
     * cofator 1, entao todo ponto dela tem ordem n. */
    if ((fe_menor(qx, c_p) == 0u) || (fe_menor(qy, c_p) == 0u)) {
        goto fim;
    }
    modulo_p();
    carrega_ponto(qx, qy);
    if ((na_curva() == 0u) || (g_erro != 0)) {
        goto fim;
    }

    /* r e s em [1, n-1]; senao a assinatura e invalida, nao um erro. */
    if ((escalar_valido(g_r) == 0u) || (escalar_valido(g_s) == 0u)) {
        r = 0;
        goto fim;
    }

    /* u1 = e/s, u2 = r/s, modulo n. */
    modulo(c_n);
    inverso_no_core(g_s, c_n);                       /* R_X = (1/s)*R */
    hsm_cfs_rsa_escreve_w(J_REG(R_BASE), g_e, W);
    produto(u1, R_BASE, R_X);
    hsm_cfs_rsa_escreve_w(J_REG(R_BASE), g_r, W);
    produto(u2, R_BASE, R_X);

    /* P2 = u2*Q. u2 nao e zero, porque r e 1/s nao sao. */
    modulo_p();
    carrega_ponto(qx, qy);
    ponto_mult(x2, y2, u2);

    /* P1 = u1*G. u1 e zero quando e e multiplo de n: ai a soma e P2. */
    tem_p1 = fe_zero(u1) ^ 1u;
    if (tem_p1 != 0u) {
        carrega_ponto(c_gx, c_gy);
        ponto_mult(g_x1, g_y1, u1);

        /* x de P1 + P2, pela formula afim. Os casos de excecao sao raros
         * com assinaturas honestas, mas quem escolhe a entrada os produz. */
        if (fe_igual(g_x1, x2) != 0u) {
            if (fe_igual(g_y1, y2) == 0u) {
                r = 0;                               /* P1 = -P2: infinito */
                goto fim;
            }
            /* P1 = P2: inclinacao da tangente, 3*(x^2 - 1) / (2*y). */
            f_quad(g_t4, g_x1);
            fe_sub(g_t4, g_t4, g_um, c_p);
            fe_soma(g_t5, g_t4, g_t4, c_p);
            fe_soma(g_t4, g_t5, g_t4, c_p);
            fe_soma(g_t5, g_y1, g_y1, c_p);
        } else {
            fe_sub(g_t4, y2, g_y1, c_p);             /* y2 - y1 */
            fe_sub(g_t5, x2, g_x1, c_p);             /* x2 - x1 */
        }
        f_inv(g_t5, g_t5);
        f_mul(g_t4, g_t4, g_t5);                     /* inclinacao */
        f_quad(g_t4, g_t4);
        fe_sub(g_t4, g_t4, g_x1, c_p);
        fe_sub(x2, g_t4, x2, c_p);                   /* x3 */
    }

    /* v = x3 mod n; a assinatura vale se v == r. */
    de_mont(x2, x2);
    (void)sub_bruta(g_b, x2, c_n);
    fe_escolhe(x2, x2, g_b, 0u - fe_menor(x2, c_n));
    if (g_erro == 0) {
        r = (int)fe_igual(x2, g_r);
    }
fim:
    limpa();
    return r;
}

int ec_publica(const uint8_t d[EC_BYTES], uint8_t q[EC_PUB])
{
    int r = -1;

    g_erro = 0;
    fe_de_be(g_d, d);
    if (escalar_valido(g_d) != 0u) {
        modulo_p();
        carrega_ponto(c_gx, c_gy);
        ponto_mult(g_x1, g_y1, g_d);
        de_mont(g_x1, g_x1);
        de_mont(g_y1, g_y1);
        if (g_erro == 0) {
            fe_para_be(&q[0], g_x1);
            fe_para_be(&q[EC_BYTES], g_y1);
            r = 0;
        }
    }
    limpa();
    return r;
}

int ecdsa_assina(const uint8_t chave[EC_CHAVE_PRIV],
                 const uint8_t digest[EC_BYTES], uint8_t sig[EC_SIG])
{
    uint8_t  rs[EC_SIG];
    uint32_t i, tentativa;
    int      r = -1;

    g_erro = 0;
    fe_de_be(g_d, &chave[0]);
    if (escalar_valido(g_d) == 0u) {
        goto fim;
    }
    /* r ou s zero pede outro k. A chance e desprezivel; o limite existe
     * para o laco terminar. */
    for (tentativa = 0u; tentativa < 4u; tentativa++) {
        fe_de_be(g_d, &chave[0]);
        digest_para_e(g_e, digest);
        if (sorteia_escalar(g_k) != 0) {
            goto fim;
        }
        if (assina_interno() == 0) {
            break;
        }
        if (g_erro != 0) {
            goto fim;
        }
    }
    if (tentativa == 4u) {
        goto fim;
    }
    fe_para_be(&rs[0], g_r);
    fe_para_be(&rs[EC_BYTES], g_s);

    /* Verificar ANTES de emitir, com a chave publica e por outro caminho:
     * e a segunda conta do que vai ao host. Uma falha induzida em k*G ou
     * em s daria uma assinatura errada, e certas assinaturas erradas
     * entregam d. Ela nao sai. */
    if (ecdsa_verifica(&chave[EC_BYTES], digest, rs) != 1) {
        r = -2;
        goto fim;
    }
    for (i = 0u; i < EC_SIG; i++) {
        sig[i] = rs[i];
    }
    r = 0;
fim:
    wipe(rs, sizeof rs);
    limpa();
    return r;
}

int ecdsa_gera(uint8_t chave[EC_CHAVE_PRIV])
{
    int r = -1;

    g_erro = 0;
    if (sorteia_escalar(g_d) == 0) {
        fe_para_be(&chave[0], g_d);
        r = ec_publica(&chave[0], &chave[EC_BYTES]);
    }
    limpa();
    if (r != 0) {
        wipe(chave, EC_CHAVE_PRIV);
    }
    return r;
}
