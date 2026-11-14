/* fw/src/mont.c -- o coprocessador de Montgomery visto do firmware.
 * Ver fw/include/mont.h.
 *
 * FRONTEIRA: dentro. O modulo e o expoente podem ser segredos (os primos e
 * os expoentes do CRT, o nonce do ECDSA).
 */
#include "mont.h"
#include "bn.h"
#include "hsm_cfs.h"

/* -n^-1 mod 2^16, por Newton: cada passo dobra os bits certos. */
static uint16_t n0_linha(uint16_t n0)
{
    uint32_t x = 1u;
    unsigned i;

    for (i = 0u; i < 4u; i++) {
        x = (x * (2u - (uint32_t)n0 * x)) & 0xFFFFu;
    }
    return (uint16_t)(0u - x);
}

/* Programa o modulo m (n bytes, bit alto ligado, impar) e deixa R^2 mod m
 * em R_R2 e 1 em R_UM. R = 2^(8n). `x` e rascunho de n bytes.
 *
 * R^2 sai de 2R mod m com k quadrados, onde 2^k = 8n: cada produto de
 * Montgomery dobra o expoente de 2. */
int mont_prepara(const uint8_t *m, uint32_t n, uint8_t *x)
{
    uint32_t i, k, limbs = n / 2u, vai;

    hsm_cfs_rsa_n0p(n0_linha((uint16_t)(((uint16_t)m[n - 2u] << 8) | m[n - 1u])));
    hsm_cfs_rsa_escreve(J_MOD, m, limbs);

    /* 2R mod m. Como m tem o bit alto ligado, R - m < m. */
    for (i = 0u; i < n; i++) {
        x[i] = 0u;
    }
    (void)bn_subtrai(x, m, n);                  /* 0 - m = R - m */
    vai = 0u;
    for (i = n; i > 0u; i--) {
        uint32_t d = ((uint32_t)x[i - 1u] << 1) | vai;
        x[i - 1u] = (uint8_t)d;
        vai = d >> 8;
    }
    /* Dado publico ou nao, o desvio aqui depende so de m, que no caso
     * secreto (p ou q) e o mesmo a cada assinatura. */
    if ((vai != 0u) || !bn_menor(x, m, n)) {
        (void)bn_subtrai(x, m, n);
    }
    hsm_cfs_rsa_escreve(J_REG(R_R2), x, limbs);

    for (k = 0u; (1u << k) < 8u * n; k++) {
        if (hsm_cfs_rsa_mont(R_R2, R_R2, R_R2, limbs) != 0) {
            return -1;
        }
    }

    for (i = 0u; i < n; i++) {
        x[i] = 0u;
    }
    x[n - 1u] = 1u;
    hsm_cfs_rsa_escreve(J_REG(R_UM), x, limbs);
    return 0;
}

/* Escada de Montgomery: R_X = base^d, tudo na representacao de
 * Montgomery. A base esta em R_BASE; R_UM ja tem 1 e R_R2, R^2.
 *
 * TEMPO CONSTANTE. Todo bit, 0 ou 1, custa exatamente um produto e um
 * quadrado, e d e percorrido inteiro, zeros a esquerda inclusive. O bit
 * so escolhe QUAIS registradores entram no comando, por mascara -- e o
 * core leva o mesmo numero de ciclos qualquer que seja o registrador. */
int mont_escada(const uint8_t *d, uint32_t n)
{
    uint32_t limbs = n / 2u, i, bit;
    unsigned produto, quadrado;
    int      b;

    /* R_X = 1 em Montgomery (= R mod m), R_Y = base em Montgomery. */
    if ((hsm_cfs_rsa_mont(R_X, R_UM, R_R2, limbs) != 0) ||
        (hsm_cfs_rsa_mont(R_Y, R_BASE, R_R2, limbs) != 0)) {
        return -1;
    }

    for (i = 0u; i < n; i++) {
        for (b = 7; b >= 0; b--) {
            bit = ((uint32_t)d[i] >> b) & 1u;
            /* bit 0: Y = X*Y, X = X^2.   bit 1: X = X*Y, Y = Y^2.
             * O quadrado le o valor ANTIGO do seu registrador, que o
             * produto nao tocou. */
            produto  = (unsigned)((R_X & (0u - bit)) | (R_Y & (bit - 1u)));
            quadrado = (unsigned)((R_Y & (0u - bit)) | (R_X & (bit - 1u)));
            if ((hsm_cfs_rsa_mont(produto, R_X, R_Y, limbs) != 0) ||
                (hsm_cfs_rsa_mont(quadrado, quadrado, quadrado, limbs) != 0)) {
                return -1;
            }
        }
    }
    return 0;
}
