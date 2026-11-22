/* fw/src/cmac_tdes.c -- CMAC sobre 3DES, NIST SP 800-38B (fase 8, etapa 8.7)
 *
 * FRONTEIRA: dentro. Ver cmac_tdes.h. A estrutura e a de cmac.c, linha a
 * linha, com o bloco de 8 bytes.
 */
#include "cmac_tdes.h"
#include "des.h"
#include "wipe.h"

#define BLK  8u

/* Dobra no corpo de 2^64: um bit a esquerda e, se saiu um 1, XOR com 0x1B
 * (x^64 + x^4 + x^3 + x + 1). Por mascara, como em cmac.c. */
static void dobra(const uint8_t entrada[BLK], uint8_t saida[BLK])
{
    uint32_t i;
    uint8_t  carry = (uint8_t)(entrada[0] >> 7);

    for (i = 0u; i < BLK - 1u; i++) {
        saida[i] = (uint8_t)((entrada[i] << 1) | (entrada[i + 1u] >> 7));
    }
    saida[BLK - 1u] = (uint8_t)(entrada[BLK - 1u] << 1);
    saida[BLK - 1u] ^= (uint8_t)(0x1Bu * carry);
}

int cmac_tdes(const uint8_t *chave, uint32_t chave_n,
              const uint8_t *msg, uint32_t msg_n,
              uint8_t tag[CMAC_TDES_TAG])
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    uint8_t     l[BLK], k1[BLK], k2[BLK], x[BLK], bloco[BLK];
    uint32_t    completos, resto, i, j;
    int         r = -1;

    for (i = 0u; i < BLK; i++) {
        l[i] = 0u;
        x[i] = 0u;
    }
    if ((chave == 0) || (tag == 0) || ((msg == 0) && (msg_n != 0u)) ||
        (tdes_prepara(ctx, chave, chave_n) != 0)) {
        goto fim;
    }

    /* L = 3DES(K, 0^64); K1 = L.x; K2 = K1.x */
    tdes_bloco(ctx, l, l, 1);
    dobra(l, k1);
    dobra(k1, k2);

    /* A mensagem vazia cai no ramo do enchimento, com zero blocos antes. */
    if ((msg_n != 0u) && ((msg_n % BLK) == 0u)) {
        completos = (msg_n / BLK) - 1u;
        resto     = BLK;
    } else {
        completos = msg_n / BLK;
        resto     = msg_n % BLK;
    }

    for (i = 0u; i < completos; i++) {
        for (j = 0u; j < BLK; j++) {
            bloco[j] = (uint8_t)(x[j] ^ msg[i * BLK + j]);
        }
        tdes_bloco(ctx, bloco, x, 1);
    }

    /* Ultimo bloco: cheio usa K1; com enchimento 10..0 usa K2. */
    if (resto == BLK) {
        for (j = 0u; j < BLK; j++) {
            bloco[j] = (uint8_t)(msg[completos * BLK + j] ^ k1[j]);
        }
    } else {
        for (j = 0u; j < resto; j++) {
            bloco[j] = msg[completos * BLK + j];
        }
        bloco[resto] = 0x80u;
        for (j = resto + 1u; j < BLK; j++) {
            bloco[j] = 0x00u;
        }
        for (j = 0u; j < BLK; j++) {
            bloco[j] ^= k2[j];
        }
    }
    for (j = 0u; j < BLK; j++) {
        bloco[j] ^= x[j];
    }
    tdes_bloco(ctx, bloco, tag, 1);
    r = 0;

fim:
    /* k1 e k2 vem da chave: quem os tem forja MAC. */
    tdes_apaga(ctx);
    wipe(l, sizeof l);
    wipe(k1, sizeof k1);
    wipe(k2, sizeof k2);
    wipe(x, sizeof x);
    wipe(bloco, sizeof bloco);
    if ((r != 0) && (tag != 0)) {
        wipe(tag, CMAC_TDES_TAG);
    }
    return r;
}

int cmac_tdes_verifica(const uint8_t *chave, uint32_t chave_n,
                       const uint8_t *msg, uint32_t msg_n,
                       const uint8_t tag[CMAC_TDES_TAG])
{
    uint8_t  calc[CMAC_TDES_TAG];
    uint8_t  d = 0u;
    uint32_t i;
    int      r = 0;

    if ((tag != 0) && (cmac_tdes(chave, chave_n, msg, msg_n, calc) == 0)) {
        for (i = 0u; i < CMAC_TDES_TAG; i++) {
            d |= (uint8_t)(calc[i] ^ tag[i]);
        }
        /* d == 0 -> 1, sem desvio sobre o valor. */
        r = (int)(1u & (((uint32_t)d - 1u) >> 8));
    }
    wipe(calc, sizeof calc);
    return r;
}
