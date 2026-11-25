/* fw/src/mac_tdes.c -- retail MAC (ISO/IEC 9797-1, algoritmo 3), etapa 8.9a
 *
 * Ver mac_tdes.h. FRONTEIRA: dentro.
 */
#include "mac_tdes.h"
#include "des.h"
#include "wipe.h"

/* O bloco `j` da mensagem preenchida. Os blocos inteiros vem da mensagem; o
 * ultimo, se existir, leva o resto e o preenchimento. */
static void bloco_j(const uint8_t *msg, uint32_t n, uint8_t metodo,
                    uint32_t j, uint8_t b[DES_BLOCO])
{
    uint32_t k, base = j * DES_BLOCO;

    for (k = 0u; k < DES_BLOCO; k++) {
        if (base + k < n) {
            b[k] = msg[base + k];
        } else if ((base + k == n) && (metodo == 2u)) {
            b[k] = 0x80u;
        } else {
            b[k] = 0u;
        }
    }
}

int retail_mac(const uint8_t chave[16], uint8_t metodo,
               const uint8_t *msg, uint32_t n, uint8_t mac[RETAIL_MAC_LEN])
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    uint8_t     kk[TDES_CHAVE_2], h[DES_BLOCO], b[DES_BLOCO];
    uint32_t    q, j, k;
    int         r = -1;

    if ((chave == 0) || (msg == 0) || (mac == 0) || (n == 0u) ||
        ((metodo != 1u) && (metodo != 2u))) {
        return -1;
    }

    /* Quantos blocos depois de preencher. O 2 sempre acrescenta o 80, e por
     * isso um bloco a mais quando a mensagem ja e multipla de 8. */
    q = n / DES_BLOCO;
    if (((n % DES_BLOCO) != 0u) || (metodo == 2u)) {
        q++;
    }

    /* DES de K: o motor de 3DES com a chave K.K (o meio desfaz o primeiro
     * passo), porque ha um contexto so no firmware. */
    for (k = 0u; k < DES_CHAVE; k++) {
        kk[k]             = chave[k];
        kk[DES_CHAVE + k] = chave[k];
        h[k]              = 0u;
    }
    if (tdes_prepara(ctx, kk, TDES_CHAVE_2) == 0) {
        for (j = 0u; j + 1u < q; j++) {
            bloco_j(msg, n, metodo, j, b);
            for (k = 0u; k < DES_BLOCO; k++) {
                h[k] ^= b[k];
            }
            tdes_bloco(ctx, h, h, 1);
        }
        bloco_j(msg, n, metodo, q - 1u, b);
        for (k = 0u; k < DES_BLOCO; k++) {
            h[k] ^= b[k];
        }
        if (tdes_prepara(ctx, chave, TDES_CHAVE_2) == 0) {
            tdes_bloco(ctx, h, mac, 1);
            r = 0;
        }
    }
    tdes_apaga(ctx);
    wipe(kk, sizeof kk);
    wipe(h, sizeof h);
    wipe(b, sizeof b);
    return r;
}
