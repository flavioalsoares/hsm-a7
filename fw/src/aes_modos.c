/* fw/src/aes_modos.c -- modos de operacao do AES
 *
 * FRONTEIRA: dentro, e com uma propriedade que vale notar: este arquivo
 * NAO TEM parametro de chave em funcao nenhuma. Ver aes_modos.h.
 *
 * O hardware faz ECB de um bloco; encadeamento e daqui (hsm_cfs.h).
 */
#include "aes_modos.h"
#include "hsm_cfs.h"
#include "wipe.h"

#define BLK  AES_BLOCO

static void bloco_xor(uint8_t dst[BLK], const uint8_t src[BLK])
{
    uint32_t i;
    for (i = 0u; i < BLK; i++) {
        dst[i] ^= src[i];
    }
}

/* ---------------------------------------------------------------------
 * AES-CBC sobre o coprocessador
 *
 * A chave JA ESTA carregada -- ver aes_modos.h para por que nao ha
 * parametro de chave aqui. `n` e multiplo de BLK e o chamador garante
 * isso; um CBC que "trata" tamanho invalido em silencio processa lixo.
 * ------------------------------------------------------------------- */
int aes_cbc(const uint8_t iv[BLK],
            const uint8_t *entrada, uint8_t *saida, uint32_t n, int cifrar)
{
    uint8_t  encadeia[BLK], anterior[BLK], tmp[BLK];
    uint32_t i, j;
    int      r = 0;

    for (i = 0u; i < BLK; i++) {
        encadeia[i] = iv[i];
    }

    for (i = 0u; i < n; i += BLK) {
        if (cifrar) {
            for (j = 0u; j < BLK; j++) {
                tmp[j] = entrada[i + j];
            }
            bloco_xor(tmp, encadeia);
            if (hsm_cfs_aes_block(tmp, &saida[i], 1) != 0) {
                r = -1;
                goto fim;
            }
            for (j = 0u; j < BLK; j++) {
                encadeia[j] = saida[i + j];
            }
        } else {
            /* O criptograma deste bloco e o encadeamento do proximo, e
             * precisa ser guardado ANTES de decifrar: entrada e saida
             * podem ser o mesmo buffer. */
            for (j = 0u; j < BLK; j++) {
                anterior[j] = entrada[i + j];
            }
            if (hsm_cfs_aes_block(&entrada[i], tmp, 0) != 0) {
                r = -1;
                goto fim;
            }
            bloco_xor(tmp, encadeia);
            for (j = 0u; j < BLK; j++) {
                saida[i + j]  = tmp[j];
                encadeia[j]   = anterior[j];
            }
        }
    }

fim:
    wipe(encadeia, sizeof encadeia);
    wipe(anterior, sizeof anterior);
    wipe(tmp, sizeof tmp);
    return r;
}

