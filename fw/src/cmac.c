/* fw/src/cmac.c -- AES-CMAC, NIST SP 800-38B
 *
 * FRONTEIRA: dentro. Ver o cabeçalho de cmac.h.
 *
 * O AES vem do coprocessador, como em todo o resto do firmware. Não há AES
 * em software aqui.
 */
#include "cmac.h"
#include "hsm_cfs.h"
#include "wipe.h"

#define BLK  16u

/* Deslocamento de um bit à esquerda sobre um bloco de 128 bits,
 * big-endian, com redução pelo polinômio do campo.
 *
 * O 0x87 não é arbitrário: é a representação do polinômio irredutível
 * x^128 + x^7 + x^2 + x + 1, que define GF(2^128) para blocos de 128 bits.
 * Multiplicar por x é deslocar; se "transbordar" o grau 128, subtrai-se o
 * polinômio — e em GF(2) subtrair é XOR. */
static void dobra(const uint8_t entrada[BLK], uint8_t saida[BLK])
{
    uint32_t i;
    uint8_t  carry = (uint8_t)(entrada[0] >> 7);

    for (i = 0u; i < BLK - 1u; i++) {
        saida[i] = (uint8_t)((entrada[i] << 1) | (entrada[i + 1u] >> 7));
    }
    saida[BLK - 1u] = (uint8_t)(entrada[BLK - 1u] << 1);

    /* Condicional em VALOR, não em ramo: o XOR acontece sempre, com uma
     * máscara que é 0x87 ou 0x00. Aqui a entrada não é secreta, mas a
     * mesma rotina será usada onde é, e ter duas versões é como se escolhe
     * a errada. */
    saida[BLK - 1u] ^= (uint8_t)(0x87u * carry);
}

int cmac_aes256(const uint8_t chave[CMAC_KEY_LEN],
                const uint8_t *msg, uint32_t msg_n,
                uint8_t tag[CMAC_TAG_LEN])
{
    uint8_t  l[BLK], k1[BLK], k2[BLK];
    uint8_t  x[BLK], bloco[BLK];
    uint32_t completos, resto, i, j;
    int      r = 0;

    for (i = 0u; i < BLK; i++) {
        l[i] = 0x00u;
        x[i] = 0x00u;
    }

    if (hsm_cfs_aes_key(chave) != 0) {
        r = -1;
        goto fim;
    }

    /* Subkeys: L = AES(K, 0^128); K1 = L·x; K2 = K1·x */
    if (hsm_cfs_aes_block(l, l, 1) != 0) {
        r = -1;
        goto fim;
    }
    dobra(l, k1);
    dobra(k1, k2);

    /* Quantos blocos INTEIROS ficam antes do último.
     *
     * A mensagem vazia é um caso legítimo com MAC definido: ela cai no
     * ramo do padding, com zero blocos completos antes. Tratar o vazio
     * como erro é o bug clássico aqui, e os vetores do CAVP o incluem
     * justamente por isso. */
    if ((msg_n != 0u) && ((msg_n % BLK) == 0u)) {
        completos = (msg_n / BLK) - 1u;
        resto     = BLK;                 /* último bloco está cheio */
    } else {
        completos = msg_n / BLK;
        resto     = msg_n % BLK;         /* pode ser 0: mensagem vazia */
    }

    for (i = 0u; i < completos; i++) {
        for (j = 0u; j < BLK; j++) {
            bloco[j] = x[j] ^ msg[i * BLK + j];
        }
        if (hsm_cfs_aes_block(bloco, x, 1) != 0) {
            r = -1;
            goto fim;
        }
    }

    /* Último bloco: alinhado usa K1, com padding usa K2. É esta escolha
     * que fecha o ataque de extensão do CBC-MAC. */
    if (resto == BLK) {
        for (j = 0u; j < BLK; j++) {
            bloco[j] = msg[completos * BLK + j] ^ k1[j];
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
    if (hsm_cfs_aes_block(bloco, tag, 1) != 0) {
        r = -1;
        goto fim;
    }

fim:
    /* k1 e k2 são derivados da chave: quem os tem forja MAC. */
    wipe(l, sizeof l);
    wipe(k1, sizeof k1);
    wipe(k2, sizeof k2);
    wipe(x, sizeof x);
    wipe(bloco, sizeof bloco);
    (void)hsm_cfs_wipe();

    if (r != 0) {
        wipe(tag, CMAC_TAG_LEN);
    }
    return r;
}

int cmac_aes256_verifica(const uint8_t chave[CMAC_KEY_LEN],
                         const uint8_t *msg, uint32_t msg_n,
                         const uint8_t tag[CMAC_TAG_LEN])
{
    uint8_t  calculado[CMAC_TAG_LEN];
    uint8_t  d = 0u;
    uint32_t i;
    int      ok;

    if (cmac_aes256(chave, msg, msg_n, calculado) != 0) {
        wipe(calculado, sizeof calculado);
        return 0;
    }

    /* Tempo constante: acumula as diferenças e decide no fim. Sair no
     * primeiro byte diferente conta, pelo relógio, quantos bateram. */
    for (i = 0u; i < CMAC_TAG_LEN; i++) {
        d |= (uint8_t)(calculado[i] ^ tag[i]);
    }
    ok = (d == 0u) ? 1 : 0;

    wipe(calculado, sizeof calculado);
    return ok;
}
