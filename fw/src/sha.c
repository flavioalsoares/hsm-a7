/* fw/src/sha.c -- SHA-256 de mensagem e HMAC-SHA-256 sobre o CFS
 *
 * FRONTEIRA: dentro. Ver o cabecalho de sha.h.
 */
#include "sha.h"
#include "hsm_cfs.h"
#include "wipe.h"

/* Um bloco de 512 bits para o coprocessador. */
static int comprime(hsm_sha_ctx_t *c, const uint8_t *bloco)
{
    if (hsm_cfs_sha_block(bloco, c->primeiro) != 0) {
        c->erro = 1;
        return -1;
    }
    c->primeiro = 0;
    return 0;
}

void hsm_sha_init(hsm_sha_ctx_t *c)
{
    c->buflen   = 0u;
    c->total    = 0u;
    c->primeiro = 1;
    c->erro     = 0;
}

void hsm_sha_update(hsm_sha_ctx_t *c, const uint8_t *dados, uint32_t n)
{
    uint32_t i = 0u;

    if (c->erro) {
        return;
    }
    c->total += (uint64_t)n;

    /* completa o bloco parcial que sobrou da chamada anterior */
    if (c->buflen != 0u) {
        while ((i < n) && (c->buflen < HSM_SHA256_BLOCK)) {
            c->buf[c->buflen++] = dados[i++];
        }
        if (c->buflen == HSM_SHA256_BLOCK) {
            if (comprime(c, c->buf) != 0) {
                return;
            }
            c->buflen = 0u;
        }
    }

    /* blocos inteiros, direto da origem */
    while ((n - i) >= HSM_SHA256_BLOCK) {
        if (comprime(c, &dados[i]) != 0) {
            return;
        }
        i += HSM_SHA256_BLOCK;
    }

    /* resto fica para a proxima chamada ou para o padding */
    while (i < n) {
        c->buf[c->buflen++] = dados[i++];
    }
}

int hsm_sha_final(hsm_sha_ctx_t *c, uint8_t out[HSM_SHA256_LEN])
{
    uint64_t bits;
    uint32_t i;

    if (c->erro) {
        wipe(out, HSM_SHA256_LEN);
        return -1;
    }

    /* Padding do FIPS 180-4: 0x80, zeros, e o comprimento em BITS num
     * inteiro de 64 bits big-endian. Bits, nao bytes -- o erro passa
     * despercebido em mensagens de tamanho redondo. */
    bits = c->total * 8u;

    c->buf[c->buflen++] = 0x80u;

    /* Se nao couberem os 8 bytes de comprimento, fecha este bloco com
     * zeros e o comprimento vai num bloco extra, so de padding. */
    if (c->buflen > (HSM_SHA256_BLOCK - 8u)) {
        while (c->buflen < HSM_SHA256_BLOCK) {
            c->buf[c->buflen++] = 0x00u;
        }
        if (comprime(c, c->buf) != 0) {
            wipe(out, HSM_SHA256_LEN);
            return -1;
        }
        c->buflen = 0u;
    }

    while (c->buflen < (HSM_SHA256_BLOCK - 8u)) {
        c->buf[c->buflen++] = 0x00u;
    }
    for (i = 0u; i < 8u; i++) {
        c->buf[HSM_SHA256_BLOCK - 1u - i] = (uint8_t)(bits >> (8u * i));
    }

    if (comprime(c, c->buf) != 0) {
        wipe(out, HSM_SHA256_LEN);
        return -1;
    }

    if (hsm_cfs_sha_digest(out) != 0) {
        wipe(out, HSM_SHA256_LEN);
        return -1;
    }
    return 0;
}

int hsm_sha256(const uint8_t *msg, uint32_t n, uint8_t out[HSM_SHA256_LEN])
{
    hsm_sha_ctx_t c;

    hsm_sha_init(&c);
    hsm_sha_update(&c, msg, n);
    return hsm_sha_final(&c, out);
}

/* HMAC-SHA-256 -- RFC 2104
 *
 *   HMAC(K, m) = H( (K' ^ opad) || H( (K' ^ ipad) || m ) )
 *
 * K' e a chave ajustada para o tamanho do BLOCO (64 bytes): chave maior
 * que o bloco e substituida pelo seu proprio hash, chave menor e
 * preenchida com zeros a direita.
 *
 * O caso "chave maior que o bloco" e o que mais falha em implementacao
 * caseira, e o RFC 4231 tem um vetor so para ele. Nao e detalhe: uma
 * implementacao que ignora esse caso produz HMAC diferente do resto do
 * mundo para chaves longas, e o sintoma so aparece em integracao.
 *
 * FRONTEIRA: dentro. k_pad guarda a chave XOR pad -- material derivado de
 * chave. Zeroizado com barreira antes de sair, nao com memset.
 */
int hsm_hmac_sha256(const uint8_t *chave, uint32_t chave_n,
                    const uint8_t *msg,   uint32_t msg_n,
                    uint8_t out[HSM_SHA256_LEN])
{
    uint8_t       k_pad[HSM_SHA256_BLOCK];
    uint8_t       k_ajustada[HSM_SHA256_BLOCK];
    uint8_t       interno[HSM_SHA256_LEN];
    hsm_sha_ctx_t c;
    uint32_t      i;
    int           r = 0;

    for (i = 0u; i < HSM_SHA256_BLOCK; i++) {
        k_ajustada[i] = 0x00u;
    }

    if (chave_n > HSM_SHA256_BLOCK) {
        if (hsm_sha256(chave, chave_n, k_ajustada) != 0) {
            r = -1;
            goto fim;
        }
    } else {
        for (i = 0u; i < chave_n; i++) {
            k_ajustada[i] = chave[i];
        }
    }

    /* hash interno: (K' ^ ipad) || msg */
    for (i = 0u; i < HSM_SHA256_BLOCK; i++) {
        k_pad[i] = k_ajustada[i] ^ 0x36u;
    }
    hsm_sha_init(&c);
    hsm_sha_update(&c, k_pad, HSM_SHA256_BLOCK);
    hsm_sha_update(&c, msg, msg_n);
    if (hsm_sha_final(&c, interno) != 0) {
        r = -1;
        goto fim;
    }

    /* hash externo: (K' ^ opad) || interno */
    for (i = 0u; i < HSM_SHA256_BLOCK; i++) {
        k_pad[i] = k_ajustada[i] ^ 0x5Cu;
    }
    hsm_sha_init(&c);
    hsm_sha_update(&c, k_pad, HSM_SHA256_BLOCK);
    hsm_sha_update(&c, interno, HSM_SHA256_LEN);
    if (hsm_sha_final(&c, out) != 0) {
        r = -1;
    }

fim:
    wipe(k_pad, sizeof k_pad);
    wipe(k_ajustada, sizeof k_ajustada);
    wipe(interno, sizeof interno);
    if (r != 0) {
        wipe(out, HSM_SHA256_LEN);
    }
    return r;
}
