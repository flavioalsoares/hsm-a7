/* fw/src/dukpt.c -- DUKPT TDES, ANSI X9.24-1:2009 (fase 8, etapa 8.8a), e
 * DUKPT AES, ANSI X9.24-3:2017 (etapa 8.8b)
 *
 * FRONTEIRA: dentro. Ver dukpt.h. A referencia independente e host/dukpt.py.
 */
#include "dukpt.h"
#include "aes128.h"
#include "des.h"
#include "mac_tdes.h"
#include "hsm_cfs.h"
#include "wipe.h"
#include "kat_vectors.h"

#define CONTADOR_BITS  21u

static const uint8_t C0[DUKPT_TDES_CHAVE] = {
    0xC0u, 0xC0u, 0xC0u, 0xC0u, 0x00u, 0x00u, 0x00u, 0x00u,
    0xC0u, 0xC0u, 0xC0u, 0xC0u, 0x00u, 0x00u, 0x00u, 0x00u
};

/* Os 21 bits da direita do KSN. */
static uint32_t contador(const uint8_t ksn[DUKPT_KSN_LEN])
{
    return (((uint32_t)ksn[7] & 0x1Fu) << 16) | ((uint32_t)ksn[8] << 8) |
           (uint32_t)ksn[9];
}

int dukpt_ksn_valido(const uint8_t ksn[DUKPT_KSN_LEN])
{
    uint32_t c, uns = 0u;

    if (ksn == 0) {
        return 0;
    }
    c = contador(ksn);
    while (c != 0u) {
        uns += c & 1u;
        c >>= 1;
    }
    return ((contador(ksn) != 0u) && (uns <= DUKPT_MAX_UNS)) ? 1 : 0;
}

/* 3DES de um bloco sob `chave` (16 bytes). Para DES simples, chave = A || A.
 * FRONTEIRA: dentro. */
static int cifra(const uint8_t *chave, const uint8_t ent[DES_BLOCO],
                 uint8_t sai[DES_BLOCO])
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    int r = -1;

    if (tdes_prepara(ctx, chave, DUKPT_TDES_CHAVE) == 0) {
        tdes_bloco(ctx, ent, sai, 1);
        r = 0;
    }
    tdes_apaga(ctx);
    return r;
}

int dukpt_tdes_ipek(const uint8_t bdk[DUKPT_TDES_CHAVE],
                    const uint8_t ksn[DUKPT_KSN_LEN],
                    uint8_t ipek[DUKPT_TDES_CHAVE])
{
    uint8_t  k[DES_BLOCO], var[DUKPT_TDES_CHAVE];
    uint32_t i;
    int      r = -1;

    if ((bdk == 0) || (ksn == 0) || (ipek == 0)) {
        return -1;
    }
    /* Os 8 bytes da esquerda do KSN, com os bits do contador zerados: so o
     * byte 7 tem bits do contador entre os 8 primeiros. */
    for (i = 0u; i < DES_BLOCO; i++) {
        k[i] = ksn[i];
    }
    k[7] = (uint8_t)(k[7] & 0xE0u);
    for (i = 0u; i < DUKPT_TDES_CHAVE; i++) {
        var[i] = (uint8_t)(bdk[i] ^ C0[i]);
    }
    if ((cifra(bdk, k, &ipek[0]) == 0) && (cifra(var, k, &ipek[8]) == 0)) {
        r = 0;
    }
    wipe(var, sizeof var);
    wipe(k, sizeof k);
    if (r != 0) {
        wipe(ipek, DUKPT_TDES_CHAVE);
    }
    return r;
}

/* Uma metade do processo nao reversivel (X9.24-1, A.2):
 *     saida = DES(esq, reg ^ dir) ^ dir
 * FRONTEIRA: dentro. */
static int metade(const uint8_t chave[DUKPT_TDES_CHAVE],
                  const uint8_t reg[DES_BLOCO], uint8_t saida[DES_BLOCO])
{
    uint8_t  simples[DUKPT_TDES_CHAVE], ent[DES_BLOCO];
    uint32_t i;
    int      r;

    for (i = 0u; i < DES_BLOCO; i++) {
        simples[i]      = chave[i];
        simples[i + 8u] = chave[i];
        ent[i] = (uint8_t)(reg[i] ^ chave[i + 8u]);
    }
    r = cifra(simples, ent, saida);
    for (i = 0u; i < DES_BLOCO; i++) {
        saida[i] ^= chave[i + 8u];
    }
    wipe(simples, sizeof simples);
    wipe(ent, sizeof ent);
    return r;
}

/* chave <- NRKGP(chave, reg): direita da chave original, esquerda da chave
 * com a variante C0. FRONTEIRA: dentro. */
static int nrkgp(uint8_t chave[DUKPT_TDES_CHAVE], const uint8_t reg[DES_BLOCO])
{
    uint8_t  var[DUKPT_TDES_CHAVE], esq[DES_BLOCO], dir[DES_BLOCO];
    uint32_t i;
    int      r;

    for (i = 0u; i < DUKPT_TDES_CHAVE; i++) {
        var[i] = (uint8_t)(chave[i] ^ C0[i]);
    }
    r = metade(chave, reg, dir);
    if (r == 0) {
        r = metade(var, reg, esq);
    }
    for (i = 0u; i < DES_BLOCO; i++) {
        chave[i]      = esq[i];
        chave[i + 8u] = dir[i];
    }
    wipe(var, sizeof var);
    wipe(esq, sizeof esq);
    wipe(dir, sizeof dir);
    return r;
}

int dukpt_tdes_chave_transacao(const uint8_t bdk[DUKPT_TDES_CHAVE],
                               const uint8_t ksn[DUKPT_KSN_LEN],
                               uint8_t chave[DUKPT_TDES_CHAVE])
{
    uint8_t  reg[DES_BLOCO];
    uint32_t c, bit, i;
    int      r;

    if ((chave == 0) || !dukpt_ksn_valido(ksn)) {
        if (chave != 0) {
            wipe(chave, DUKPT_TDES_CHAVE);
        }
        return -1;
    }
    r = dukpt_tdes_ipek(bdk, ksn, chave);
    /* O registrador: os 8 bytes da direita do KSN, com o contador zerado. Os
     * bits do contador entram um a um, do mais alto para o mais baixo. */
    for (i = 0u; i < DES_BLOCO; i++) {
        reg[i] = ksn[i + 2u];
    }
    reg[5] = (uint8_t)(reg[5] & 0xE0u);
    reg[6] = 0u;
    reg[7] = 0u;
    c = contador(ksn);
    for (bit = CONTADOR_BITS; (bit > 0u) && (r == 0); bit--) {
        uint32_t m = 1u << (bit - 1u);
        if ((c & m) != 0u) {
            reg[5] = (uint8_t)(reg[5] | (uint8_t)(m >> 16));
            reg[6] = (uint8_t)(reg[6] | (uint8_t)(m >> 8));
            reg[7] = (uint8_t)(reg[7] | (uint8_t)m);
            r = nrkgp(chave, reg);
        }
    }
    wipe(reg, sizeof reg);
    if (r != 0) {
        wipe(chave, DUKPT_TDES_CHAVE);
    }
    return r;
}

int dukpt_tdes_chave_pin(const uint8_t bdk[DUKPT_TDES_CHAVE],
                         const uint8_t ksn[DUKPT_KSN_LEN],
                         uint8_t chave[DUKPT_TDES_CHAVE])
{
    /* Variante de PIN: 00000000000000FF nas duas metades. */
    if (dukpt_tdes_chave_transacao(bdk, ksn, chave) != 0) {
        return -1;
    }
    chave[7]  ^= 0xFFu;
    chave[15] ^= 0xFFu;
    return 0;
}

int dukpt_selftest(void)
{
    uint8_t  k[DUKPT_TDES_CHAVE], epb[DES_BLOCO];
    uint8_t  d = 0u;
    uint32_t i;
    int      r = -1;

    if (dukpt_tdes_ipek(kat_dukpt_bdk, kat_dukpt_ksn, k) == 0) {
        for (i = 0u; i < DUKPT_TDES_CHAVE; i++) {
            d |= (uint8_t)(k[i] ^ kat_dukpt_ipek[i]);
        }
        if (dukpt_tdes_chave_pin(kat_dukpt_bdk, kat_dukpt_ksn, k) == 0) {
            if (cifra(k, kat_dukpt_claro, epb) == 0) {
                for (i = 0u; i < DES_BLOCO; i++) {
                    d |= (uint8_t)(epb[i] ^ kat_dukpt_epb[i]);
                }
                r = (d == 0u) ? 0 : -1;
            }
        }
    }
    /* Etapa 8.9b: o MAC de pedido publicado da mesma transacao (retail MAC
     * sob a variante de MAC, 4 bytes). */
    if (r == 0) {
        uint8_t mac[RETAIL_MAC_LEN];
        r = -1;
        if ((dukpt_tdes_chave_uso(kat_dukpt_bdk, kat_dukpt_ksn,
                                  DUKPT_USO_MAC_PEDIDO, k) == 0) &&
            (retail_mac(k, 1u, kat_dukpt_msg, KAT_DUKPT_MSG_LEN, mac) == 0)) {
            d = 0u;
            for (i = 0u; i < 4u; i++) {
                d |= (uint8_t)(mac[i] ^ kat_dukpt_reqmac[i]);
            }
            r = (d == 0u) ? 0 : -1;
        }
        wipe(mac, sizeof mac);
    }
    wipe(k, sizeof k);
    wipe(epb, sizeof epb);
    return r;
}

/* --------------------------------------------------------------------
 * DUKPT AES, ANSI X9.24-3:2017 (etapa 8.8b)
 *
 * Uma funcao de derivacao, AES-ECB sobre 16 bytes:
 *   01 . bloco(1) . uso(2) . algoritmo(2) . bits(2) . 8 bytes
 * O algoritmo e os bits sao os da chave DERIVADA; uma chave de 256 bits sai
 * de dois blocos. A chave que deriva e AES-128 (motor em C, aes128.c) ou
 * AES-256 (coprocessador).
 * -------------------------------------------------------------------- */

#define USO_DERIVA_INICIAL  0x8001u
#define USO_DERIVA          0x8000u
#define USO_PIN             0x1000u

/* Um bloco AES-ECB (cifra) sob `chave` de `n` bytes. FRONTEIRA: dentro. */
static int aes_cifra(const uint8_t *chave, uint32_t n,
                     const uint8_t ent[16], uint8_t sai[16])
{
    int r = -1;

    if (n == DUKPT_AES128) {
        aes128_ctx_t *ctx = aes128_ctx_comum();
        if (aes128_prepara(ctx, chave) == 0) {
            aes128_bloco(ctx, ent, sai, 1);
            r = 0;
        }
        aes128_apaga(ctx);
    } else if (n == DUKPT_AES256) {
        if ((hsm_cfs_aes_key(chave) == 0) && (hsm_cfs_aes_block(ent, sai, 1) == 0)) {
            r = 0;
        }
        (void)hsm_cfs_wipe();
    }
    return r;
}

/* saida (n_saida bytes) = deriva(chave de n bytes, uso, dados8).
 * FRONTEIRA: dentro. */
static int aes_deriva(const uint8_t *chave, uint32_t n, uint32_t uso,
                      uint32_t n_saida, const uint8_t dados8[8], uint8_t *saida)
{
    uint8_t  d[16];
    uint32_t blk, i;
    int      r = 0;

    if ((n_saida != DUKPT_AES128) && (n_saida != DUKPT_AES256)) {
        return -1;
    }
    for (blk = 1u; (blk <= n_saida / 16u) && (r == 0); blk++) {
        d[0] = 0x01u;
        d[1] = (uint8_t)blk;
        d[2] = (uint8_t)(uso >> 8);
        d[3] = (uint8_t)uso;
        d[4] = 0x00u;
        d[5] = (n_saida == DUKPT_AES128) ? 0x02u : 0x04u;
        d[6] = (uint8_t)((n_saida * 8u) >> 8);
        d[7] = (uint8_t)(n_saida * 8u);
        for (i = 0u; i < 8u; i++) {
            d[8u + i] = dados8[i];
        }
        r = aes_cifra(chave, n, d, &saida[16u * (blk - 1u)]);
    }
    wipe(d, sizeof d);
    if (r != 0) {
        wipe(saida, n_saida);
    }
    return r;
}

static uint32_t aes_contador(const uint8_t ksn[DUKPT_AES_KSN_LEN])
{
    return ((uint32_t)ksn[8] << 24) | ((uint32_t)ksn[9] << 16) |
           ((uint32_t)ksn[10] << 8) | (uint32_t)ksn[11];
}

int dukpt_aes_ksn_valido(const uint8_t ksn[DUKPT_AES_KSN_LEN])
{
    uint32_t c, uns = 0u;

    if (ksn == 0) {
        return 0;
    }
    c = aes_contador(ksn);
    while (c != 0u) {
        uns += c & 1u;
        c >>= 1;
    }
    return ((aes_contador(ksn) != 0u) && (uns <= DUKPT_AES_MAX_UNS)) ? 1 : 0;
}

int dukpt_aes_ik(const uint8_t *bdk, uint32_t n,
                 const uint8_t ksn[DUKPT_AES_KSN_LEN], uint8_t *ik)
{
    if ((bdk == 0) || (ksn == 0) || (ik == 0) ||
        ((n != DUKPT_AES128) && (n != DUKPT_AES256))) {
        return -1;
    }
    /* Os 8 bytes da esquerda do KSN sao o IKID. */
    return aes_deriva(bdk, n, USO_DERIVA_INICIAL, n, ksn, ik);
}

int dukpt_aes_chave_transacao(const uint8_t *bdk, uint32_t n,
                              const uint8_t ksn[DUKPT_AES_KSN_LEN],
                              uint8_t *chave)
{
    uint8_t  dados[8], prox[DUKPT_AES256];
    uint32_t c, reg = 0u, bit, i;
    int      r;

    if ((chave == 0) || !dukpt_aes_ksn_valido(ksn)) {
        if ((chave != 0) && ((n == DUKPT_AES128) || (n == DUKPT_AES256))) {
            wipe(chave, n);
        }
        return -1;
    }
    r = dukpt_aes_ik(bdk, n, ksn, chave);
    c = aes_contador(ksn);
    for (i = 0u; i < 4u; i++) {
        dados[i] = ksn[4u + i];
    }
    for (bit = 32u; (bit > 0u) && (r == 0); bit--) {
        uint32_t m = 1u << (bit - 1u);
        if ((c & m) != 0u) {
            reg |= m;
            dados[4] = (uint8_t)(reg >> 24);
            dados[5] = (uint8_t)(reg >> 16);
            dados[6] = (uint8_t)(reg >> 8);
            dados[7] = (uint8_t)reg;
            r = aes_deriva(chave, n, USO_DERIVA, n, dados, prox);
            for (i = 0u; i < n; i++) {
                chave[i] = prox[i];
            }
        }
    }
    wipe(dados, sizeof dados);
    wipe(prox, sizeof prox);
    if (r != 0) {
        wipe(chave, n);
    }
    return r;
}

int dukpt_aes_chave_pin(const uint8_t *bdk, uint32_t n,
                        const uint8_t ksn[DUKPT_AES_KSN_LEN],
                        uint32_t n_trabalho, uint8_t *chave)
{
    uint8_t t[DUKPT_AES256];
    int     r = -1;

    if ((chave == 0) ||
        ((n_trabalho != DUKPT_AES128) && (n_trabalho != DUKPT_AES256))) {
        return -1;
    }
    if (dukpt_aes_chave_transacao(bdk, n, ksn, t) == 0) {
        /* IKID[4:8] . contador = os 8 bytes da direita do KSN. */
        r = aes_deriva(t, n, USO_PIN, n_trabalho, &ksn[4], chave);
    }
    wipe(t, sizeof t);
    return r;
}

/* O autoteste. FRONTEIRA: dentro. */
static uint8_t difere(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint8_t  d = 0u;
    uint32_t i;

    for (i = 0u; i < n; i++) {
        d |= (uint8_t)(a[i] ^ b[i]);
    }
    return d;
}

int dukpt_aes_selftest(void)
{
    aes128_ctx_t *ctx = aes128_ctx_comum();
    uint8_t       k[DUKPT_AES256], x[16];
    uint8_t       d = 0u;
    uint32_t      i;

    /* 1. O motor AES-128, nas duas direcoes (CAVP). */
    if (aes128_prepara(ctx, kat_aes128_cifra_chave) != 0) {
        d = 1u;
    }
    aes128_bloco(ctx, kat_aes128_cifra_claro, x, 1);
    d |= difere(x, kat_aes128_cifra_cifrado, 16u);
    if (aes128_prepara(ctx, kat_aes128_decifra_chave) != 0) {
        d = 1u;
    }
    aes128_bloco(ctx, kat_aes128_decifra_cifrado, x, 0);
    d |= difere(x, kat_aes128_decifra_claro, 16u);
    aes128_apaga(ctx);

    /* 2. BDK AES-128: a chave de PIN AES-128 da transacao, e o PIN block
     *    formato 4 refeito sob ela: E(K, E(K, campo do PIN) ^ campo do PAN). */
    if (dukpt_aes_chave_pin(kat_dukpt_aes_bdk128, DUKPT_AES128, kat_dukpt_aes_ksn,
                            DUKPT_AES128, k) != 0) {
        d = 1u;
    }
    d |= difere(k, kat_dukpt_aes_pin128, DUKPT_AES128);
    if (aes128_prepara(ctx, k) != 0) {
        d = 1u;
    }
    aes128_bloco(ctx, kat_dukpt_aes_campo_pin, x, 1);
    for (i = 0u; i < 16u; i++) {
        x[i] ^= kat_dukpt_aes_campo_pan[i];
    }
    aes128_bloco(ctx, x, x, 1);
    aes128_apaga(ctx);
    d |= difere(x, kat_dukpt_aes_epb, 16u);

    /* 3. BDK AES-256: a chave de PIN AES-256, pelo coprocessador. */
    if (dukpt_aes_chave_pin(kat_dukpt_aes_bdk256, DUKPT_AES256, kat_dukpt_aes_ksn,
                            DUKPT_AES256, k) != 0) {
        d = 1u;
    }
    d |= difere(k, kat_dukpt_aes_pin256, DUKPT_AES256);
    /* Etapa 8.9b: as chaves de MAC (2000) e de dados (3000) publicadas da
     * mesma transacao, com a BDK AES-128. */
    if (dukpt_aes_chave_uso(kat_dukpt_aes_bdk128, DUKPT_AES128,
                            kat_dukpt_aes_ksn, DUKPT_USO_MAC_PEDIDO,
                            DUKPT_AES128, k) != 0) {
        d = 1u;
    }
    d |= difere(k, kat_dukpt_aes_mackey, DUKPT_AES128);
    if (dukpt_aes_chave_uso(kat_dukpt_aes_bdk128, DUKPT_AES128,
                            kat_dukpt_aes_ksn, DUKPT_USO_DADOS_PEDIDO,
                            DUKPT_AES128, k) != 0) {
        d = 1u;
    }
    d |= difere(k, kat_dukpt_aes_datakey, DUKPT_AES128);

    wipe(k, sizeof k);
    wipe(x, sizeof x);
    return (d == 0u) ? 0 : -1;
}

/* --------------------------------------------------------------------
 * MAC e dados com a chave da transacao (etapa 8.9b)
 * -------------------------------------------------------------------- */

int dukpt_tdes_chave_uso(const uint8_t bdk[DUKPT_TDES_CHAVE],
                         const uint8_t ksn[DUKPT_KSN_LEN], uint8_t uso,
                         uint8_t chave[DUKPT_TDES_CHAVE])
{
    /* Os bytes da variante, por uso (X9.24-1, A.4.1). */
    static const uint8_t var[4] = { 6u, 4u, 5u, 3u };
    tdes_ctx_t *ctx = tdes_ctx_comum();
    uint8_t     t[DUKPT_TDES_CHAVE];
    uint32_t    i;
    int         r = -1;

    if ((chave == 0) || (uso > DUKPT_USO_DADOS_RESPOSTA)) {
        return -1;
    }
    if (dukpt_tdes_chave_transacao(bdk, ksn, t) == 0) {
        t[var[uso]]           ^= 0xFFu;
        t[var[uso] + 8u]      ^= 0xFFu;
        if (uso < DUKPT_USO_DADOS_PEDIDO) {
            for (i = 0u; i < DUKPT_TDES_CHAVE; i++) {
                chave[i] = t[i];
            }
            r = 0;
        } else if (tdes_prepara(ctx, t, DUKPT_TDES_CHAVE) == 0) {
            /* A funcao de mao unica: cada metade cifrada sob a chave toda. */
            tdes_bloco(ctx, &t[0], &chave[0], 1);
            tdes_bloco(ctx, &t[8], &chave[8], 1);
            r = 0;
        }
        tdes_apaga(ctx);
    }
    wipe(t, sizeof t);
    if (r != 0) {
        wipe(chave, DUKPT_TDES_CHAVE);
    }
    return r;
}

int dukpt_aes_chave_uso(const uint8_t *bdk, uint32_t n,
                        const uint8_t ksn[DUKPT_AES_KSN_LEN], uint8_t uso,
                        uint32_t n_trabalho, uint8_t *chave)
{
    static const uint16_t usos[4] = { 0x2000u, 0x2001u, 0x3000u, 0x3001u };
    uint8_t t[DUKPT_AES256];
    int     r = -1;

    if ((chave == 0) || (uso > DUKPT_USO_DADOS_RESPOSTA) ||
        ((n_trabalho != DUKPT_AES128) && (n_trabalho != DUKPT_AES256))) {
        return -1;
    }
    if (dukpt_aes_chave_transacao(bdk, n, ksn, t) == 0) {
        r = aes_deriva(t, n, usos[uso], n_trabalho, &ksn[4], chave);
    }
    wipe(t, sizeof t);
    return r;
}

/* O motor AES de uma chave de 16 ou 32 bytes, aberto uma vez para varios
 * blocos. FRONTEIRA: dentro. */
static int aesm_abre(const uint8_t *chave, uint32_t n)
{
    if (n == DUKPT_AES128) {
        return aes128_prepara(aes128_ctx_comum(), chave);
    }
    if (n == DUKPT_AES256) {
        return (hsm_cfs_aes_key(chave) == 0) ? 0 : -1;
    }
    return -1;
}

static int aesm_bloco(uint32_t n, const uint8_t ent[16], uint8_t sai[16],
                      int cifrar)
{
    if (n == DUKPT_AES128) {
        aes128_bloco(aes128_ctx_comum(), ent, sai, cifrar);
        return 0;
    }
    return (hsm_cfs_aes_block(ent, sai, cifrar) == 0) ? 0 : -1;
}

static void aesm_fecha(uint32_t n)
{
    if (n == DUKPT_AES128) {
        aes128_apaga(aes128_ctx_comum());
    } else {
        (void)hsm_cfs_wipe();
    }
}

/* Dobra do CMAC no corpo de 2^128: desloca 1 bit e, se saiu um 1, XOR 87. */
static void dobra128(const uint8_t e[16], uint8_t s[16])
{
    uint32_t i;
    uint8_t  vai = (uint8_t)(e[0] >> 7);

    for (i = 0u; i < 15u; i++) {
        s[i] = (uint8_t)((e[i] << 1) | (e[i + 1u] >> 7));
    }
    s[15] = (uint8_t)((uint8_t)(e[15] << 1) ^ (uint8_t)(0x87u * vai));
}

int dukpt_aes_cmac(const uint8_t *chave, uint32_t n, const uint8_t *msg,
                   uint32_t msg_n, uint8_t tag[16])
{
    uint8_t  l[16], k1[16], k2[16], x[16], b[16];
    uint32_t completos, resto, i, j;
    int      r = -1;

    for (i = 0u; i < 16u; i++) {
        l[i] = 0u;
        x[i] = 0u;
    }
    if ((tag == 0) || ((msg == 0) && (msg_n != 0u)) || (aesm_abre(chave, n) != 0)) {
        goto fim;
    }
    if (aesm_bloco(n, l, l, 1) != 0) {
        goto fim;
    }
    dobra128(l, k1);
    dobra128(k1, k2);
    if ((msg_n != 0u) && ((msg_n % 16u) == 0u)) {
        completos = (msg_n / 16u) - 1u;
        resto     = 16u;
    } else {
        completos = msg_n / 16u;
        resto     = msg_n % 16u;
    }
    for (i = 0u; i < completos; i++) {
        for (j = 0u; j < 16u; j++) {
            b[j] = (uint8_t)(x[j] ^ msg[i * 16u + j]);
        }
        if (aesm_bloco(n, b, x, 1) != 0) {
            goto fim;
        }
    }
    for (j = 0u; j < 16u; j++) {
        uint8_t m;
        if (j < resto) {
            m = msg[completos * 16u + j];
        } else {
            m = (j == resto) ? 0x80u : 0u;
        }
        b[j] = (uint8_t)(x[j] ^ m ^ ((resto == 16u) ? k1[j] : k2[j]));
    }
    if (aesm_bloco(n, b, tag, 1) == 0) {
        r = 0;
    }
fim:
    aesm_fecha(n);
    wipe(l, sizeof l);
    wipe(k1, sizeof k1);
    wipe(k2, sizeof k2);
    wipe(x, sizeof x);
    wipe(b, sizeof b);
    if ((r != 0) && (tag != 0)) {
        wipe(tag, 16u);
    }
    return r;
}

int dukpt_aes_cbc(const uint8_t *chave, uint32_t n, const uint8_t iv[16],
                  const uint8_t *entrada, uint8_t *saida, uint32_t n_dados,
                  int cifrar)
{
    uint8_t  v[16], b[16], c[16];
    uint32_t i, j;
    int      r = -1;

    if ((entrada == 0) || (saida == 0) || (iv == 0) || (n_dados == 0u) ||
        ((n_dados % 16u) != 0u) || (aesm_abre(chave, n) != 0)) {
        aesm_fecha(n);
        return -1;
    }
    for (j = 0u; j < 16u; j++) {
        v[j] = iv[j];
    }
    r = 0;
    for (i = 0u; (i < n_dados) && (r == 0); i += 16u) {
        for (j = 0u; j < 16u; j++) {
            c[j] = entrada[i + j];
        }
        if (cifrar) {
            for (j = 0u; j < 16u; j++) {
                b[j] = (uint8_t)(c[j] ^ v[j]);
            }
            r = aesm_bloco(n, b, &saida[i], 1);
            for (j = 0u; j < 16u; j++) {
                v[j] = saida[i + j];
            }
        } else {
            r = aesm_bloco(n, c, b, 0);
            for (j = 0u; j < 16u; j++) {
                saida[i + j] = (uint8_t)(b[j] ^ v[j]);
                v[j] = c[j];
            }
        }
    }
    aesm_fecha(n);
    wipe(v, sizeof v);
    wipe(b, sizeof b);
    wipe(c, sizeof c);
    if (r != 0) {
        wipe(saida, n_dados);
    }
    return r;
}
