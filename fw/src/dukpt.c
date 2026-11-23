/* fw/src/dukpt.c -- DUKPT TDES, ANSI X9.24-1:2009 (fase 8, etapa 8.8a)
 *
 * FRONTEIRA: dentro. Ver dukpt.h. A referencia independente e host/dukpt.py.
 */
#include "dukpt.h"
#include "des.h"
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
    wipe(k, sizeof k);
    wipe(epb, sizeof epb);
    return r;
}
