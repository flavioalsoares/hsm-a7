/* fw/src/emv.c -- ARQC e ARPC do EMV, 3DES (fase 8, etapa 8.10)
 *
 * So as contas. Quem pode usar qual chave (uso E0, modo X), o limite do PAN
 * e a conferencia dupla estao em keystore.c. Ver emv.h.
 *
 * FRONTEIRA: dentro. Toda variavel com chave sai apagada.
 */
#include "emv.h"
#include "des.h"
#include "mac_tdes.h"
#include "wipe.h"
#include "kat_vectors.h"

/* 3DES de um bloco sob `chave` (16 bytes). FRONTEIRA: dentro. */
static int cifra(const uint8_t chave[EMV_CHAVE], const uint8_t ent[DES_BLOCO],
                 uint8_t sai[DES_BLOCO])
{
    tdes_ctx_t *ctx = tdes_ctx_comum();
    int r = -1;

    if (tdes_prepara(ctx, chave, EMV_CHAVE) == 0) {
        tdes_bloco(ctx, ent, sai, 1);
        r = 0;
    }
    tdes_apaga(ctx);
    return r;
}

/* Cifra `y` e `y` invertido sob `k`; paridade impar. A Opcao A e a chave de
 * sessao comum tem esta forma: so muda o bloco da direita. */
static int duas_metades(const uint8_t k[EMV_CHAVE], const uint8_t esq[8],
                        const uint8_t dir[8], uint8_t out[EMV_CHAVE])
{
    int r = -1;

    if ((cifra(k, esq, out) == 0) && (cifra(k, dir, out + 8) == 0)) {
        des_paridade_ajusta(out, EMV_CHAVE);
        r = 0;
    }
    if (r != 0) {
        wipe(out, EMV_CHAVE);
    }
    return r;
}

int emv_mk_opcao_a(const uint8_t imk[EMV_CHAVE], const uint8_t *pan,
                   uint32_t pan_n, const uint8_t psn[2],
                   uint8_t mk[EMV_CHAVE])
{
    uint8_t  dig[16], y[8], ny[8];
    uint32_t i, total = pan_n + 2u, ini;
    int      r = -1;

    if ((imk == 0) || (pan == 0) || (psn == 0) || (mk == 0) ||
        (pan_n == 0u) || (pan_n > EMV_PAN_MAX)) {
        return -1;
    }
    /* Os 16 digitos da direita de PAN || PSN; com menos, zeros a esquerda. */
    ini = (total > 16u) ? (total - 16u) : 0u;
    for (i = 0u; i < 16u; i++) {
        dig[i] = (uint8_t)'0';
    }
    for (i = ini; i < total; i++) {
        uint8_t c = (i < pan_n) ? pan[i] : psn[i - pan_n];
        if ((c < (uint8_t)'0') || (c > (uint8_t)'9')) {
            return -1;
        }
        dig[16u - (total - i)] = c;
    }
    for (i = 0u; i < 8u; i++) {
        y[i]  = (uint8_t)(((dig[2u * i] - (uint8_t)'0') << 4) |
                          (dig[2u * i + 1u] - (uint8_t)'0'));
        ny[i] = (uint8_t)(y[i] ^ 0xFFu);
    }
    r = duas_metades(imk, y, ny, mk);
    wipe(y, sizeof y);
    wipe(ny, sizeof ny);
    return r;
}

int emv_csk(const uint8_t mk[EMV_CHAVE], const uint8_t r[8],
            uint8_t sk[EMV_CHAVE])
{
    uint8_t esq[8], dir[8];
    uint32_t i;
    int      res;

    if ((mk == 0) || (r == 0) || (sk == 0)) {
        return -1;
    }
    for (i = 0u; i < 8u; i++) {
        esq[i] = r[i];
        dir[i] = r[i];
    }
    esq[2] = 0xF0u;
    dir[2] = 0x0Fu;
    res = duas_metades(mk, esq, dir, sk);
    wipe(esq, sizeof esq);
    wipe(dir, sizeof dir);
    return res;
}

int emv_chave_ac(const uint8_t imk[EMV_CHAVE], const uint8_t *pan,
                 uint32_t pan_n, const uint8_t psn[2], const uint8_t atc[2],
                 int esquema, uint8_t chave[EMV_CHAVE])
{
    uint8_t  mk[EMV_CHAVE], r[8];
    uint32_t i;
    int      res = -1;

    if ((atc == 0) || (chave == 0) ||
        ((esquema != EMV_ESQ_MK) && (esquema != EMV_ESQ_CSK))) {
        return -1;
    }
    if (emv_mk_opcao_a(imk, pan, pan_n, psn, mk) == 0) {
        if (esquema == EMV_ESQ_MK) {
            for (i = 0u; i < EMV_CHAVE; i++) {
                chave[i] = mk[i];
            }
            res = 0;
        } else {
            r[0] = atc[0];
            r[1] = atc[1];
            for (i = 2u; i < 8u; i++) {
                r[i] = 0u;
            }
            res = emv_csk(mk, r, chave);
        }
    }
    wipe(mk, sizeof mk);
    if (res != 0) {
        wipe(chave, EMV_CHAVE);
    }
    return res;
}

int emv_criptograma(const uint8_t chave[EMV_CHAVE], const uint8_t *dados,
                    uint32_t n, uint8_t pad, uint8_t ac[EMV_AC_LEN])
{
    if ((chave == 0) || (dados == 0) || (ac == 0) || (n == 0u) ||
        ((pad != 1u) && (pad != 2u))) {
        return -1;
    }
    return retail_mac(chave, pad, dados, n, ac);
}

int emv_arpc1(const uint8_t chave[EMV_CHAVE], const uint8_t arqc[EMV_AC_LEN],
              const uint8_t arc[EMV_ARC_LEN], uint8_t arpc[EMV_ARPC1_LEN])
{
    uint8_t  b[8];
    uint32_t i;
    int      r;

    if ((chave == 0) || (arqc == 0) || (arc == 0) || (arpc == 0)) {
        return -1;
    }
    for (i = 0u; i < 8u; i++) {
        b[i] = arqc[i];
    }
    b[0] = (uint8_t)(b[0] ^ arc[0]);
    b[1] = (uint8_t)(b[1] ^ arc[1]);
    r = cifra(chave, b, arpc);
    wipe(b, sizeof b);
    return r;
}

int emv_arpc2(const uint8_t chave[EMV_CHAVE], const uint8_t arqc[EMV_AC_LEN],
              const uint8_t csu[EMV_CSU_LEN], const uint8_t *pad_aut,
              uint32_t pad_aut_n, uint8_t arpc[EMV_ARPC2_LEN])
{
    uint8_t  msg[EMV_AC_LEN + EMV_CSU_LEN + EMV_PAD_AUT_MAX];
    uint8_t  mac[RETAIL_MAC_LEN];
    uint32_t i, n = 0u;
    int      r = -1;

    if ((chave == 0) || (arqc == 0) || (csu == 0) || (arpc == 0) ||
        (pad_aut_n > EMV_PAD_AUT_MAX) || ((pad_aut_n > 0u) && (pad_aut == 0))) {
        return -1;
    }
    for (i = 0u; i < EMV_AC_LEN; i++) {
        msg[n++] = arqc[i];
    }
    for (i = 0u; i < EMV_CSU_LEN; i++) {
        msg[n++] = csu[i];
    }
    for (i = 0u; i < pad_aut_n; i++) {
        msg[n++] = pad_aut[i];
    }
    if (retail_mac(chave, 2u, msg, n, mac) == 0) {
        for (i = 0u; i < EMV_ARPC2_LEN; i++) {
            arpc[i] = mac[i];
        }
        r = 0;
    }
    wipe(msg, sizeof msg);
    wipe(mac, sizeof mac);
    return r;
}

/* Um caso do autoteste: a chave, o criptograma e o ARPC publicados. */
static int caso(const uint8_t *imk, const uint8_t *pan, uint32_t pan_n,
                const uint8_t *psn, const uint8_t *atc, int esquema,
                const uint8_t *dados, uint32_t n, uint8_t pad,
                const uint8_t *arqc_pub, int metodo, const uint8_t *arg,
                const uint8_t *arpc_pub)
{
    uint8_t  k[EMV_CHAVE], ac[EMV_AC_LEN], arpc[EMV_ARPC1_LEN];
    uint32_t i, m = (metodo == 1) ? EMV_ARPC1_LEN : EMV_ARPC2_LEN;
    uint8_t  d = 0u;
    int      r = -1;

    if ((emv_chave_ac(imk, pan, pan_n, psn, atc, esquema, k) == 0) &&
        (emv_criptograma(k, dados, n, pad, ac) == 0) &&
        (((metodo == 1) && (emv_arpc1(k, ac, arg, arpc) == 0)) ||
         ((metodo == 2) && (emv_arpc2(k, ac, arg, 0, 0u, arpc) == 0)))) {
        for (i = 0u; i < EMV_AC_LEN; i++) {
            d |= (uint8_t)(ac[i] ^ arqc_pub[i]);
        }
        for (i = 0u; i < m; i++) {
            d |= (uint8_t)(arpc[i] ^ arpc_pub[i]);
        }
        r = (d == 0u) ? 0 : -1;
    }
    wipe(k, sizeof k);
    wipe(ac, sizeof ac);
    wipe(arpc, sizeof arpc);
    return r;
}

int emv_selftest(void)
{
    if (caso(kat_emv1_imk, kat_emv1_pan, KAT_EMV1_PAN_LEN, kat_emv1_psn,
             kat_emv1_atc, KAT_EMV1_ESQ, kat_emv1_dados, KAT_EMV1_DADOS_LEN,
             (uint8_t)KAT_EMV1_PAD, kat_emv1_arqc, KAT_EMV1_METODO,
             kat_emv1_arg, kat_emv1_arpc) != 0) {
        return -1;
    }
    return caso(kat_emv2_imk, kat_emv2_pan, KAT_EMV2_PAN_LEN, kat_emv2_psn,
                kat_emv2_atc, KAT_EMV2_ESQ, kat_emv2_dados, KAT_EMV2_DADOS_LEN,
                (uint8_t)KAT_EMV2_PAD, kat_emv2_arqc, KAT_EMV2_METODO,
                kat_emv2_arg, kat_emv2_arpc);
}
