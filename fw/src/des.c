/* fw/src/des.c -- DES e 3DES (TDEA), em software (fase 8)
 *
 * Ver des.h. Implementacao direta da FIPS 46-3, com as tabelas da norma e
 * uma rotina so de permutacao de bits. E pequena e lenta de proposito: o
 * 3DES aqui cifra blocos de 8 bytes de PIN e de verificacao, nao dados em
 * volume.
 *
 * As tabelas numeram os bits de 1 (o mais alto do primeiro byte) em diante,
 * como a norma. Quem garante que estao certas sao os KATs da SP 800-20
 * (vectors/tdes/), feitos para exercitar cada entrada de cada tabela.
 *
 * FRONTEIRA: dentro. Todo valor intermediario de rodada depende da chave, e
 * as rotinas apagam os seus locais antes de voltar.
 */
#include "des.h"
#include "wipe.h"

/* Permutacao inicial e a inversa dela. */
static const uint8_t IP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
};

static const uint8_t FP[64] = {
    40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25,
};

/* Expansao de 32 para 48 bits, e a permutacao P no fim da funcao f. */
static const uint8_t E[48] = {
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1,
};

static const uint8_t P[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25,
};

/* Escalonamento: PC-1 tira a paridade (64 -> 56), PC-2 escolhe os 48 bits de
 * cada rodada, e ROT diz quanto cada metade gira. */
static const uint8_t PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
};

static const uint8_t PC2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
};

static const uint8_t ROT[16] = {
     1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1,
};

/* As oito caixas S, 64 entradas cada, indexadas pelos 6 bits de entrada na
 * ordem em que chegam. A norma as escreve por linha (bits 1 e 6) e coluna
 * (bits 2 a 5); aqui a conversao ja esta feita. */
static const uint8_t SBOX[8 * 64] = {
    14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
     3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
     4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
    15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13,
    15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
     9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
     0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
     5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9,
    10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
     1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
    13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
    11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12,
     7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
     1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
    10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
    15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14,
     2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
     8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
     4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
    15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3,
    12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
     0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
     9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
     7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13,
     4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
     3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
     1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
    10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12,
    13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
    10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
     7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
     0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11,
};

/* Bit `pos` (1 = o mais alto do primeiro byte) de `v`. */
static uint8_t bit(const uint8_t *v, uint32_t pos)
{
    pos--;
    return (uint8_t)((v[pos >> 3] >> (7u - (pos & 7u))) & 1u);
}

/* saida[i] = entrada[tabela[i]], bit a bit. `n` e o numero de bits de saida,
 * multiplo de 8. `saida` nao pode ser `entrada`. */
static void permuta(const uint8_t *entrada, uint8_t *saida,
                    const uint8_t *tabela, uint32_t n)
{
    uint32_t i;
    uint8_t  acc = 0u;

    for (i = 0u; i < n; i++) {
        acc = (uint8_t)((acc << 1) | bit(entrada, tabela[i]));
        if ((i & 7u) == 7u) {
            saida[i >> 3] = acc;
            acc = 0u;
        }
    }
}

/* Gira 28 bits um para a esquerda. As metades C e D ficam em 4 bytes, com
 * os 28 bits alinhados pelo alto e os 4 baixos em zero. */
static void gira28(uint8_t m[4])
{
    uint8_t alto = (uint8_t)(m[0] >> 7);

    m[0] = (uint8_t)((m[0] << 1) | (m[1] >> 7));
    m[1] = (uint8_t)((m[1] << 1) | (m[2] >> 7));
    m[2] = (uint8_t)((m[2] << 1) | (m[3] >> 7));
    m[3] = (uint8_t)(((m[3] << 1) | (uint8_t)(alto << 4)) & 0xF0u);
}

/* As 16 subchaves de uma chave DES. */
static void agenda(const uint8_t chave[DES_CHAVE], uint8_t ks[16][6])
{
    uint8_t  cd[7], c[4], d[4];
    uint32_t r, j;

    permuta(chave, cd, PC1, 56u);
    c[0] = cd[0]; c[1] = cd[1]; c[2] = cd[2];
    c[3] = (uint8_t)(cd[3] & 0xF0u);
    d[0] = (uint8_t)((cd[3] << 4) | (cd[4] >> 4));
    d[1] = (uint8_t)((cd[4] << 4) | (cd[5] >> 4));
    d[2] = (uint8_t)((cd[5] << 4) | (cd[6] >> 4));
    d[3] = (uint8_t)(cd[6] << 4);

    for (r = 0u; r < 16u; r++) {
        for (j = 0u; j < ROT[r]; j++) {
            gira28(c);
            gira28(d);
        }
        cd[0] = c[0]; cd[1] = c[1]; cd[2] = c[2];
        cd[3] = (uint8_t)(c[3] | (d[0] >> 4));
        cd[4] = (uint8_t)((d[0] << 4) | (d[1] >> 4));
        cd[5] = (uint8_t)((d[1] << 4) | (d[2] >> 4));
        cd[6] = (uint8_t)((d[2] << 4) | (d[3] >> 4));
        permuta(cd, ks[r], PC2, 48u);
    }
    wipe(cd, sizeof cd);
    wipe(c, sizeof c);
    wipe(d, sizeof d);
}

/* A funcao de rodada: expande R para 48 bits, mistura a subchave, passa
 * pelas caixas S e permuta. */
static void f(const uint8_t r[4], const uint8_t k[6], uint8_t saida[4])
{
    uint8_t  x[6], s[4];
    uint32_t i, seis;

    permuta(r, x, E, 48u);
    for (i = 0u; i < 6u; i++) {
        x[i] ^= k[i];
    }
    /* Oito grupos de 6 bits, dos 48. */
    for (i = 0u; i < 4u; i++) {
        s[i] = 0u;
    }
    for (i = 0u; i < 8u; i++) {
        uint32_t pos = 6u * i;                  /* bit inicial, de 0 */
        uint32_t par = ((uint32_t)x[pos >> 3] << 8) |
                       (((pos >> 3) + 1u < 6u) ? x[(pos >> 3) + 1u] : 0u);
        seis = (par >> (10u - (pos & 7u))) & 0x3Fu;
        s[i >> 1] |= (uint8_t)(SBOX[64u * i + seis] << (((i & 1u) == 0u) ? 4 : 0));
    }
    permuta(s, saida, P, 32u);
    wipe(x, sizeof x);
    wipe(s, sizeof s);
}

/* Um bloco de DES simples. Decifrar e cifrar com as subchaves na ordem
 * inversa: e a propriedade da rede de Feistel. */
static void des_bloco(const uint8_t ks[16][6], const uint8_t entrada[DES_BLOCO],
                      uint8_t saida[DES_BLOCO], int cifrar)
{
    uint8_t  v[8], t[4], pre[8];
    uint32_t r, i;

    permuta(entrada, v, IP, 64u);               /* v = L (0..3) | R (4..7) */
    for (r = 0u; r < 16u; r++) {
        f(&v[4], ks[cifrar ? r : (15u - r)], t);
        for (i = 0u; i < 4u; i++) {
            uint8_t novo_r = (uint8_t)(v[i] ^ t[i]);
            v[i]      = v[4u + i];
            v[4u + i] = novo_r;
        }
    }
    /* As metades saem trocadas da ultima rodada. */
    for (i = 0u; i < 4u; i++) {
        pre[i]      = v[4u + i];
        pre[4u + i] = v[i];
    }
    permuta(pre, saida, FP, 64u);
    wipe(v, sizeof v);
    wipe(t, sizeof t);
    wipe(pre, sizeof pre);
}

static tdes_ctx_t g_ctx;

tdes_ctx_t *tdes_ctx_comum(void)
{
    return &g_ctx;
}

int tdes_prepara(tdes_ctx_t *ctx, const uint8_t *chave, uint32_t n)
{
    if ((ctx == 0) || (chave == 0) ||
        ((n != TDES_CHAVE_2) && (n != TDES_CHAVE_3))) {
        return -1;
    }
    agenda(&chave[0], ctx->ks[0]);
    agenda(&chave[8], ctx->ks[1]);
    /* Chave dupla: K3 = K1. */
    agenda((n == TDES_CHAVE_3) ? &chave[16] : &chave[0], ctx->ks[2]);
    return 0;
}

void tdes_bloco(const tdes_ctx_t *ctx, const uint8_t entrada[DES_BLOCO],
                uint8_t saida[DES_BLOCO], int cifrar)
{
    uint8_t a[DES_BLOCO], b[DES_BLOCO];

    if (cifrar) {                               /* E(K3, D(K2, E(K1, P))) */
        des_bloco(ctx->ks[0], entrada, a, 1);
        des_bloco(ctx->ks[1], a, b, 0);
        des_bloco(ctx->ks[2], b, saida, 1);
    } else {                                    /* D(K1, E(K2, D(K3, C))) */
        des_bloco(ctx->ks[2], entrada, a, 0);
        des_bloco(ctx->ks[1], a, b, 1);
        des_bloco(ctx->ks[0], b, saida, 0);
    }
    wipe(a, sizeof a);
    wipe(b, sizeof b);
}

int tdes_cbc(const tdes_ctx_t *ctx, const uint8_t iv[DES_BLOCO],
             const uint8_t *entrada, uint8_t *saida, uint32_t n, int cifrar)
{
    uint8_t  ant[DES_BLOCO], cif[DES_BLOCO], t[DES_BLOCO];
    uint32_t i, j;

    if ((n % DES_BLOCO) != 0u) {
        return -1;
    }
    for (j = 0u; j < DES_BLOCO; j++) {
        ant[j] = iv[j];
    }
    for (i = 0u; i < n; i += DES_BLOCO) {
        if (cifrar) {
            for (j = 0u; j < DES_BLOCO; j++) {
                t[j] = (uint8_t)(entrada[i + j] ^ ant[j]);
            }
            tdes_bloco(ctx, t, ant, 1);
            for (j = 0u; j < DES_BLOCO; j++) {
                saida[i + j] = ant[j];
            }
        } else {
            /* Guarda o bloco cifrado antes de escrever: os buffers podem
             * ser o mesmo. */
            for (j = 0u; j < DES_BLOCO; j++) {
                cif[j] = entrada[i + j];
            }
            tdes_bloco(ctx, cif, t, 0);
            for (j = 0u; j < DES_BLOCO; j++) {
                saida[i + j] = (uint8_t)(t[j] ^ ant[j]);
                ant[j]       = cif[j];
            }
        }
    }
    wipe(ant, sizeof ant);
    wipe(cif, sizeof cif);
    wipe(t, sizeof t);
    return 0;
}

void tdes_apaga(tdes_ctx_t *ctx)
{
    wipe(ctx, sizeof *ctx);
}

/* 1 se `b` tem um numero impar de bits em um. Sem desvio. */
static uint8_t impar(uint8_t b)
{
    b ^= (uint8_t)(b >> 4);
    b ^= (uint8_t)(b >> 2);
    b ^= (uint8_t)(b >> 1);
    return (uint8_t)(b & 1u);
}

void des_paridade_ajusta(uint8_t *chave, uint32_t n)
{
    uint32_t i;

    for (i = 0u; i < n; i++) {
        /* Com os 7 bits altos pares, o bit baixo vira 1; senao, 0. */
        chave[i] = (uint8_t)((chave[i] & 0xFEu) |
                             (impar((uint8_t)(chave[i] & 0xFEu)) ^ 1u));
    }
}

int des_paridade_ok(const uint8_t *chave, uint32_t n)
{
    uint32_t i;
    uint8_t  ruim = 0u;

    for (i = 0u; i < n; i++) {
        ruim |= (uint8_t)(impar(chave[i]) ^ 1u);
    }
    return (ruim == 0u) ? 1 : 0;
}


/* As 4 chaves fracas e as 12 semifracas do DES, com paridade impar. Numa
 * chave fraca as 16 subchaves sao iguais, e cifrar duas vezes devolve o
 * texto. As semifracas vem em pares em que uma desfaz a outra. A lista foi
 * conferida por programa, com essas duas propriedades (host/test_des.py). */
static const uint8_t FRACAS[16][DES_CHAVE] = {
    { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
    { 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE },
    { 0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1 },
    { 0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E },
    { 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE },
    { 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01 },
    { 0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1 },
    { 0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E },
    { 0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1 },
    { 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01 },
    { 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE },
    { 0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E },
    { 0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E },
    { 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01 },
    { 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE },
    { 0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1 },
};

/* 1 se as duas chaves DES sao iguais nos 56 bits uteis. Sem desvio. */
static uint8_t iguais56(const uint8_t *a, const uint8_t *b)
{
    uint32_t i;
    uint8_t  dif = 0u;

    for (i = 0u; i < DES_CHAVE; i++) {
        dif |= (uint8_t)((a[i] ^ b[i]) & 0xFEu);
    }
    return (uint8_t)(dif == 0u);
}

int tdes_chave_ruim(const uint8_t *chave, uint32_t n)
{
    uint32_t p, j;
    uint8_t  ruim = 0u;

    if ((n != TDES_CHAVE_2) && (n != TDES_CHAVE_3)) {
        return 1;
    }
    for (p = 0u; p < n; p += DES_CHAVE) {
        for (j = 0u; j < 16u; j++) {
            ruim |= iguais56(&chave[p], FRACAS[j]);
        }
    }
    ruim |= iguais56(&chave[0], &chave[8]);
    if (n == TDES_CHAVE_3) {
        ruim |= iguais56(&chave[8], &chave[16]);
        ruim |= iguais56(&chave[0], &chave[16]);
    }
    return (ruim != 0u) ? 1 : 0;
}
