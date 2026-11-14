/* fw/src/rsa.c -- RSA-2048 sobre o produto de Montgomery. Ver fw/include/rsa.h.
 *
 * FRONTEIRA: dentro. A operacao publica so ve dados publicos; a assinatura
 * (`rsa_crt_assina`) recebe a chave privada em claro e opera DENTRO da
 * fronteira. A chave vem do keystore e volta para ele -- este modulo nao
 * guarda nada entre chamadas, e apaga o coprocessador ao terminar.
 *
 * Divisao de trabalho: toda multiplicacao modular, inclusive o produto
 * comum p*q e h*q da recombinacao do CRT, e feita pelo coprocessador. Em
 * C ficam so soma, subtracao, comparacao e a montagem do enchimento.
 */
#include "rsa.h"
#include "hsm_cfs.h"
#include "bn.h"
#include "mont.h"
#include "wipe.h"

#define METADE  (RSA_BYTES / 2u)     /* 128 bytes: p, q, dp, dq, qinv */

/* DigestInfo de SHA-256, RFC 8017, secao 9.2. */
static const uint8_t g_prefixo[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

int rsa_publica(const uint8_t n[RSA_BYTES], uint32_t e,
                const uint8_t s[RSA_BYTES], uint8_t out[RSA_BYTES])
{
    const uint32_t limbs = RSA_BYTES / 2u;
    int b;

    if (((n[0] & 0x80u) == 0u) || ((n[RSA_BYTES - 1u] & 1u) == 0u) ||
        ((e & 1u) == 0u) || (e < 3u) || !bn_menor(s, n, RSA_BYTES)) {
        return -1;
    }
    if (mont_prepara(n, RSA_BYTES, out) != 0) {
        return -1;
    }
    hsm_cfs_rsa_escreve(J_REG(R_BASE), s, limbs);

    if ((hsm_cfs_rsa_mont(R_BASE, R_BASE, R_R2, limbs) != 0) ||
        (hsm_cfs_rsa_mont(R_ACC, R_BASE, R_UM, limbs) != 0) ||
        (hsm_cfs_rsa_mont(R_ACC, R_ACC, R_R2, limbs) != 0)) {
        return -1;
    }

    /* e e publico: pode desviar por bit. A operacao privada nao pode --
     * ver mont_escada() abaixo. */
    b = 31;
    while (((e >> b) & 1u) == 0u) {
        b--;
    }
    for (b = b - 1; b >= 0; b--) {
        if (hsm_cfs_rsa_mont(R_ACC, R_ACC, R_ACC, limbs) != 0) {
            return -1;
        }
        if (((e >> b) & 1u) != 0u) {
            if (hsm_cfs_rsa_mont(R_ACC, R_ACC, R_BASE, limbs) != 0) {
                return -1;
            }
        }
    }

    if (hsm_cfs_rsa_mont(R_ACC, R_ACC, R_UM, limbs) != 0) {
        return -1;
    }
    hsm_cfs_rsa_le(J_REG(R_ACC), out, limbs);
    return 0;
}

/* 00 01 FF..FF 00 DigestInfo digest. */
static void monta_em(const uint8_t digest[RSA_SHA256_LEN], uint8_t em[RSA_BYTES])
{
    uint32_t i, p = RSA_BYTES - RSA_SHA256_LEN - sizeof g_prefixo;

    em[0] = 0x00u;
    em[1] = 0x01u;
    for (i = 2u; i < p - 1u; i++) {
        em[i] = 0xFFu;
    }
    em[p - 1u] = 0x00u;
    for (i = 0u; i < sizeof g_prefixo; i++) {
        em[p + i] = g_prefixo[i];
    }
    for (i = 0u; i < RSA_SHA256_LEN; i++) {
        em[p + sizeof g_prefixo + i] = digest[i];
    }
}

int rsa_verifica(const uint8_t n[RSA_BYTES], uint32_t e,
                 const uint8_t digest[RSA_SHA256_LEN],
                 const uint8_t s[RSA_BYTES])
{
    uint8_t  em[RSA_BYTES], esperado[RSA_BYTES];
    uint32_t i;
    uint8_t  d = 0u;

    if (rsa_publica(n, e, s, em) != 0) {
        return -1;
    }

    /* Reconstroi o EM e compara inteiro: um parser do EM e como nasceu o
     * ataque de Bleichenbacher a assinaturas. */
    monta_em(digest, esperado);
    for (i = 0u; i < RSA_BYTES; i++) {
        d |= (uint8_t)(em[i] ^ esperado[i]);
    }
    return (d == 0u) ? 1 : 0;
}

/* ---------------------------------------------------------------------
 * Operacao privada
 * ------------------------------------------------------------------- */

/* Rascunho da operacao privada. Estatico para nao pesar na pilha;
 * apagado no fim de toda assinatura.
 *
 * FRONTEIRA: dentro. Contem metades da assinatura e valores derivados de
 * p e q enquanto rsa_crt_assina() roda. */
static uint8_t g_em[RSA_BYTES];     /* EM; depois, h*q e a assinatura */
static uint8_t g_a[METADE], g_b[METADE], g_t[METADE], g_sq[METADE];
static uint8_t g_n[RSA_BYTES];

/* x = (a * b) como inteiro, a e b < 2^1024 e o produto < 2^2048 - 1.
 *
 * Feito no coprocessador com o modulo M = 2^2048 - 1. Como R = 2^2048 e
 * congruente a 1 modulo M, o produto de Montgomery a*b*R^-1 mod M e o
 * proprio a*b mod M -- e a*b < M, entao e o inteiro. n0' de M e 1, porque
 * M e congruente a -1 modulo 2^16. */
static int produto_inteiro(const uint8_t a[METADE], const uint8_t b[METADE],
                           uint8_t x[RSA_BYTES])
{
    const uint32_t limbs = RSA_BYTES / 2u;
    uint32_t i;

    for (i = 0u; i < RSA_BYTES; i++) {
        x[i] = 0xFFu;
    }
    hsm_cfs_rsa_n0p(1u);
    hsm_cfs_rsa_escreve(J_MOD, x, limbs);

    for (i = 0u; i < METADE; i++) {
        x[i] = 0u;
        x[METADE + i] = a[i];
    }
    hsm_cfs_rsa_escreve(J_REG(R_BASE), x, limbs);
    for (i = 0u; i < METADE; i++) {
        x[METADE + i] = b[i];
    }
    hsm_cfs_rsa_escreve(J_REG(R_ACC), x, limbs);
    if (hsm_cfs_rsa_mont(R_T, R_BASE, R_ACC, limbs) != 0) {
        return -1;
    }
    hsm_cfs_rsa_le(J_REG(R_T), x, limbs);
    return 0;
}

/* Metade do CRT: s = em^d mod m, com m = p ou q.
 *
 * em tem 2048 bits e m, 1024. A reducao tambem e do coprocessador, sem
 * divisao: com R = 2^1024 e em = hi*R + lo, a representacao de Montgomery
 * de em e hi*R^2 + lo*R mod m = Mont(hi, R^3) + Mont(lo, R^2). hi e lo
 * podem passar de m; o produto de Montgomery aceita isso desde que o outro
 * fator seja menor que m.
 *
 * `mont` != 0 devolve s na representacao de Montgomery; senao, normal. */
static int metade(const uint8_t *m, const uint8_t *d, uint8_t s[METADE], int mont)
{
    const uint32_t limbs = METADE / 2u;

    if (mont_prepara(m, METADE, g_t) != 0) {
        return -1;
    }
    /* R_T = R^3 = Mont(R^2, R^2). */
    hsm_cfs_rsa_escreve(J_REG(R_BASE), &g_em[0], limbs);
    hsm_cfs_rsa_escreve(J_REG(R_ACC), &g_em[METADE], limbs);
    if ((hsm_cfs_rsa_mont(R_T, R_R2, R_R2, limbs) != 0) ||
        (hsm_cfs_rsa_mont(R_BASE, R_BASE, R_T, limbs) != 0) ||
        (hsm_cfs_rsa_mont(R_ACC, R_ACC, R_R2, limbs) != 0)) {
        return -1;
    }
    hsm_cfs_rsa_le(J_REG(R_BASE), g_a, limbs);
    hsm_cfs_rsa_le(J_REG(R_ACC), g_b, limbs);
    bn_soma_mod(g_a, g_b, m, g_t, METADE);          /* em*R mod m */

    /* A escada quer a base em forma normal: tira o R com um produto por 1. */
    hsm_cfs_rsa_escreve(J_REG(R_BASE), g_a, limbs);
    if ((hsm_cfs_rsa_mont(R_BASE, R_BASE, R_UM, limbs) != 0) ||
        (mont_escada(d, METADE) != 0)) {
        return -1;
    }
    if (!mont) {
        if (hsm_cfs_rsa_mont(R_X, R_X, R_UM, limbs) != 0) {
            return -1;
        }
    }
    hsm_cfs_rsa_le(J_REG(R_X), s, limbs);
    return 0;
}

int rsa_crt_assina(const uint8_t chave[RSA_CHAVE_PRIV],
                   const uint8_t digest[RSA_SHA256_LEN],
                   uint8_t sig[RSA_BYTES])
{
    const uint8_t *p    = &chave[4];
    const uint8_t *q    = &chave[4u + METADE];
    const uint8_t *dp   = &chave[4u + 2u * METADE];
    const uint8_t *dq   = &chave[4u + 3u * METADE];
    const uint8_t *qinv = &chave[4u + 4u * METADE];
    const uint32_t limbs = METADE / 2u;
    uint32_t e, i;
    int      r = -1;

    e = ((uint32_t)chave[0] << 24) | ((uint32_t)chave[1] << 16) |
        ((uint32_t)chave[2] << 8) | chave[3];
    if (((p[0] & 0x80u) == 0u) || ((q[0] & 0x80u) == 0u) ||
        ((p[METADE - 1u] & 1u) == 0u) || ((q[METADE - 1u] & 1u) == 0u) ||
        ((e & 1u) == 0u) || (e < 3u)) {
        goto fim;
    }

    monta_em(digest, g_em);

    /* sq = em^dq mod q, em forma normal. */
    if (metade(q, dq, g_a, 0) != 0) {
        goto fim;
    }
    for (i = 0u; i < METADE; i++) {
        g_sq[i] = g_a[i];
    }

    /* sp~ = em^dp mod p, em Montgomery. sq~ = sq mod p, em Montgomery
     * (sq < 2^1024 = R, entao um produto por R^2 basta). sq vem de g_sq:
     * metade() usa g_a e g_b como rascunho. */
    if (metade(p, dp, g_b, 1) != 0) {
        goto fim;
    }
    hsm_cfs_rsa_escreve(J_REG(R_BASE), g_sq, limbs);
    if (hsm_cfs_rsa_mont(R_BASE, R_BASE, R_R2, limbs) != 0) {
        goto fim;
    }
    hsm_cfs_rsa_le(J_REG(R_BASE), g_a, limbs);

    /* h = qinv * (sp - sq) mod p. O produto de Montgomery de (sp - sq)~
     * por qinv em forma normal ja da h em forma normal. */
    bn_subtrai_mod(g_b, g_a, p, g_t, METADE);
    hsm_cfs_rsa_escreve(J_REG(R_BASE), g_b, limbs);
    hsm_cfs_rsa_escreve(J_REG(R_ACC), qinv, limbs);
    if (hsm_cfs_rsa_mont(R_T, R_BASE, R_ACC, limbs) != 0) {
        goto fim;
    }
    hsm_cfs_rsa_le(J_REG(R_T), g_a, limbs);

    /* s = sq + h*q, e n = p*q para verificar. O EM ja nao e preciso: o
     * buffer dele recebe h*q. A soma nao transborda, porque s < n. */
    if ((produto_inteiro(g_a, q, g_em) != 0) ||
        (produto_inteiro(p, q, g_n) != 0)) {
        goto fim;
    }
    if (bn_soma(&g_em[METADE], g_sq, METADE) != 0u) {
        for (i = METADE; i > 0u; i--) {
            g_em[i - 1u] = (uint8_t)(g_em[i - 1u] + 1u);
            if (g_em[i - 1u] != 0u) {
                break;
            }
        }
    }

    /* Verificar ANTES de emitir: e a contramedida do ataque Bellcore
     * (manual, secao 17.1). Uma metade errada por falha induzida da uma
     * assinatura que fatora n -- ela nao sai. A verificacao usa e, por
     * outro caminho, e e a segunda conta do que vai ao host. */
    if (rsa_verifica(g_n, e, digest, g_em) != 1) {
        r = -2;
        goto fim;
    }
    for (i = 0u; i < RSA_BYTES; i++) {
        sig[i] = g_em[i];
    }
    r = 0;

fim:
    wipe(g_em, sizeof g_em);
    wipe(g_a, sizeof g_a);
    wipe(g_b, sizeof g_b);
    wipe(g_t, sizeof g_t);
    wipe(g_sq, sizeof g_sq);
    wipe(g_n, sizeof g_n);
    (void)hsm_cfs_wipe();
    return r;
}

/* ---------------------------------------------------------------------
 * Geracao de chave -- FIPS 186-5, Apendice A.1.3 (primos provaveis)
 *
 * p e q de 1024 bits, e = 65537, 5 rodadas de Miller-Rabin (Tabela B.1:
 * erro de 2^-112, a forca de seguranca do RSA-2048). Os dois bits altos
 * de cada candidato vao a 1 (passo 4.2.1), o que ja garante
 * p >= sqrt(2) * 2^1023 (passo 4.4).
 *
 * Toda exponenciacao e da escada, no coprocessador. Em C ficam a divisao
 * por primos pequenos, as comparacoes e o calculo de dp e dq, que so
 * envolve numeros pequenos (e).
 *
 * Desvio de tempo: um candidato COMPOSTO e descartado assim que se revela,
 * e isso leva tempo variavel. O tempo nao diz nada sobre o primo aceito,
 * porque cada candidato e sorteado de novo, independente dos anteriores.
 * ------------------------------------------------------------------- */
#include "drbg.h"

#define RSA_MR_RODADAS  5u

/* x mod k, para k < 2^23. */
static uint32_t mod_pequeno(const uint8_t *x, uint32_t n, uint32_t k)
{
    uint32_t i, r = 0u;

    for (i = 0u; i < n; i++) {
        r = ((r << 8) | x[i]) % k;
    }
    return r;
}

/* Miller-Rabin, FIPS 186-5 B.3.1, sobre w de 1024 bits com o bit alto
 * ligado. 1 = provavelmente primo, 0 = composto, -1 = falha. Usa g_a (base
 * e z), g_b (m), g_sq (1 em Montgomery) e g_n (w - 1 em Montgomery). */
static int miller_rabin(const uint8_t w[METADE])
{
    const uint32_t limbs = METADE / 2u;
    uint8_t  *um = g_sq, *menos_um = g_n;
    uint32_t  a = 0u, i, j, rodada;

    if (mont_prepara(w, METADE, g_t) != 0) {
        return -1;
    }
    /* 1 e w - 1 na representacao de Montgomery: R mod w, e w - (R mod w). */
    if (hsm_cfs_rsa_mont(R_T, R_UM, R_R2, limbs) != 0) {
        return -1;
    }
    hsm_cfs_rsa_le(J_REG(R_T), um, limbs);
    for (i = 0u; i < METADE; i++) {
        menos_um[i] = w[i];
    }
    (void)bn_subtrai(menos_um, um, METADE);

    /* w - 1 = 2^a * m. w e impar: basta zerar o bit baixo e deslocar. */
    for (i = 0u; i < METADE; i++) {
        g_b[i] = w[i];
    }
    g_b[METADE - 1u] &= 0xFEu;
    while ((g_b[METADE - 1u] & 1u) == 0u) {
        uint32_t vem = 0u;
        for (i = 0u; i < METADE; i++) {
            uint32_t v = g_b[i];
            g_b[i] = (uint8_t)((v >> 1) | vem);
            vem = (v & 1u) << 7;
        }
        a++;
    }

    /* w - 1 comum, para sortear a base. */
    for (i = 0u; i < METADE; i++) {
        g_t[i] = w[i];
    }
    g_t[METADE - 1u] &= 0xFEu;

    for (rodada = 0u; rodada < RSA_MR_RODADAS; rodada++) {
        /* Passos 4.1 e 4.2: b com o tamanho de w; se b <= 1 ou b >= w - 1,
         * sorteia de novo. */
        for (;;) {
            uint8_t alto = 0u;
            if (drbg_dispositivo_bytes(g_a, METADE) != 0) {
                return -1;
            }
            for (i = 0u; i < METADE - 1u; i++) {
                alto |= g_a[i];
            }
            alto |= (uint8_t)(g_a[METADE - 1u] & 0xFEu);
            if ((alto != 0u) && bn_menor(g_a, g_t, METADE)) {
                break;
            }
        }
        hsm_cfs_rsa_escreve(J_REG(R_BASE), g_a, limbs);

        /* z = b^m mod w, em Montgomery, em R_X. */
        if (mont_escada(g_b, METADE) != 0) {
            return -1;
        }
        hsm_cfs_rsa_le(J_REG(R_X), g_a, limbs);
        if (bn_iguais(g_a, um, METADE) || bn_iguais(g_a, menos_um, METADE)) {
            continue;
        }
        for (j = 1u; j < a; j++) {
            if (hsm_cfs_rsa_mont(R_X, R_X, R_X, limbs) != 0) {
                return -1;
            }
            hsm_cfs_rsa_le(J_REG(R_X), g_a, limbs);
            if (bn_iguais(g_a, menos_um, METADE)) {
                break;
            }
            if (bn_iguais(g_a, um, METADE)) {
                return 0;
            }
        }
        if (j == a) {
            return 0;
        }
    }
    return 1;
}

/* Um primo de 1024 bits em `p`. Com `outro`, exige |p - outro| > 2^924
 * (passo 5.5; aqui um pouco mais estrito: algum bit acima do 924). */
static int primo(uint8_t p[METADE], const uint8_t *outro, uint32_t e,
                 uint32_t limite)
{
    uint32_t i, k;
    int      r;

    for (i = 0u; i < limite; i++) {
        if (drbg_dispositivo_bytes(p, METADE) != 0) {
            return -1;
        }
        p[0] |= 0xC0u;
        p[METADE - 1u] |= 0x01u;

        if (outro != 0) {
            uint8_t acc = 0u;
            for (k = 0u; k < METADE; k++) {
                g_t[k] = p[k];
            }
            if (bn_subtrai(g_t, outro, METADE) != 0u) {
                for (k = 0u; k < METADE; k++) {
                    g_t[k] = outro[k];
                }
                (void)bn_subtrai(g_t, p, METADE);
            }
            for (k = 0u; k < 12u; k++) {
                acc |= g_t[k];
            }
            acc |= (uint8_t)(g_t[12] & 0xE0u);      /* bits 927..925 */
            if (acc == 0u) {
                continue;
            }
        }

        /* Divisao por todo impar ate 1023: descarta ~84% dos candidatos
         * antes de gastar uma exponenciacao. */
        for (k = 3u; k < 1024u; k += 2u) {
            if (mod_pequeno(p, METADE, k) == 0u) {
                break;
            }
        }
        if (k < 1024u) {
            continue;
        }
        /* mdc(p - 1, e) = 1. e e primo: basta p - 1 nao ser multiplo dele. */
        if (mod_pequeno(p, METADE, e) == 1u) {
            continue;
        }
        r = miller_rabin(p);
        if (r < 0) {
            return -1;
        }
        if (r == 1) {
            return 0;
        }
    }
    return -1;
}

/* Inverso de a modulo m, numeros pequenos. a e m coprimos. */
static uint32_t inverso_pequeno(uint32_t a, uint32_t m)
{
    int32_t t = 0, t1 = 1, r = (int32_t)m, r1 = (int32_t)a, q, x;

    while (r1 != 0) {
        q = r / r1;
        x = t - q * t1;  t = t1;  t1 = x;
        x = r - q * r1;  r = r1;  r1 = x;
    }
    return (uint32_t)((t < 0) ? (t + (int32_t)m) : t);
}

/* d mod (p - 1) = e^-1 mod (p - 1), sem dividir numero grande por numero
 * grande: com k = -(p - 1)^-1 mod e, 1 + k(p - 1) e multiplo de e, e o
 * quociente e o inverso procurado. So conta com e, que e pequeno. */
static void exp_crt(const uint8_t p[METADE], uint32_t e, uint8_t d[METADE])
{
    uint32_t r, k, i, vai, acc;

    r = (mod_pequeno(p, METADE, e) + e - 1u) % e;      /* (p - 1) mod e */
    k = (e - inverso_pequeno(r, e)) % e;

    /* g_em = (p - 1) * k + 1, em 132 bytes. */
    vai = 1u;
    for (i = METADE; i > 0u; i--) {
        uint32_t v = (i == METADE) ? (uint32_t)(p[i - 1u] & 0xFEu) : p[i - 1u];
        v = v * k + vai;
        g_em[3u + i] = (uint8_t)v;
        vai = v >> 8;
    }
    g_em[3] = (uint8_t)vai;
    g_em[2] = (uint8_t)(vai >> 8);
    g_em[1] = (uint8_t)(vai >> 16);
    g_em[0] = 0u;

    /* / e, divisao longa por numero pequeno. Cabe em 128 bytes. */
    acc = 0u;
    for (i = 0u; i < METADE + 4u; i++) {
        acc = (acc << 8) | g_em[i];
        if (i >= 4u) {
            d[i - 4u] = (uint8_t)(acc / e);
        }
        acc %= e;
    }
}

int rsa_primo_provavel(const uint8_t w[METADE])
{
    int r = -1;

    if (((w[0] & 0x80u) != 0u) && ((w[METADE - 1u] & 1u) != 0u)) {
        r = miller_rabin(w);
    }
    wipe(g_a, sizeof g_a);
    wipe(g_b, sizeof g_b);
    wipe(g_t, sizeof g_t);
    wipe(g_sq, sizeof g_sq);
    wipe(g_n, sizeof g_n);
    (void)hsm_cfs_wipe();
    return r;
}

int rsa_gera(uint8_t chave[RSA_CHAVE_PRIV], uint8_t n[RSA_BYTES])
{
    uint8_t *p    = &chave[4];
    uint8_t *q    = &chave[4u + METADE];
    uint8_t *dp   = &chave[4u + 2u * METADE];
    uint8_t *dq   = &chave[4u + 3u * METADE];
    uint8_t *qinv = &chave[4u + 4u * METADE];
    const uint32_t limbs = METADE / 2u, e = RSA_E_PADRAO;
    uint32_t i;
    int      r = -1;

    chave[0] = (uint8_t)(e >> 24);
    chave[1] = (uint8_t)(e >> 16);
    chave[2] = (uint8_t)(e >> 8);
    chave[3] = (uint8_t)e;

    /* Limites de tentativa do A.1.3: 5 * nlen para p, 10 * nlen para q. */
    if ((primo(p, 0, e, 5u * 2048u) != 0) || (primo(q, p, e, 10u * 2048u) != 0)) {
        goto fim;
    }
    exp_crt(p, e, dp);
    exp_crt(q, e, dq);

    /* qinv = q^(p-2) mod p, pelo pequeno teorema de Fermat: tambem na
     * escada, porque p e segredo. */
    if (mont_prepara(p, METADE, g_t) != 0) {
        goto fim;
    }
    for (i = 0u; i < METADE; i++) {
        g_b[i] = p[i];
        g_a[i] = 0u;
    }
    g_a[METADE - 1u] = 2u;
    (void)bn_subtrai(g_b, g_a, METADE);                       /* p - 2 */
    hsm_cfs_rsa_escreve(J_REG(R_BASE), q, limbs);
    if ((mont_escada(g_b, METADE) != 0) ||
        (hsm_cfs_rsa_mont(R_X, R_X, R_UM, limbs) != 0)) {
        goto fim;
    }
    hsm_cfs_rsa_le(J_REG(R_X), qinv, limbs);

    if (produto_inteiro(p, q, n) != 0) {
        goto fim;
    }
    r = 0;
fim:
    wipe(g_em, sizeof g_em);
    wipe(g_a, sizeof g_a);
    wipe(g_b, sizeof g_b);
    wipe(g_t, sizeof g_t);
    wipe(g_sq, sizeof g_sq);
    wipe(g_n, sizeof g_n);
    (void)hsm_cfs_wipe();
    if (r != 0) {
        wipe(chave, RSA_CHAVE_PRIV);
    }
    return r;
}
