/* fw/src/rsa.c -- exponenciacao RSA-2048. Ver fw/include/rsa.h.
 *
 * FRONTEIRA: dentro. So dados publicos passam por aqui, por enquanto.
 */
#include "rsa.h"
#include "hsm_cfs.h"

#define LIMBS   (RSA_BYTES / 2u)
#define J_REG(r) ((uint16_t)((r) << 7))
#define J_MOD   0x400u

/* Registradores do core. */
#define R_BASE  0u
#define R_ACC   1u
#define R_R2    2u
#define R_UM    3u

/* DigestInfo de SHA-256, RFC 8017, secao 9.2. */
static const uint8_t g_prefixo[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

/* -n^-1 mod 2^16, por Newton: cada passo dobra os bits certos. */
static uint16_t n0_linha(uint16_t n0)
{
    uint32_t x = 1u;
    unsigned i;

    for (i = 0u; i < 4u; i++) {
        x = (x * (2u - (uint32_t)n0 * x)) & 0xFFFFu;
    }
    return (uint16_t)(0u - x);
}

/* a < b, comparando big-endian. */
static int menor(const uint8_t *a, const uint8_t *b)
{
    uint32_t i;

    for (i = 0u; i < RSA_BYTES; i++) {
        if (a[i] != b[i]) {
            return (a[i] < b[i]) ? 1 : 0;
        }
    }
    return 0;
}

/* x = x - n, big-endian. */
static void subtrai(uint8_t *x, const uint8_t *n)
{
    uint32_t i, emprestimo = 0u, d;

    for (i = RSA_BYTES; i > 0u; i--) {
        d = (uint32_t)x[i - 1u] - n[i - 1u] - emprestimo;
        x[i - 1u] = (uint8_t)d;
        emprestimo = (d >> 8) & 1u;
    }
}

/* x = 2R mod n, com R = 2^2048. Como n tem o bit alto ligado, R - n < n. */
static void dois_r(const uint8_t *n, uint8_t *x)
{
    uint32_t i, vai;

    for (i = 0u; i < RSA_BYTES; i++) {
        x[i] = 0u;
    }
    subtrai(x, n);                  /* 0 - n = R - n, em 2048 bits */
    vai = 0u;
    for (i = RSA_BYTES; i > 0u; i--) {
        uint32_t d = ((uint32_t)x[i - 1u] << 1) | vai;
        x[i - 1u] = (uint8_t)d;
        vai = d >> 8;
    }
    if ((vai != 0u) || !menor(x, n)) {
        subtrai(x, n);
    }
}

int rsa_publica(const uint8_t n[RSA_BYTES], uint32_t e,
                const uint8_t s[RSA_BYTES], uint8_t out[RSA_BYTES])
{
    uint8_t um[RSA_BYTES];
    uint32_t i;
    int      b;

    if (((n[0] & 0x80u) == 0u) || ((n[RSA_BYTES - 1u] & 1u) == 0u) ||
        ((e & 1u) == 0u) || (e < 3u) || !menor(s, n)) {
        return -1;
    }

    hsm_cfs_rsa_n0p(n0_linha((uint16_t)(((uint16_t)n[RSA_BYTES - 2u] << 8) |
                                        n[RSA_BYTES - 1u])));
    hsm_cfs_rsa_escreve(J_MOD, n, LIMBS);

    /* R^2 mod n: 2R, e cada produto dobra o expoente. 2^(2^11) = R. */
    dois_r(n, out);
    hsm_cfs_rsa_escreve(J_REG(R_R2), out, LIMBS);
    for (i = 0u; i < 11u; i++) {
        if (hsm_cfs_rsa_mont(R_R2, R_R2, R_R2, LIMBS) != 0) {
            return -1;
        }
    }

    for (i = 0u; i < RSA_BYTES; i++) {
        um[i] = 0u;
    }
    um[RSA_BYTES - 1u] = 1u;
    hsm_cfs_rsa_escreve(J_REG(R_UM), um, LIMBS);
    hsm_cfs_rsa_escreve(J_REG(R_BASE), s, LIMBS);

    if ((hsm_cfs_rsa_mont(R_BASE, R_BASE, R_R2, LIMBS) != 0) ||
        (hsm_cfs_rsa_mont(R_ACC, R_BASE, R_UM, LIMBS) != 0) ||
        (hsm_cfs_rsa_mont(R_ACC, R_ACC, R_R2, LIMBS) != 0)) {
        return -1;
    }

    /* e e publico: pode desviar por bit. A operacao privada nao pode. */
    b = 31;
    while (((e >> b) & 1u) == 0u) {
        b--;
    }
    for (b = b - 1; b >= 0; b--) {
        if (hsm_cfs_rsa_mont(R_ACC, R_ACC, R_ACC, LIMBS) != 0) {
            return -1;
        }
        if (((e >> b) & 1u) != 0u) {
            if (hsm_cfs_rsa_mont(R_ACC, R_ACC, R_BASE, LIMBS) != 0) {
                return -1;
            }
        }
    }

    if (hsm_cfs_rsa_mont(R_ACC, R_ACC, R_UM, LIMBS) != 0) {
        return -1;
    }
    hsm_cfs_rsa_le(J_REG(R_ACC), out, LIMBS);
    return 0;
}

int rsa_verifica(const uint8_t n[RSA_BYTES], uint32_t e,
                 const uint8_t digest[RSA_SHA256_LEN],
                 const uint8_t s[RSA_BYTES])
{
    uint8_t  em[RSA_BYTES];
    uint32_t i, p;
    uint8_t  d = 0u;

    if (rsa_publica(n, e, s, em) != 0) {
        return -1;
    }

    /* 00 01 FF..FF 00 DigestInfo digest. Reconstroi e compara inteiro: um
     * parser do EM e como nasceu o ataque de Bleichenbacher a assinaturas. */
    p = RSA_BYTES - RSA_SHA256_LEN - sizeof g_prefixo;
    d |= em[0];
    d |= (uint8_t)(em[1] ^ 0x01u);
    for (i = 2u; i < p - 1u; i++) {
        d |= (uint8_t)(em[i] ^ 0xFFu);
    }
    d |= em[p - 1u];
    for (i = 0u; i < sizeof g_prefixo; i++) {
        d |= (uint8_t)(em[p + i] ^ g_prefixo[i]);
    }
    for (i = 0u; i < RSA_SHA256_LEN; i++) {
        d |= (uint8_t)(em[p + sizeof g_prefixo + i] ^ digest[i]);
    }
    return (d == 0u) ? 1 : 0;
}
