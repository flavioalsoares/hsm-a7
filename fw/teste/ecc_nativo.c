/* fw/teste/ecc_nativo.c -- o ECDSA do firmware, compilado para o PC
 *
 * NAO E FIRMWARE. Este arquivo fica fora de fw/src/ e o Makefile nao o ve.
 * Ele liga fw/src/ecc.c, mont.c e bn.c -- os MESMOS arquivos do firmware --
 * a um modelo em C do coprocessador de Montgomery, e atende comandos pela
 * entrada padrao. Quem o dirige e host/test_ecc.py, com os vetores do CAVP.
 *
 * Para que serve: achar em segundos um erro de formula ou de conta que a
 * simulacao levaria horas para mostrar. O que ele NAO prova: que o C fala
 * certo com o hardware de verdade. Isso e do tb_ecdsa.
 *
 * O modelo do core segue rtl/crypto/rsa_mont.v no que o firmware enxerga:
 * 8 registradores, modulo so de escrita, janela com endereco que anda
 * sozinho, e dst = a * b * R^-1 mod N com a subtracao final.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecc.h"
#include "hsm_cfs.h"
#include "drbg.h"
#include "wipe.h"

#define LIMBS_MAX 128

static uint16_t g_reg[8][LIMBS_MAX];
static uint16_t g_mod[LIMBS_MAX];
static uint16_t g_n0p;
static unsigned long g_produtos, g_limbs;

static uint16_t *janela(uint16_t j)
{
    return (j & 0x400u) ? g_mod : g_reg[(j >> 7) & 7u];
}

void hsm_cfs_rsa_n0p(uint16_t v) { g_n0p = v; }

void hsm_cfs_rsa_escreve(uint16_t j, const uint8_t *be, uint32_t limbs)
{
    uint16_t *r = janela(j);
    uint32_t i;
    for (i = 0; i < limbs; i++) {
        uint32_t p = 2u * (limbs - 1u - i);
        r[i] = (uint16_t)((be[p] << 8) | be[p + 1u]);
    }
    g_limbs += limbs;
}

void hsm_cfs_rsa_le(uint16_t j, uint8_t *be, uint32_t limbs)
{
    uint16_t *r = janela(j);
    uint32_t i;
    if (j & 0x400u) { memset(be, 0, 2u * limbs); return; }   /* so de escrita */
    for (i = 0; i < limbs; i++) {
        uint32_t p = 2u * (limbs - 1u - i);
        be[p] = (uint8_t)(r[i] >> 8);
        be[p + 1u] = (uint8_t)r[i];
    }
    g_limbs += limbs;
}

void hsm_cfs_rsa_escreve_w(uint16_t j, const uint32_t *w, uint32_t palavras)
{
    uint16_t *r = janela(j);
    uint32_t i;
    for (i = 0; i < palavras; i++) {
        r[2u * i] = (uint16_t)w[i];
        r[2u * i + 1u] = (uint16_t)(w[i] >> 16);
    }
    g_limbs += 2u * palavras;
}

void hsm_cfs_rsa_le_w(uint16_t j, uint32_t *w, uint32_t palavras)
{
    uint16_t *r = janela(j);
    uint32_t i;
    for (i = 0; i < palavras; i++) {
        w[i] = (j & 0x400u) ? 0u : ((uint32_t)r[2u * i] | ((uint32_t)r[2u * i + 1u] << 16));
    }
    g_limbs += 2u * palavras;
}

/* CIOS com limbs de 16 bits. Usa n0' como o hardware, para um n0' errado
 * aparecer aqui tambem. */
int hsm_cfs_rsa_mont(unsigned dst, unsigned a, unsigned b, uint32_t len)
{
    uint32_t t[LIMBS_MAX + 2], u[LIMBS_MAX + 1];
    uint32_t i, j;
    uint64_t c;
    int64_t  emp;

    memset(t, 0, sizeof t);
    for (i = 0; i < len; i++) {
        uint32_t m;
        c = 0;
        for (j = 0; j < len; j++) {
            c += (uint64_t)t[j] + (uint64_t)g_reg[a][j] * g_reg[b][i];
            t[j] = (uint32_t)(c & 0xFFFFu);
            c >>= 16;
        }
        c += t[len];
        t[len] = (uint32_t)(c & 0xFFFFu);
        t[len + 1] = (uint32_t)(c >> 16);

        m = (t[0] * g_n0p) & 0xFFFFu;
        c = ((uint64_t)t[0] + (uint64_t)m * g_mod[0]) >> 16;
        for (j = 1; j < len; j++) {
            c += (uint64_t)t[j] + (uint64_t)m * g_mod[j];
            t[j - 1] = (uint32_t)(c & 0xFFFFu);
            c >>= 16;
        }
        c += t[len];
        t[len - 1] = (uint32_t)(c & 0xFFFFu);
        t[len] = t[len + 1] + (uint32_t)(c >> 16);
    }
    /* u = t - N; fica com u se nao houve emprestimo. */
    emp = 0;
    for (j = 0; j < len; j++) {
        int64_t d = (int64_t)t[j] - g_mod[j] + emp;
        u[j] = (uint32_t)(d & 0xFFFF);
        emp = d >> 16;
    }
    emp += t[len];
    for (j = 0; j < len; j++) {
        g_reg[dst][j] = (uint16_t)((emp >= 0) ? u[j] : t[j]);
    }
    g_produtos++;
    return 0;
}

int hsm_cfs_wipe(void)
{
    memset(g_reg, 0, sizeof g_reg);
    memset(g_mod, 0, sizeof g_mod);
    g_n0p = 0;
    return 0;
}

void wipe(void *p, size_t n) { memset(p, 0, n); }

int drbg_dispositivo_bytes(uint8_t *saida, uint32_t n)
{
    static FILE *f;
    if (!f) { f = fopen("/dev/urandom", "rb"); }
    return (f && fread(saida, 1, n, f) == n) ? 0 : -1;
}

static int hex(const char *s, uint8_t *out, size_t n)
{
    size_t i;
    if (strlen(s) != 2 * n) { return -1; }
    for (i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(&s[2 * i], "%2x", &v) != 1) { return -1; }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static void poe(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) { printf("%02x", b[i]); }
}

int main(void)
{
    char linha[1024], cmd[16], a[5][200];
    uint8_t d[32], e[32], k[32], q[64], sig[64], chave[96];

    while (fgets(linha, sizeof linha, stdin)) {
        int n = sscanf(linha, "%15s %199s %199s %199s %199s %199s",
                       cmd, a[0], a[1], a[2], a[3], a[4]);
        int r = -9;
        g_produtos = g_limbs = 0;
        if (!strcmp(cmd, "pub") && n == 2 && !hex(a[0], d, 32)) {
            r = ec_publica(d, q);
            printf("%d ", r); if (!r) { poe(q, 64); }
        } else if (!strcmp(cmd, "sigk") && n == 4 && !hex(a[0], d, 32) &&
                   !hex(a[1], e, 32) && !hex(a[2], k, 32)) {
            r = ecdsa_assina_k(d, e, k, sig);
            printf("%d ", r); if (!r) { poe(sig, 64); }
        } else if (!strcmp(cmd, "ver") && n == 4 && !hex(a[0], q, 64) &&
                   !hex(a[1], e, 32) && !hex(a[2], sig, 64)) {
            r = ecdsa_verifica(q, e, sig);
            printf("%d ", r);
        } else if (!strcmp(cmd, "sign") && n == 3 && !hex(a[0], chave, 96) &&
                   !hex(a[1], e, 32)) {
            r = ecdsa_assina(chave, e, sig);
            printf("%d ", r); if (!r) { poe(sig, 64); }
        } else if (!strcmp(cmd, "gen") && n == 1) {
            r = ecdsa_gera(chave);
            printf("%d ", r); if (!r) { poe(chave, 96); }
        } else {
            printf("? ");
        }
        printf(" # %lu produtos, %lu limbs\n", g_produtos, g_limbs);
        fflush(stdout);
    }
    return 0;
}
