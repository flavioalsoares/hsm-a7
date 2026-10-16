/* fw/src/audit_log.c -- log de auditoria na flash
 *
 * FRONTEIRA: dentro, sem material de chave. Ver audit_log.h.
 */
#include "audit_log.h"
#include "cmd.h"
#include "flash.h"

#define REG_POR_SUB   (FLASH_SUBSETOR / LOG_REG_LEN)     /* 256 */
#define N_SUB         (LOG_TAMANHO / FLASH_SUBSETOR)     /* 16  */

static uint32_t g_prox;      /* seq do proximo registro */
static int      g_ok;        /* 1 se log_init() achou a flash */

static uint32_t endereco(uint32_t seq)
{
    return LOG_BASE + (seq % LOG_N_REG) * LOG_REG_LEN;
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint32_t crc_reg(const uint8_t r[LOG_REG_LEN])
{
    uint8_t t[11];
    uint8_t i;

    /* bytes 0..6 e 8..11: o resultado (7) fica de fora, ver o header */
    for (i = 0u; i < 7u; i++) {
        t[i] = r[i];
    }
    for (i = 0u; i < 4u; i++) {
        t[7u + i] = r[8u + i];
    }
    return crc32_hsm(t, sizeof t);
}

static int valido(const uint8_t r[LOG_REG_LEN])
{
    return (be32(&r[12]) == crc_reg(r)) ? 1 : 0;
}

void log_init(void)
{
    uint8_t  r[LOG_REG_LEN];
    uint32_t s, j, seq, maior = 0u;
    int      achou = 0;

    g_ok   = 0;
    g_prox = 0u;
    if (!flash_presente()) {
        return;
    }

    /* 1. O primeiro registro de cada subsetor diz qual e o mais novo. */
    for (s = 0u; s < N_SUB; s++) {
        if (flash_le(LOG_BASE + s * FLASH_SUBSETOR, r, LOG_REG_LEN) != 0) {
            return;
        }
        if (valido(r)) {
            seq = be32(r);
            if (!achou || (seq > maior)) {
                maior = seq;
                achou = 1;
            }
        }
    }

    /* 2. Dentro dele, o primeiro buraco e o fim. */
    if (achou) {
        g_prox = maior + 1u;
        for (j = 1u; j < REG_POR_SUB; j++) {
            seq = maior + j;
            if (flash_le(endereco(seq), r, LOG_REG_LEN) != 0) {
                return;
            }
            if (!valido(r) || (be32(r) != seq)) {
                break;
            }
            g_prox = seq + 1u;
        }
    }
    g_ok = 1;
}

int log_registra(uint8_t comando, uint8_t estado, uint8_t argumento,
                 uint32_t *seq)
{
    uint8_t  r[LOG_REG_LEN];
    uint32_t a, c;
    uint8_t  i;

    if (!g_ok) {
        return -1;
    }
    a = endereco(g_prox);

    /* Comeco de subsetor: apagar antes. Os 256 registros mais velhos vao
     * embora aqui -- e o preco do anel. */
    if ((a % FLASH_SUBSETOR) == 0u) {
        if (flash_apaga_4k(a) != 0) {
            return -1;
        }
    }

    r[0] = (uint8_t)(g_prox >> 24);
    r[1] = (uint8_t)(g_prox >> 16);
    r[2] = (uint8_t)(g_prox >> 8);
    r[3] = (uint8_t)g_prox;
    r[4] = comando;
    r[5] = estado;
    r[6] = argumento;
    r[7] = LOG_PENDENTE;
    for (i = 8u; i < 12u; i++) {
        r[i] = 0u;
    }
    c = crc_reg(r);
    r[12] = (uint8_t)(c >> 24);
    r[13] = (uint8_t)(c >> 16);
    r[14] = (uint8_t)(c >> 8);
    r[15] = (uint8_t)c;

    if (flash_grava(a, r, LOG_REG_LEN) != 0) {
        return -1;
    }
    if (seq != 0) {
        *seq = g_prox;
    }
    g_prox++;
    return 0;
}

int log_resultado(uint32_t seq, uint8_t resultado)
{
    if (!g_ok) {
        return -1;
    }
    return flash_grava(endereco(seq) + 7u, &resultado, 1u);
}

uint32_t log_proximo(void)
{
    return g_prox;
}

int log_le(uint32_t seq, uint8_t out[LOG_REG_LEN])
{
    if (!g_ok || (seq >= g_prox) || ((g_prox - seq) > LOG_N_REG)) {
        return -1;
    }
    if (flash_le(endereco(seq), out, LOG_REG_LEN) != 0) {
        return -1;
    }
    if (!valido(out) || (be32(out) != seq)) {
        return -1;
    }
    return 0;
}
