/* fw/src/persist.c -- o registro persistente: LMK, estado e slots
 *
 * FRONTEIRA: dentro. O buffer deste arquivo carrega a LMK em claro
 * enquanto um registro e montado ou lido, e e zerado ao fim de cada uso.
 * Ver persist.h.
 */
#include "persist.h"
#include "cmd.h"
#include "flash.h"
#include "keystore.h"
#include "wipe.h"

#define CAB_LEN   16u
#define CRC_LEN    4u
#define VERSAO     1u

static uint8_t  g_reg[CAB_LEN + KS_REGISTRO_MAX + CRC_LEN];
static uint8_t  g_conf[FLASH_PAGINA];     /* conferencia da gravacao */
static uint32_t g_contador;               /* maior contador visto */

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void poe32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Le o cabecalho de uma copia. Devolve o comprimento total do registro
 * (cabecalho + corpo + crc), ou 0 se nao parece um registro. */
static uint32_t le_cabecalho(uint32_t base, uint8_t cab[CAB_LEN])
{
    uint32_t corpo;

    if (flash_le(base, cab, CAB_LEN) != 0) {
        return 0u;
    }
    if ((cab[0] != 'H') || (cab[1] != 'S') || (cab[2] != 'M') ||
        (cab[3] != '4') || (cab[4] != VERSAO)) {
        return 0u;
    }
    corpo = ((uint32_t)cab[6] << 8) | cab[7];
    if (corpo > KS_REGISTRO_MAX) {
        return 0u;
    }
    return CAB_LEN + corpo + CRC_LEN;
}

/* Le o registro inteiro para g_reg e confere o CRC. */
static int le_inteiro(uint32_t base, uint32_t total)
{
    if (flash_le(base, g_reg, total) != 0) {
        return -1;
    }
    return (crc32_hsm(g_reg, total - CRC_LEN) == be32(&g_reg[total - CRC_LEN]))
           ? 0 : -1;
}

int persist_salva(hsm_state_t estado)
{
    uint32_t corpo = 0u, total, base, i, k, pedaco;
    uint32_t novo = g_contador + 1u;
    int      r = -1;

    if (!flash_presente()) {
        return -1;
    }
    if (keystore_registro_monta(&g_reg[CAB_LEN], KS_REGISTRO_MAX, &corpo) != 0) {
        goto fim;
    }

    g_reg[0] = 'H'; g_reg[1] = 'S'; g_reg[2] = 'M'; g_reg[3] = '4';
    g_reg[4] = VERSAO;
    g_reg[5] = (uint8_t)estado;
    g_reg[6] = (uint8_t)(corpo >> 8);
    g_reg[7] = (uint8_t)corpo;
    poe32(&g_reg[8], novo);
    poe32(&g_reg[12], 0u);
    total = CAB_LEN + corpo;
    poe32(&g_reg[total], crc32_hsm(g_reg, total));
    total += CRC_LEN;

    /* A copia mais velha. A outra fica intacta ate esta estar conferida. */
    base = (novo & 1u) ? PERSIST_COPIA_B : PERSIST_COPIA_A;

    if (flash_apaga_4k(base) != 0) {
        goto fim;
    }
    if (flash_grava(base, g_reg, total) != 0) {
        goto fim;
    }

    /* Conferir lendo de volta. Uma gravacao que reportou sucesso e nao
     * gravou faria o dispositivo perder a chave no proximo boot -- e
     * dizer que tinha guardado. */
    for (i = 0u; i < total; i += pedaco) {
        pedaco = total - i;
        if (pedaco > FLASH_PAGINA) {
            pedaco = FLASH_PAGINA;
        }
        if (flash_le(base + i, g_conf, pedaco) != 0) {
            goto fim;
        }
        for (k = 0u; k < pedaco; k++) {
            if (g_conf[k] != g_reg[i + k]) {
                goto fim;
            }
        }
    }

    g_contador = novo;
    r = 0;

fim:
    wipe(g_reg, sizeof g_reg);
    wipe(g_conf, sizeof g_conf);
    return r;
}

hsm_state_t persist_restaura(uint8_t *achou)
{
    uint8_t     cab_a[CAB_LEN], cab_b[CAB_LEN];
    uint32_t    tot_a, tot_b, cont_a = 0u, cont_b = 0u;
    uint32_t    ordem[2], tot[2];
    hsm_state_t est = HSM_UNINITIALIZED;
    uint8_t     q;
    int         n = 0, i;

    *achou = 0u;
    keystore_init();
    g_contador = 0u;

    tot_a = le_cabecalho(PERSIST_COPIA_A, cab_a);
    tot_b = le_cabecalho(PERSIST_COPIA_B, cab_b);
    if (tot_a) { cont_a = be32(&cab_a[8]); }
    if (tot_b) { cont_b = be32(&cab_b[8]); }

    /* O contador continua de onde estava mesmo que nenhuma copia se
     * restaure -- senao a proxima gravacao poderia ir para a copia boa. */
    g_contador = (cont_a > cont_b) ? cont_a : cont_b;

    /* Mais nova primeiro. */
    if (tot_a && (!tot_b || (cont_a >= cont_b))) {
        ordem[n] = PERSIST_COPIA_A; tot[n++] = tot_a;
        if (tot_b) { ordem[n] = PERSIST_COPIA_B; tot[n++] = tot_b; }
    } else if (tot_b) {
        ordem[n] = PERSIST_COPIA_B; tot[n++] = tot_b;
        if (tot_a) { ordem[n] = PERSIST_COPIA_A; tot[n++] = tot_a; }
    }
    if (n == 0) {
        return HSM_UNINITIALIZED;
    }

    *achou = 2u;
    for (i = 0; i < n; i++) {
        if (le_inteiro(ordem[i], tot[i]) != 0) {
            continue;
        }
        q = g_reg[5];
        if ((q != (uint8_t)HSM_AUTHORIZED) && (q != (uint8_t)HSM_OPERATIONAL)) {
            continue;
        }
        if (keystore_registro_carrega(&g_reg[CAB_LEN],
                                      tot[i] - CAB_LEN - CRC_LEN) != 0) {
            continue;
        }
        est    = (hsm_state_t)q;
        *achou = 1u;

        /* A proxima gravacao NAO pode cair em cima da copia que acabou de
         * ser restaurada -- ela pode ser a unica boa. O contador escolhe a
         * copia pela paridade; se ela apontar para esta, pula um. */
        if ((((g_contador + 1u) & 1u) != 0u) == (ordem[i] == PERSIST_COPIA_B)) {
            g_contador++;
        }
        break;
    }
    wipe(g_reg, sizeof g_reg);
    return est;
}

int persist_apaga(void)
{
    int r = 0;

    if (!flash_presente()) {
        return -1;
    }
    if (flash_apaga_4k(PERSIST_COPIA_A) != 0) { r = -1; }
    if (flash_apaga_4k(PERSIST_COPIA_B) != 0) { r = -1; }
    return r;
}
