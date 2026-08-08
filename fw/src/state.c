/* fw/src/state.c -- maquina de estados do HSM
 *
 * FRONTEIRA: dentro. Nao toca material de chave, mas decide quem pode.
 */
#include "state.h"

/* Fase 1: o dispositivo nasce e permanece em UNINITIALIZED. As transicoes
 * chegam na fase 3 com a cerimonia de LMK. */
static hsm_state_t g_state;

void state_init(void)
{
    g_state = HSM_UNINITIALIZED;
}

void state_set(hsm_state_t s)
{
    /* TAMPERED e absorvente. Ver state.h. */
    if (g_state == HSM_TAMPERED) {
        return;
    }
    g_state = s;
}

hsm_state_t state_get(void)
{
    return g_state;
}

uint32_t state_mask(void)
{
    return 1u << (uint32_t)g_state;
}

const char *state_name(hsm_state_t s)
{
    /* Os mnemonicos batem com o que o display de 7 segmentos mostrara na
     * fase 3: Uni / Aut / OPE / tPr. Manter os dois em sincronia. */
    switch (s) {
        case HSM_UNINITIALIZED: return "Uni";
        case HSM_AUTHORIZED:    return "Aut";
        case HSM_OPERATIONAL:   return "OPE";
        case HSM_TAMPERED:      return "tPr";
        default:                return "???";
    }
}
