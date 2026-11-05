/* fw/src/ambiente.c -- ver ambiente.h */
#include <stdint.h>

#include "ambiente.h"
#include "audit_log.h"
#include "hsm_cfs.h"
#include "hsm_status.h"
#include "keystore.h"
#include "persist.h"
#include "state.h"

/* Bem mais que os ~200 us ate a primeira leitura; o POST ja gastou 9 ms. */
#define ESPERA_LEITURAS  200000u

/* Causas ja respondidas neste boot. */
static uint8_t g_respondido;

/* FRONTEIRA: dentro. Manda apagar; nao ve a chave. */
static void responde(uint8_t causa)
{
    uint32_t seq    = 0u;
    uint8_t  antes  = (uint8_t)state_get();
    int      logado;
    int      flash;

    g_respondido |= causa;

    /* Se a prova da zeroizacao falhar nao ha o que fazer alem do que ja
     * vem a seguir: TAMPERED e o estado para quem nao sabe o que sobrou. */
    (void)keystore_zeroiza_tudo();
    state_set(HSM_TAMPERED);

    logado = (log_registra(LOG_CMD_TAMPER, antes, causa, &seq) == 0);
    flash  = persist_apaga();
    if (logado) {
        (void)log_resultado(seq, (flash == 0) ? (uint8_t)STATUS_OK
                                              : (uint8_t)STATUS_STORE_FAIL);
    }
}

int ambiente_boot(void)
{
    hsm_env_t e;
    uint32_t  i;

    hsm_env_le(&e);
    for (i = 0u; (i < ESPERA_LEITURAS) && !e.valido; i++) {
        hsm_env_le(&e);
    }

    if (!e.valido) {
        e.retido |= HSM_ENV_SENSOR;
    }
    if (e.retido == 0u) {
        return 0;
    }
    responde(e.retido);
    return 1;
}

int ambiente_poll(void)
{
    hsm_env_t e;
    uint8_t   nova;

    hsm_env_le(&e);
    nova = (uint8_t)(e.retido & (uint8_t)~g_respondido);
    if (nova == 0u) {
        return 0;
    }
    responde(nova);
    return 1;
}
