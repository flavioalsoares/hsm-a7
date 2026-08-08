/* fw/include/state.h -- maquina de estados do HSM
 *
 * FRONTEIRA: dentro. O estado decide o que a fronteira deixa passar.
 *
 *   UNINITIALIZED --LMK completa--> AUTHORIZED --ativar--> OPERATIONAL
 *         ^                              |                      |
 *         +---------- zeroize -----------+--- tamper/zeroize ---+
 *                                        v
 *                                    TAMPERED
 *
 * Fase 1 implementa apenas o enum e a consulta: o dispositivo nasce e fica
 * em UNINITIALIZED. As transicoes chegam na fase 3, junto com a cerimonia
 * de LMK. Existe desde ja porque a tabela de comandos carrega a mascara de
 * estados permitidos -- e mais barato acertar isso agora do que retroajustar
 * cada handler depois.
 */
#ifndef STATE_H
#define STATE_H

#include <stdint.h>

typedef enum {
    HSM_UNINITIALIZED = 0,
    HSM_AUTHORIZED    = 1,
    HSM_OPERATIONAL   = 2,
    HSM_TAMPERED      = 3
} hsm_state_t;

/* Mascaras para a tabela de comandos */
#define ST_UNINIT       (1u << HSM_UNINITIALIZED)
#define ST_AUTH         (1u << HSM_AUTHORIZED)
#define ST_OPER         (1u << HSM_OPERATIONAL)
#define ST_TAMPERED     (1u << HSM_TAMPERED)

/* Estados em que um comando puramente informativo pode rodar.
 * TAMPERED fica DE FORA de proposito: um dispositivo comprometido responde
 * o minimo possivel. */
#define ST_NORMAL       (ST_UNINIT | ST_AUTH | ST_OPER)

void        state_init(void);

/* Transicao de estado.
 *
 * TAMPERED e ABSORVENTE: uma vez la, nao se sai por software. Sair exigiria
 * uma zeroizacao com dual control -- fase 3. Um dispositivo que se
 * auto-recupera de tamper nao detectou tamper nenhum, so registrou um
 * incomodo. */
void        state_set(hsm_state_t s);
hsm_state_t state_get(void);
uint32_t    state_mask(void);
const char *state_name(hsm_state_t s);

#endif /* STATE_H */
