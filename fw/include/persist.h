/* fw/include/persist.h -- o registro persistente: LMK, estado e slots
 *
 * FRONTEIRA: dentro. O registro contem a LMK em claro -- a regiao da
 * flash e tratada como memoria segura (CLAUDE.md, regra 2, decisao de
 * 2026-10-15). Faz o papel da memoria com bateria de um HSM comercial:
 * o dispositivo desliga e volta com a LMK e as chaves.
 *
 * ---------------------------------------------------------------------
 * DUAS COPIAS, E O CONTADOR ESCOLHE
 *
 * Gravar exige apagar 4 KB antes, e uma queda de energia entre o apagar
 * e o terminar deixaria o dispositivo sem registro nenhum. Por isso ha
 * duas copias (A em 0x400000, B em 0x401000): cada gravacao vai para a
 * MAIS VELHA, e a outra continua inteira ate a nova estar conferida. No
 * boot vale a de maior contador cujo CRC confere.
 *
 * O contador NAO e anti-rollback. Quem regravar a flash com uma imagem
 * antiga volta no tempo, e o dispositivo nao percebe. Seria preciso um
 * contador monotonico fora da flash, e a placa nao tem. Limitacao
 * documentada em doc/fase4-notas.md, nao mitigada.
 *
 * ---------------------------------------------------------------------
 * FORMATO
 *
 *   0..3   "HSM4"
 *   4      versao (1)
 *   5      estado: AUTHORIZED ou OPERATIONAL
 *   6..7   comprimento do corpo
 *   8..11  contador
 *   12..15 reservado
 *   16..   corpo (keystore_registro_monta)
 *   fim    crc32 sobre tudo antes dele
 */
#ifndef PERSIST_H
#define PERSIST_H

#include <stdint.h>

#include "state.h"

#define PERSIST_COPIA_A  0x400000u
#define PERSIST_COPIA_B  0x401000u

/* Grava LMK + slots + `estado` na copia mais velha, e confere lendo de
 * volta. Devolve 0 em sucesso. */
int persist_salva(hsm_state_t estado);

/* Le o registro mais novo e valido, restaura LMK e slots, e devolve o
 * estado gravado. Sem registro valido: key store zerado e
 * HSM_UNINITIALIZED. `*achou` diz o que houve: 0 nenhum registro,
 * 1 restaurado, 2 havia registro e nenhum era valido. */
hsm_state_t persist_restaura(uint8_t *achou);

/* Apaga as duas copias. E o ZEROIZE na flash. Devolve 0 em sucesso. */
int persist_apaga(void);

#endif /* PERSIST_H */
