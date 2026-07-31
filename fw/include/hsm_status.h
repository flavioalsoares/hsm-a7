/* fw/include/hsm_status.h -- codigos de status do protocolo
 *
 * FRONTEIRA: fora. Estes codigos atravessam a UART e sao visiveis ao host.
 *
 * Regra para codigos novos: um status nunca pode revelar mais do que o host
 * tem direito de saber. "Chave errada" e "slot vazio" devem ser o mesmo
 * codigo sempre que a distincao ajudar um atacante a enumerar o key store.
 * Na duvida, agrupar.
 */
#ifndef HSM_STATUS_H
#define HSM_STATUS_H

#include <stdint.h>

typedef enum {
    STATUS_OK              = 0x00,

    /* Enquadramento e transporte */
    STATUS_BAD_CRC         = 0x01,  /* CRC32 nao confere */
    STATUS_BAD_LEN         = 0x02,  /* LEN fora da faixa aceitavel */
    STATUS_TIMEOUT         = 0x03,  /* frame incompleto, resincronizado */

    /* Comando */
    STATUS_UNKNOWN_CMD     = 0x10,  /* opcode nao esta na tabela */
    STATUS_BAD_PARAM       = 0x11,  /* tamanho ou conteudo do payload */
    STATUS_NOT_IMPLEMENTED = 0x12,  /* na tabela, sem implementacao ainda */

    /* Politica -- ganham uso de verdade na fase 3 */
    STATUS_WRONG_STATE     = 0x20,  /* comando nao permitido neste estado */
    STATUS_NOT_AUTHORIZED  = 0x21,  /* falta dual control */
    STATUS_NOT_EXPORTABLE  = 0x22,  /* exportability do slot proibe */

    /* Falhas do dispositivo */
    STATUS_SELFTEST_FAIL   = 0x30,
    STATUS_TAMPERED        = 0x31,

    STATUS_INTERNAL_ERROR  = 0xFF
} hsm_status_t;

#endif /* HSM_STATUS_H */
