/* fw/include/cmd.h -- enquadramento e despacho de comandos
 *
 * FRONTEIRA: fora. Este modulo so ve bytes do host. Nenhum handler pode
 * devolver material de chave em claro por aqui -- ver PLANO.md secao 1.
 *
 * Protocolo (PLANO.md secao 2):
 *
 *   pedido    LEN(2) | CMD(1)    | PAYLOAD | CRC32(4)
 *   resposta  LEN(2) | STATUS(1) | PAYLOAD | CRC32(4)
 *
 * Tudo big-endian. LEN cobre CMD/STATUS + PAYLOAD, e NAO se inclui nem
 * inclui o CRC.
 *
 * O CRC32 cobre LEN + CMD/STATUS + PAYLOAD -- ou seja, todos os bytes do
 * frame menos os quatro do proprio CRC. Polinomio IEEE 802.3 refletido
 * (0xEDB88320), init 0xFFFFFFFF, xor final 0xFFFFFFFF: e o mesmo do
 * zlib.crc32 do Python, o que mantem o host trivial.
 */
#ifndef CMD_H
#define CMD_H

#include <stdint.h>
#include "hsm_status.h"

/* Payload maximo. Dimensionado para o key block TR-31 da fase 3, que e o
 * maior objeto previsto atravessar a fronteira. Dois buffers deste tamanho
 * custam ~1 KB dos 8 KB de DMEM. */
#define CMD_MAX_PAYLOAD   512u

/* LEN minimo = 1 (so o byte de CMD, payload vazio) */
#define CMD_MIN_LEN       1u
#define CMD_MAX_LEN       (CMD_MAX_PAYLOAD + 1u)

/* Se um frame parar no meio por mais que isto, o parser resincroniza.
 * E o que garante o criterio "frame malformado nunca trava a maquina de
 * estados" (PLANO.md secao 2): sem timeout, um frame truncado deixaria o
 * parser esperando para sempre e o dispositivo mudo. */
#define CMD_INTERBYTE_TIMEOUT_MS  250u

/* Opcodes -- fase 1 */
#define CMD_PING          0x01u
#define CMD_GET_VERSION   0x02u
#define CMD_GET_DNA       0x03u

/* ---------------------------------------------------------------------
 * Fase 2 -- primitivas. LEIA ANTES DE USAR.
 *
 * AES_ENC, AES_DEC e HMAC recebem a CHAVE NO PAYLOAD, vinda do host. Um
 * HSM de verdade nao faz isso: chave entra uma vez, na cerimonia, e depois
 * so se fala com ela por HANDLE. Estes comandos existem porque a fase 2 e
 * sobre primitivas e o key store so chega na fase 3.
 *
 * Por isso eles sao permitidos APENAS em UNINITIALIZED. No instante em que
 * o dispositivo tiver uma LMK, param de responder -- e nao por convencao,
 * por mascara de estado na tabela. Um comando que aceita chave em claro nao
 * pode coexistir com chave de verdade no mesmo dispositivo.
 *
 * Na fase 3 eles sao SUBSTITUIDOS por versoes que recebem handle de slot.
 * Nao "estendidos": substituidos.
 * ------------------------------------------------------------------- */
#define CMD_AES_ENC       0x10u   /* chave(32) || bloco(16)  -> 16 bytes  */
#define CMD_AES_DEC       0x11u   /* chave(32) || bloco(16)  -> 16 bytes  */
#define CMD_SHA256        0x12u   /* mensagem                -> 32 bytes  */
#define CMD_HMAC          0x13u   /* klen(1) || chave || msg -> 32 bytes  */
#define CMD_RANDOM        0x14u   /* n(2, big-endian)        -> n bytes   */
#define CMD_SELFTEST      0x15u   /* vazio                   -> 1 byte    */

/* Maximo de bytes que RANDOM devolve numa chamada. Limitado pelo buffer de
 * resposta; para 1 MB o host chama em laco. */
#define CMD_RANDOM_MAX    256u

void         cmd_init(void);
void         cmd_poll(void);
uint32_t     crc32_hsm(const uint8_t *data, uint32_t len);

#endif /* CMD_H */
