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

/* ---------------------------------------------------------------------
 * Fase 3 -- hierarquia de chaves
 *
 * A partir daqui o dispositivo GUARDA chave, e a diferenca aparece na
 * tabela: estes comandos nao recebem material de chave para usar e
 * devolver, eles constroem estado interno que so sai como KCV ou handle.
 * ------------------------------------------------------------------- */

/* Cerimonia de LMK. Exige dual control -- ver dualctl.h.
 *   pedido    n(1) || componente(32)
 *   resposta  kcv_do_componente(3) || carregados(1) || estado(1)  */
#define CMD_LMK_LOAD_COMPONENT  0x20u

/*   pedido    vazio
 *   resposta  carregados(1) || completa(1) || kcv_da_lmk(3)
 * O KCV vem zerado enquanto a LMK nao estiver completa. Comprimento fixo
 * de proposito: resposta curta e resposta longa distinguiveis de fora sao
 * um canal, ainda que estreito. */
#define CMD_LMK_STATUS          0x21u

/* Transicao de estado operada por gente. Exige dual control.
 *   pedido    estado_alvo(1)
 *   resposta  estado_atual(1)
 * A unica transicao aceita e AUTHORIZED -> OPERATIONAL. Voltar para
 * UNINITIALIZED e trabalho do ZEROIZE, que apaga; um SET_STATE que
 * "desinicializasse" deixaria a chave viva com o estado mentindo. */
#define CMD_SET_STATE           0x26u

/* ZEROIZE -- apaga TODA chave, e prova que apagou. Exige dual control.
 *   pedido    vazio
 *   resposta  estado_atual(1)
 *
 * Permitido em TODOS os estados, TAMPERED inclusive. Um dispositivo que
 * nao se deixa apagar e pior que um que se deixa: a unica coisa que ele
 * garante e que a chave continua la.
 *
 * De TAMPERED nao se SAI -- a chave e apagada e o estado permanece. A
 * maquina de estados ja e absorvente ali (state.h), entao isso sai de
 * graca e nao precisa de caso especial.
 *
 * O status distingue "apagou" de "nao consegui provar que apagou". Nao e
 * excesso de zelo: um zeroize que reporta sucesso sem ter apagado e pior
 * que um que falha, porque o operador acredita nele. */
#define CMD_ZEROIZE             0x2Fu


void         cmd_init(void);
void         cmd_poll(void);
uint32_t     crc32_hsm(const uint8_t *data, uint32_t len);

#endif /* CMD_H */
