/* fw/include/cmd_ascii.h -- porta HOST: command set ASCII (fase 5)
 *
 * FRONTEIRA: fora, como cmd.c. Recebe a mensagem do host e devolve a
 * resposta; a chave de trabalho chega embrulhada num key block e e aberta
 * DENTRO do key store, no slot efemero (keystore.h).
 *
 * Formato completo, comandos e codigos de erro: doc/fase5-notas.md.
 *
 *   pedido     cabecalho(4) | comando(2) | campos
 *   resposta   cabecalho(4) | resposta(2) | erro(2) | campos
 *
 * Os codigos de comando e de erro sao DESTE projeto. Da categoria vem so a
 * forma geral -- dois caracteres, resposta = comando + 1, erro em dois
 * digitos --, que e publica e observavel.
 */
#ifndef CMD_ASCII_H
#define CMD_ASCII_H

#include <stdint.h>

/* O primeiro byte do corpo separa os protocolos: cabecalho ASCII e
 * imprimivel, de '0' a '~'; qualquer outro valor e opcode binario. Os
 * opcodes binarios em uso vao ate 0x2F. Ver cmd.c. */
#define ASCII_PRIMEIRO_MIN  0x30u
#define ASCII_PRIMEIRO_MAX  0x7Eu

#define ASCII_CAB_LEN       4u
#define ASCII_MIN_LEN       (ASCII_CAB_LEN + 2u)

/* Dados de C0/C2/M0/M2. O limite sai do frame: 513 bytes, com um key
 * block de 144 caracteres e os dados em hex. */
#define ASCII_DADOS_MAX     160u

/* Codigos de erro -- doc/fase5-notas.md. */
#define ASCII_OK            0u
#define ASCII_VERIF_FALHOU  1u
#define ASCII_BLOCO_INVAL   10u
#define ASCII_MODO          11u
#define ASCII_NAO_EXPORTA   12u   /* K4: a chave e 'N'               */
#define ASCII_NAO_KEK       13u   /* K4/K6: o bloco de protecao nao e K0 */
#define ASCII_DADOS         15u
#define ASCII_PARAM         16u
#define ASCII_ESTADO        20u
#define ASCII_DESCONHECIDO  21u
#define ASCII_MALFORMADA    22u
#define ASCII_LOG           27u
#define ASCII_INTERNO       90u

/* Processa uma mensagem e escreve a resposta inteira (sem LEN) em `resp`,
 * que tem `resp_max` bytes. Sempre produz resposta. */
void ascii_despacha(const uint8_t *msg, uint16_t n,
                    uint8_t *resp, uint16_t resp_max, uint16_t *resp_n);

#endif /* CMD_ASCII_H */
