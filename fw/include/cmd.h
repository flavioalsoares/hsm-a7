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

/* ---------------------------------------------------------------------
 * Comandos de chave -- so em OPERATIONAL.
 *
 * Os quatro tem a mesma mascara e nenhum exige dual control, e vale dizer
 * por que: dual control e para CERIMONIA, nao para operacao. Carregar a
 * chave mestra e ativar o dispositivo sao eventos raros, com gente na
 * frente da placa. Gerar, exportar e importar chave e o que o dispositivo
 * faz o dia inteiro -- exigir dois dedos ali nao aumentaria seguranca
 * nenhuma, so garantiria que ninguem usa o equipamento.
 *
 * O que protege estes comandos e outra coisa: a chave nunca sai em claro,
 * o key block e autenticado, e `exportabilidade` decide quem pode sair.
 * ------------------------------------------------------------------- */

/* GEN_KEY -- gera chave DENTRO do dispositivo, do CTR_DRBG.
 *   pedido    uso(2) || algoritmo(1) || modo(1) || exportabilidade(1)
 *   resposta  handle(1) || kcv(3)
 *
 * A chave nunca existe fora da fronteira. E a diferenca entre este
 * comando e o AES_ENC da fase 2, que recebia chave do host: aqui o host
 * escolhe os METADADOS e nao ve o material. */
#define CMD_GEN_KEY             0x22u

/* EXPORT_KEY -- embrulha a chave de um slot num key block X9.143 sob a LMK.
 *   pedido    handle(1)
 *   resposta  key block em ASCII
 *
 * O UNICO comando que faz material de chave atravessar a fronteira, e ele
 * atravessa EMBRULHADO. Respeita `exportabilidade`: um slot marcado 'N'
 * e recusado com STATUS_NOT_EXPORTABLE. */
#define CMD_EXPORT_KEY          0x23u

/* IMPORT_KEY -- desembrulha um key block e instala num slot livre.
 *   pedido    key block em ASCII
 *   resposta  handle(1) || kcv(3)
 *
 * Os metadados vem DO BLOCO, nao do pedido -- e e por isso que o
 * cabecalho entra no MAC. Um bloco adulterado e recusado com
 * STATUS_BAD_PARAM, o mesmo codigo de um bloco malformado: distinguir
 * "MAC invalido" de "enchimento invalido" e o oraculo de padding
 * classico. */
#define CMD_IMPORT_KEY          0x24u

/* KEY_INFO -- metadados de um slot. NUNCA chave.
 *   pedido    handle(1)
 *   resposta  uso(2)||alg(1)||modo(1)||exp(1)||key_len(1)||kcv(3)||usos(4)
 *
 * Nao existe "me devolva o slot inteiro": o tipo que contem chave nem
 * aparece no header do key store. */
#define CMD_KEY_INFO            0x25u

/* ---------------------------------------------------------------------
 * USAR uma chave guardada -- e o que faltava para o dispositivo ser um HSM
 *
 * Ate aqui ele sabia GUARDAR, EXPORTAR e IMPORTAR chave, e nao sabia
 * USA-LA. Um cofre que nao deixa trabalhar com o que guarda nao e cofre,
 * e deposito.
 *
 * A chave e referida por HANDLE. O contraste com os comandos da fase 2 e
 * o ponto: la a chave vinha no payload, aqui vem um numero de gaveta.
 *
 * CBC com IV explicito, e nao ECB de um bloco. ECB para dados e o erro
 * que a Parte III do manual usa como exemplo -- blocos iguais viram
 * criptogramas iguais, e a estrutura do texto claro atravessa a cifra.
 *
 * O IV vem do host e nao e gerado aqui: uma funcao que puxa entropia por
 * conta propria e impossivel de testar de forma deterministica. Quem
 * quiser IV aleatorio pede ao RANDOM.
 * ------------------------------------------------------------------- */

/*   pedido    handle(1) || iv(16) || dados (multiplo de 16)
 *   resposta  dados processados, mesmo comprimento
 *
 * O `modo` do slot decide: uma chave marcada 'E' (so cifrar) recusa
 * DECRYPT com STATUS_BAD_KEY_USE. A checagem vive dentro de
 * `keystore_usa_aes()`, num lugar so -- e a confusao de tipo de chave e a
 * origem de uma familia inteira de ataques de API. */
#define CMD_ENCRYPT             0x27u
#define CMD_DECRYPT             0x28u

/* Maximo de dados por chamada. Cabe no buffer de resposta com folga; para
 * mais que isso o host encadeia, e encadear e trabalho do host -- o
 * dispositivo nao guarda estado entre comandos. */
#define CMD_CRIPTO_MAX    256u

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
