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
 * Fase 2 -- primitivas
 *
 * ⚠ 0x10 (AES_ENC), 0x11 (AES_DEC) e 0x13 (HMAC) FORAM REMOVIDOS. Os
 * dois primeiros em 2026-09-01, o HMAC em 2026-09-25. Os opcodes ficam
 * RESERVADOS: nao reaproveitar, para que um host antigo receba
 * UNKNOWN_CMD em vez de acertar outro comando por acidente.
 *
 * NENHUM COMANDO DESTE DISPOSITIVO ACEITA MAIS CHAVE EM CLARO.
 *
 * Eles recebiam a chave no payload. O argumento que decidiu nao foi "nao
 * podem coexistir com chave de verdade" -- foi que um comando assim faz
 * material de chave ATRAVESSAR A FRONTEIRA na direcao de ENTRADA, e isso
 * e errado em UNINITIALIZED tanto quanto em OPERATIONAL. Defeito que nao
 * e de estado nao se conserta com mascara de estado.
 *
 * SUBSTITUTOS, todos escritos ANTES da remocao correspondente:
 *
 *   0x10 / 0x11  ->  0x27 ENCRYPT / 0x28 DECRYPT
 *   0x13         ->  0x29 MAC_GENERATE / 0x2A MAC_VERIFY
 *
 * ⚠ O que sobra aqui NAO recebe chave: SHA-256 e funcao publica e RANDOM
 * devolve saida do DRBG.
 * ------------------------------------------------------------------- */
#define CMD_SHA256        0x12u   /* mensagem                -> 32 bytes  */
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

/* ---------------------------------------------------------------------
 * MAC por handle -- CMAC-AES-256 (SP 800-38B)
 *
 * CMAC e nao HMAC, e a escolha nao e de gosto: os slots guardam chaves
 * AES (`algoritmo='A'`), e usa-las para HMAC seria a confusao de tipo que
 * o resto do projeto passa o tempo todo evitando. CMAC e o que a
 * categoria usa para MAC de dados com chave AES, e ja esta validado
 * contra o CAVP.
 *
 * A CHAVE NAO SAI DO KEYSTORE. `cmac_aes256()` precisa dos bytes, entao
 * o calculo mora em `keystore_cmac()`, dentro de keystore.c -- mesmo
 * padrao de `lmk_deriva_kb()`. Um handler que calculasse por conta
 * propria precisaria de `keystore_exporta()`, e aí uma chave marcada
 * 'N' nao poderia mais autenticar -- ou `exportabilidade` viraria um
 * controle sobre USO, que nao e o que ela e.
 *
 * MODO DE USO: estes comandos exigem o grupo de MAC ('G', 'V' ou 'C').
 * Uma chave de cifra ('E'/'D'/'B') e RECUSADA, e vice-versa. Os dois
 * grupos nao se cruzam -- e e isso que fecha a confusao de tipo.
 * ------------------------------------------------------------------- */

/*   pedido    handle(1) || mensagem
 *   resposta  tag(16)
 * Exige modo 'G' ou 'C'. */
#define CMD_MAC_GENERATE        0x29u

/*   pedido    handle(1) || tag(16) || mensagem
 *   resposta  vazio -- o veredito e o STATUS
 * Exige modo 'V' ou 'C'. Devolve STATUS_MAC_INVALID se nao confere.
 *
 * O dispositivo COMPARA e devolve o veredito; ele nao devolve o MAC para
 * o host comparar. Comparar MAC do lado de fora e um canal lateral: o
 * tempo de retorno conta quantos bytes bateram, e com isso se forja tag
 * byte a byte em 16*256 tentativas em vez de 2^128. E por isso que
 * verificar dentro vale mais que gerar. */
#define CMD_MAC_VERIFY          0x2Au

/* Maior mensagem por chamada. Cabe no buffer com folga; para mais que
 * isso o host teria de encadear, e CMAC nao encadeia entre comandos --
 * o dispositivo nao guarda estado. */
#define CMD_MAC_MSG_MAX   256u

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
