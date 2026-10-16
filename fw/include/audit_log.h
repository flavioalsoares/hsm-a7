/* fw/include/audit_log.h -- log de auditoria na flash
 *
 * FRONTEIRA: dentro, e sem material de chave. O log e uma das coisas que
 * PODEM sair (CLAUDE.md, regra 3): ele registra o que foi pedido, em que
 * estado, sobre qual slot, e com que resultado -- nunca bytes de chave,
 * nunca payload.
 *
 * ---------------------------------------------------------------------
 * GRAVADO ANTES DE EXECUTAR
 *
 * PLANO.md secao 5. Um registro escrito depois so conta o que deu certo;
 * a tentativa que travou o dispositivo, ou que foi cortada pela energia
 * no meio, nao apareceria. Entao:
 *
 *   1. antes do handler: o registro vai para a flash com o RESULTADO em
 *      0xFF -- "pendente";
 *   2. depois: so o byte de resultado e programado por cima.
 *
 * O passo 2 nao precisa apagar nada. Flash so DESCE bits, e 0xFF e o
 * valor apagado: programar o resultado sobre ele e uma escrita de um
 * byte. Um registro que ficou em 0xFF e um comando que comecou e nao
 * terminou -- exatamente o que a trilha forense quer ver.
 *
 * E se o registro nao puder ser gravado, o comando NAO executa
 * (STATUS_LOG_FAIL). A unica excecao e o ZEROIZE: um dispositivo que nao
 * consegue apagar a chave porque o log esta com defeito e pior que um
 * que apaga sem registrar.
 *
 * ---------------------------------------------------------------------
 * FORMATO -- 16 bytes por registro, big-endian
 *
 *   0..3   seq        numero de sequencia, sobe 1 por registro
 *   4      comando    opcode; 0x00 = boot
 *   5      estado     estado do dispositivo ANTES do comando
 *   6      argumento  primeiro byte do payload (handle, indice...), ou 0
 *   7      resultado  status devolvido; 0xFF = pendente
 *   8..11  reservado  0
 *   12..15 crc32      sobre os bytes 0..6 e 8..11 (o 7 fica de fora,
 *                     porque e escrito depois)
 *
 * Anel de 64 KB = 4096 registros. O registro de numero `seq` mora na
 * posicao seq % 4096 -- entao achar um registro antigo e conta, nao
 * busca. Ao entrar num subsetor novo, ele e apagado: os 256 registros
 * mais velhos se perdem. Limitacao documentada, nao resolvida.
 */
#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <stdint.h>

#define LOG_BASE        0x410000u
#define LOG_TAMANHO     0x10000u            /* 64 KB */
#define LOG_REG_LEN     16u
#define LOG_N_REG       (LOG_TAMANHO / LOG_REG_LEN)
#define LOG_PENDENTE    0xFFu
#define LOG_CMD_BOOT    0x00u

/* Acha o fim do log. Chamado no boot, depois de flash_init(). */
void log_init(void);

/* Grava um registro com resultado pendente. `*seq` recebe o numero dele.
 * Devolve 0 em sucesso. */
int log_registra(uint8_t comando, uint8_t estado, uint8_t argumento,
                 uint32_t *seq);

/* Programa o resultado de um registro ja gravado. */
int log_resultado(uint32_t seq, uint8_t resultado);

/* Proximo numero de sequencia (= quantos registros ja houve). */
uint32_t log_proximo(void);

/* Le o registro `seq` para `out` (16 bytes). Devolve 0 se ele existe e o
 * CRC confere; -1 se foi sobrescrito, nunca existiu ou esta corrompido. */
int log_le(uint32_t seq, uint8_t out[LOG_REG_LEN]);

#endif /* AUDIT_LOG_H */
