/* fw/include/versao.h -- a versao do firmware, num lugar so
 *
 * O console (GET_VERSION, GET_BUILD) e a porta host (D0) leem daqui. Ate
 * 2026-11-14 o numero era um 0.1.0 fixo, escrito em dois arquivos, e nao
 * dizia nada sobre o que estava gravado na placa.
 *
 * Regra: MINOR e a fase, PATCH e a etapa entregue dentro dela. Toda etapa
 * que vai para a placa muda o PATCH.
 *
 * O numero identifica a ETAPA. Quem identifica o firmware gravado, byte a
 * byte, e o hash do GET_BUILD.
 */
#ifndef VERSAO_H
#define VERSAO_H

#define HSM_VERSAO_MAJOR  0u
#define HSM_VERSAO_MINOR  8u    /* fase 8 */
#define HSM_VERSAO_PATCH  4u    /* etapas 8.1 a 8.4, e PKCS#8 */

/* A memoria de codigo: comeca no endereco 0 e tem 64 KB. Tem de casar com
 * __neorv32_rom_size no Makefile e com IMEM_SIZE no wrapper. */
#define HSM_IMEM_BYTES    (64u * 1024u)

#endif /* VERSAO_H */
