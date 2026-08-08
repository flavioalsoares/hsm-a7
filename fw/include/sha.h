/* fw/include/sha.h -- SHA-256 de mensagem e HMAC-SHA-256
 *
 * FRONTEIRA: dentro. O HMAC recebe chave em claro.
 *
 * ---------------------------------------------------------------------
 * DIVISAO COM O HARDWARE
 *
 * O CFS entrega a FUNCAO DE COMPRESSAO: recebe blocos de 512 bits ja
 * prontos e encadeia o estado. Ele nao faz padding, e isso e deliberado
 * (ver o cabecalho de rtl/crypto/hsm_cfs.v): padding em RTL custa fabric e
 * esconde um erro de comprimento num lugar onde depurar exige simulacao.
 *
 * Entao o padding do FIPS 180-4 e daqui: 0x80, zeros, e o comprimento em
 * BITS num inteiro de 64 bits big-endian. O erro classico -- contar bytes
 * onde a norma pede bits -- passa em mensagens de tamanho "redondo" e
 * reprova no resto, que e por que os vetores do SHAVS variam o tamanho.
 *
 * ---------------------------------------------------------------------
 * ESTADO GLOBAL, E O QUE ISSO IMPEDE
 *
 * O estado do SHA vive no sha256_core, em hardware. Existe UM. Portanto
 * nao ha dois hashes simultaneos: o contexto abaixo guarda so o buffer
 * parcial e o contador, e quem estiver no meio de um hash perde o estado
 * se outro comecar.
 *
 * O HMAC respeita isso naturalmente -- hash interno inteiro, depois o
 * externo -- mas quem escrever codigo novo precisa saber.
 */
#ifndef SHA_H
#define SHA_H

#include <stdint.h>

#define HSM_SHA256_LEN   32u
#define HSM_SHA256_BLOCK 64u

typedef struct {
    uint8_t  buf[HSM_SHA256_BLOCK];
    uint32_t buflen;      /* bytes ocupados em buf */
    uint64_t total;       /* bytes ja absorvidos, para o campo de comprimento */
    int      primeiro;    /* o proximo bloco ainda usa SHA_INIT */
    int      erro;        /* qualquer falha do CFS gruda ate o final */
} hsm_sha_ctx_t;

void hsm_sha_init(hsm_sha_ctx_t *c);
void hsm_sha_update(hsm_sha_ctx_t *c, const uint8_t *dados, uint32_t n);

/* Devolve 0 em sucesso. Em falha zeroiza 'out' -- devolver digest parcial
 * seria pior que devolver nada, porque parece um resultado. */
int  hsm_sha_final(hsm_sha_ctx_t *c, uint8_t out[HSM_SHA256_LEN]);

/* Atalho para mensagem inteira na memoria. */
int  hsm_sha256(const uint8_t *msg, uint32_t n, uint8_t out[HSM_SHA256_LEN]);

/* HMAC-SHA-256, RFC 2104.
 *
 * FRONTEIRA: 'chave' e material de chave em claro. O chamador zeroiza a
 * origem; esta funcao zeroiza os blocos ipad/opad que constroi. */
int  hsm_hmac_sha256(const uint8_t *chave, uint32_t chave_n,
                     const uint8_t *msg,   uint32_t msg_n,
                     uint8_t out[HSM_SHA256_LEN]);

#endif /* SHA_H */
