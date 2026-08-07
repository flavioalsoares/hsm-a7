/* fw/include/hsm_cfs.h -- driver do coprocessador criptografico (CFS)
 *
 * FRONTEIRA: dentro. Este modulo e o unico caminho do firmware ate o
 * hardware de cripto, e chave em claro passa por aqui. Nenhuma funcao
 * deste arquivo pode ser chamada com um buffer que venha direto do host
 * sem passar antes pela politica -- ver PLANO.md secao 1.
 *
 * O hardware esta em rtl/crypto/hsm_cfs.v, com o mapa de registradores
 * documentado no cabecalho. Este arquivo e o outro lado do mesmo contrato:
 * se um dos dois mudar sozinho, tb_cfs reprova.
 *
 * Divisao de responsabilidade, herdada dos testbenches de KAT:
 *
 *   - o hardware faz AES-256 ECB de UM bloco. CBC, CTR e CMAC sao
 *     encadeamento, e encadeamento e daqui.
 *   - o hardware faz a compressao SHA-256 de UM bloco de 512 bits ja
 *     preenchido. O padding do FIPS 180-4 e daqui.
 *
 * Isso e deliberado: modo de operacao em firmware e legivel e testavel;
 * modo de operacao em RTL custa fabric e esconde erro de padding num lugar
 * onde depurar exige simulacao.
 */
#ifndef HSM_CFS_H
#define HSM_CFS_H

#include <stdint.h>

/* Lido de CFS.ID. Serve para o boot recusar subir sobre um bitstream que
 * nao tem o coprocessador -- falha silenciosa aqui viraria "cripto que nao
 * criptografa", que e a pior falha possivel num HSM. */
#define HSM_CFS_ID_MAGIC   0x48534D31u   /* "HSM1" */

/* Tamanhos, em bytes */
#define HSM_AES_KEY_LEN    32u    /* AES-256, e so */
#define HSM_AES_BLOCK_LEN  16u
#define HSM_SHA_BLOCK_LEN  64u    /* 512 bits, ja preenchido */
#define HSM_SHA_DIGEST_LEN 32u
#define HSM_DNA_LEN         8u    /* 57 bits uteis, 7 bits de zero a frente */

/* 1 se o CFS respondeu com o ID esperado. */
int hsm_cfs_present(void);

/* Identidade de fabrica do die, 57 bits, big-endian em 8 bytes.
 *
 * NAO E SEGREDO. O DNA e legivel por JTAG em qualquer placa e nao tem
 * protecao nenhuma. Serve para o dispositivo dizer QUEM ele e -- em log de
 * auditoria, em rastreio de inventario. Derivar chave dele e um erro
 * classico e continua sendo um erro por mais tentador que pareca.
 *
 * Devolve 0 em sucesso, -1 se o hardware nao terminou a leitura. */
int hsm_cfs_dna(uint8_t out[HSM_DNA_LEN]);

/* Carrega a chave e dispara a expansao.
 *
 * FRONTEIRA: dentro. 'key' aponta para material de chave em claro. O
 * chamador e responsavel por zeroizar o buffer de origem com wipe(). */
int hsm_cfs_aes_key(const uint8_t key[HSM_AES_KEY_LEN]);

/* Um bloco de AES-256 ECB. 'encrypt' nao-zero cifra, zero decifra.
 * in e out podem apontar para o mesmo buffer. */
int hsm_cfs_aes_block(const uint8_t in[HSM_AES_BLOCK_LEN],
                      uint8_t out[HSM_AES_BLOCK_LEN],
                      int encrypt);

/* Compressao de um bloco de 512 bits. 'first' nao-zero inicia uma mensagem
 * nova (carrega o IV do FIPS 180-4); zero encadeia no estado corrente. */
int hsm_cfs_sha_block(const uint8_t block[HSM_SHA_BLOCK_LEN], int first);

/* Le o digest corrente. So faz sentido depois do ultimo bloco. */
int hsm_cfs_sha_digest(uint8_t out[HSM_SHA_DIGEST_LEN]);

/* Zeroizacao do coprocessador.
 *
 * Nao e so zerar registrador: o hardware sobrescreve a chave EXPANDIDA no
 * aes_key_mem, o resultado e o estado do SHA. Zerar apenas o que se ve de
 * fora seria teatro. Bloqueia ate terminar (algumas centenas de ciclos). */
int hsm_cfs_wipe(void);

#endif /* HSM_CFS_H */
