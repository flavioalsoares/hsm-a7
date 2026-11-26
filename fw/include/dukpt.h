/* fw/include/dukpt.h -- DUKPT TDES, ANSI X9.24-1:2009 (fase 8, etapa 8.8a), e
 * DUKPT AES, ANSI X9.24-3:2017 (etapa 8.8b)
 *
 * FRONTEIRA: dentro. Recebe a BDK em claro e devolve chaves em claro.
 *
 * So keystore.c chama estas funcoes: a BDK so existe em claro dentro do key
 * store, e o que sai daqui (a IPEK, a chave de PIN da transacao) volta para
 * ele. Um segundo chamador e sinal de que a pergunta certa e "por que este
 * codigo tem a BDK?".
 *
 * O HSM faz o lado do adquirente: da BDK e do KSN que chega com a transacao
 * ele refaz a chave que o terminal usou. Nao ha registro de chaves futuras:
 * isso e do terminal.
 *
 * Usa o contexto comum de 3DES (tdes_ctx_comum()), e o apaga antes de voltar.
 * O DUKPT AES usa o motor AES-128 em C (aes128.c) com chave de 16 bytes, e o
 * coprocessador com chave de 32; os dois sao apagados antes de voltar.
 * Compila no PC, onde host/test_dukpt.py o confere contra os valores de
 * terceiros e contra host/dukpt.py.
 */
#ifndef DUKPT_H
#define DUKPT_H

#include <stdint.h>

#define DUKPT_KSN_LEN     10u
#define DUKPT_TDES_CHAVE  16u
#define DUKPT_MAX_UNS     10u   /* bits 1 no contador de um KSN valido */

/* 1 se o contador de 21 bits do KSN e diferente de zero e tem no maximo 10
 * bits 1. O contador zero e a propria IPEK, que nunca cifra transacao; um
 * contador com 11 bits 1 ou mais nunca sai de um terminal que segue a norma.
 * O KSN e dado publico. */
int dukpt_ksn_valido(const uint8_t ksn[DUKPT_KSN_LEN]);

/* IPEK (chave inicial do terminal) da BDK dupla e do KSN. O contador do KSN
 * e ignorado (zerado antes da conta). Devolve 0, ou -1 com a IPEK zerada.
 * FRONTEIRA: dentro. */
int dukpt_tdes_ipek(const uint8_t bdk[DUKPT_TDES_CHAVE],
                    const uint8_t ksn[DUKPT_KSN_LEN],
                    uint8_t ipek[DUKPT_TDES_CHAVE]);

/* A chave de PIN da transacao: IPEK, depois a chave de transacao pelo
 * contador, depois a variante de PIN. Devolve 0, ou -1 (KSN invalido,
 * chave zerada). FRONTEIRA: dentro. */
int dukpt_tdes_chave_pin(const uint8_t bdk[DUKPT_TDES_CHAVE],
                         const uint8_t ksn[DUKPT_KSN_LEN],
                         uint8_t chave[DUKPT_TDES_CHAVE]);

/* So para o KAT e para o teste no PC: a chave de transacao sem a variante,
 * que e o que os valores de terceiros trazem. */
int dukpt_tdes_chave_transacao(const uint8_t bdk[DUKPT_TDES_CHAVE],
                               const uint8_t ksn[DUKPT_KSN_LEN],
                               uint8_t chave[DUKPT_TDES_CHAVE]);

/* Autoteste: IPEK e uma chave de PIN dos valores de terceiros
 * (kat_vectors.h), e o PIN block cifrado conferido. 0 se passou. */
int dukpt_selftest(void);

/* ------------------------------------------------------------------
 * DUKPT AES (etapa 8.8b)
 *
 * KSN de 12 bytes: o IKID (8, a identificacao da chave inicial) e o
 * contador de transacao (4). A BDK e a chave de trabalho sao AES-128 (16
 * bytes) ou AES-256 (32), cada uma pelo seu tamanho.
 * ------------------------------------------------------------------ */
#define DUKPT_AES_KSN_LEN  12u
#define DUKPT_AES128       16u
#define DUKPT_AES256       32u
#define DUKPT_AES_MAX_UNS  16u   /* bits 1 no contador de um KSN valido */

/* 1 se o contador de 32 bits e diferente de zero e tem no maximo 16 bits 1.
 * O KSN e dado publico. */
int dukpt_aes_ksn_valido(const uint8_t ksn[DUKPT_AES_KSN_LEN]);

/* A chave inicial (IK) do terminal: deriva(BDK, uso 8001, IKID). Tem o
 * tamanho da BDK (`n`, 16 ou 32). O contador do KSN e ignorado. Devolve 0,
 * ou -1 com a IK zerada. FRONTEIRA: dentro. */
int dukpt_aes_ik(const uint8_t *bdk, uint32_t n,
                 const uint8_t ksn[DUKPT_AES_KSN_LEN], uint8_t *ik);

/* A chave de PIN da transacao, de `n_trabalho` bytes (16 ou 32). Devolve 0,
 * ou -1 (KSN invalido, tamanho invalido, chave zerada). FRONTEIRA: dentro. */
int dukpt_aes_chave_pin(const uint8_t *bdk, uint32_t n,
                        const uint8_t ksn[DUKPT_AES_KSN_LEN],
                        uint32_t n_trabalho, uint8_t *chave);

/* So para o KAT e para o teste no PC: a chave de transacao (a chave de
 * derivacao do contador), que e o que os valores de terceiros trazem. */
int dukpt_aes_chave_transacao(const uint8_t *bdk, uint32_t n,
                              const uint8_t ksn[DUKPT_AES_KSN_LEN],
                              uint8_t *chave);

/* Autoteste do AES-128 (vetores do CAVP, cifra e decifra) e do DUKPT AES
 * (valores de terceiros: chave de PIN AES-128 com o PIN block cifrado, e
 * chave de PIN AES-256). 0 se passou. Roda no primeiro uso. */
int dukpt_aes_selftest(void);

/* ------------------------------------------------------------------
 * MAC e dados com a chave da transacao (etapa 8.9b)
 *
 * Pedido e resposta sao do ponto de vista do terminal: ele faz o MAC e
 * cifra o pedido; o HSM do adquirente confere esse MAC e decifra, e faz o
 * MAC e cifra a resposta.
 *
 *   TDES: a chave da transacao com uma variante por uso (XOR de FF em dois
 *         bytes); nas de dados, ainda a funcao de mao unica da norma (cada
 *         metade cifrada em 3DES sob a propria chave).
 *   AES:  a derivacao da chave de PIN com outro uso: 2000, 2001, 3000, 3001.
 * ------------------------------------------------------------------ */
#define DUKPT_USO_MAC_PEDIDO      0u
#define DUKPT_USO_MAC_RESPOSTA    1u
#define DUKPT_USO_DADOS_PEDIDO    2u
#define DUKPT_USO_DADOS_RESPOSTA  3u

/* A chave TDES de `uso` da transacao. Devolve 0, ou -1 (KSN invalido, uso
 * invalido, chave zerada). FRONTEIRA: dentro. */
int dukpt_tdes_chave_uso(const uint8_t bdk[DUKPT_TDES_CHAVE],
                         const uint8_t ksn[DUKPT_KSN_LEN], uint8_t uso,
                         uint8_t chave[DUKPT_TDES_CHAVE]);

/* A chave AES de `uso`, de `n_trabalho` bytes (16 ou 32). Devolve 0, ou -1.
 * FRONTEIRA: dentro. */
int dukpt_aes_chave_uso(const uint8_t *bdk, uint32_t n,
                        const uint8_t ksn[DUKPT_AES_KSN_LEN], uint8_t uso,
                        uint32_t n_trabalho, uint8_t *chave);

/* CMAC (SP 800-38B) e AES-CBC sob uma chave AES de `n` bytes: 16 pelo motor
 * em C, 32 pelo coprocessador, que sai apagado. `n_dados` do CBC e multiplo
 * de 16. Devolvem 0, ou -1. FRONTEIRA: dentro. */
int dukpt_aes_cmac(const uint8_t *chave, uint32_t n, const uint8_t *msg,
                   uint32_t msg_n, uint8_t tag[16]);
int dukpt_aes_cbc(const uint8_t *chave, uint32_t n, const uint8_t iv[16],
                  const uint8_t *entrada, uint8_t *saida, uint32_t n_dados,
                  int cifrar);

#endif /* DUKPT_H */
