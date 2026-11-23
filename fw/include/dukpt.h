/* fw/include/dukpt.h -- DUKPT TDES, ANSI X9.24-1:2009 (fase 8, etapa 8.8a)
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

#endif /* DUKPT_H */
