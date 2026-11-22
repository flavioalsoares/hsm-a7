/* fw/include/cmac_tdes.h -- CMAC sobre 3DES, NIST SP 800-38B (fase 8, etapa 8.7)
 *
 * FRONTEIRA: dentro. Recebe chave em claro.
 *
 * E o CMAC de cmac.h com o bloco de 64 bits do 3DES no lugar do de 128 do
 * AES. Muda a constante da dobra (0x1B em vez de 0x87, o polinomio de grau 64
 * da norma) e o tamanho do bloco. Serve ao key block X9.143 versao B, sob uma
 * KEK 3DES: deriva KBEK e KBAK da KEK e autentica o bloco.
 *
 * Arquivo separado de cmac.c de proposito: aquele usa o coprocessador AES;
 * este usa o motor 3DES em C (des.c), e compila no PC, onde
 * host/test_cmac_tdes.py o confere contra os vetores do NIST.
 *
 * Usa o contexto comum de 3DES (tdes_ctx_comum()), e o apaga antes de voltar.
 * Quem chama nao pode ter uma chave 3DES carregada nele esperando uso.
 */
#ifndef CMAC_TDES_H
#define CMAC_TDES_H

#include <stdint.h>

#define CMAC_TDES_TAG  8u

/* CMAC-TDES de uma mensagem inteira. `chave_n` e 16 ou 24. `msg` pode ser
 * NULL com msg_n == 0. Devolve 0, ou -1 (e `tag` zerada) com chave de outro
 * tamanho. */
int cmac_tdes(const uint8_t *chave, uint32_t chave_n,
              const uint8_t *msg, uint32_t msg_n,
              uint8_t tag[CMAC_TDES_TAG]);

/* Verificacao em tempo constante: 1 se confere, 0 se nao (ou erro). */
int cmac_tdes_verifica(const uint8_t *chave, uint32_t chave_n,
                       const uint8_t *msg, uint32_t msg_n,
                       const uint8_t tag[CMAC_TDES_TAG]);

#endif /* CMAC_TDES_H */
