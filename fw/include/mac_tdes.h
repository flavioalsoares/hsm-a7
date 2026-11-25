/* fw/include/mac_tdes.h -- retail MAC: ISO/IEC 9797-1, algoritmo 3; ANSI X9.19
 * (etapa 8.9a)
 *
 * O MAC de mensagem com chave 3DES de comprimento duplo K . K' que a rede de
 * pagamento usa. A cadeia e um CBC-MAC com DES simples sob K; so o ultimo
 * bloco passa pelo 3DES de K . K'. A conta e a mesma da norma, que escreve o
 * fim como E_K( D_K'( H ) ):
 *
 *   H_0 = 0
 *   H_j = DES_K( H_(j-1) xor M_j )              j = 1 .. q-1
 *   MAC = 3DES_(K.K')( H_(q-1) xor M_q )        o 3DES e E_K D_K' E_K
 *
 * Preenchimento 1: zeros ate o multiplo de 8 (nada, se ja for). Preenchimento
 * 2: um byte 80, e zeros. A mensagem vazia e recusada.
 *
 * Aqui so a conta. Quem pode usar qual chave (o uso, o modo, o comprimento)
 * e decidido em keystore.c, onde a chave mora.
 *
 * FRONTEIRA: dentro. Recebe os bytes da chave; usa o contexto 3DES comum e o
 * apaga na saida.
 *
 * O algoritmo esta escrito duas vezes: aqui e em host/mac_tdes.py. Mexer num
 * exige mexer no outro e rodar host/test_retail_mac.py.
 */
#ifndef MAC_TDES_H
#define MAC_TDES_H

#include <stdint.h>

#define RETAIL_MAC_LEN  8u

/* O MAC inteiro, de 8 bytes; quem chama trunca para 4 se quiser.
 * `metodo` e 1 ou 2. Devolve 0, ou -1 se `metodo` for outro ou `n` for 0. */
int retail_mac(const uint8_t chave[16], uint8_t metodo,
               const uint8_t *msg, uint32_t n, uint8_t mac[RETAIL_MAC_LEN]);

#endif /* MAC_TDES_H */
