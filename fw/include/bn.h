/* fw/include/bn.h -- aritmetica de numeros grandes em bytes, big-endian
 *
 * FRONTEIRA: dentro. Usada pelo RSA e pelo preparo do modulo de
 * Montgomery. Toda multiplicacao e do coprocessador; aqui ficam soma,
 * subtracao e comparacao.
 */
#ifndef BN_H
#define BN_H

#include <stdint.h>

/* a < b. Sai cedo: so sobre dados publicos. */
int bn_menor(const uint8_t *a, const uint8_t *b, uint32_t n);

/* a == b, comparando tudo (sem sair cedo). */
int bn_iguais(const uint8_t *a, const uint8_t *b, uint32_t n);

/* x = x - y; devolve o emprestimo final. Sem desvio pelo valor. */
uint32_t bn_subtrai(uint8_t *x, const uint8_t *y, uint32_t n);

/* x = x + y; devolve o vai-um final. Sem desvio pelo valor. */
uint32_t bn_soma(uint8_t *x, const uint8_t *y, uint32_t n);

/* a = (a + b) mod m e a = (a - b) mod m, com a, b < m. Tempo constante.
 * `t` e rascunho de n bytes. */
void bn_soma_mod(uint8_t *a, const uint8_t *b, const uint8_t *m,
                 uint8_t *t, uint32_t n);
void bn_subtrai_mod(uint8_t *a, const uint8_t *b, const uint8_t *m,
                    uint8_t *t, uint32_t n);

#endif
