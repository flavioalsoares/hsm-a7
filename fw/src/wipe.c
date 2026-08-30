/* fw/src/wipe.c -- zeroizacao nao-otimizavel
 *
 * FRONTEIRA: dentro.
 */
#include "wipe.h"

void wipe(void *p, size_t n)
{
    /* volatile aqui e o ponto inteiro do arquivo: obriga o compilador a
     * emitir cada store, mesmo sabendo que ninguem le o buffer depois. */
    volatile uint8_t *q = (volatile uint8_t *)p;

    while (n--) {
        *q++ = 0u;
    }

    /* Barreira de memoria: impede que o compilador mova as escritas acima
     * para depois de algo que dependa do buffer ja estar limpo. */
    __asm__ __volatile__("" ::: "memory");
}

void wipe_padrao(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    size_t            k = n;

    /* 0xAA: metade dos bits em 1. Um padrao de zeros nao se distinguiria
     * do resultado final, e um de 0xFF nao se distinguiria de memoria
     * nunca escrita em algumas tecnologias. */
    while (k--) {
        *q++ = 0xAAu;
    }
    __asm__ __volatile__("" ::: "memory");

    wipe(p, n);
}
