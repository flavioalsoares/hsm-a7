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
