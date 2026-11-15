/* fw/src/wipe.c -- zeroizacao nao-otimizavel
 *
 * FRONTEIRA: dentro.
 */
#include "wipe.h"

/* Preenche com `byte`, uma palavra de 32 bits por vez onde o alinhamento
 * deixa. Com o payload maximo em 3072 bytes, o despachante apaga 9 KB de
 * buffers depois de cada resposta, e byte a byte isso passava de 1 ms: o laco
 * principal ficava esse tempo sem olhar os botoes do dual control.
 *
 * volatile e o ponto inteiro do arquivo: obriga o compilador a emitir cada
 * store, mesmo sabendo que ninguem le o buffer depois. */
static void preenche(void *p, size_t n, uint8_t byte)
{
    volatile uint8_t  *q = (volatile uint8_t *)p;
    volatile uint32_t *w;
    uint32_t           palavra = 0x01010101u * (uint32_t)byte;

    while ((n > 0u) && ((((uintptr_t)q) & 3u) != 0u)) {
        *q++ = byte;
        n--;
    }
    w = (volatile uint32_t *)(void *)q;
    while (n >= 4u) {
        *w++ = palavra;
        n -= 4u;
    }
    q = (volatile uint8_t *)(void *)w;
    while (n > 0u) {
        *q++ = byte;
        n--;
    }

    /* Barreira de memoria: impede que o compilador mova as escritas acima
     * para depois de algo que dependa do buffer ja estar limpo. */
    __asm__ __volatile__("" ::: "memory");
}

void wipe(void *p, size_t n)
{
    preenche(p, n, 0x00u);
}

void wipe_padrao(void *p, size_t n)
{
    /* 0xAA: metade dos bits em 1. Um padrao de zeros nao se distinguiria
     * do resultado final, e um de 0xFF nao se distinguiria de memoria
     * nunca escrita em algumas tecnologias. */
    preenche(p, n, 0xAAu);
    wipe(p, n);
}
