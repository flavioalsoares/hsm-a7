/* fw/src/pinblock.c -- PIN block ISO 9564-1 formato 4 (fase 8)
 *
 * Ver pinblock.h. Aqui nao ha chave nem cifra.
 */
#include "pinblock.h"

int pinblock_campo_pan(const uint8_t *pan, uint32_t n,
                       uint8_t campo[PIN_BLOCO])
{
    uint8_t  nib[2u * PIN_BLOCO];
    uint32_t i, zeros;

    if ((pan == 0) || (n < 1u) || (n > PIN_PAN_MAX)) {
        return -1;
    }
    for (i = 0u; i < n; i++) {
        if ((pan[i] < (uint8_t)'0') || (pan[i] > (uint8_t)'9')) {
            return -1;
        }
    }
    for (i = 0u; i < sizeof nib; i++) {
        nib[i] = 0u;
    }
    /* Com menos de 12 digitos, zeros a esquerda ate 12. */
    zeros  = (n < 12u) ? (12u - n) : 0u;
    nib[0] = (n > 12u) ? (uint8_t)(n - 12u) : 0u;
    for (i = 0u; i < n; i++) {
        nib[1u + zeros + i] = (uint8_t)(pan[i] - (uint8_t)'0');
    }
    for (i = 0u; i < PIN_BLOCO; i++) {
        campo[i] = (uint8_t)((nib[2u * i] << 4) | nib[2u * i + 1u]);
    }
    return 0;
}

/* Nibble `i` do campo, 0 = o mais alto do primeiro byte. */
static uint8_t nibble(const uint8_t campo[PIN_BLOCO], uint32_t i)
{
    uint8_t b = campo[i >> 1];
    return (uint8_t)(((i & 1u) == 0u) ? (b >> 4) : (b & 0x0Fu));
}

/* 0xFF se a < b, senao 0. Sem desvio. Vale para valores de 0 a 255. */
static uint8_t menor(uint32_t a, uint32_t b)
{
    return (uint8_t)(0u - ((a - b) >> 31));
}

int pinblock_campo_valido(const uint8_t campo[PIN_BLOCO])
{
    uint32_t n = nibble(campo, 1u);
    uint32_t i;
    uint8_t  ruim = 0u;
    uint8_t  v, e_pin;

    ruim |= (uint8_t)(nibble(campo, 0u) ^ 0x4u);
    ruim |= menor(n, PIN_MIN);              /* tamanho < 4  */
    ruim |= menor(PIN_MAX, n);              /* tamanho > 12 */

    /* As 14 posicoes depois do tamanho: digito de PIN nas `n` primeiras,
     * enchimento A nas demais. A posicao decide a regra por mascara. */
    for (i = 0u; i < 14u; i++) {
        v     = nibble(campo, 2u + i);
        e_pin = menor(i, n);                            /* 0xFF: e digito */
        ruim |= (uint8_t)(e_pin & menor(9u, v));        /* digito > 9     */
        ruim |= (uint8_t)((uint8_t)~e_pin & (uint8_t)(v ^ 0xAu));
    }
    return (ruim == 0u) ? 1 : 0;
}
