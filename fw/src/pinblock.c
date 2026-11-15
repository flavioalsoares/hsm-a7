/* fw/src/pinblock.c -- PIN block ISO 9564-1, formatos 0 e 4 (fase 8)
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

/* Os 8 primeiros bytes de um campo de PIN, nos dois formatos, tem a mesma
 * forma: controle, tamanho, digitos e enchimento. So mudam o valor do
 * controle (4 ou 0) e o do enchimento (A ou F). */
static int forma_valida(const uint8_t *campo, uint8_t controle,
                        uint8_t enchimento)
{
    uint32_t n = nibble(campo, 1u);
    uint32_t i;
    uint8_t  ruim = 0u;
    uint8_t  v, e_pin;

    ruim |= (uint8_t)(nibble(campo, 0u) ^ controle);
    ruim |= menor(n, PIN_MIN);              /* tamanho < 4  */
    ruim |= menor(PIN_MAX, n);              /* tamanho > 12 */

    /* As 14 posicoes depois do tamanho: digito de PIN nas `n` primeiras,
     * enchimento nas demais. A posicao decide a regra por mascara. */
    for (i = 0u; i < 14u; i++) {
        v     = nibble(campo, 2u + i);
        e_pin = menor(i, n);                            /* 0xFF: e digito */
        ruim |= (uint8_t)(e_pin & menor(9u, v));        /* digito > 9     */
        ruim |= (uint8_t)((uint8_t)~e_pin & (uint8_t)(v ^ enchimento));
    }
    return (ruim == 0u) ? 1 : 0;
}

/* Copia os 8 bytes da forma, trocando o controle e o enchimento. A posicao
 * decide por mascara o que e digito e o que e enchimento. */
static void forma_troca(const uint8_t *de, uint8_t *para, uint8_t controle,
                        uint8_t enchimento)
{
    uint32_t n = nibble(de, 1u);
    uint32_t i;
    uint8_t  nib[16];
    uint8_t  v, e_pin;

    nib[0] = controle;
    nib[1] = (uint8_t)n;
    for (i = 0u; i < 14u; i++) {
        v     = nibble(de, 2u + i);
        e_pin = menor(i, n);
        nib[2u + i] = (uint8_t)((e_pin & v) | ((uint8_t)~e_pin & enchimento));
    }
    for (i = 0u; i < 8u; i++) {
        para[i] = (uint8_t)((nib[2u * i] << 4) | nib[2u * i + 1u]);
    }
    for (i = 0u; i < sizeof nib; i++) {
        ((volatile uint8_t *)nib)[i] = 0u;
    }
}

int pinblock_campo_valido(const uint8_t campo[PIN_BLOCO])
{
    return forma_valida(campo, 0x4u, 0xAu);
}

int pinblock_campo_pan0(const uint8_t *pan, uint32_t n,
                        uint8_t campo[PIN_BLOCO_0])
{
    uint8_t  nib[2u * PIN_BLOCO_0];
    uint32_t i;

    if ((pan == 0) || (n < PIN_PAN0_MIN) || (n > PIN_PAN_MAX)) {
        return -1;
    }
    for (i = 0u; i < n; i++) {
        if ((pan[i] < (uint8_t)'0') || (pan[i] > (uint8_t)'9')) {
            return -1;
        }
    }
    nib[0] = 0u; nib[1] = 0u; nib[2] = 0u; nib[3] = 0u;
    /* Os 12 digitos antes do ultimo. */
    for (i = 0u; i < 12u; i++) {
        nib[4u + i] = (uint8_t)(pan[n - 13u + i] - (uint8_t)'0');
    }
    for (i = 0u; i < PIN_BLOCO_0; i++) {
        campo[i] = (uint8_t)((nib[2u * i] << 4) | nib[2u * i + 1u]);
    }
    return 0;
}

int pinblock_f0_para_f4(const uint8_t campo0[PIN_BLOCO_0],
                        uint8_t campo4[PIN_BLOCO])
{
    uint32_t i;

    forma_troca(campo0, campo4, 0x4u, 0xAu);
    for (i = 8u; i < PIN_BLOCO; i++) {
        campo4[i] = 0u;
    }
    return forma_valida(campo0, 0x0u, 0xFu);
}

void pinblock_f4_para_f0(const uint8_t campo4[PIN_BLOCO],
                         uint8_t campo0[PIN_BLOCO_0])
{
    forma_troca(campo4, campo0, 0x0u, 0xFu);
}
