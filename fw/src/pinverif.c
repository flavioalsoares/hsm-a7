/* fw/src/pinverif.c -- verificacao de PIN: offset e PVV (fase 8, etapa 8.5)
 *
 * Ver pinverif.h. Aqui nao ha chave nem cifra.
 */
#include "pinverif.h"

/* 0xFF se a < b, senao 0. Sem desvio. Vale para valores de 0 a 255. */
static uint8_t menor(uint32_t a, uint32_t b)
{
    return (uint8_t)(0u - ((a - b) >> 31));
}

/* 0xFF se a == b, senao 0. Sem desvio. */
static uint8_t igual(uint32_t a, uint32_t b)
{
    uint32_t d = a ^ b;
    return (uint8_t)(((d | (0u - d)) >> 31) - 1u);
}

/* Digito hexadecimal `i` do bloco, 0 = o mais alto do primeiro byte. */
static uint8_t nibble(const uint8_t *b, uint32_t i)
{
    uint8_t v = b[i >> 1];
    return (uint8_t)(((i & 1u) == 0u) ? (v >> 4) : (v & 0x0Fu));
}

int pinv_tabela_forma(const uint8_t tab[PINV_TABELA])
{
    uint32_t i;

    for (i = 0u; i < PINV_TABELA; i++) {
        if ((tab[i] < (uint8_t)'0') || (tab[i] > (uint8_t)'9')) {
            return 0;
        }
    }
    return 1;
}

/* A tabela e publica, e o indice e segredo. Um `tab[v]` simples leria uma
 * posicao de memoria que depende do segredo; aqui as 16 entradas sao lidas
 * sempre, e a mascara escolhe. */
void pinv_decimaliza(const uint8_t cifrado[PINV_DADOS],
                     const uint8_t tab[PINV_TABELA],
                     uint8_t natural[PINV_NATURAL])
{
    uint32_t i, j;
    uint8_t  v, d;

    for (i = 0u; i < PINV_NATURAL; i++) {
        v = nibble(cifrado, i);
        d = 0u;
        for (j = 0u; j < PINV_TABELA; j++) {
            d |= (uint8_t)(igual(v, j) & (uint8_t)(tab[j] - (uint8_t)'0'));
        }
        natural[i] = d;
    }
}

void pinv_offset(const uint8_t *pin, const uint8_t *natural, uint32_t n,
                 uint8_t *offset)
{
    uint32_t i, d;

    for (i = 0u; i < n; i++) {
        /* 10 + pin - natural fica de 1 a 19; tira 10 se passou de 9. */
        d = 10u + (uint32_t)pin[i] - (uint32_t)natural[i];
        d -= (uint32_t)((uint8_t)~menor(d, 10u) & 10u);
        offset[i] = (uint8_t)d;
    }
}

int pinv_offset_confere(const uint8_t *pin, const uint8_t *natural,
                        const uint8_t *offset, uint32_t n)
{
    uint32_t i, s;
    uint8_t  dif = 0u;

    for (i = 0u; i < n; i++) {
        s = (uint32_t)natural[i] + (uint32_t)offset[i];      /* 0 a 18 */
        s -= (uint32_t)((uint8_t)~menor(s, 10u) & 10u);
        dif |= (uint8_t)(s ^ (uint32_t)pin[i]);
    }
    return (dif == 0u) ? 1 : 0;
}

int pinv_pvv_tsp(const uint8_t *pan, uint32_t pan_n, uint8_t indice,
                 const uint8_t pin4[4], uint8_t tsp[PINV_DADOS])
{
    uint8_t  nib[2u * PINV_DADOS];
    uint32_t i;

    if ((pan == 0) || (pan_n < PINV_PVV_PAN) || (pan_n > 19u) ||
        (indice > 9u)) {
        return -1;
    }
    for (i = 0u; i < pan_n; i++) {
        if ((pan[i] < (uint8_t)'0') || (pan[i] > (uint8_t)'9')) {
            return -1;
        }
    }
    /* Os 11 digitos antes do ultimo, que e o verificador. */
    for (i = 0u; i < 11u; i++) {
        nib[i] = (uint8_t)(pan[pan_n - 12u + i] - (uint8_t)'0');
    }
    nib[11] = indice;
    for (i = 0u; i < 4u; i++) {
        nib[12u + i] = pin4[i];
    }
    for (i = 0u; i < PINV_DADOS; i++) {
        tsp[i] = (uint8_t)((nib[2u * i] << 4) | nib[2u * i + 1u]);
    }
    for (i = 0u; i < sizeof nib; i++) {
        ((volatile uint8_t *)nib)[i] = 0u;
    }
    return 0;
}

/* Duas passadas sobre os 16 digitos: na primeira valem os decimais, na
 * segunda as letras, menos 10. `achados` conta quantos digitos ja sairam; o
 * digito corrente vai para a posicao `achados`, se ela for menor que 4. A
 * posicao e escolhida por mascara: o laco faz sempre as mesmas 128 voltas. */
void pinv_pvv_extrai(const uint8_t cifrado[PINV_DADOS],
                     uint8_t pvv[PINV_PVV])
{
    uint32_t passada, i, k;
    uint32_t achados = 0u;
    uint8_t  v, serve, valor, m;

    for (k = 0u; k < PINV_PVV; k++) {
        pvv[k] = 0u;
    }
    for (passada = 0u; passada < 2u; passada++) {
        for (i = 0u; i < 2u * PINV_DADOS; i++) {
            v     = nibble(cifrado, i);
            serve = menor(v, 10u);                        /* 0xFF: decimal */
            valor = v;
            if (passada == 1u) {                          /* nao e segredo */
                serve = (uint8_t)~serve;
                valor = (uint8_t)(v - 10u);
            }
            for (k = 0u; k < PINV_PVV; k++) {
                m = (uint8_t)(serve & igual(achados, k));
                pvv[k] |= (uint8_t)(m & valor);
            }
            achados += (uint32_t)(serve & 1u);
        }
    }
}
