/* fw/src/cvv.c -- CVV, CVV2 e iCVV (fase 8, etapa 8.6)
 *
 * Ver cvv.h. Aqui nao ha chave nem cifra.
 */
#include "cvv.h"

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

static int digitos(const uint8_t *s, uint32_t n)
{
    uint32_t i;

    for (i = 0u; i < n; i++) {
        if ((s[i] < (uint8_t)'0') || (s[i] > (uint8_t)'9')) {
            return 0;
        }
    }
    return 1;
}

int cvv_dados(const uint8_t *pan, uint32_t pan_n,
              const uint8_t validade[CVV_VALIDADE],
              const uint8_t servico[CVV_SERVICO],
              uint8_t dados[CVV_DADOS])
{
    uint8_t  nib[2u * CVV_DADOS];
    uint32_t i, k = 0u;

    if ((pan == 0) || (validade == 0) || (servico == 0) || (dados == 0) ||
        (pan_n < CVV_PAN_MIN) || (pan_n > CVV_PAN_MAX) ||
        !digitos(pan, pan_n) || !digitos(validade, CVV_VALIDADE) ||
        !digitos(servico, CVV_SERVICO)) {
        return -1;
    }
    for (i = 0u; i < pan_n; i++)        { nib[k++] = (uint8_t)(pan[i] - '0'); }
    for (i = 0u; i < CVV_VALIDADE; i++) { nib[k++] = (uint8_t)(validade[i] - '0'); }
    for (i = 0u; i < CVV_SERVICO; i++)  { nib[k++] = (uint8_t)(servico[i] - '0'); }
    while (k < sizeof nib) {
        nib[k++] = 0u;
    }
    for (i = 0u; i < CVV_DADOS; i++) {
        dados[i] = (uint8_t)((nib[2u * i] << 4) | nib[2u * i + 1u]);
    }
    return 0;
}

/* Duas passadas sobre os 16 digitos: na primeira valem os decimais, na
 * segunda as letras, menos 10. `achados` conta quantos digitos ja sairam; o
 * digito corrente vai para a posicao `achados`, se ela for menor que 3. A
 * posicao e escolhida por mascara: o laco faz sempre as mesmas voltas. E a
 * extracao de pinv_pvv_extrai(), com 3 digitos em vez de 4. */
void cvv_extrai(const uint8_t cifrado[8], uint8_t cvv[CVV_DIGITOS])
{
    uint32_t passada, i, k;
    uint32_t achados = 0u;
    uint8_t  v, serve, valor, m;

    for (k = 0u; k < CVV_DIGITOS; k++) {
        cvv[k] = 0u;
    }
    for (passada = 0u; passada < 2u; passada++) {
        for (i = 0u; i < 16u; i++) {
            v     = (uint8_t)(((i & 1u) == 0u) ? (cifrado[i >> 1] >> 4)
                                               : (cifrado[i >> 1] & 0x0Fu));
            serve = menor(v, 10u);                        /* 0xFF: decimal */
            valor = v;
            if (passada == 1u) {                          /* nao e segredo */
                serve = (uint8_t)~serve;
                valor = (uint8_t)(v - 10u);
            }
            for (k = 0u; k < CVV_DIGITOS; k++) {
                m = (uint8_t)(serve & igual(achados, k));
                cvv[k] |= (uint8_t)(m & valor);
            }
            achados += (uint32_t)(serve & 1u);
        }
    }
}
