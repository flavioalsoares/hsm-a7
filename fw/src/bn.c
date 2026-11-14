/* fw/src/bn.c -- aritmetica de numeros grandes em bytes. Ver fw/include/bn.h.
 *
 * FRONTEIRA: dentro. Os operandos podem ser segredos; cada funcao diz se
 * seu tempo depende do valor.
 */
#include "bn.h"

/* a < b, comparando big-endian. So sobre dados publicos. */
int bn_menor(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint32_t i;

    for (i = 0u; i < n; i++) {
        if (a[i] != b[i]) {
            return (a[i] < b[i]) ? 1 : 0;
        }
    }
    return 0;
}

/* x = x - y, big-endian; devolve o emprestimo final (0 ou 1). Sem desvio
 * pelo valor: serve tambem para segredos. */
uint32_t bn_subtrai(uint8_t *x, const uint8_t *y, uint32_t n)
{
    uint32_t i, emprestimo = 0u, d;

    for (i = n; i > 0u; i--) {
        d = (uint32_t)x[i - 1u] - y[i - 1u] - emprestimo;
        x[i - 1u] = (uint8_t)d;
        emprestimo = (d >> 8) & 1u;
    }
    return emprestimo;
}

/* x = x + y, big-endian; devolve o vai-um final. */
uint32_t bn_soma(uint8_t *x, const uint8_t *y, uint32_t n)
{
    uint32_t i, vai = 0u, d;

    for (i = n; i > 0u; i--) {
        d = (uint32_t)x[i - 1u] + y[i - 1u] + vai;
        x[i - 1u] = (uint8_t)d;
        vai = d >> 8;
    }
    return vai;
}

/* a = (a + b) mod m, com a, b < m. Tempo constante: calcula a + b - m
 * sempre e escolhe por mascara. `t` e rascunho de n bytes. */
void bn_soma_mod(uint8_t *a, const uint8_t *b, const uint8_t *m,
                     uint8_t *t, uint32_t n)
{
    uint32_t i, vai, emp, fica;
    uint8_t  mascara;

    vai = bn_soma(a, b, n);
    for (i = 0u; i < n; i++) {
        t[i] = a[i];
    }
    emp = bn_subtrai(t, m, n);
    /* Fica com a soma (sem subtrair) se ela era menor que m: emprestimo
     * sem vai-um. */
    fica    = emp & (vai ^ 1u);
    mascara = (uint8_t)(0u - fica);
    for (i = 0u; i < n; i++) {
        a[i] = (uint8_t)((a[i] & mascara) | (t[i] & (uint8_t)~mascara));
    }
}

/* a = (a - b) mod m, com a, b < m. Tempo constante. */
void bn_subtrai_mod(uint8_t *a, const uint8_t *b, const uint8_t *m,
                        uint8_t *t, uint32_t n)
{
    uint32_t i, emp;
    uint8_t  mascara;

    emp = bn_subtrai(a, b, n);
    for (i = 0u; i < n; i++) {
        t[i] = a[i];
    }
    (void)bn_soma(t, m, n);
    mascara = (uint8_t)(0u - emp);
    for (i = 0u; i < n; i++) {
        a[i] = (uint8_t)((t[i] & mascara) | (a[i] & (uint8_t)~mascara));
    }
}

/* Iguais, comparando tudo (sem sair cedo). */
int bn_iguais(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint32_t i;
    uint8_t  d = 0u;

    for (i = 0u; i < n; i++) {
        d |= (uint8_t)(a[i] ^ b[i]);
    }
    return d == 0u;
}
