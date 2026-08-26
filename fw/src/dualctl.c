/* fw/src/dualctl.c -- dual control pelos dois botoes fisicos
 *
 * FRONTEIRA: dentro. Ver dualctl.h para o raciocinio inteiro, inclusive o
 * que este mecanismo deliberadamente NAO prova.
 */
#include <neorv32.h>

#include "dualctl.h"

/* 1 = os dois botoes foram vistos soltos desde a ultima autorizacao.
 *
 * volatile porque o valor e observado e alterado em pontos diferentes do
 * laco principal, e porque um estado de autorizacao e exatamente o tipo de
 * variavel que nao se quer ver o compilador cacheando em registrador
 * atraves de uma chamada. */
static volatile uint8_t g_armado;

static int pressionado(unsigned bit)
{
    /* neorv32_gpio_pin_get devolve a mascara, nao 0/1. Comparar com != 0
     * e nao com == 1: um `== 1` funcionaria so para o bit 0, e falharia em
     * silencio para o botao B. */
    return (neorv32_gpio_pin_get((int)bit) != 0u) ? 1 : 0;
}

static int ambos_pressionados(void)
{
    /* Sem curto-circuito de proposito: as duas leituras acontecem sempre,
     * na mesma ordem, gastando o mesmo tempo. Nao e uma contramedida seria
     * de canal lateral -- o segredo aqui nao esta nos botoes -- mas o
     * habito de nao ramificar sobre condicao de autorizacao e barato. */
    int a = pressionado(DUALCTL_BIT_A);
    int b = pressionado(DUALCTL_BIT_B);
    return (a & b);
}

static int ambos_soltos(void)
{
    int a = pressionado(DUALCTL_BIT_A);
    int b = pressionado(DUALCTL_BIT_B);
    return ((a | b) == 0) ? 1 : 0;
}

void dualctl_init(void)
{
    /* Desarmado. Se a placa ligou com um botao colado, ele nao vale como
     * consentimento -- e nunca valera, ate alguem soltar. */
    g_armado = 0u;
}

void dualctl_poll(void)
{
    if (ambos_soltos()) {
        g_armado = 1u;
    }
}

int dualctl_pronto(void)
{
    /* Consulta pura. Se um dia esta funcao ganhar efeito colateral, ela
     * deixa de ser consulta e o painel vira caminho de autorizacao. */
    if (g_armado == 0u) {
        return 0;
    }
    return ambos_pressionados();
}

int dualctl_autoriza(void)
{
    if (g_armado == 0u) {
        return 0;
    }
    if (!ambos_pressionados()) {
        /* Recusa SEM desarmar: o rearme e do operador, e um host que chame
         * o comando em laco nao pode gasta-lo. Do contrario, um cliente
         * hostil bastaria para impedir a cerimonia. */
        return 0;
    }

    g_armado = 0u;
    return 1;
}
