/* fw/src/main.c -- firmware do HSM educacional
 *
 * FRONTEIRA: este arquivo nao toca material de chave. Ele so inicializa o
 * hardware e roda o laco de comandos.
 *
 * Fase 1: infraestrutura. Sem cripto, sem key store, sem POST -- esses
 * chegam na fase 2 (PLANO.md secao 3), e a partir dali o dispositivo nao
 * pode aceitar comando algum antes dos KAT passarem.
 */
#include <neorv32.h>

#include "cmd.h"
#include "state.h"

/* PLANO.md secao 2. Nao confundir com os 19200 do bootloader do NEORV32. */
#define BAUD_RATE  115200u

/* GPIO -- ver rtl/top/hsm_top.v
 *   saida 0..3 -> LEDs D2..D5 (o toplevel inverte para a placa)
 *   entrada 0  -> SW2, entrada 1 -> SW5 (dual control, fase 3) */
#define LED_ALIVE      0u
#define LED_CMD        1u
#define LED_STATE      2u
#define LED_TAMPER     3u

int main(void)
{
    neorv32_uart0_setup(BAUD_RATE, 0);

    state_init();
    cmd_init();

    /* O CLINT e a base do timeout de resincronizacao do parser. Sem ele o
     * dispositivo aceitaria um frame truncado e ficaria mudo -- negacao de
     * servico com um unico byte. Melhor nao subir do que subir quebrado. */
    if (neorv32_clint_available() == 0) {
        neorv32_gpio_pin_set(LED_TAMPER, 1);
        while (1) { /* trava de proposito */ }
    }

    neorv32_gpio_pin_set(LED_ALIVE, 1);

    /* Laco principal. Nao ha interrupcao: o caminho de comando e sincrono e
     * de passo unico, que e mais facil de auditar do que um handler de IRQ
     * mexendo nos mesmos buffers. */
    while (1) {
        cmd_poll();
    }

    return 0;
}
