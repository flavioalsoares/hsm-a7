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
#include "hsm_cfs.h"
#include "kat.h"
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

/* Marco de boot -- so no build de diagnostico (make HSM_DIAG=1 image).
 *
 * Acende um LED E manda uma linha pela UART. Os dois, porque cada um
 * reprova uma coisa diferente: LED aceso com UART muda isola o caminho
 * serial; UART falando com LED apagado isola o GPIO. Um so nao separa.
 *
 * FRONTEIRA: nao toca material de chave. Nao pode passar a tocar -- se um
 * dia este marco imprimir estado interno, vira canal lateral ligado por
 * flag de compilacao, que e a pior forma de vazamento porque nao aparece
 * em nenhuma revisao de codigo de runtime. */
#ifdef HSM_DIAG
#  define MARCO(led, texto)                        \
      do {                                         \
          neorv32_gpio_pin_set((led), 1);          \
          neorv32_uart0_puts("[diag] " texto "\r\n"); \
      } while (0)
#else
#  define MARCO(led, texto) do { (void)(led); } while (0)
#endif

int main(void)
{
    neorv32_uart0_setup(BAUD_RATE, 0);

    /* Primeiro sinal de vida possivel: se este nao sair, o problema esta
     * antes de main() -- crt0, IMEM ou a propria CPU. */
    MARCO(LED_CMD, "main");

    state_init();
    cmd_init();

    MARCO(LED_STATE, "state+cmd");

    /* O CLINT e a base do timeout de resincronizacao do parser. Sem ele o
     * dispositivo aceitaria um frame truncado e ficaria mudo -- negacao de
     * servico com um unico byte. Melhor nao subir do que subir quebrado. */
    if (neorv32_clint_available() == 0) {
#ifdef HSM_DIAG
        neorv32_uart0_puts("[diag] SEM CLINT -- travando\r\n");
#endif
        neorv32_gpio_pin_set(LED_TAMPER, 1);
        while (1) { /* trava de proposito */ }
    }

    MARCO(LED_CMD, "clint ok");

    /* O coprocessador criptografico tem de estar presente e se identificar.
     *
     * Nao e o POST -- esse chega com os KAT no boot, ainda nesta fase, e
     * verifica que o hardware calcula CERTO. Este teste e mais fraco de
     * proposito: verifica que o hardware EXISTE. Sem ele, um bitstream
     * gerado com IO_CFS_EN desligado subiria normalmente e so falharia na
     * hora de usar cripto, que e tarde demais para descobrir.
     *
     * Recusar subir e a resposta certa: um modulo criptografico que nao
     * consegue fazer criptografia nao deve aceitar comando nenhum. */
    if (hsm_cfs_present() == 0) {
#ifdef HSM_DIAG
        neorv32_uart0_puts("[diag] SEM CFS -- travando\r\n");
#endif
        neorv32_gpio_pin_set(LED_TAMPER, 1);
        while (1) { /* trava de proposito */ }
    }

    MARCO(LED_STATE, "cfs ok");

    /* ------------------------------------------------------------------
     * POST -- power-on self-test
     *
     * Roda ANTES de aceitar qualquer comando. Nao e capricho: e o
     * requisito de self-test do FIPS 140-3, e a logica dele e simples --
     * um modulo criptografico que nao consegue provar que calcula certo
     * AGORA nao deve aceitar comando nenhum. Cripto errada e pior que
     * cripto ausente, porque parece que funcionou.
     *
     * Cobre AES, SHA, HMAC e CTR_DRBG contra vetores oficiais, e os
     * testes de partida da fonte de entropia. Ver fw/src/kat.c.
     *
     * Falhou: o dispositivo vai para TAMPERED e FICA. Nao trava e nao
     * reinicia -- continua atendendo, porque o unico comando que responde
     * em TAMPERED e o SELFTEST, e sem ele o operador teria apenas um LED
     * vermelho e nenhuma informacao sobre o que reprovou.
     * ------------------------------------------------------------------ */
    if (kat_post() != KAT_OK) {
#ifdef HSM_DIAG
        neorv32_uart0_puts("[diag] POST REPROVOU\r\n");
#endif
        neorv32_gpio_pin_set(LED_TAMPER, 1);
        state_set(HSM_TAMPERED);
    } else {
        MARCO(LED_CMD, "post ok");
        neorv32_gpio_pin_set(LED_ALIVE, 1);
    }

#ifdef HSM_DIAG
    neorv32_uart0_puts("[diag] laco de comandos\r\n");
#endif

    /* Laco principal. Nao ha interrupcao: o caminho de comando e sincrono e
     * de passo unico, que e mais facil de auditar do que um handler de IRQ
     * mexendo nos mesmos buffers. */
    while (1) {
        cmd_poll();
    }

    return 0;
}
