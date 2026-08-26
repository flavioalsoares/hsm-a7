`timescale 1ns/1ps
//
// hsm_top.v -- toplevel do HSM educacional (Artix-7 XC7A35T, QMTECH)
//
// FASE 1, entregavel 1: infraestrutura de clock e reset + bring-up de I/O.
// O NEORV32 ainda nao esta instanciado -- ver o slot marcado abaixo.
//
// Este e o unico arquivo do projeto que conhece nomes de pino. Pinagem e
// procedencia em doc/pinout.md; restricoes em constraints/qmtech_a35t.xdc.
//
// Polaridades da daughterboard (esquematico DB V03):
//   - LEDs D1..D5  : ATIVOS BAIXOS ('0' acende)
//   - Botoes SW1..5: ATIVOS BAIXOS (pull-up 4,7k, fecham para GND)
// O toplevel absorve as duas inversoes, para que a logica interna trabalhe
// sempre em nivel alto = ativo.
//
module hsm_top #(
    // Frequencia do clock do SoC. Parametrizado para o testbench poder
    // encolher o divisor do heartbeat sem simular meio segundo.
    parameter integer CLK_HZ = 100_000_000,

    // Display de 7 segmentos -- VERIFICADO EM HARDWARE 2026-08-09, com o
    // esquematico concordando. Ver doc/pinout.md.
    //
    //   segmento acende com 0   -> SEG_ACTIVE_LOW = 1
    //   digito habilita com 1   -> AN_ACTIVE_LOW  = 0
    //
    // O AN estava em 1 por palpite, e o palpite estava INVERTIDO. Nao
    // aparecia porque o display fica apagado nesta fase de qualquer jeito:
    // com os segmentos todos desligados, habilitar ou nao os digitos da no
    // mesmo. Apareceria na fase 3, no primeiro estado exibido.
    parameter SEG_ACTIVE_LOW = 1'b1,
    parameter AN_ACTIVE_LOW  = 1'b0,

    // Qual anodo e o digito da ESQUERDA. Ver rtl/top/seg_display.v.
    //
    // VERIFICADO EM HARDWARE 2026-08-26: seg_an_o[0] e o digito da
    // esquerda. A medida de 2026-08-09 nao servia para isto -- ela desenhou
    // "222" nos tres digitos ao mesmo tempo, o que confirma polaridade e
    // mapeamento de segmento mas nao distingue ORDEM. Ver doc/pinout.md.
    parameter DIGITO0_A_ESQUERDA = 1'b1
)(
    // clock e reset
    input  wire       sys_clk_i,    // N11, 50 MHz
    input  wire       rst_n_i,      // B7  (SW1), ativo baixo

    // UART -- canal do hsmtool.py, via CP2102 do core board
    input  wire       uart_rxd_i,   // T15
    output wire       uart_txd_o,   // T14

    // dual control da cerimonia de LMK (fase 3)
    input  wire       btn_a_i,      // M6 (SW2), ativo baixo
    input  wire       btn_b_i,      // P6 (SW5), ativo baixo

    // indicadores
    output wire [4:0] led_o,        // D1..D5, ativos baixos

    // display de estado (fase 3): Uni / Aut / OPE / tPr
    output wire [7:0] seg_o,        // segmentos a..g, dp
    output wire [2:0] seg_an_o      // varredura dos 3 digitos
);

    // ------------------------------------------------------------------
    // Clock e reset
    // ------------------------------------------------------------------
    wire clk;        // 100 MHz -- dominio unico de todo o SoC
    wire rst_n;      // sincrono a clk, ativo baixo
    wire mmcm_locked;

    clk_rst_gen #(
        .RST_HOLD_CYCLES (64)
    ) u_clk_rst (
        .clk_in_i (sys_clk_i),
        .rst_n_i  (rst_n_i),
        .clk_o    (clk),
        .rst_n_o  (rst_n),
        .locked_o (mmcm_locked)
    );

    // ------------------------------------------------------------------
    // Sincronizadores de entrada assincrona
    //
    // Os botoes sao mecanicos e assincronos. Aqui e so sincronizacao de
    // dominio; o filtro de ressalto vem logo abaixo, no debounce.
    // ------------------------------------------------------------------
    (* ASYNC_REG = "TRUE" *) reg [1:0] btn_a_sync = 2'b00;
    (* ASYNC_REG = "TRUE" *) reg [1:0] btn_b_sync = 2'b00;

    always @(posedge clk) begin
        if (!rst_n) begin
            btn_a_sync <= 2'b00;
            btn_b_sync <= 2'b00;
        end else begin
            // inverte aqui: interno ativo alto = botao pressionado
            btn_a_sync <= {btn_a_sync[0], ~btn_a_i};
            btn_b_sync <= {btn_b_sync[0], ~btn_b_i};
        end
    end

    wire btn_a_raw = btn_a_sync[1];
    wire btn_b_raw = btn_b_sync[1];

    // ------------------------------------------------------------------
    // Debounce dos botoes de dual control
    //
    // 10 ms de estabilidade. Escala com CLK_HZ para o testbench nao
    // precisar simular 10 ms reais.
    // ------------------------------------------------------------------
    localparam integer DEBOUNCE_CYCLES = CLK_HZ / 100;

    wire btn_a_db, btn_b_db;

    debounce #(.STABLE_CYCLES (DEBOUNCE_CYCLES)) u_db_a (
        .clk_i (clk), .rst_n_i (rst_n), .d_i (btn_a_raw), .q_o (btn_a_db)
    );

    debounce #(.STABLE_CYCLES (DEBOUNCE_CYCLES)) u_db_b (
        .clk_i (clk), .rst_n_i (rst_n), .d_i (btn_b_raw), .q_o (btn_b_db)
    );

    // ------------------------------------------------------------------
    // Heartbeat -- prova de vida do dominio de 100 MHz
    //
    // Se D1 pisca a 1 Hz, o MMCM travou e esta entregando a frequencia
    // esperada. E o teste mais barato de bring-up do entregavel 1.
    // ------------------------------------------------------------------
    localparam integer HB_DIV = CLK_HZ / 2;   // meia contagem = meio periodo

    // Valor inicial explicito, como nos sincronizadores: em hardware vira o
    // INIT do flip-flop, em simulacao evita que o LED fique em X antes da
    // primeira borda. O reset e sincrono, entao sem isto existe uma janela
    // entre a configuracao do FPGA e o primeiro clock em que a saida nao
    // esta definida -- e a saida aqui e um indicador visivel de estado.
    reg [31:0] hb_cnt    = 32'd0;
    reg        heartbeat = 1'b0;

    always @(posedge clk) begin
        if (!rst_n) begin
            hb_cnt    <= 32'd0;
            heartbeat <= 1'b0;
        end else if (hb_cnt == (HB_DIV - 1)) begin
            hb_cnt    <= 32'd0;
            heartbeat <= ~heartbeat;
        end else begin
            hb_cnt <= hb_cnt + 32'd1;
        end
    end

    // ------------------------------------------------------------------
    // SoC NEORV32
    //
    // Configuracao inteira em rtl/soc/neorv32_wrapper.vhd -- inclusive a
    // lista do que esta deliberadamente DESLIGADO (OCD, caches, XBUS).
    // O core externo fica intocado no submodulo third_party/neorv32.
    // ------------------------------------------------------------------
    wire [7:0] gpio_out;
    wire [7:0] gpio_in;

    assign gpio_in[0]   = btn_a_db;     // SW2 -- dual control A
    assign gpio_in[1]   = btn_b_db;     // SW5 -- dual control B
    assign gpio_in[7:2] = 6'b000000;

    // Saidas do firmware, alem dos LEDs (ver fw/src/main.c):
    //   gpio_out[3:0]  D2..D5
    //   gpio_out[5:4]  estado da maquina, para o display
    //   gpio_out[6]    dual control satisfeito -> ponto decimal
    //   gpio_out[7]    livre

    neorv32_wrapper u_soc (
        .clk_i       (clk),
        .rstn_i      (rst_n),
        .uart0_txd_o (uart_txd_o),
        .uart0_rxd_i (uart_rxd_i),
        .gpio_o      (gpio_out),
        .gpio_i      (gpio_in)
    );

    // ------------------------------------------------------------------
    // LEDs
    //
    // D1 e heartbeat em HARDWARE, independente da CPU. E deliberado: se
    // o firmware travar, D1 continua piscando e distingue "clock morto"
    // de "firmware pendurado". Num dispositivo sem console isso e a
    // diferenca entre depurar e adivinhar.
    //
    // D2..D5 sao do firmware via GPIO. Ficam apagados ate existir
    // firmware (entregavel 4); a fase 3 usa D5 para TAMPERED.
    //
    // O MMCM nao precisa mais de LED proprio: sem lock o reset fica
    // afirmado, o heartbeat nao corre e D1 fica apagado.
    // ------------------------------------------------------------------
    wire [4:0] led_int;

    assign led_int[0]   = heartbeat;        // D1: 1 Hz => 100 MHz vivo
    assign led_int[4:1] = gpio_out[3:0];    // D2..D5: firmware

    // inversao unica para a polaridade da placa
    assign led_o = ~led_int;

    // ------------------------------------------------------------------
    // Display 7 segmentos -- estado da maquina
    //
    // Soletra Uni / Aut / OPE / tPr, e acende o ponto decimal quando o dual
    // control esta satisfeito. Os cinco LEDs desta placa sao todos
    // vermelhos, entao a cor nao distingue nada e e este display que
    // carrega informacao de estado. Ver rtl/top/seg_display.v.
    //
    // Note que o display NAO le a maquina de estados diretamente -- ela
    // vive no firmware. Chegam dois bits pelo GPIO, e so. Um caminho de
    // hardware ate a estrutura de estado seria caminho de hardware ate o
    // que esta ao lado dela na DMEM.
    // ------------------------------------------------------------------
    seg_display #(
        .CLK_HZ              (CLK_HZ),
        .SEG_ACTIVE_LOW      (SEG_ACTIVE_LOW),
        .AN_ACTIVE_LOW       (AN_ACTIVE_LOW),
        .DIGITO0_A_ESQUERDA  (DIGITO0_A_ESQUERDA)
    ) u_seg (
        .clk_i     (clk),
        .rst_n_i   (rst_n),
        .estado_i  (gpio_out[5:4]),
        .dual_ok_i (gpio_out[6]),
        .seg_o     (seg_o),
        .seg_an_o  (seg_an_o)
    );

endmodule
