`timescale 1ns/1ps
//
// clk_rst_gen.v -- geracao de clock e reset do SoC
//
// 50 MHz (N11, oscilador do core board) -> 100 MHz para todo o HSM.
// MMCME2_BASE: VCO = 50 * 20 = 1000 MHz, dentro da faixa 600-1200 MHz do
// Artix-7 -1; CLKOUT0 = VCO / 10 = 100 MHz.
//
// Fica fora da fronteira criptografica: nao toca material de chave. Mas o
// reset e infraestrutura de seguranca -- um SoC que guarda LMK em BRAM nao
// pode rodar com clock fora de lock, entao a queda de LOCKED reafirma o reset
// em vez de ser ignorada.
//
// Convencao do projeto: reset sincrono, ativo baixo. O gerador e a unica
// excecao: ele precisa de afirmacao assincrona porque, com o MMCM em reset,
// clk_o nao esta correndo e nao existe borda para registrar nada. O padrao
// e o classico afirma-assincrono / libera-sincrono, de modo que todo o resto
// do projeto possa usar reset puramente sincrono.
//
module clk_rst_gen #(
    // Ciclos de clk_o com reset afirmado depois que o MMCM trava.
    // Deve caber em 8 bits (1..256).
    parameter integer RST_HOLD_CYCLES = 64
)(
    input  wire clk_in_i,    // 50 MHz, pino N11
    input  wire rst_n_i,     // assincrono, ativo baixo (SW1, pull-up na placa)
    output wire clk_o,       // 100 MHz
    output wire rst_n_o,     // sincrono a clk_o, ativo baixo
    output wire locked_o     // MMCM travado
);

    // ------------------------------------------------------------------
    // Sincronizacao do reset de entrada no dominio de clk_in_i
    //
    // clk_in_i vem do oscilador e corre sempre, inclusive com o MMCM em
    // reset -- por isso este sincronizador e seguro aqui. O botao e
    // assincrono e ressaltante; sem os dois flip-flops, a metaestabilidade
    // entra direto no pino RST do MMCM.
    // ------------------------------------------------------------------
    // Valor inicial explicito: em hardware vira o INIT do flip-flop (reset
    // afirmado ao sair da configuracao); em simulacao evita que X entre no
    // pino RST do MMCM antes da primeira borda.
    (* ASYNC_REG = "TRUE" *) reg [1:0] rst_n_sync = 2'b00;

    always @(posedge clk_in_i) begin
        rst_n_sync <= {rst_n_sync[0], rst_n_i};
    end

    wire mmcm_rst = ~rst_n_sync[1];

    // ------------------------------------------------------------------
    // MMCM 50 -> 100 MHz
    // ------------------------------------------------------------------
    wire clkfb_out, clkfb_in;
    wire clk_out0;
    wire locked_w;

    MMCME2_BASE #(
        .BANDWIDTH          ("OPTIMIZED"),
        .CLKIN1_PERIOD      (20.000),   // 50 MHz
        .DIVCLK_DIVIDE      (1),
        .CLKFBOUT_MULT_F    (20.000),   // VCO = 50 * 20 = 1000 MHz
        .CLKFBOUT_PHASE     (0.000),
        .CLKOUT0_DIVIDE_F   (10.000),   // 1000 / 10 = 100 MHz
        .CLKOUT0_DUTY_CYCLE (0.500),
        .CLKOUT0_PHASE      (0.000),
        .CLKOUT1_DIVIDE     (1),
        .CLKOUT2_DIVIDE     (1),
        .CLKOUT3_DIVIDE     (1),
        .CLKOUT4_DIVIDE     (1),
        .CLKOUT5_DIVIDE     (1),
        .CLKOUT6_DIVIDE     (1),
        .REF_JITTER1        (0.000),
        .STARTUP_WAIT       ("FALSE")
    ) u_mmcm (
        .CLKIN1   (clk_in_i),
        .CLKFBIN  (clkfb_in),
        .CLKFBOUT (clkfb_out),
        .CLKFBOUTB(),
        .CLKOUT0  (clk_out0),
        .CLKOUT0B (),
        .CLKOUT1  (),
        .CLKOUT1B (),
        .CLKOUT2  (),
        .CLKOUT2B (),
        .CLKOUT3  (),
        .CLKOUT3B (),
        .CLKOUT4  (),
        .CLKOUT5  (),
        .CLKOUT6  (),
        .LOCKED   (locked_w),
        .PWRDWN   (1'b0),
        .RST      (mmcm_rst)
    );

    // Realimentacao por BUFG: compensa o atraso da rede global e mantem
    // clk_o alinhado em fase com clk_in_i.
    BUFG u_bufg_fb  (.I(clkfb_out), .O(clkfb_in));
    BUFG u_bufg_out (.I(clk_out0),  .O(clk_o));

    assign locked_o = locked_w;

    // ------------------------------------------------------------------
    // Reset de saida: afirma assincrono, libera sincrono
    //
    // Fonte de afirmacao = botao OU perda de lock. Depois que ambos estao
    // bons, ainda segura RST_HOLD_CYCLES bordas de clk_o antes de liberar,
    // dando margem para a rede global estabilizar.
    // ------------------------------------------------------------------
    wire rst_src_n = locked_w & rst_n_sync[1];

    reg [7:0] rst_cnt;
    reg       rst_n_q;

    always @(posedge clk_o or negedge rst_src_n) begin
        if (!rst_src_n) begin
            rst_cnt <= 8'd0;
            rst_n_q <= 1'b0;
        end else if (rst_cnt != (RST_HOLD_CYCLES[7:0] - 8'd1)) begin
            rst_cnt <= rst_cnt + 8'd1;
            rst_n_q <= 1'b0;
        end else begin
            rst_n_q <= 1'b1;
        end
    end

    assign rst_n_o = rst_n_q;

endmodule
