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
    output wire locked_o,    // MMCM travado
`ifdef HSM_ATAQUE
    input  wire glitch_i,    // so no bitstream de ataque: clock rapido
`endif
    output wire lock_perdido_o  // retido: o lock caiu sem ninguem pedir
);

`ifndef GLITCH_DIV
`define GLITCH_DIV 7         // 1000 MHz / 7 = 143 MHz
`endif

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

    wire rst_botao = ~rst_n_sync[1];
    reg  religa    = 1'b0;   // ver "Perda de lock", abaixo
    wire mmcm_rst  = rst_botao | religa;

    // ------------------------------------------------------------------
    // MMCM 50 -> 100 MHz
    // ------------------------------------------------------------------
    wire clkfb_out, clkfb_in;
    wire clk_out0;
    wire clk_out1;
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
`ifdef HSM_ATAQUE
        .CLKOUT1_DIVIDE     (`GLITCH_DIV),
`else
        .CLKOUT1_DIVIDE     (1),
`endif
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
        .CLKOUT1  (clk_out1),
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
`ifdef HSM_ATAQUE
    BUFGMUX u_bufg_out (.I0(clk_out0), .I1(clk_out1), .S(glitch_i), .O(clk_o));
`else
    BUFG u_bufg_out (.I(clk_out0),  .O(clk_o));
`endif

    assign locked_o = locked_w;

    // ------------------------------------------------------------------
    // Perda de lock, retida (fase 6)
    //
    // Reafirmar o reset e o que ja se fazia, mas a CPU voltava sem saber o
    // que tinha acontecido. Este flip-flop conta a historia ao boot
    // seguinte, e por isso NAO tem reset: so reconfigurar o FPGA limpa,
    // como o alarme de ambiente (rtl/crypto/hsm_xadc.v).
    //
    // Mora no dominio de clk_in_i, o unico que corre com o MMCM fora de
    // lock. Se o proprio oscilador parar, este bloco para junto, e a
    // queda e vista quando ele voltar: o LOCKED ainda estara baixo.
    //
    // O SW1 tambem derruba o LOCKED, pelo RST do MMCM. Isso e pedido, nao
    // ataque: `ja_travou` limpa enquanto o reset esta afirmado.
    //
    // O MMCM NAO volta sozinho: depois que o LOCKED cai ele exige um RST
    // (UG953, MMCME2_BASE). Sem isso a CPU ficaria presa em reset e a
    // resposta nunca rodaria, com a LMK intacta na flash, ate alguem apertar
    // o SW1. `religa` pulsa o RST por 16 ciclos a cada 2^16 (1,3 ms) enquanto
    // nao travar: um pulso so se perderia num clock que volta instavel.
    // ------------------------------------------------------------------
    reg        ja_travou = 1'b0;
    reg        perdeu    = 1'b0;
    reg [15:0] tentativa = 16'd0;

    always @(posedge clk_in_i) begin
        if (!perdeu || locked_w) begin
            tentativa <= 16'd0;
            religa    <= 1'b0;
        end else begin
            tentativa <= tentativa + 16'd1;
            religa    <= (tentativa[15:4] == 12'd0);
        end
    end

    always @(posedge clk_in_i) begin
        if (rst_botao) begin
            ja_travou <= 1'b0;
        end else if (locked_w) begin
            ja_travou <= 1'b1;
        end else if (ja_travou) begin
            perdeu    <= 1'b1;
        end
    end

    assign lock_perdido_o = perdeu;

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
