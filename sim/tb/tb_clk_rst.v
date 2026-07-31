`timescale 1ns/1ps
//
// tb_clk_rst -- verifica clk_rst_gen (MMCM 50 -> 100 MHz + reset)
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// Precisa das unisims (MMCME2_BASE e primitiva Xilinx) -- roda em xsim,
// nao em iverilog. Ver scripts/sim.sh.
//
// O que e verificado:
//   1. clk_o sai a 100,00 MHz (periodo de 10 ns)
//   2. rst_n_o comeca afirmado e so libera depois de LOCKED
//   3. a liberacao acontece numa borda de subida de clk_o (sincrona)
//   4. o reset fica afirmado por RST_HOLD_CYCLES depois do lock
//   5. rst_n_i afirma o reset de novo e ele se recupera sozinho
//
module tb_clk_rst;

    localparam integer HOLD = 64;

    reg  clk50 = 1'b0;
    reg  rst_n = 1'b0;

    wire clk100;
    wire rst_n_o;
    wire locked;

    integer errors = 0;

    // 50 MHz: meio periodo = 10 ns
    always #10 clk50 = ~clk50;

    clk_rst_gen #(
        .RST_HOLD_CYCLES (HOLD)
    ) dut (
        .clk_in_i (clk50),
        .rst_n_i  (rst_n),
        .clk_o    (clk100),
        .rst_n_o  (rst_n_o),
        .locked_o (locked)
    );

    // ------------------------------------------------------------------
    // Instrumentacao
    // ------------------------------------------------------------------

    // instante da ultima borda de subida de clk100, para provar que a
    // liberacao do reset e sincrona
    real t_last_clk_edge = -1.0;
    always @(posedge clk100) t_last_clk_edge = $realtime;

    // conta bordas de clk100 com lock ja alto e reset ainda afirmado
    integer hold_cycles = 0;
    always @(posedge clk100) begin
        if (locked && !rst_n_o) hold_cycles = hold_cycles + 1;
    end

    // watchdog: se o MMCM nunca travar, falha em vez de rodar para sempre
    initial begin
        #500000;
        $display("[tb_clk_rst] FAIL: timeout -- MMCM nao travou");
        $display("[tb_clk_rst] FAIL");
        $finish;
    end

    // ------------------------------------------------------------------
    // Cenario
    // ------------------------------------------------------------------
    real t0, t1, period;
    real t_release;

    initial begin
        $display("[tb_clk_rst] inicio");

        // ---- 2. reset afirmado desde o inicio -------------------------
        #1;
        if (rst_n_o !== 1'b0) begin
            $display("[tb_clk_rst] FAIL: rst_n_o=%b em t=0, esperado 0", rst_n_o);
            errors = errors + 1;
        end

        // solta o botao de reset; o MMCM comeca a adquirir lock
        #200;
        rst_n = 1'b1;

        // ---- espera o lock --------------------------------------------
        @(posedge locked);
        $display("[tb_clk_rst] LOCKED em t=%0.1f ns", $realtime);

        if (rst_n_o !== 1'b0) begin
            $display("[tb_clk_rst] FAIL: rst_n_o liberou antes/junto do lock");
            errors = errors + 1;
        end

        // ---- 3 e 4. liberacao sincrona, depois do hold ----------------
        @(posedge rst_n_o);
        t_release = $realtime;
        $display("[tb_clk_rst] rst_n_o liberado em t=%0.1f ns apos %0d ciclos",
                 t_release, hold_cycles);

        if (t_release != t_last_clk_edge) begin
            $display("[tb_clk_rst] FAIL: liberacao assincrona (t=%0.1f, ultima borda=%0.1f)",
                     t_release, t_last_clk_edge);
            errors = errors + 1;
        end

        if (hold_cycles < (HOLD - 1) || hold_cycles > (HOLD + 1)) begin
            $display("[tb_clk_rst] FAIL: hold de %0d ciclos, esperado ~%0d",
                     hold_cycles, HOLD);
            errors = errors + 1;
        end

        if (locked !== 1'b1) begin
            $display("[tb_clk_rst] FAIL: locked caiu");
            errors = errors + 1;
        end

        // ---- 1. frequencia de saida -----------------------------------
        @(posedge clk100);
        t0 = $realtime;
        repeat (100) @(posedge clk100);
        t1 = $realtime;
        period = (t1 - t0) / 100.0;

        $display("[tb_clk_rst] periodo medido = %0.4f ns (%0.4f MHz)",
                 period, 1000.0 / period);

        if (period < 9.99 || period > 10.01) begin
            $display("[tb_clk_rst] FAIL: periodo %0.4f ns, esperado 10.0000 ns", period);
            errors = errors + 1;
        end

        // ---- 5. reassercao pelo botao ---------------------------------
        rst_n = 1'b0;
        repeat (10) @(posedge clk50);
        if (rst_n_o !== 1'b0) begin
            $display("[tb_clk_rst] FAIL: rst_n_i baixo nao afirmou rst_n_o");
            errors = errors + 1;
        end

        rst_n = 1'b1;
        // recuperacao: novo lock + hold
        @(posedge rst_n_o);
        $display("[tb_clk_rst] recuperou o reset em t=%0.1f ns", $realtime);

        // ---- veredito --------------------------------------------------
        if (errors == 0)
            $display("[tb_clk_rst] PASS");
        else
            $display("[tb_clk_rst] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
