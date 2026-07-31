`timescale 1ns/1ps
//
// tb_debounce -- filtro de ressalto dos botoes de dual control
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// O que importa provar: um trem de ressaltos NAO produz pressionamento.
// Os dois botoes autorizam LMK_LOAD_COMPONENT; um pulso espurio aceito
// como autorizacao e uma falha de controle de acesso, nao um glitch
// cosmetico.
//
module tb_debounce;

    localparam integer STABLE = 8;

    reg  clk   = 1'b0;
    reg  rst_n = 1'b0;
    reg  d     = 1'b0;
    wire q;

    integer errors = 0;
    integer i;

    always #5 clk = ~clk;    // 100 MHz

    debounce #(.STABLE_CYCLES (STABLE)) dut (
        .clk_i   (clk),
        .rst_n_i (rst_n),
        .d_i     (d),
        .q_o     (q)
    );

    initial begin
        #200000;
        $display("[tb_debounce] FAIL: timeout");
        $display("[tb_debounce] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_debounce] inicio");

        repeat (4) @(posedge clk);
        rst_n = 1'b1;
        repeat (2) @(posedge clk);

        if (q !== 1'b0) begin
            $display("[tb_debounce] FAIL: q=%b apos reset, esperado 0", q);
            errors = errors + 1;
        end

        // ---- trem de ressaltos: nunca fica estavel por STABLE ciclos --
        // Cada pulso dura menos que a janela exigida, entao a saida tem
        // de permanecer em 0 o tempo todo.
        for (i = 0; i < 12; i = i + 1) begin
            d = 1'b1;
            repeat (STABLE - 3) @(posedge clk);
            if (q !== 1'b0) begin
                $display("[tb_debounce] FAIL: ressalto %0d acionou a saida", i);
                errors = errors + 1;
            end
            d = 1'b0;
            repeat (2) @(posedge clk);
        end
        $display("[tb_debounce] 12 ressaltos curtos ignorados");

        // ---- pressionamento de verdade ---------------------------------
        d = 1'b1;
        repeat (STABLE - 1) @(posedge clk);
        if (q !== 1'b0) begin
            $display("[tb_debounce] FAIL: saida subiu antes de %0d ciclos", STABLE);
            errors = errors + 1;
        end
        @(posedge clk);
        #1;
        if (q !== 1'b1) begin
            $display("[tb_debounce] FAIL: saida nao subiu apos %0d ciclos estaveis", STABLE);
            errors = errors + 1;
        end else begin
            $display("[tb_debounce] pressionamento estavel aceito em %0d ciclos", STABLE);
        end

        // ---- ressalto na SOLTURA nao pode derrubar a saida ------------
        for (i = 0; i < 6; i = i + 1) begin
            d = 1'b0;
            repeat (STABLE - 3) @(posedge clk);
            if (q !== 1'b1) begin
                $display("[tb_debounce] FAIL: ressalto de soltura %0d derrubou a saida", i);
                errors = errors + 1;
            end
            d = 1'b1;
            repeat (2) @(posedge clk);
        end

        // ---- soltura de verdade ----------------------------------------
        d = 1'b0;
        repeat (STABLE) @(posedge clk);
        #1;
        if (q !== 1'b0) begin
            $display("[tb_debounce] FAIL: saida nao desceu na soltura estavel");
            errors = errors + 1;
        end

        if (errors == 0)
            $display("[tb_debounce] PASS");
        else
            $display("[tb_debounce] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
