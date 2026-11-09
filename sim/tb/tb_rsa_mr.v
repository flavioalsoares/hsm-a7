`timescale 1ns/1ps
//
// tb_rsa_mr -- o Miller-Rabin da geracao de chave RSA, contra o KAT de
// primalidade do CAVP (fase 7)
//
// sim-firmware: HSM_TESTE_MR=1
//
// Roda o FIRMWARE DE TESTE (make HSM_TESTE_MR=1, ver fw/Makefile): depois do
// boot ele testa tres candidatos de fw/include/kat_mr.h -- um primo e dois
// compostos, copiados do KeyGen_186-3_RandomProbablyPrime3_3_KAT.txt -- e
// escreve uma linha por caso na UART. O codigo do Miller-Rabin e o mesmo da
// producao; muda so quem o chama. A geracao de ponta a ponta (R0) nao cabe
// em simulacao -- a busca de primos leva segundos -- e e provada na placa.
//
// Cada rodada e uma exponenciacao de 1024 bits na escada: o primo custa
// cinco, e o teste leva cerca de 0,7 s simulado.
//
module tb_rsa_mr;

    localparam real BIT_NS = 1000000000.0 / 115200.0;
    localparam integer TB_CLK_HZ = 100_000;

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;
    wire uart_tx;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;

    always #10 sys_clk = ~sys_clk;
    wire flash_csn, flash_mosi, flash_miso;

    hsm_top #(
        .CLK_HZ (TB_CLK_HZ)
    ) dut (
        .sys_clk_i  (sys_clk),
        .rst_n_i    (rst_n),
        .uart_rxd_i (uart_rx),
        .uart_txd_o (uart_tx),
        .btn_a_i    (1'b1),
        .btn_b_i    (1'b1),
        .led_o      (led),
        .seg_o      (seg),
        .seg_an_o   (seg_an),
        .flash_csn_o    (flash_csn),
        .flash_mosi_o   (flash_mosi),
        .flash_miso_i   (flash_miso),
        .flash_wp_n_o   (),
        .flash_hold_n_o ()
    );

    spi_flash_model flash (
        .sck  (dut.flash_sck),
        .csn  (flash_csn),
        .mosi (flash_mosi),
        .miso (flash_miso)
    );

    task uart_get(output [7:0] data);
        integer k;
        reg     valid;
        begin
            valid = 1'b0;
            while (!valid) begin
                @(negedge uart_tx);
                #(BIT_NS * 0.5);
                if (uart_tx === 1'b0) valid = 1'b1;
            end
            for (k = 0; k < 8; k = k + 1) begin
                #(BIT_NS);
                data[k] = uart_tx;
            end
            #(BIT_NS);
        end
    endtask

    // Uma linha da UART, sem o \r\n, em `linha`.
    reg [8*40-1:0] linha;
    task le_linha;
        reg [7:0] c;
        begin
            linha = 0;
            uart_get(c);
            while (c != 8'h0A) begin
                if (c != 8'h0D) linha = {linha[8*39-1:0], c};
                uart_get(c);
            end
        end
    endtask

    integer errors = 0;
    integer ok = 0;
    integer n;

    initial begin
        #1500000000;                    // 1,5 s
        $display("[tb_rsa_mr] FAIL: timeout");
        $finish;
    end

    initial begin
        $display("[tb_rsa_mr] inicio");
        #200;
        rst_n = 1'b1;

        // Tres linhas, uma por candidato, e o veredito do proprio firmware.
        for (n = 0; n < 3; n = n + 1) begin
            le_linha();
            if (linha == "[mr] ok") begin
                ok = ok + 1;
                $display("[tb_rsa_mr] candidato %0d: %0s", n,
                         (n == 0) ? "primo, aceito" : "composto, recusado");
            end else begin
                $display("[tb_rsa_mr] FAIL: candidato %0d -> '%0s'", n, linha);
                errors = errors + 1;
            end
        end
        le_linha();
        if (linha != "[mr] PASS") begin
            $display("[tb_rsa_mr] FAIL: veredito do firmware '%0s'", linha);
            errors = errors + 1;
        end
        if (led[4] === 1'b0) begin
            $display("[tb_rsa_mr] FAIL: o POST reprovou");
            errors = errors + 1;
        end

        if (errors == 0 && ok == 3) $display("[tb_rsa_mr] PASS");
        else                        $display("[tb_rsa_mr] FAIL: %0d erro(s)", errors);
        $finish;
    end

endmodule
