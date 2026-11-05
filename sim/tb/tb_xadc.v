`timescale 1ns/1ps
//
// tb_xadc -- os limites de ambiente, um a um, no modelo do XADC da Xilinx
//
// O sinal analogico entra pelo SIM_MONITOR_FILE, que e o unico caminho
// (UG480): quem compara e a logica de alarme do modelo, com os INIT do
// RTL. Nada aqui forca o veredito do sensor. Curva: sim/stim/tb_xadc.txt.
//
//   * dentro da faixa, perto da borda dos dois lados: nenhum alarme
//   * fora, nos oito sentidos: o bit certo, e so ele
//   * de volta a faixa: live cai, sticky fica
//   * reset nao apaga o sticky
//   * sensor parado: o bit 5, com o EOS forcado (nao ha como parar o
//     modelo por curva)
//
module tb_xadc;

    reg clk = 1'b0;
    reg rstn = 1'b0;
    always #5 clk = ~clk;

    wire        valid;
    wire [5:0]  sticky, live;
    wire [11:0] temp, vccint, vccaux, vccbram;

    hsm_xadc #(.WD_BITS(16)) dut (
        .clk_i(clk), .rstn_i(rstn), .valid_o(valid),
        .sticky_o(sticky), .live_o(live),
        .temp_o(temp), .vccint_o(vccint), .vccaux_o(vccaux), .vccbram_o(vccbram)
    );

    integer errors = 0;

    task confere(input [5:0] esp_sticky, input [5:0] esp_live, input [255:0] nome);
        begin
            if (sticky !== esp_sticky || live !== esp_live) begin
                $display("[tb_xadc] FAIL %0s: sticky=%b (esperado %b) live=%b (esperado %b)",
                         nome, sticky, esp_sticky, live, esp_live);
                errors = errors + 1;
            end else begin
                $display("[tb_xadc] %0s: sticky=%b live=%b", nome, sticky, live);
            end
        end
    endtask

    // Fim do degrau n: 450 us depois do inicio, com a media de 16 ja cheia.
    task ate_degrau(input integer n);
        begin
            while ($realtime < n * 500000.0 + 450000.0) #1000;
        end
    endtask

    // Limpa a retencao entre os casos. So o testbench faz isso: no RTL nao
    // existe caminho, e e o que o passo do reset abaixo confere.
    task limpa;
        begin
            force dut.sticky = 6'd0;
            #20;
            release dut.sticky;
        end
    endtask

    task caso(input integer n, input [5:0] bitm, input [255:0] nome);
        begin
            ate_degrau(n);
            confere(bitm, bitm, nome);
            ate_degrau(n + 1);
            confere(bitm, 6'd0, "de volta a faixa");
            limpa;
        end
    endtask

    function real graus(input [11:0] c);
        graus = c * 503.975 / 4096.0 - 273.15;
    endfunction
    function real volts(input [11:0] c);
        volts = c * 3.0 / 4096.0;
    endfunction
    function perto(input real a, input real b, input real tol);
        perto = (a > b - tol) && (a < b + tol);
    endfunction

    initial begin
        #1000 rstn = 1'b1;

        ate_degrau(0);
        if (valid !== 1'b1) begin
            $display("[tb_xadc] FAIL valid nao subiu"); errors = errors + 1;
        end
        $display("[tb_xadc] leituras: %0.1f C, VCCINT %0.3f, VCCAUX %0.3f, VCCBRAM %0.3f",
                 graus(temp), volts(vccint), volts(vccaux), volts(vccbram));
        if (!perto(graus(temp), 36.0, 0.5) || !perto(volts(vccint), 1.0, 0.005) ||
            !perto(volts(vccaux), 1.8, 0.005) || !perto(volts(vccbram), 1.0, 0.005)) begin
            $display("[tb_xadc] FAIL leitura nominal"); errors = errors + 1;
        end
        confere(6'd0, 6'd0, "nominal");

        ate_degrau(1); confere(6'd0, 6'd0, "dentro, perto do teto");
        ate_degrau(3); confere(6'd0, 6'd0, "dentro, perto do piso");

        caso( 5, 6'b000001, "90 C");
        caso( 7, 6'b000010, "VCCINT 1,08");
        caso( 9, 6'b000010, "VCCINT 0,92");
        caso(11, 6'b000100, "VCCAUX 1,92");
        caso(13, 6'b000100, "VCCAUX 1,68");
        caso(15, 6'b001000, "VCCBRAM 1,08");
        caso(17, 6'b001000, "VCCBRAM 0,92");

        ate_degrau(19);
        confere(6'b010000, 6'b010000, "-5 C");

        // Reset nao apaga a prova, mas a condicao ja passou.
        ate_degrau(20);
        rstn = 1'b0; #200; rstn = 1'b1;
        #300000;
        confere(6'b010000, 6'd0, "depois do reset");
        limpa;

        // Sensor parado: sem EOS, 2^16 ciclos = 655 us.
        force dut.eos = 1'b0;
        #800000;
        release dut.eos;
        if (sticky[5] !== 1'b1) begin
            $display("[tb_xadc] FAIL sensor parado nao detectado"); errors = errors + 1;
        end else begin
            $display("[tb_xadc] sensor parado detectado");
        end

        if (errors == 0) $display("[tb_xadc] PASS");
        else             $display("[tb_xadc] FAIL: %0d erros", errors);
        $finish;
    end

    initial begin
        #20000000;
        $display("[tb_xadc] FAIL: timeout");
        $finish;
    end

endmodule
