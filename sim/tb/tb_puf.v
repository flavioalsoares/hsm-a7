`timescale 1ns/1ps
//
// tb_puf -- bitstream do experimento de RO-PUF (fase 6)
// sim-define: HSM_PUF_SIM
//
// Prova o contador, o protocolo e as regras de seguranca: nunca dois aneis
// ligados, nada liga acima de 70 C, a carga desliga sozinha, e a varredura
// recusa com FFFFFF. Curva de temperatura: sim/stim/tb_puf.txt.
//
// Os aneis aqui sao o modelo de puf_ro.v. Nada disto diz algo sobre o silicio:
// so a placa mostra frequencia, ruido e deriva.
//
module tb_puf;

    localparam real    BIT_NS  = 1000000000.0 / 115200.0;
    localparam integer JANELA  = 2000;
    localparam [11:0]  LIMITE  = 12'd2789;

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;
    wire uart_tx;
    wire [4:0] led;

    always #10 sys_clk = ~sys_clk;

    hsm_puf_top #(.JANELA(JANELA), .ASSENTA(8), .WD_BITS(20)) dut (
        .sys_clk_i (sys_clk),
        .rst_n_i   (rst_n),
        .uart_rxd_i(uart_rx),
        .uart_txd_o(uart_tx),
        .btn_a_i   (1'b1),
        .btn_b_i   (1'b1),
        .led_o     (led),
        .seg_o     (),
        .seg_an_o  ()
    );

    integer erros = 0;

    task falha(input [8*48-1:0] msg);
        begin
            $display("[tb_puf] FAIL: %0s", msg);
            erros = erros + 1;
        end
    endtask

    // ---- monitores: valem o tempo todo ----------------------------------
    integer max_ligados = 0;
    integer ligou_quente = 0;
    integer k, n;

    always @(dut.en) begin
        n = 0;
        for (k = 0; k < 64; k = k + 1) if (dut.en[k] === 1'b1) n = n + 1;
        if (n > max_ligados) max_ligados = n;
        if (n != 0 && dut.temp >= LIMITE) ligou_quente = ligou_quente + 1;
    end

    // ---- UART -----------------------------------------------------------
    task uart_put(input [7:0] b);
        integer i;
        begin
            uart_rx = 1'b0;
            #(BIT_NS);
            for (i = 0; i < 8; i = i + 1) begin
                uart_rx = b[i];
                #(BIT_NS);
            end
            // O dispositivo responde no meio do stop: esperar o stop inteiro
            // perderia a borda de start da resposta.
            uart_rx = 1'b1;
            #(BIT_NS * 0.4);
        end
    endtask

    task uart_get(output [7:0] d);
        integer i;
        begin
            @(negedge uart_tx);
            #(BIT_NS * 1.5);
            for (i = 0; i < 8; i = i + 1) begin
                d[i] = uart_tx;
                #(BIT_NS);
            end
        end
    endtask

    // wait() sobre $realtime nunca reavalia: nao ha sinal que o acorde.
    task ate(input real t);
        begin
            if ($realtime < t) #(t - $realtime);
        end
    endtask

    reg [7:0] b0, b1, b2, b3;

    task resp4;
        begin
            uart_get(b0); uart_get(b1); uart_get(b2); uart_get(b3);
        end
    endtask

    // Varredura: conta quantos aneis mediram e quantos foram recusados.
    integer medidos, recusados, fora;

    task varre;
        integer r, esperado, c;
        begin
            medidos = 0; recusados = 0; fora = 0;
            uart_put("S");
            resp4;
            if (b0 !== "S" || b3 !== 8'd64) falha("cabecalho do S");
            for (r = 0; r < 64; r = r + 1) begin
                uart_get(b0); uart_get(b1); uart_get(b2);
                c = {b0, b1, b2};
                if (c == 24'hFFFFFF) begin
                    recusados = recusados + 1;
                end else begin
                    medidos = medidos + 1;
                    // JANELA ciclos de 10 ns, periodo 2 x MEIO_PS
                    esperado = (JANELA * 10 * 1000) / (2 * (3000 + ((r * 37) % 53)));
                    if (c < esperado - 2 || c > esperado + 2) begin
                        // Janela cortada pelo limite no meio da medida
                        if (dut.temp < LIMITE) begin
                            $display("[tb_puf] anel %0d: %0d, esperado %0d", r, c, esperado);
                            fora = fora + 1;
                        end
                    end
                end
            end
            resp4;
            if (b0 !== "E") falha("fim do S");
        end
    endtask

    initial begin
        #200;
        rst_n = 1'b1;
        wait (dut.rst_n === 1'b1);
        wait (dut.xadc_ok === 1'b1);
        #1000;

        // Antes de qualquer pedido, tudo desligado
        if (dut.en !== 64'd0) falha("anel ligado sem pedido");
        if (dut.nivel !== 4'd0) falha("carga ligada sem pedido");

        uart_put("V");
        resp4;
        if ({b0, b1, b2, b3} !== "PUF1") falha("V");
        else $display("[tb_puf] V ok");

        uart_put("T");
        resp4;
        if (b0 !== "T") falha("T");
        if ({b1, b2} < 16'd2500 || {b1, b2} > 16'd2525) falha("temperatura de 36 C");
        if (b3[2:0] !== 3'b101) falha("estado em T");
        $display("[tb_puf] T ok: codigo %0d", {b1, b2});

        varre;
        if (medidos != 64 || fora != 0) falha("varredura fria");
        else $display("[tb_puf] 64 aneis medidos, contagens certas");

        // Carga
        uart_put("C"); #(BIT_NS); uart_put(8'd3);
        resp4;
        if (b0 !== "K" || b1 !== 8'd3) falha("C 3");
        #200;
        if (dut.carga_en !== 8'h07) falha("bancos da carga");
        $display("[tb_puf] carga em 3 bancos");

        // Aquece em 25 ms: a varredura atravessa o limite.
        ate(24000000.0);
        varre;
        if (recusados == 0) falha("varredura nao recusou");
        if (dut.nivel !== 4'd0 && dut.temp >= LIMITE) falha("carga nao desligou");
        $display("[tb_puf] limite no meio da varredura: %0d medidos, %0d recusados",
                 medidos, recusados);

        ate(30000000.0);
        if (dut.nivel !== 4'd0) falha("carga nao desligou");
        if (led[3] !== 1'b0) falha("D4 apagado com limite atingido");
        uart_put("C"); #(BIT_NS); uart_put(8'd5);
        resp4;
        if (b1 !== 8'd0) falha("carga aceita acima do limite");
        uart_put("T");
        resp4;
        if (b3[1:0] !== 2'b10) falha("estado quente");
        varre;
        if (medidos != 0 || recusados != 64) falha("varredura quente mediu");
        else $display("[tb_puf] acima de 70 C: 64 recusados, carga recusada");

        // Esfria
        ate(72000000.0);
        uart_put("T");
        resp4;
        if (b3[0] !== 1'b1) falha("nao voltou");
        varre;
        if (medidos != 64 || fora != 0) falha("varredura depois de esfriar");
        else $display("[tb_puf] esfriou: 64 aneis medidos");

        // VCCINT cai abaixo do piso em 95 ms: a carga desliga.
        uart_put("C"); #(BIT_NS); uart_put(8'd2);
        resp4;
        if (b1 !== 8'd2) falha("C 2");
        uart_put("U");
        resp4;
        if (b0 !== "U" || {b1, b2} < 16'd1360 || b3[3] !== 1'b1) falha("VCCINT de 1 V");
        ate(97000000.0);
        if (dut.nivel !== 4'd0) falha("carga nao desligou com VCCINT baixa");
        uart_put("C"); #(BIT_NS); uart_put(8'd2);
        resp4;
        if (b1 !== 8'd0) falha("carga aceita com VCCINT baixa");
        uart_put("U");
        resp4;
        if (b3[3] !== 1'b0) falha("estado com VCCINT baixa");
        varre;
        if (medidos != 64) falha("aneis sao guardados so por temperatura");
        $display("[tb_puf] VCCINT abaixo do piso: carga desligou e foi recusada");

        if (max_ligados != 1) falha("mais de um anel ligado");
        if (ligou_quente != 0) falha("anel ligou acima do limite");
        $display("[tb_puf] maximo de aneis ligados: %0d", max_ligados);

        if (erros == 0) $display("[tb_puf] PASS");
        $finish;
    end

    initial begin
        #200000000;
        $display("[tb_puf] FAIL: timeout");
        $finish;
    end

endmodule
