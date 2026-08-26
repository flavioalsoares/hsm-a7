`timescale 1ns/1ps
//
// tb_hsm_top -- verifica a fiacao do toplevel
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// O alvo principal sao as POLARIDADES. LEDs e botoes da daughterboard sao
// ativos em nivel baixo; inverter no lugar errado da um resultado que
// parece funcionar na bancada e mente sobre o estado do HSM. Um LED de
// TAMPERED invertido e um defeito de seguranca, nao um detalhe cosmetico.
//
// Sim curta e de proposito: quem exercita a CPU de verdade e tb_soc_boot.
//
// O heartbeat usa CLK_HZ reduzido (1000) para o divisor caber na
// simulacao: HB_DIV = 500 ciclos, entao 1000 ciclos = exatamente 2
// transicoes. O mesmo parametro encolhe a janela do debounce para 10
// ciclos.
//
module tb_hsm_top;

    localparam integer TB_CLK_HZ = 1000;
    localparam integer HB_DIV    = TB_CLK_HZ / 2;    // 500
    localparam integer DB_CYC    = TB_CLK_HZ / 100;  // 10

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;
    reg  btn_a   = 1'b1;   // ativo baixo => 1 = solto
    reg  btn_b   = 1'b1;

    wire       uart_tx;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;

    integer errors  = 0;
    integer toggles = 0;
    integer i;
    reg     hb_prev;

    // Amostras da varredura do display, uma por anodo.
    reg [7:0] visto_d0, visto_d1, visto_d2;
    reg [2:0] vistos;

    // Glifos de "Uni", ATIVO ALTO, escritos segmento a segmento.
    // bit0=a bit1=b bit2=c bit3=d bit4=e bit5=f bit6=g
    localparam [6:0] GL_U = 7'b011_1110;   // b c d e f
    localparam [6:0] GL_n = 7'b101_0100;   // c e g
    localparam [6:0] GL_i = 7'b000_0100;   // c

    // 50 MHz
    always #10 sys_clk = ~sys_clk;

    hsm_top #(
        .CLK_HZ (TB_CLK_HZ)
    ) dut (
        .sys_clk_i  (sys_clk),
        .rst_n_i    (rst_n),
        .uart_rxd_i (uart_rx),
        .uart_txd_o (uart_tx),
        .btn_a_i    (btn_a),
        .btn_b_i    (btn_b),
        .led_o      (led),
        .seg_o      (seg),
        .seg_an_o   (seg_an)
    );

    initial begin
        #2000000;
        $display("[tb_hsm_top] FAIL: timeout");
        $display("[tb_hsm_top] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_hsm_top] inicio");

        // ---- LEDs apagados enquanto em reset --------------------------
        // Ativos baixos: apagado = '1'. Se algum LED nascer aceso, a
        // inversao do toplevel esta errada.
        #1;
        if (led !== 5'b11111) begin
            $display("[tb_hsm_top] FAIL: led=%b em reset, esperado 11111 (todos apagados)", led);
            errors = errors + 1;
        end

        #200;
        rst_n = 1'b1;

        wait (dut.rst_n === 1'b1);
        @(posedge dut.clk);
        $display("[tb_hsm_top] SoC fora de reset em t=%0.1f ns", $realtime);

        if (dut.mmcm_locked !== 1'b1) begin
            $display("[tb_hsm_top] FAIL: mmcm_locked=%b", dut.mmcm_locked);
            errors = errors + 1;
        end

        // ---- D2..D5 vem do GPIO do firmware ---------------------------
        // Sem firmware o GPIO le zero, entao os quatro ficam apagados.
        // Confirma a inversao: gpio_out=0 tem de virar led=1.
        if (dut.gpio_out[3:0] !== 4'b0000) begin
            $display("[tb_hsm_top] FAIL: gpio_out=%b, esperado 0 sem firmware", dut.gpio_out[3:0]);
            errors = errors + 1;
        end
        if (led[4:1] !== 4'b1111) begin
            $display("[tb_hsm_top] FAIL: led[4:1]=%b com gpio_out=0, esperado 1111 (apagados)",
                     led[4:1]);
            errors = errors + 1;
        end

        // ---- display: fiacao do seg_display ate os pinos --------------
        //
        // Ate 2026-08-26 este teste conferia que o display estava APAGADO,
        // porque nao havia estado para exibir. Agora ha, e o que se
        // verifica aqui e a FIACAO: que gpio_out[5:4] chega ao modulo,
        // que a polaridade e aplicada uma vez so, e que os tres anodos
        // saem na ordem certa nos pinos.
        //
        // Os glifos em si sao de tb_seg, com a tabela escrita segmento a
        // segmento. Aqui basta "Uni", que e o estado do dispositivo antes
        // de qualquer cerimonia -- e gpio_out vale 0 nesta janela, o que
        // torna o valor esperado independente do firmware.
        //
        // A ORDEM FISICA dos digitos nao se verifica em simulacao: e fato
        // do cobre, medido em 2026-08-26 desenhando "123" pelo rtl/diag/
        // (doc/pinout.md). Aqui so se confere que o parametro chega.
        vistos   = 3'b000;
        visto_d0 = 8'h00;
        visto_d1 = 8'h00;
        visto_d2 = 8'h00;

        for (i = 0; i < 200; i = i + 1) begin
            @(posedge dut.clk);
            case (seg_an)
                3'b001: begin visto_d0 = ~seg; vistos[0] = 1'b1; end
                3'b010: begin visto_d1 = ~seg; vistos[1] = 1'b1; end
                3'b100: begin visto_d2 = ~seg; vistos[2] = 1'b1; end
                3'b000: ;   // apagamento entre digitos
                default: begin
                    $display("[tb_hsm_top] FAIL: dois digitos acesos ao mesmo tempo (an=%b)",
                             seg_an);
                    errors = errors + 1;
                end
            endcase
        end

        if (vistos !== 3'b111) begin
            $display("[tb_hsm_top] FAIL: varredura nao acendeu os tres digitos (vistos=%b)",
                     vistos);
            errors = errors + 1;
        end else if (visto_d0[6:0] !== GL_U || visto_d1[6:0] !== GL_n ||
                     visto_d2[6:0] !== GL_i) begin
            $display("[tb_hsm_top] FAIL: display mostra %b %b %b, esperado Uni (%b %b %b)",
                     visto_d0[6:0], visto_d1[6:0], visto_d2[6:0], GL_U, GL_n, GL_i);
            errors = errors + 1;
        end else if (visto_d0[7] !== 1'b0 || visto_d1[7] !== 1'b0 ||
                     visto_d2[7] !== 1'b0) begin
            // Ponto decimal = dual control satisfeito. Os botoes ainda nao
            // foram apertados nesta altura do teste, entao ele tem de estar
            // apagado -- se acender aqui, o painel esta anunciando
            // autorizacao que ninguem deu.
            $display("[tb_hsm_top] FAIL: ponto decimal aceso com os botoes soltos");
            errors = errors + 1;
        end else begin
            $display("[tb_hsm_top] display -> Uni, tres digitos, sem ponto decimal");
        end

        // ---- botoes: pino baixo = pressionado = 1 no GPIO -------------
        // Passa pelo sincronizador e pelo debounce antes de chegar no SoC.
        if (dut.gpio_in[1:0] !== 2'b00) begin
            $display("[tb_hsm_top] FAIL: gpio_in=%b com botoes soltos, esperado 00",
                     dut.gpio_in[1:0]);
            errors = errors + 1;
        end

        btn_a = 1'b0;                             // pressiona SW2
        repeat (DB_CYC + 6) @(posedge dut.clk);
        if (dut.gpio_in[0] !== 1'b1) begin
            $display("[tb_hsm_top] FAIL: SW2 pressionado, gpio_in[0]=%b, esperado 1",
                     dut.gpio_in[0]);
            errors = errors + 1;
        end
        if (dut.gpio_in[1] !== 1'b0) begin
            $display("[tb_hsm_top] FAIL: SW5 solto, gpio_in[1]=%b, esperado 0", dut.gpio_in[1]);
            errors = errors + 1;
        end

        btn_a = 1'b1;                             // solta
        btn_b = 1'b0;                             // pressiona SW5
        repeat (DB_CYC + 6) @(posedge dut.clk);
        if (dut.gpio_in[1:0] !== 2'b10) begin
            $display("[tb_hsm_top] FAIL: troca de botao errada (gpio_in=%b)", dut.gpio_in[1:0]);
            errors = errors + 1;
        end

        // ---- dual control: os dois ao mesmo tempo ---------------------
        btn_a = 1'b0;
        repeat (DB_CYC + 6) @(posedge dut.clk);
        if (dut.gpio_in[1:0] !== 2'b11) begin
            $display("[tb_hsm_top] FAIL: dois botoes, gpio_in=%b, esperado 11", dut.gpio_in[1:0]);
            errors = errors + 1;
        end else begin
            $display("[tb_hsm_top] dual control: ambos os botoes chegam ao SoC");
        end
        btn_a = 1'b1;
        btn_b = 1'b1;

        // ---- heartbeat: periodo do divisor -----------------------------
        // Em 2*HB_DIV ciclos deve haver exatamente 2 transicoes.
        @(posedge dut.clk); #1;
        hb_prev = led[0];
        toggles = 0;
        for (i = 0; i < (2 * HB_DIV); i = i + 1) begin
            @(posedge dut.clk); #1;
            if (led[0] !== hb_prev) begin
                toggles = toggles + 1;
                hb_prev = led[0];
            end
        end

        $display("[tb_hsm_top] heartbeat: %0d transicoes em %0d ciclos", toggles, 2 * HB_DIV);
        if (toggles != 2) begin
            $display("[tb_hsm_top] FAIL: esperado 2 transicoes (HB_DIV=%0d)", HB_DIV);
            errors = errors + 1;
        end

        if (errors == 0)
            $display("[tb_hsm_top] PASS");
        else
            $display("[tb_hsm_top] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
