`timescale 1ns/1ps
//
// tb_glitch -- o injetor de falha, no SoC inteiro (fase 6)
// sim-define: HSM_ATAQUE
//
// Prova que o pulso de clock sai quando deve: na largura pedida, no atraso
// pedido, uma vez so, sem derrubar o LOCKED e com o firmware de producao.
//
// A FALHA em si nao aparece aqui. Simulacao RTL nao tem atraso de porta, entao
// o clock rapido nao viola nada. So a placa mostra o resultado errado.
//
module tb_glitch;

    localparam real BIT_NS = 1000000000.0 / 115200.0;
    localparam integer TB_CLK_HZ = 100_000;

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;
    wire uart_tx;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;
    wire flash_csn, flash_mosi, flash_miso;

    integer errors = 0;
    reg [7:0] resp [0:31];
    integer   resp_len;
    reg [7:0] st;
    reg [7:0] req_pl [0:63];
    integer   req_plen;

    always #10 sys_clk = ~sys_clk;

    hsm_top #(.CLK_HZ (TB_CLK_HZ)) dut (
        .sys_clk_i (sys_clk), .rst_n_i (rst_n),
        .uart_rxd_i (uart_rx), .uart_txd_o (uart_tx),
        .btn_a_i (1'b1), .btn_b_i (1'b1),
        .led_o (led), .seg_o (seg), .seg_an_o (seg_an),
        .flash_csn_o (flash_csn), .flash_mosi_o (flash_mosi),
        .flash_miso_i (flash_miso),
        .flash_wp_n_o (), .flash_hold_n_o ()
    );

    spi_flash_model flash (
        .sck (dut.flash_sck), .csn (flash_csn),
        .mosi (flash_mosi), .miso (flash_miso)
    );

    function [31:0] crc32_update;
        input [31:0] crc;
        input [7:0]  b;
        integer k;
        reg [31:0] c;
        begin
            c = crc ^ {24'd0, b};
            for (k = 0; k < 8; k = k + 1)
                c = c[0] ? ((c >> 1) ^ 32'hEDB88320) : (c >> 1);
            crc32_update = c;
        end
    endfunction

    task uart_put(input [7:0] b);
        integer k;
        begin
            uart_rx = 1'b0;
            #(BIT_NS);
            for (k = 0; k < 8; k = k + 1) begin
                uart_rx = b[k];
                #(BIT_NS);
            end
            uart_rx = 1'b1;
            #(BIT_NS);
        end
    endtask

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

    task send_cmd_pl;
        input [7:0]  opcode;
        reg   [31:0] crc;
        reg   [15:0] len;
        integer      k;
        begin
            len = req_plen + 1;
            crc = 32'hFFFFFFFF;
            crc = crc32_update(crc, len[15:8]);
            crc = crc32_update(crc, len[7:0]);
            crc = crc32_update(crc, opcode);
            for (k = 0; k < req_plen; k = k + 1)
                crc = crc32_update(crc, req_pl[k]);
            crc = ~crc;

            uart_put(len[15:8]);
            uart_put(len[7:0]);
            uart_put(opcode);
            for (k = 0; k < req_plen; k = k + 1)
                uart_put(req_pl[k]);
            uart_put(crc[31:24]);
            uart_put(crc[23:16]);
            uart_put(crc[15:8]);
            uart_put(crc[7:0]);
        end
    endtask
    task get_response;
        reg [15:0] len;
        reg [31:0] crc, crc_rx;
        reg [7:0]  b;
        integer    k;
        begin
            uart_get(b); len[15:8] = b;
            uart_get(b); len[7:0]  = b;

            crc = 32'hFFFFFFFF;
            crc = crc32_update(crc, len[15:8]);
            crc = crc32_update(crc, len[7:0]);

            resp_len = len;
            for (k = 0; k < len; k = k + 1) begin
                uart_get(b);
                resp[k] = b;
                crc = crc32_update(crc, b);
            end
            crc = ~crc;

            uart_get(b); crc_rx[31:24] = b;
            uart_get(b); crc_rx[23:16] = b;
            uart_get(b); crc_rx[15:8]  = b;
            uart_get(b); crc_rx[7:0]   = b;

            if (crc !== crc_rx) begin
                $display("[tb_uart_frame] FAIL: CRC da resposta invalido (calc=%08h rx=%08h)",
                         crc, crc_rx);
                errors = errors + 1;
            end

            st = resp[0];
        end
    endtask


    // Mede o clock do SoC: quantos periodos curtos, e quando foi o primeiro.
    integer curtos = 0;
    realtime t_ant = 0, t_primeiro = 0;
    always @(posedge dut.clk) begin
        if (t_ant != 0 && ($realtime - t_ant) < 9.0) begin
            if (curtos == 0) t_primeiro = $realtime;
            curtos = curtos + 1;
        end
        t_ant = $realtime;
    end

    // O LOCKED nao pode cair: o clock de realimentacao nao passa pelo mux.
    integer quedas = 0;
    always @(negedge dut.mmcm_locked) if ($realtime > 10000) quedas = quedas + 1;

    task arma(input [23:0] atraso, input [7:0] largura, input [15:0] alvo);
        begin
            req_pl[0] = "G"; req_pl[1] = "L";
            req_pl[2] = atraso[23:16]; req_pl[3] = atraso[15:8]; req_pl[4] = atraso[7:0];
            req_pl[5] = largura;
            req_pl[6] = alvo[15:8]; req_pl[7] = alvo[7:0];
            req_plen = 8;
            send_cmd_pl(8'hF7);
            get_response();
            if (st !== 8'h10) begin
                $display("[tb_glitch] FAIL: o firmware nao recusou o frame: 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    task ping;
        begin
            req_plen = 0;
            send_cmd_pl(8'h01);
            get_response();
            if (st !== 8'h00) begin
                $display("[tb_glitch] FAIL: PING -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    realtime t_fim_quadro;

    initial begin
        #100000000;
        $display("[tb_glitch] FAIL: timeout");
        $finish;
    end

    initial begin
        $display("[tb_glitch] inicio");
        #2000 rst_n = 1'b1;
        wait (led[1] === 1'b0);
        #2000000;

        ping;
        if (curtos != 0) begin
            $display("[tb_glitch] FAIL: %0d periodos curtos sem armar", curtos);
            errors = errors + 1;
        end
        $display("[tb_glitch] desarmado: clock so de 10 ns");

        // ---- pulso --------------------------------------------------------
        arma(24'd5000, 8'd40, 16'd7);    // PING tem 7 bytes
        if (curtos != 0) begin
            $display("[tb_glitch] FAIL: disparou no proprio frame de configuracao");
            errors = errors + 1;
        end
        ping;
        t_fim_quadro = t_primeiro;
        // A troca do mux leva alguns ciclos em cada ponta.
        if (curtos < 36 || curtos > 44) begin
            $display("[tb_glitch] FAIL: pediu 40 ciclos, saiu %0d", curtos);
            errors = errors + 1;
        end
        $display("[tb_glitch] pulso: %0d periodos curtos em t = %0t", curtos, t_primeiro);

        // ---- uma vez so ---------------------------------------------------
        ping;
        if (curtos > 44) begin
            $display("[tb_glitch] FAIL: disparou de novo, %0d periodos", curtos);
            errors = errors + 1;
        end

        // ---- o atraso conta ------------------------------------------------
        // Mesmo pedido com 5000 ciclos a mais: o pulso anda 50 us.
        begin : atraso
            realtime t1, t2;
            integer  c0;
            c0 = curtos;
            arma(24'd5000, 8'd40, 16'd7);
            curtos = 0;
            t_fim_quadro = $realtime;
            ping;
            t1 = t_primeiro - t_fim_quadro;
            arma(24'd10000, 8'd40, 16'd7);
            curtos = 0;
            t_fim_quadro = $realtime;
            ping;
            t2 = t_primeiro - t_fim_quadro;
            if ((t2 - t1) < 49900.0 || (t2 - t1) > 50100.0) begin
                $display("[tb_glitch] FAIL: 5000 ciclos a mais andaram %0.1f ns", t2 - t1);
                errors = errors + 1;
            end
            $display("[tb_glitch] atraso: 5000 ciclos a mais = %0.1f ns", t2 - t1);
        end

        // ---- o dispositivo seguiu ----------------------------------------
        if (quedas != 0 || dut.lock_perdido !== 1'b0) begin
            $display("[tb_glitch] FAIL: LOCKED caiu %0d vezes, retido=%b", quedas, dut.lock_perdido);
            errors = errors + 1;
        end
        $display("[tb_glitch] LOCKED firme, sem perda de lock retida");

        if (errors == 0) $display("[tb_glitch] PASS");
        else             $display("[tb_glitch] FAIL: %0d erros", errors);
        $finish;
    end

endmodule
