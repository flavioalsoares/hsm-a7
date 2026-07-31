`timescale 1ns/1ps
//
// tb_uart_frame -- protocolo de comandos, ponta a ponta
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// Roda o firmware de verdade (fw/, embutido na IMEM) no SoC de verdade, e
// conversa com ele pela UART a 115200 baud, byte a byte, como o host fara.
//
//   pedido    LEN(2) | CMD(1)    | PAYLOAD | CRC32(4)
//   resposta  LEN(2) | STATUS(1) | PAYLOAD | CRC32(4)
//
// big-endian; LEN cobre CMD/STATUS + PAYLOAD; CRC32 (IEEE 802.3 refletido,
// igual ao zlib.crc32) cobre tudo menos os proprios 4 bytes de CRC.
//
// O CRC e calculado AQUI de forma independente do firmware. Se as duas
// implementacoes divergirem, o teste falha -- que e o ponto.
//
module tb_uart_frame;

    localparam real BIT_NS = 1000000000.0 / 115200.0;   // 8680.6 ns

    // Boot do firmware ate estar pronto para receber. Medido com folga:
    // o banner do bootloader comecava em ~690 us, e este firmware faz bem
    // menos que aquele.
    localparam real BOOT_WAIT_NS = 1500000.0;           // 1,5 ms

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;      // linha do host -> HSM (idle alto)
    reg  btn_a   = 1'b1;
    reg  btn_b   = 1'b1;

    wire       uart_tx;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;

    integer errors = 0;
    integer i;

    reg [7:0] resp [0:31];
    integer   resp_len;
    reg [7:0] st;

    always #10 sys_clk = ~sys_clk;   // 50 MHz

    hsm_top dut (
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

    // ------------------------------------------------------------------
    // CRC32 IEEE 802.3 refletido -- implementacao independente do firmware
    // ------------------------------------------------------------------
    function [31:0] crc32_update;
        input [31:0] crc;
        input [7:0]  b;
        integer k;
        reg [31:0] c;
        begin
            c = crc ^ {24'd0, b};
            for (k = 0; k < 8; k = k + 1) begin
                if (c[0])
                    c = (c >> 1) ^ 32'hEDB88320;
                else
                    c = c >> 1;
            end
            crc32_update = c;
        end
    endfunction

    // ------------------------------------------------------------------
    // UART
    // ------------------------------------------------------------------
    task uart_put(input [7:0] b);
        integer k;
        begin
            uart_rx = 1'b0;              // start
            #(BIT_NS);
            for (k = 0; k < 8; k = k + 1) begin
                uart_rx = b[k];          // LSB primeiro
                #(BIT_NS);
            end
            uart_rx = 1'b1;              // stop
            #(BIT_NS);
        end
    endtask

    // Com validacao de start bit no meio do periodo -- ver tb_soc_boot.
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

    // ------------------------------------------------------------------
    // Envia um frame de comando completo, com CRC correto ou corrompido
    // ------------------------------------------------------------------
    task send_cmd;
        input [7:0]  opcode;
        input        corrupt_crc;
        reg   [31:0] crc;
        reg   [15:0] len;
        begin
            len = 16'd1;                 // so o opcode, sem payload
            crc = 32'hFFFFFFFF;
            crc = crc32_update(crc, len[15:8]);
            crc = crc32_update(crc, len[7:0]);
            crc = crc32_update(crc, opcode);
            crc = ~crc;

            if (corrupt_crc) crc = crc ^ 32'h00000001;

            uart_put(len[15:8]);
            uart_put(len[7:0]);
            uart_put(opcode);
            uart_put(crc[31:24]);
            uart_put(crc[23:16]);
            uart_put(crc[15:8]);
            uart_put(crc[7:0]);
        end
    endtask

    // Recebe um frame de resposta e confere o CRC de forma independente
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

    initial begin
        #60000000;                       // 60 ms
        $display("[tb_uart_frame] FAIL: timeout");
        $display("[tb_uart_frame] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_uart_frame] inicio -- 115200 baud");

        #200;
        rst_n = 1'b1;
        #(BOOT_WAIT_NS);

        // ---- 1. PING -> PONG ------------------------------------------
        send_cmd(8'h01, 1'b0);
        get_response();

        if (st !== 8'h00) begin
            $display("[tb_uart_frame] FAIL: PING status=0x%02h, esperado 0x00", st);
            errors = errors + 1;
        end else if (resp_len !== 5) begin
            $display("[tb_uart_frame] FAIL: PING len=%0d, esperado 5", resp_len);
            errors = errors + 1;
        end else if (resp[1] !== "P" || resp[2] !== "O" ||
                     resp[3] !== "N" || resp[4] !== "G") begin
            $display("[tb_uart_frame] FAIL: PING payload = %c%c%c%c, esperado PONG",
                     resp[1], resp[2], resp[3], resp[4]);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] PING -> PONG");
        end

        // ---- 2. GET_VERSION -------------------------------------------
        send_cmd(8'h02, 1'b0);
        get_response();

        if (st !== 8'h00 || resp_len !== 5) begin
            $display("[tb_uart_frame] FAIL: GET_VERSION status=0x%02h len=%0d",
                     st, resp_len);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] GET_VERSION -> v%0d.%0d.%0d estado=%0d",
                     resp[1], resp[2], resp[3], resp[4]);
            // Fase 1: o dispositivo nasce e fica em UNINITIALIZED (0)
            if (resp[4] !== 8'd0) begin
                $display("[tb_uart_frame] FAIL: estado=%0d, esperado 0 (UNINITIALIZED)",
                         resp[4]);
                errors = errors + 1;
            end
        end

        // ---- 3. CRC corrompido -> STATUS_BAD_CRC ----------------------
        send_cmd(8'h01, 1'b1);
        get_response();

        if (st !== 8'h01) begin
            $display("[tb_uart_frame] FAIL: CRC ruim -> status=0x%02h, esperado 0x01", st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] CRC corrompido -> STATUS_BAD_CRC");
        end

        // ---- 4. opcode desconhecido -> STATUS_UNKNOWN_CMD -------------
        send_cmd(8'hAA, 1'b0);
        get_response();

        if (st !== 8'h10) begin
            $display("[tb_uart_frame] FAIL: opcode 0xAA -> status=0x%02h, esperado 0x10", st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] opcode desconhecido -> STATUS_UNKNOWN_CMD");
        end

        // ---- 5. o dispositivo continua vivo depois dos erros ----------
        // Este e o criterio que importa (PLANO.md secao 2): frame malformado
        // nunca trava a maquina de estados. Se o parser tivesse ficado preso
        // num dos casos acima, este PING nao voltaria.
        send_cmd(8'h01, 1'b0);
        get_response();

        if (st !== 8'h00 || resp[1] !== "P") begin
            $display("[tb_uart_frame] FAIL: dispositivo nao respondeu apos os erros");
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] recuperou: PING responde depois dos frames ruins");
        end

        if (errors == 0)
            $display("[tb_uart_frame] PASS");
        else
            $display("[tb_uart_frame] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
