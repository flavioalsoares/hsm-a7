`timescale 1ns/1ps
//
// tb_post_tamper -- fonte de entropia travada leva o dispositivo a TAMPERED
//
// ---------------------------------------------------------------------
// O QUE ESTE TESTE PROVA, E POR QUE ELE PRECISA EXISTIR
//
// Os outros testes provam pedaços da corrente:
//
//   tb_trng_health   o RCT reprova uma fonte travada, na amostra exata
//   tb_cfs           o veredito do RCT chega ao registrador de status
//   tb_uart_frame    o POST passa e o dispositivo entra em operação
//
// Falta o que liga tudo: uma fonte fisicamente travada faz o POST
// reprovar, o firmware ir para TAMPERED, e o dispositivo RECUSAR comando.
// Cada elo estar certo não prova que estão ligados -- e é justamente na
// emenda entre hardware e firmware que este projeto já perdeu uma sessão.
//
// Um health test que detecta e não desliga nada é decoração.
//
// ---------------------------------------------------------------------
// COMO A FALHA É INJETADA, E O QUE ISSO CUSTA EM PRECISÃO
//
// A injeção ideal seria travar a amostra bruta em 0 -- o modo de falha real
// de um oscilador em anel que para de oscilar. **Não dá:** o xsim não
// suporta `force` atravessando a fronteira VHDL/Verilog, nem sobre o sinal
// VHDL nem sobre a porta Verilog ligada a ele:
//
//   ERROR: [XSIM 43-4289] Force not supported yet in mixed language
//   scenarios. Verilog formal ent_raw_i, which is connected to VHDL actual
//   ent_raw, is forced.
//
// Então a injeção é um degrau acima: força-se o VEREDITO do RCT, que é um
// registrador puramente Verilog dentro de hsm_health. O que este teste
// prova passa a ser:
//
//   RCT reprovado --> status --> firmware --> TAMPERED --> comando recusado
//
// E o elo que ele NÃO prova -- fonte travada produz RCT reprovado -- já é
// provado por tb_trng_health, na amostra exata, e por tb_cfs através do
// barramento. Os três juntos cobrem a corrente inteira; nenhum sozinho
// cobre.
//
// Registrar essa costura importa: um teste que se descreve como "fonte
// travada" quando na verdade força o resultado do teste é um teste que
// mente sobre a própria cobertura.
//
// Não há knob de auto-sabotagem no RTL de produção, e não pode haver: um
// caminho que force a fonte a travar é um caminho para derrubar o
// dispositivo. A injeção vive aqui, no testbench.
//
module tb_post_tamper;

    localparam real BIT_NS = 1000000000.0 / 115200.0;

    // Veredito do RCT dentro do coprocessador. Se a hierarquia mudar, o
    // `force` falha na elaboração -- que é o modo certo de descobrir, e
    // melhor do que este teste passar sem forçar nada.
    `define RCT_FAIL dut.u_soc.u_neorv32.io_system.neorv32_cfs_enabled.neorv32_cfs_inst.u_core.u_health.rct_fail_o

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;

    wire       uart_tx;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;

    integer errors = 0;

    always #10 sys_clk = ~sys_clk;      // 50 MHz -> MMCM -> 100 MHz

    hsm_top dut (
        .sys_clk_i  (sys_clk),
        .rst_n_i    (rst_n),
        .uart_rxd_i (uart_rx),
        .uart_txd_o (uart_tx),
        .btn_a_i    (1'b1),
        .btn_b_i    (1'b1),
        .led_o      (led),
        .seg_o      (seg),
        .seg_an_o   (seg_an)
    );

    // ------------------------------------------------------------------
    function [31:0] crc32_update;
        input [31:0] crc;
        input [7:0]  b;
        integer k;
        reg [31:0] c;
        begin
            c = crc ^ {24'd0, b};
            for (k = 0; k < 8; k = k + 1) begin
                if (c[0]) c = (c >> 1) ^ 32'hEDB88320;
                else      c = c >> 1;
            end
            crc32_update = c;
        end
    endfunction

    task uart_put(input [7:0] b);
        integer k;
        begin
            uart_rx = 1'b0;  #(BIT_NS);
            for (k = 0; k < 8; k = k + 1) begin
                uart_rx = b[k];  #(BIT_NS);
            end
            uart_rx = 1'b1;  #(BIT_NS);
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

    task send_cmd(input [7:0] opcode);
        reg [31:0] crc;
        reg [15:0] len;
        begin
            len = 16'd1;
            crc = 32'hFFFFFFFF;
            crc = crc32_update(crc, len[15:8]);
            crc = crc32_update(crc, len[7:0]);
            crc = crc32_update(crc, opcode);
            crc = ~crc;
            uart_put(len[15:8]); uart_put(len[7:0]); uart_put(opcode);
            uart_put(crc[31:24]); uart_put(crc[23:16]);
            uart_put(crc[15:8]);  uart_put(crc[7:0]);
        end
    endtask

    reg [7:0]  resp [0:63];
    reg [15:0] resp_len;

    task get_response;
        reg [15:0] len;
        reg [7:0]  b;
        integer    k;
        begin
            uart_get(b); len[15:8] = b;
            uart_get(b); len[7:0]  = b;
            resp_len = len;
            for (k = 0; (k < len) && (k < 64); k = k + 1) begin
                uart_get(b);
                resp[k] = b;
            end
            for (k = 0; k < 4; k = k + 1) uart_get(b);   // CRC, ignorado aqui
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        $display("[tb_post_tamper] inicio -- RCT reprovado a forca");

        // Força ANTES de soltar o reset: o POST tem de encontrar a fonte já
        // reprovada, como encontraria num oscilador que nunca partiu.
        force `RCT_FAIL = 1'b1;

        #200;
        rst_n = 1'b1;

        // Espera o desfecho do POST: LED de tamper (led[4]) ou de atividade
        // (led[1]), os dois ativos baixos. Esperar só por um travaria.
        wait ((led[4] === 1'b0) || (led[1] === 1'b0));
        #1000;

        if (led[1] === 1'b0) begin
            $display("[tb_post_tamper] FAIL: o POST PASSOU com a fonte travada");
            $display("[tb_post_tamper] FAIL");
            $finish;
        end

        if (led[4] !== 1'b0) begin
            $display("[tb_post_tamper] FAIL: nenhum LED decidiu");
            errors = errors + 1;
        end else begin
            $display("[tb_post_tamper] POST reprovou em %.2f ms, LED de tamper aceso",
                     $realtime / 1000000.0);
        end

        // O dispositivo tem de RECUSAR comando de operação. Estar em
        // TAMPERED e continuar respondendo PING seria detectar a falha e
        // não fazer nada com ela.
        send_cmd(8'h01);                 // PING
        get_response;
        if (resp_len < 16'd1) begin
            $display("[tb_post_tamper] FAIL: PING sem resposta");
            errors = errors + 1;
        end else if (resp[0] !== 8'h20) begin
            $display("[tb_post_tamper] FAIL: PING em TAMPERED -> status=0x%02h, esperado 0x20 (WRONG_STATE)",
                     resp[0]);
            errors = errors + 1;
        end else begin
            $display("[tb_post_tamper] PING recusado com WRONG_STATE, como deve");
        end

        // SELFTEST é a única exceção: responde em TAMPERED, e diz o que
        // falhou. Sem ele o operador teria apenas um LED vermelho.
        send_cmd(8'h15);
        get_response;
        if (resp_len < 16'd2) begin
            $display("[tb_post_tamper] FAIL: SELFTEST sem payload (len=%0d)", resp_len);
            errors = errors + 1;
        end else if (resp[0] !== 8'h30) begin
            $display("[tb_post_tamper] FAIL: SELFTEST -> status=0x%02h, esperado 0x30",
                     resp[0]);
            errors = errors + 1;
        end else if ((resp[1] & 8'h10) === 8'h00) begin
            $display("[tb_post_tamper] FAIL: mascara 0x%02h nao acusa o TRNG (bit 0x10)",
                     resp[1]);
            errors = errors + 1;
        end else begin
            $display("[tb_post_tamper] SELFTEST responde em TAMPERED e acusa o TRNG (0x%02h)",
                     resp[1]);
        end

        release `RCT_FAIL;

        if (errors == 0) $display("[tb_post_tamper] PASS");
        else             $display("[tb_post_tamper] FAIL -- %0d erro(s)", errors);
        $finish;
    end

    initial begin
        #40000000;                       // 40 ms
        $display("[tb_post_tamper] FAIL -- timeout");
        $display("[tb_post_tamper] FAIL");
        $finish;
    end

endmodule
