`timescale 1ns/1ps
//
// tb_tr31_block -- key block ANSI X9.143 no firmware de verdade
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// ---------------------------------------------------------------------
// O QUE ESTE TESTE PROVA
//
// Que a implementação em C do key block roda no NEORV32 real, sobre o
// coprocessador real, através do mapa de registradores real -- e acerta.
//
// Ele não reimplementa X9.143 em Verilog para comparar. Reimplementar
// seria escrever a MESMA leitura da norma uma terceira vez, com a mesma
// pessoa e o mesmo entendimento: três cópias de um erro concordam tão bem
// quanto duas. O que ele faz é rodar `tr31_selftest()` (fw/src/tr31.c)
// pelo caminho por onde o dispositivo roda de verdade, e cobrar o
// resultado pela UART.
//
// Dentro de `tr31_selftest()` estão três verificações, e vale saber quais
// porque este testbench herda a cobertura delas:
//
//   1. desembrulhar um key block de PROCEDÊNCIA EXTERNA e achar a chave
//      certa. Prova a derivação de KBEK/KBAK, o CBC e o CMAC de uma vez,
//      contra um número que este projeto não escolheu.
//   2. um bit trocado no byte de EXPORTABILIDADE tem de ser recusado.
//      É o que faz o campo significar alguma coisa.
//   3. ida e volta, que cobre a direção de embrulhar -- a que não tem
//      KAT possível, porque o enchimento é aleatório por norma.
//
// ---------------------------------------------------------------------
// O QUE ELE AINDA NÃO PROVA, E QUANDO VAI PROVAR
//
// O critério de aceitação da fase (PLANO.md §4) pede que o parser Python
// e o firmware C concordem em **100 blocos aleatórios**. Isso exige
// entregar um key block ao dispositivo e receber outro de volta, e os
// comandos que fazem isso -- `IMPORT_KEY` (0x24) e `EXPORT_KEY` (0x23) --
// ainda não existem. Enquanto não existirem, o acordo entre as duas
// implementações está provado só no ponto onde as duas tocam o MESMO
// número externo: o vetor de vectors/tr31/.
//
// Registrar isso importa. Um testbench que se descreve como "C e Python
// concordam" quando na verdade roda só o lado C é um testbench que mente
// sobre a própria cobertura.
//
// ⚠ O vetor NÃO é do CAVP, e não há como ser: o CAVP valida ALGORITMO, e
// X9.143 é FORMATO. É valor conhecido de terceiros, fixado por commit e
// hash em vectors/MANIFEST.txt.
//
module tb_tr31_block;

    localparam real BIT_NS = 1000000000.0 / 115200.0;

    // Espelham fw/include/kat.h. Se divergirem, este teste passa a
    // conferir o bit errado -- e conferir o bit errado é pior que não
    // conferir, porque parece cobertura.
    localparam [7:0] KAT_FALHA_TR31 = 8'h80;
    localparam [7:0] KAT_FALHA_CMAC = 8'h20;

    localparam [7:0] CMD_SELFTEST = 8'h15;
    localparam [7:0] STATUS_OK    = 8'h00;

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
            for (k = 0; k < 4; k = k + 1) uart_get(b);   // CRC
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #300000000;                     // 300 ms
        $display("[tb_tr31_block] FAIL: timeout");
        $display("[tb_tr31_block] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_tr31_block] inicio -- key block X9.143 no firmware real");

        #200;
        rst_n = 1'b1;

        // O POST decide antes de qualquer comando. led[1] = firmware vivo,
        // led[4] = tamper; os dois ativos baixos. Esperar por um só
        // travaria o teste no caso que ele existe para pegar.
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));
        #1000;

        if (led[4] === 1'b0) begin
            $display("[tb_tr31_block] FAIL: o POST reprovou -- o dispositivo foi para TAMPERED");
            $display("[tb_tr31_block] (o SELFTEST abaixo diz qual bit)");
            errors = errors + 1;
        end else begin
            $display("[tb_tr31_block] POST verde em %.2f ms", $realtime / 1000000.0);
        end

        // ---- a máscara, byte a byte -----------------------------------
        //
        // Cobrar a máscara e não só o LED: um POST que passasse por não
        // ter rodado o teste de key block acenderia o mesmo LED verde.
        send_cmd(CMD_SELFTEST);
        get_response;

        if (resp_len < 16'd2) begin
            $display("[tb_tr31_block] FAIL: SELFTEST sem mascara (len=%0d)", resp_len);
            errors = errors + 1;
        end else begin
            if (resp[0] !== STATUS_OK) begin
                $display("[tb_tr31_block] FAIL: SELFTEST -> status=0x%02h, esperado 0x00",
                         resp[0]);
                errors = errors + 1;
            end

            if ((resp[1] & KAT_FALHA_TR31) !== 8'h00) begin
                $display("[tb_tr31_block] FAIL: bit de key block aceso (mascara=0x%02h)",
                         resp[1]);
                $display("[tb_tr31_block]   tr31_selftest() reprovou: ou o vetor externo");
                $display("[tb_tr31_block]   nao desembrulhou, ou um cabecalho adulterado");
                $display("[tb_tr31_block]   foi aceito, ou a ida-e-volta nao fechou.");
                errors = errors + 1;
            end else begin
                $display("[tb_tr31_block] key block X9.143: vetor externo, cabecalho");
                $display("[tb_tr31_block]   adulterado recusado, ida e volta -- OK");
            end

            // O CMAC sustenta a derivação e a autenticação do bloco. Se
            // os dois bits acendessem juntos, o de baixo é onde procurar.
            if ((resp[1] & KAT_FALHA_CMAC) !== 8'h00) begin
                $display("[tb_tr31_block] nota: o CMAC tambem reprovou -- e a causa mais provavel");
            end

            if (resp[1] !== 8'h00) begin
                $display("[tb_tr31_block] FAIL: mascara do POST = 0x%02h, esperado 0x00",
                         resp[1]);
                errors = errors + 1;
            end
        end

        if (errors == 0)
            $display("[tb_tr31_block] PASS");
        else
            $display("[tb_tr31_block] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
