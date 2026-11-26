`timescale 1ns/1ps
//
// tb_dukpt_mac -- MAC e dados com DUKPT pela porta host (fase 8, etapa 8.9b)
//
// sim-timeout: 28800
//
// Contra o firmware real no NEORV32. Todos os valores esperados sao de
// TERCEIROS, de duas fontes (vectors/dukpt/dukpt_mac_dados.rsp):
//
//   1. BDK do anexo A.4 da X9.24-1, transacao ...E00001:
//      M4 confere o MAC de pedido de 4 bytes publicado (openemv); M6 da o MAC
//      de resposta de 8 bytes publicado (moov-io); C4 decifra os dados de
//      pedido publicados (openemv); C6 cifra a resposta igual ao publicado
//      (moov-io). O primeiro uso de chave 3DES roda o autoteste do 3DES, que
//      inclui o MAC de pedido de uma transacao.
//   2. BDK AES-128 do suplemento da X9.24-3, transacao ...00000001, chave de
//      trabalho AES-128 (moov-io): M4 confere o CMAC de pedido, e recusa um
//      trocado (01); M6 da o CMAC de resposta; C4 e C6 os dados. O primeiro
//      uso roda o autoteste do DUKPT AES, que inclui as chaves de MAC e de
//      dados da transacao 7.
//   3. recusas: KSN de contador zero (16), chave de trabalho '3' (16), chave
//      de zona no lugar da BDK (11), dados que nao sao multiplos de 8 (15).
//
// O que ele NAO cobre: a chave de trabalho AES-256 com MAC e dados, e
// mensagens ao acaso. Isso e do host/test_dukpt.py, no PC, e do hsmhost.py
// dukpt-confere, na placa.
//
module tb_dukpt_mac;

    localparam real BIT_NS = 1000000000.0 / 115200.0;

    // Ver tb_uart_frame: clock nominal reduzido so para encolher o divisor
    // do debounce. O clock real continua sendo o de 100 MHz.
    localparam integer TB_CLK_HZ     = 100_000;
    localparam real    BTN_SETTLE_NS = 1000000.0;

    localparam [7:0] CMD_GET_VERSION = 8'h02;
    localparam [7:0] CMD_LMK_LOAD    = 8'h20;
    localparam [7:0] CMD_SET_STATE   = 8'h26;


    localparam [7:0] ST_OK        = 8'h00;
    localparam [7:0] ST_BAD_PARAM = 8'h11;

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;
    reg  btn_a   = 1'b1;
    reg  btn_b   = 1'b1;

    wire       uart_tx;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;

    integer errors = 0;
    integer erros_antes;
    integer i, c;

    reg [7:0] resp [0:2047];
    integer   resp_len;
    reg [7:0] st;

    reg [7:0] req [0:2047];
    integer   req_len;

    reg [7:0] comp0 [0:31];
    reg [7:0] comp1 [0:31];
    reg [7:0] comp2 [0:31];
    reg [7:0] lmk   [0:31];

    // Blocos sob a LMK, de 112 caracteres: 0 a BDK do anexo A.4 (B0, T, X),
    // 1 a BDK AES-128 do suplemento (B0, A, X), 2 uma chave de zona (P0).
    reg [7:0] b112 [0:335];
    // KSN TDES(20) . MAC de pedido de 4(8) . MAC de resposta de 8(16) .
    // dados de pedido(48) . dados de resposta(48) . mensagem(34) . claro de
    // 24(48) . KSN AES(24) . CMAC de pedido(32) . de resposta(32) . dados de
    // pedido(64) . de resposta(64) . claro de 32(64)
    reg [7:0] dd   [0:501];

    always #10 sys_clk = ~sys_clk;
    wire flash_csn, flash_mosi, flash_miso;

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

    // ------------------------------------------------------------------
    // CRC32 IEEE 802.3 refletido -- so o console usa
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

    function [7:0] hexdig;
        input [3:0] v;
        hexdig = (v < 10) ? (8'd48 + v) : (8'd55 + v);
    endfunction

    // Dois digitos hex -> um byte, numa chamada so, com nomes que nao
    // existem em nenhum outro escopo. A versao anterior -- {hexval(x),
    // hexval(y)} -- leu "47" como 4B nesta simulacao, enquanto o firmware
    // e o console concordavam em 47 (2026-11-03). Num modulo isolado a mesma
    // expressao funcionou; a causa no xsim nao foi isolada, e o padrao foi
    // trocado por este, que nao depende de duas chamadas da mesma funcao
    // estatica na mesma expressao.
    function [7:0] hexbyte;
        input [7:0] hb_hi;
        input [7:0] hb_lo;
        reg   [3:0] hb_a, hb_b;
        begin
            hb_a = (hb_hi >= 8'd65) ? (hb_hi - 8'd55) : (hb_hi - 8'd48);
            hb_b = (hb_lo >= 8'd65) ? (hb_lo - 8'd55) : (hb_lo - 8'd48);
            hexbyte = {hb_a, hb_b};
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

    // ---- montagem do pedido ------------------------------------------
    task limpa; begin req_len = 0; end endtask
    task poe(input [7:0] b); begin req[req_len] = b; req_len = req_len + 1; end endtask
    task poe_hex(input [7:0] b); begin poe(hexdig(b[7:4])); poe(hexdig(b[3:0])); end endtask
    task poe_dec4(input integer v);
        begin
            poe(8'd48 + (v / 1000) % 10); poe(8'd48 + (v / 100) % 10);
            poe(8'd48 + (v / 10) % 10);   poe(8'd48 + v % 10);
        end
    endtask
    // cabecalho fixo "TB01" + comando
    task inicio(input [7:0] c0, input [7:0] c1);
        begin limpa(); poe("T"); poe("B"); poe("0"); poe("1"); poe(c0); poe(c1); end
    endtask

    // ---- porta HOST: LEN(2) + mensagem, sem CRC ----------------------
    task ascii_troca;
        reg [15:0] len;
        reg [7:0]  b;
        integer    k;
        begin
            len = req_len;
            uart_put(len[15:8]);
            uart_put(len[7:0]);
            for (k = 0; k < req_len; k = k + 1)
                uart_put(req[k]);

            uart_get(b); len[15:8] = b;
            uart_get(b); len[7:0]  = b;
            resp_len = len;
            for (k = 0; k < len; k = k + 1) begin
                uart_get(b);
                resp[k] = b;
            end
        end
    endtask

    // Confere cabecalho devolvido, codigo de resposta e erro.
    task confere(input [7:0] r0, input [7:0] r1, input integer erro,
                 input [8*24-1:0] nome);
        begin
            if (resp_len < 8 ||
                resp[0] !== "T" || resp[1] !== "B" || resp[2] !== "0" || resp[3] !== "1") begin
                $display("[tb_dukpt_mac] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_dukpt_mac] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_dukpt_mac] FAIL: %0s -- erro %c%c, esperado %0d",
                         nome, resp[6], resp[7], erro);
                errors = errors + 1;
            end
        end
    endtask

    // ---- console: o frame binario de sempre ---------------------------
    task console(input [7:0] opcode);
        reg [31:0] crc, crc_rx;
        reg [15:0] len;
        reg [7:0]  b;
        integer    k;
        begin
            len = req_len + 1;
            crc = 32'hFFFFFFFF;
            crc = crc32_update(crc, len[15:8]);
            crc = crc32_update(crc, len[7:0]);
            crc = crc32_update(crc, opcode);
            for (k = 0; k < req_len; k = k + 1)
                crc = crc32_update(crc, req[k]);
            crc = ~crc;

            uart_put(len[15:8]);
            uart_put(len[7:0]);
            uart_put(opcode);
            for (k = 0; k < req_len; k = k + 1)
                uart_put(req[k]);
            uart_put(crc[31:24]); uart_put(crc[23:16]);
            uart_put(crc[15:8]);  uart_put(crc[7:0]);

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
                $display("[tb_dukpt_mac] FAIL: CRC da resposta do console invalido");
                errors = errors + 1;
            end
            st = resp[0];
        end
    endtask

    task apertar; begin btn_a = 1'b0; btn_b = 1'b0; #(BTN_SETTLE_NS); end endtask
    task soltar;  begin btn_a = 1'b1; btn_b = 1'b1; #(BTN_SETTLE_NS); end endtask

    task cerimonia;
        integer n, k;
        begin
            for (n = 0; n < 3; n = n + 1) begin
                soltar(); apertar();
                limpa();
                poe(n[7:0]);
                for (k = 0; k < 32; k = k + 1)
                    case (n)
                        0: poe(comp0[k]);
                        1: poe(comp1[k]);
                        default: poe(comp2[k]);
                    endcase
                console(CMD_LMK_LOAD);
                if (st !== ST_OK) begin
                    $display("[tb_dukpt_mac] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_dukpt_mac] FAIL: SET_STATE -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    task poe_b112(input integer q);
        integer k;
        begin
            for (k = 0; k < 112; k = k + 1) poe(b112[112*q + k]);
        end
    endtask

    task poe_dd(input integer de, input integer n);
        integer k;
        begin
            for (k = 0; k < n; k = k + 1) poe(dd[de + k]);
        end
    endtask

    task confere_dd(input integer de_r, input integer de_d, input integer n,
                    input [8*24-1:0] nome);
        integer k;
        begin
            if (resp_len != de_r + n) begin
                $display("[tb_dukpt_mac] FAIL: %0s -- %0d bytes, esperado %0d",
                         nome, resp_len, de_r + n);
                errors = errors + 1;
            end else
                for (k = 0; k < n; k = k + 1)
                    if (resp[de_r + k] !== dd[de_d + k]) begin
                        $display("[tb_dukpt_mac] FAIL: %0s -- caractere %0d: %c, esperado %c",
                                 nome, k, resp[de_r + k], dd[de_d + k]);
                        errors = errors + 1;
                    end
        end
    endtask

    // KSN: TDES de dd[0..19] (zero = 1 zera o contador); AES de dd[222..245]
    task poe_ksn(input integer aes, input integer zero);
        integer k;
        begin
            if (aes == 1) poe_dd(222, 24);
            else for (k = 0; k < 20; k = k + 1)
                poe((zero == 1 && k >= 16) ? "0" : dd[k]);
        end
    endtask

    initial begin
        $display("[tb_dukpt_mac] inicio");
        $readmemh("../vectors/dukpt_mac_b112.hex", b112);
        $readmemh("../vectors/dukpt_mac_dados.hex", dd);
        if (b112[335] === 8'hxx || dd[501] === 8'hxx) begin
            $display("[tb_dukpt_mac] FAIL: vetores nao carregados");
            $finish;
        end

        for (i = 0; i < 32; i = i + 1) begin
            comp0[i] = 8'h10 + i[7:0];
            comp1[i] = 8'h5A ^ (i[7:0] * 8'h07);
            comp2[i] = 8'hC3 + i[7:0];
        end

        #200;
        rst_n = 1'b1;
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));
        #1000;
        if (led[4] === 1'b0) begin
            $display("[tb_dukpt_mac] FAIL: o POST reprovou no boot");
            $finish;
        end
        limpa();
        console(CMD_GET_VERSION);

        cerimonia();
        $display("[tb_dukpt_mac] %0t ns: cerimonia feita", $time);

        // ---- 1. DUKPT TDES ---------------------------------------------
        erros_antes = errors;
        inicio("M", "4"); poe_b112(0); poe_ksn(0, 0); poe("4"); poe_dd(20, 8);
        poe_dec4(17); poe_dd(140, 34); ascii_troca();
        confere("M", "5", 0, "M4 TDES (openemv)");
        inicio("M", "6"); poe_b112(0); poe_ksn(0, 0); poe("8");
        poe_dec4(17); poe_dd(140, 34); ascii_troca();
        confere("M", "7", 0, "M6 TDES (moov-io)");
        confere_dd(8, 28, 16, "M6 TDES (moov-io)");
        inicio("C", "4"); poe_b112(0); poe_ksn(0, 0);
        for (i = 0; i < 16; i = i + 1) poe("0");
        poe_dec4(24); poe_dd(44, 48); ascii_troca();
        confere("C", "5", 0, "C4 TDES (openemv)");
        confere_dd(12, 174, 48, "C4 TDES (openemv)");
        inicio("C", "6"); poe_b112(0); poe_ksn(0, 0);
        for (i = 0; i < 16; i = i + 1) poe("0");
        poe_dec4(24); poe_dd(174, 48); ascii_troca();
        confere("C", "7", 0, "C6 TDES (moov-io)");
        confere_dd(12, 92, 48, "C6 TDES (moov-io)");
        if (errors == erros_antes)
            $display("[tb_dukpt_mac] %0t ns: DUKPT TDES: M4, M6, C4 e C6 iguais aos publicados (duas fontes)", $time);

        // ---- 2. DUKPT AES ----------------------------------------------
        erros_antes = errors;
        inicio("M", "4"); poe_b112(1); poe_ksn(1, 0); poe("2"); poe_dd(246, 32);
        poe_dec4(17); poe_dd(140, 34); ascii_troca();
        confere("M", "5", 0, "M4 AES (moov-io)");
        inicio("M", "4"); poe_b112(1); poe_ksn(1, 0); poe("2");
        poe((dd[246] == "0") ? "1" : "0"); poe_dd(247, 31);
        poe_dec4(17); poe_dd(140, 34); ascii_troca();
        confere("M", "5", 1, "M4 AES, CMAC trocado");
        inicio("M", "6"); poe_b112(1); poe_ksn(1, 0); poe("2");
        poe_dec4(17); poe_dd(140, 34); ascii_troca();
        confere("M", "7", 0, "M6 AES (moov-io)");
        confere_dd(8, 278, 32, "M6 AES (moov-io)");
        inicio("C", "4"); poe_b112(1); poe_ksn(1, 0); poe("2");
        for (i = 0; i < 32; i = i + 1) poe("0");
        poe_dec4(32); poe_dd(310, 64); ascii_troca();
        confere("C", "5", 0, "C4 AES (moov-io)");
        confere_dd(12, 438, 64, "C4 AES (moov-io)");
        inicio("C", "6"); poe_b112(1); poe_ksn(1, 0); poe("2");
        for (i = 0; i < 32; i = i + 1) poe("0");
        poe_dec4(32); poe_dd(438, 64); ascii_troca();
        confere("C", "7", 0, "C6 AES (moov-io)");
        confere_dd(12, 374, 64, "C6 AES (moov-io)");
        if (errors == erros_antes)
            $display("[tb_dukpt_mac] %0t ns: DUKPT AES: M4, M6, C4 e C6 iguais aos publicados", $time);

        // ---- 3. recusas --------------------------------------------------
        erros_antes = errors;
        inicio("M", "6"); poe_b112(0); poe_ksn(0, 1); poe("8");
        poe_dec4(17); poe_dd(140, 34); ascii_troca();
        confere("M", "7", 16, "M6 com contador zero");
        inicio("M", "6"); poe_b112(1); poe_ksn(1, 0); poe("3");
        poe_dec4(17); poe_dd(140, 34); ascii_troca();
        confere("M", "7", 16, "M6 com trabalho 3");
        inicio("M", "6"); poe_b112(2); poe_ksn(0, 0); poe("8");
        poe_dec4(17); poe_dd(140, 34); ascii_troca();
        confere("M", "7", 11, "M6 com chave de zona");
        inicio("C", "6"); poe_b112(0); poe_ksn(0, 0);
        for (i = 0; i < 16; i = i + 1) poe("0");
        poe_dec4(12); poe_dd(174, 24); ascii_troca();
        confere("C", "7", 15, "C6 com 12 bytes");
        if (errors == erros_antes)
            $display("[tb_dukpt_mac] %0t ns: recusas conferidas", $time);

        if (errors == 0) $display("[tb_dukpt_mac] PASS");
        else             $display("[tb_dukpt_mac] FAIL: %0d erro(s)", errors);
        $finish;
    end

    initial begin
        #2000000000;     // 2 s
        $display("[tb_dukpt_mac] FAIL: timeout");
        $display("[tb_dukpt_mac] FAIL");
        $finish;
    end

endmodule
