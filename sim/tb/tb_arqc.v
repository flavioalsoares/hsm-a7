`timescale 1ns/1ps
//
// tb_arqc -- ARQC e ARPC pela porta host (fase 8, etapa 8.10)
//
// sim-timeout: 28800
//
// Contra o firmware real no NEORV32. Todos os valores esperados sao de
// TERCEIROS, de duas fontes (vectors/emv/arqc.rsp), menos o KCV inteiro da
// MK, que e conta do host/emv.py:
//
//   1. IMK do jPOS: A0 confere o ARQC VSDC (MK do cartao, preenchimento 00)
//      e devolve o ARPC metodo 1 publicado; confere o ARQC EMV_CSKD (chave de
//      sessao comum, preenchimento 80) e devolve o ARPC metodo 2 publicado. O
//      primeiro uso de chave 3DES roda o autoteste do 3DES, que inclui um
//      caso CVN 10 e um CVN 18.
//   2. IMK do pyemv: o CVN 10 (ARPC 1) e o CVN 18 (ARPC 2) publicados.
//   3. ARQC com um caractere trocado: 01, e a resposta sem ARPC.
//   4. A2: a MK do cartao do pyemv sob uma KEK 3DES; cabecalho E0, T, X, N,
//      e o KCV comeca com o publicado (BAB0).
//   5. recusas: PAN de 17 digitos (15), esquema MK com metodo 2 (16), KEK no
//      lugar da IMK (11).
//
// O que ele NAO cobre: ARQCs ao acaso, o dado proprio do ARPC 2 e a MK sob
// KEK AES. Isso e do host/test_emv.py, no PC, e do hsmhost.py arqc-confere,
// na placa.
//
module tb_arqc;

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

    // Blocos sob a LMK, de 112 caracteres: 0 a IMK do jPOS (E0, T, X), 1 a
    // IMK do pyemv (E0, T, X), 2 uma KEK 3DES (K0, T, E) para o A2.
    reg [7:0] b112 [0:335];
    // Os campos, em ASCII, nas posicoes de scripts/mkvectors.py (arqc_tb):
    //   jPOS   0 ATC(4)  4 ARQC 00(16)  20 ARC(4)  24 ARPC1(16)  40 ARQC 80(16)
    //         56 CSU(8)  64 ARPC2(8)  72 dados(78)
    //   pyemv 150 ATC(4)  154 ARQC CVN10(16)  170 ARC(4)  174 ARPC1(16)
    //         190 dados CVN10(74)  264 ARQC CVN18(16)  280 CSU(8)
    //         288 ARPC2(8)  296 dados CVN18(80)
    //   376 PAN jPOS(16)  392 PSN(2)  394 PAN pyemv(16)  410 PSN(2)
    //   412 KCV da MK publicado(4)  416 KCV da MK, Python(6)
    reg [7:0] dd   [0:421];

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
                $display("[tb_arqc] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_arqc] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_arqc] FAIL: %0s -- erro %c%c, esperado %0d",
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
                $display("[tb_arqc] FAIL: CRC da resposta do console invalido");
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
                    $display("[tb_arqc] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_arqc] FAIL: SET_STATE -> 0x%02h", st);
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
                $display("[tb_arqc] FAIL: %0s -- %0d bytes, esperado %0d",
                         nome, resp_len, de_r + n);
                errors = errors + 1;
            end else
                for (k = 0; k < n; k = k + 1)
                    if (resp[de_r + k] !== dd[de_d + k]) begin
                        $display("[tb_arqc] FAIL: %0s -- caractere %0d: %c, esperado %c",
                                 nome, k, resp[de_r + k], dd[de_d + k]);
                        errors = errors + 1;
                    end
        end
    endtask

    // A0 com um caso: bloco q, esquema, preenchimento, PAN/PSN de `pp`, ATC,
    // ARQC, metodo ('1': ARC; '2': CSU e dado proprio vazio) e dados.
    task a0(input integer q, input [7:0] esq, input [7:0] pad,
            input integer pp, input integer atc, input integer arqc,
            input [7:0] metodo, input integer arg, input integer dados,
            input integer n);
        begin
            inicio("A", "0"); poe_b112(q); poe(esq); poe(pad);
            poe("1"); poe("6"); poe_dd(pp, 18);
            poe_dd(atc, 4); poe_dd(arqc, 16); poe(metodo);
            if (metodo == "1") poe_dd(arg, 4);
            if (metodo == "2") begin poe_dd(arg, 8); poe("0"); end
            poe_dec4(n); poe_dd(dados, 2 * n);
            ascii_troca();
        end
    endtask

    initial begin
        $display("[tb_arqc] inicio");
        $readmemh("../vectors/arqc_b112.hex", b112);
        $readmemh("../vectors/arqc_dados.hex", dd);
        if (b112[335] === 8'hxx || dd[421] === 8'hxx) begin
            $display("[tb_arqc] FAIL: vetores nao carregados");
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
            $display("[tb_arqc] FAIL: o POST reprovou no boot");
            $finish;
        end
        limpa();
        console(CMD_GET_VERSION);

        cerimonia();
        $display("[tb_arqc] %0t ns: cerimonia feita", $time);

        // ---- 1. IMK do jPOS ---------------------------------------------
        erros_antes = errors;
        a0(0, "0", "1", 376, 0, 4, "1", 20, 72, 39);
        confere("A", "1", 0, "A0 VSDC 00 (jPOS)");
        confere_dd(8, 24, 16, "A0 VSDC 00 (jPOS)");
        a0(0, "1", "2", 376, 0, 40, "2", 56, 72, 39);
        confere("A", "1", 0, "A0 CSKD 80 (jPOS)");
        confere_dd(8, 64, 8, "A0 CSKD 80 (jPOS)");
        if (errors == erros_antes)
            $display("[tb_arqc] %0t ns: jPOS: ARQC MK e CSK conferidos, ARPC 1 e 2 iguais aos publicados", $time);

        // ---- 2. IMK do pyemv --------------------------------------------
        erros_antes = errors;
        a0(1, "0", "1", 394, 150, 154, "1", 170, 190, 37);
        confere("A", "1", 0, "A0 CVN 10 (pyemv)");
        confere_dd(8, 174, 16, "A0 CVN 10 (pyemv)");
        a0(1, "1", "2", 394, 150, 264, "2", 280, 296, 40);
        confere("A", "1", 0, "A0 CVN 18 (pyemv)");
        confere_dd(8, 288, 8, "A0 CVN 18 (pyemv)");
        if (errors == erros_antes)
            $display("[tb_arqc] %0t ns: pyemv: CVN 10 e CVN 18 conferidos, ARPC iguais aos publicados", $time);

        // ---- 3. ARQC trocado ----------------------------------------------
        erros_antes = errors;
        inicio("A", "0"); poe_b112(0); poe("0"); poe("1");
        poe("1"); poe("6"); poe_dd(376, 18); poe_dd(0, 4);
        poe_dd(4, 15); poe((dd[19] == "0") ? "1" : "0");
        poe("1"); poe_dd(20, 4); poe_dec4(39); poe_dd(72, 78);
        ascii_troca();
        confere("A", "1", 1, "A0 com ARQC trocado");
        if (resp_len != 8) begin
            $display("[tb_arqc] FAIL: ARQC trocado devolveu %0d bytes, esperado 8 (sem ARPC)",
                     resp_len);
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_arqc] %0t ns: ARQC trocado: 01 e nenhum ARPC", $time);

        // ---- 4. A2: a MK do cartao sob KEK --------------------------------
        erros_antes = errors;
        inicio("A", "2"); poe_b112(2); poe_b112(1);
        poe("1"); poe("6"); poe_dd(394, 18);
        ascii_troca();
        confere("A", "3", 0, "A2 sob KEK 3DES");
        if (resp[13] !== "E" || resp[14] !== "0" || resp[15] !== "T" ||
            resp[16] !== "X" || resp[19] !== "N") begin
            $display("[tb_arqc] FAIL: A2 -- cabecalho %c%c%c%c..%c, esperado E0TX..N",
                     resp[13], resp[14], resp[15], resp[16], resp[19]);
            errors = errors + 1;
        end
        c = ((resp[9] - 8'd48) * 1000) + ((resp[10] - 8'd48) * 100) +
            ((resp[11] - 8'd48) * 10) + (resp[12] - 8'd48);
        confere_dd(8 + c, 416, 6, "A2: KCV da MK");
        for (i = 0; i < 4; i = i + 1)
            if (resp[8 + c + i] !== dd[412 + i]) begin
                $display("[tb_arqc] FAIL: A2 -- KCV nao comeca com o publicado");
                errors = errors + 1;
            end
        if (errors == erros_antes)
            $display("[tb_arqc] %0t ns: A2: MK sob KEK, E0 T X N, KCV com o publicado", $time);

        // ---- 5. recusas ----------------------------------------------------
        erros_antes = errors;
        inicio("A", "0"); poe_b112(1); poe("1"); poe("2");
        poe("1"); poe("7"); poe_dd(394, 16); poe("9"); poe_dd(410, 2);
        poe_dd(150, 4); poe_dd(264, 16); poe("0"); poe_dec4(40); poe_dd(296, 80);
        ascii_troca();
        confere("A", "1", 15, "A0 com PAN de 17");
        a0(1, "0", "1", 394, 150, 154, "2", 280, 190, 37);
        confere("A", "1", 16, "A0 MK com metodo 2");
        a0(2, "1", "2", 394, 150, 264, "0", 0, 296, 40);
        confere("A", "1", 11, "A0 com a KEK");
        if (errors == erros_antes)
            $display("[tb_arqc] %0t ns: recusas conferidas", $time);

        if (errors == 0) $display("[tb_arqc] PASS");
        else             $display("[tb_arqc] FAIL: %0d erro(s)", errors);
        $finish;
    end

    initial begin
        #2000000000;     // 2 s
        $display("[tb_arqc] FAIL: timeout");
        $display("[tb_arqc] FAIL");
        $finish;
    end

endmodule
