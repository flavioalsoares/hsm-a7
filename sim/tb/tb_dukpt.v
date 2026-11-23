`timescale 1ns/1ps
//
// tb_dukpt -- DUKPT TDES pela porta host (fase 8, etapa 8.8a)
//
// sim-timeout: 21600
//
// Contra o firmware real no NEORV32.
//
//   1. P2 com a BDK do anexo A.4 da X9.24-1 (valores de TERCEIROS,
//      vectors/dukpt/x924_1_tdes.rsp) e a transacao de KSN ...EFF800
//      (contador 0FF800, 9 bits 1): o firmware refaz a chave de PIN do terminal, abre o PIN
//      block publicado e o fecha sob uma chave de zona. A saida e formato 0,
//      sem aleatorio, e o tb a compara inteira com a conta do Python;
//   2. I0 da IPEK do anexo sob uma KEK 3DES: bloco versao B com o
//      cabecalho B1/T/X/N, e o KCV da IPEK publicada;
//   3. recusas: KSN de contador zero (16), BDK sem modo X (11), PIN block
//      adulterado (14), chave de zona no lugar da KEK do I0 (13).
//
// O que ele NAO cobre: o destino formato 4 (o fechamento e o do P0, coberto
// pelo tb_pin) e KSNs ao acaso. Isso e do host/test_dukpt.py, no PC, e do
// hsmhost.py dukpt-confere, na placa.
//
module tb_dukpt;

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

    // Os quatro blocos sob a LMK, 112 caracteres cada: a BDK do anexo com
    // modo X, a mesma BDK com modo B, a chave de zona (P0, E) e a KEK (K0, E).
    reg [7:0] blocos [0:447];
    // KSN(20) . PAN(13) . PIN block(16) . PIN block adulterado(16) .
    // esperado(16) . KCV da IPEK(6) . cabecalho do bloco do I0(16)
    reg [7:0] dd     [0:102];

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
                $display("[tb_dukpt] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_dukpt] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_dukpt] FAIL: %0s -- erro %c%c, esperado %0d",
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
                $display("[tb_dukpt] FAIL: CRC da resposta do console invalido");
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
                    $display("[tb_dukpt] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_dukpt] FAIL: SET_STATE -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    task poe_bl(input integer q);
        integer k;
        begin
            for (k = 0; k < 112; k = k + 1) poe(blocos[112*q + k]);
        end
    endtask

    task poe_dd(input integer de, input integer n);
        integer k;
        begin
            for (k = 0; k < n; k = k + 1) poe(dd[de + k]);
        end
    endtask

    // P2: BDK (bloco q) . zona . KSN . "00" . PAN . PIN block (dd[de..])
    task p2(input integer q, input integer ksn_zero, input integer de_pb);
        integer k;
        begin
            inicio("P", "2"); poe_bl(q); poe_bl(2);
            for (k = 0; k < 20; k = k + 1)
                poe((ksn_zero == 1 && k >= 15) ? "0" :
                    (ksn_zero == 1 && k == 14) ? "E" : dd[k]);
            poe("0"); poe("0"); poe("1"); poe("3");
            poe_dd(20, 13);
            poe_dd(de_pb, 16);
            ascii_troca();
        end
    endtask

    initial begin
        $display("[tb_dukpt] inicio");
        $readmemh("../vectors/dukpt_blocos.hex", blocos);
        $readmemh("../vectors/dukpt_dados.hex", dd);
        if (blocos[447] === 8'hxx || dd[102] === 8'hxx) begin
            $display("[tb_dukpt] FAIL: vetores nao carregados");
            $finish;
        end

        // LMK de teste, por tres componentes: a mesma do tb_rsa e do tb_kek3.
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
            $display("[tb_dukpt] FAIL: o POST reprovou no boot");
            $finish;
        end
        limpa();
        console(CMD_GET_VERSION);

        cerimonia();
        $display("[tb_dukpt] %0t ns: cerimonia feita", $time);

        // ---- 1. P2 com o anexo ---------------------------------------------
        erros_antes = errors;
        p2(0, 0, 33);
        confere("P", "3", 0, "P2 do anexo");
        if (resp_len != 8 + 16) begin
            $display("[tb_dukpt] FAIL: P2 -- %0d bytes", resp_len);
            errors = errors + 1;
        end
        for (i = 0; i < 16; i = i + 1)
            if (resp[8 + i] !== dd[65 + i]) begin
                $display("[tb_dukpt] FAIL: P2 -- caractere %0d: %c, esperado %c",
                         i, resp[8 + i], dd[65 + i]);
                errors = errors + 1;
            end
        if (errors == erros_antes)
            $display("[tb_dukpt] %0t ns: P2 traduz o PIN block do anexo, igual ao Python", $time);

        // ---- 2. I0 da IPEK do anexo ----------------------------------------
        erros_antes = errors;
        inicio("I", "0"); poe_bl(3); poe_bl(0); poe_dd(0, 20); ascii_troca();
        confere("I", "1", 0, "I0 sob a KEK 3DES");
        if (resp_len != 8 + 80 + 6) begin
            $display("[tb_dukpt] FAIL: I0 -- %0d bytes", resp_len);
            errors = errors + 1;
        end
        for (i = 0; i < 16; i = i + 1)
            if (resp[8 + i] !== dd[87 + i]) begin
                $display("[tb_dukpt] FAIL: I0 -- cabecalho, caractere %0d: %c, esperado %c",
                         i, resp[8 + i], dd[87 + i]);
                errors = errors + 1;
            end
        for (i = 0; i < 6; i = i + 1)
            if (resp[resp_len - 6 + i] !== dd[81 + i]) begin
                $display("[tb_dukpt] FAIL: I0 -- KCV da IPEK, caractere %0d", i);
                errors = errors + 1;
            end
        if (errors == erros_antes)
            $display("[tb_dukpt] %0t ns: I0 da a IPEK do anexo em bloco B1 versao B", $time);

        // ---- 3. recusas ----------------------------------------------------
        erros_antes = errors;
        p2(0, 1, 33);
        confere("P", "3", 16, "P2 com KSN de contador zero");
        p2(1, 0, 33);
        confere("P", "3", 11, "P2 com BDK sem modo X");
        p2(0, 0, 49);
        confere("P", "3", 14, "P2 com PIN block adulterado");
        inicio("I", "0"); poe_bl(2); poe_bl(0); poe_dd(0, 20); ascii_troca();
        confere("I", "1", 13, "I0 com a chave de zona como KEK");
        if (errors == erros_antes)
            $display("[tb_dukpt] %0t ns: recusas conferidas", $time);

        if (errors == 0) $display("[tb_dukpt] PASS");
        else             $display("[tb_dukpt] FAIL: %0d erro(s)", errors);
        $finish;
    end

    initial begin
        #1500000000;     // 1,5 s
        $display("[tb_dukpt] FAIL: timeout");
        $display("[tb_dukpt] FAIL");
        $finish;
    end

endmodule
