`timescale 1ns/1ps
//
// tb_mac3 -- dados e MAC com chave 3DES pela porta host (fase 8, etapa 8.9a)
//
// sim-timeout: 28800
//
// Contra o firmware real no NEORV32.
//
//   1. M0 com a chave e a mensagem do exemplo da ISO/IEC 9797-1:2011 B.4,
//      valor de TERCEIROS (RustCrypto; vectors/mac/retail_mac.rsp):
//      preenchimento 1, MAC de 8 bytes, igual ao publicado. O primeiro uso
//      de chave 3DES roda o autoteste do 3DES, que inclui o retail MAC;
//   2. M2 com o mesmo MAC: confere;
//   3. M2 com a chave do psec (modo V) e o MAC de 4 bytes publicado do
//      preenchimento 2: confere; com um caractere trocado: nao confere;
//   4. C0 e C2 com o vetor CBC de chave tripla do NIST (TCBCMMT3.rsp), 64
//      bytes: a saida igual a publicada, nos dois sentidos;
//   5. recusas: M0 com chave de modo V (11), com chave tripla (11), com
//      chave D0 (11); mensagem vazia (15); preenchimento 3 (16); C2 com
//      chave de modo E (11); C0 com dados que nao sao multiplos de 8 (15).
//
// O que ele NAO cobre: mensagens ao acaso e de todo tamanho, e chave dupla
// de dados. Isso e do host/test_retail_mac.py, no PC, e do hsmhost.py
// tdes-confere, na placa.
//
module tb_mac3;

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

    // Blocos sob a LMK, todos 3DES de 112 caracteres: 0 a chave do RustCrypto
    // (M3, C), 1 a do psec (M3, V), 2 a do NIST (D0, B), 3 uma chave tripla
    // de MAC (M3, C), 4 a do NIST de novo (D0, E).
    reg [7:0] b112 [0:559];
    // mensagem RustCrypto(48) . MAC(16) . mensagem psec(22) . MAC de 4(8) .
    // IV(16) . claro(128) . cifrado(128)
    reg [7:0] dd   [0:365];
    reg [7:0] nn   [0:0];

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
                $display("[tb_mac3] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_mac3] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_mac3] FAIL: %0s -- erro %c%c, esperado %0d",
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
                $display("[tb_mac3] FAIL: CRC da resposta do console invalido");
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
                    $display("[tb_mac3] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_mac3] FAIL: SET_STATE -> 0x%02h", st);
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

    // Compara a resposta, a partir de `de_r`, com dd[de_d .. de_d+n-1].
    task confere_dd(input integer de_r, input integer de_d, input integer n,
                    input [8*24-1:0] nome);
        integer k;
        begin
            if (resp_len != de_r + n) begin
                $display("[tb_mac3] FAIL: %0s -- %0d bytes, esperado %0d",
                         nome, resp_len, de_r + n);
                errors = errors + 1;
            end else
                for (k = 0; k < n; k = k + 1)
                    if (resp[de_r + k] !== dd[de_d + k]) begin
                        $display("[tb_mac3] FAIL: %0s -- caractere %0d: %c, esperado %c",
                                 nome, k, resp[de_r + k], dd[de_d + k]);
                        errors = errors + 1;
                    end
        end
    endtask

    // M0: bloco q . preenchimento . tamanho . dados (n bytes, dd[de..]).
    task m0(input integer q, input [7:0] pad, input [7:0] tam,
            input integer de, input integer n);
        begin
            inicio("M", "0"); poe_b112(q); poe(pad); poe(tam);
            poe_dec4(n); poe_dd(de, 2 * n);
            ascii_troca();
        end
    endtask

    // M2: bloco q . preenchimento . tamanho . MAC (dd[de_m..], 2*tam
    // caracteres; troca = 1 troca o primeiro) . dados.
    task m2(input integer q, input [7:0] pad, input integer tam,
            input integer de_m, input integer troca,
            input integer de, input integer n);
        integer k;
        begin
            inicio("M", "2"); poe_b112(q); poe(pad); poe(8'd48 + tam);
            for (k = 0; k < 2 * tam; k = k + 1)
                poe((k == 0 && troca == 1) ? ((dd[de_m] == "0") ? "1" : "0")
                                           : dd[de_m + k]);
            poe_dec4(n); poe_dd(de, 2 * n);
            ascii_troca();
        end
    endtask

    // C0 / C2: bloco q . IV . dados (n bytes, dd[de..]).
    task cbc(input [7:0] c1, input integer q, input integer de, input integer n);
        begin
            inicio("C", c1); poe_b112(q); poe_dd(94, 16);
            poe_dec4(n); poe_dd(de, 2 * n);
            ascii_troca();
        end
    endtask

    initial begin
        $display("[tb_mac3] inicio");
        $readmemh("../vectors/mac3_b112.hex", b112);
        $readmemh("../vectors/mac3_dados.hex", dd);
        $readmemh("../vectors/mac3_n.hex", nn);
        if (b112[559] === 8'hxx || dd[365] === 8'hxx || nn[0] !== 8'd64) begin
            $display("[tb_mac3] FAIL: vetores nao carregados");
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
            $display("[tb_mac3] FAIL: o POST reprovou no boot");
            $finish;
        end
        limpa();
        console(CMD_GET_VERSION);

        cerimonia();
        $display("[tb_mac3] %0t ns: cerimonia feita", $time);

        // ---- 1 e 2. retail MAC da ISO 9797-1 B.4 --------------------------
        erros_antes = errors;
        m0(0, "1", "8", 0, 24);
        confere("M", "1", 0, "M0 da B.4");
        confere_dd(8, 48, 16, "M0 da B.4");
        m2(0, "1", 8, 48, 0, 0, 24);
        confere("M", "3", 0, "M2 da B.4");
        if (errors == erros_antes)
            $display("[tb_mac3] %0t ns: M0 da o retail MAC publicado (ISO 9797-1 B.4), e o M2 o confere", $time);

        // ---- 3. MAC de 4 bytes, preenchimento 2, chave de modo V ----------
        erros_antes = errors;
        m2(1, "2", 4, 86, 0, 64, 11);
        confere("M", "3", 0, "M2 do psec");
        m2(1, "2", 4, 86, 1, 64, 11);
        confere("M", "3", 1, "M2 do psec, MAC trocado");
        if (errors == erros_antes)
            $display("[tb_mac3] %0t ns: M2 confere o MAC de 4 bytes publicado e recusa o trocado", $time);

        // ---- 4. 3DES-CBC do NIST, chave tripla ---------------------------
        erros_antes = errors;
        cbc("0", 2, 110, 64);
        confere("C", "1", 0, "C0 do NIST");
        confere_dd(12, 238, 128, "C0 do NIST");
        cbc("2", 2, 238, 64);
        confere("C", "3", 0, "C2 do NIST");
        confere_dd(12, 110, 128, "C2 do NIST");
        if (errors == erros_antes)
            $display("[tb_mac3] %0t ns: C0 e C2 com chave 3DES tripla, iguais ao vetor do NIST", $time);

        // ---- 5. recusas ----------------------------------------------------
        erros_antes = errors;
        m0(1, "2", "4", 64, 11);
        confere("M", "1", 11, "M0 com chave de modo V");
        m0(3, "1", "8", 0, 24);
        confere("M", "1", 11, "M0 com chave tripla");
        m0(2, "1", "8", 0, 24);
        confere("M", "1", 11, "M0 com chave D0");
        m0(0, "1", "8", 0, 0);
        confere("M", "1", 15, "M0 com mensagem vazia");
        m0(0, "3", "8", 0, 24);
        confere("M", "1", 16, "M0 com preenchimento 3");
        cbc("2", 4, 238, 64);
        confere("C", "3", 11, "C2 com chave de modo E");
        cbc("0", 2, 110, 12);
        confere("C", "1", 15, "C0 com 12 bytes");
        if (errors == erros_antes)
            $display("[tb_mac3] %0t ns: recusas conferidas", $time);

        if (errors == 0) $display("[tb_mac3] PASS");
        else             $display("[tb_mac3] FAIL: %0d erro(s)", errors);
        $finish;
    end

    initial begin
        #2000000000;     // 2 s
        $display("[tb_mac3] FAIL: timeout");
        $display("[tb_mac3] FAIL");
        $finish;
    end

endmodule
