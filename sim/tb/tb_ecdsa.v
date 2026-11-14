`timescale 1ns/1ps
//
// tb_ecdsa -- ECDSA P-256 pela porta host (fase 7)
//
// sim-timeout: 43200
//
// Contra o firmware real no NEORV32, com vetores do CAVP que o autoteste
// nao usa:
//
//   1. antes da cerimonia, E4 e recusado pelo estado (erro 20);
//   2. E4 com um vetor "P" do SigVer: E5 00. E o primeiro uso do ECDSA
//      depois do boot, entao o autoteste de primeiro uso roda aqui;
//   3. E4 com um vetor "F (S changed)" do SigVer: E5 01;
//   4. E4 com uma chave publica fora da curva (PKV): erro 16;
//   5. E4 curto: erro 22;
//   6. E2 com uma chave do SigGen do CAVP, embrulhada sob a LMK: E3 00. A
//      assinatura muda a cada chamada (o k e sorteado), entao a conferencia
//      e devolve-la ao E4 com a chave publica do vetor: E5 00;
//   7. E2 com o bloco adulterado: erro 10. Com key block AES: erro 11.
//
// Cada multiplicacao de ponto custa cerca de 0,1 s simulado, e este teste
// faz perto de 20. E o testbench mais longo da suite.
//
module tb_ecdsa;

    localparam real BIT_NS = 1000000000.0 / 115200.0;

    // Ver tb_uart_frame: clock nominal reduzido so para encolher o divisor
    // do debounce. O clock real continua sendo o de 100 MHz.
    localparam integer TB_CLK_HZ     = 100_000;
    localparam real    BTN_SETTLE_NS = 1000000.0;

    localparam [7:0] CMD_GET_VERSION = 8'h02;
    localparam [7:0] CMD_LMK_LOAD    = 8'h20;
    localparam [7:0] CMD_IMPORT_KEY  = 8'h24;
    localparam [7:0] CMD_KEY_INFO    = 8'h25;
    localparam [7:0] CMD_SET_STATE   = 8'h26;
    localparam [7:0] CMD_ENCRYPT     = 8'h27;

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
    integer i;

    reg [7:0] resp [0:2047];
    integer   resp_len;
    reg [7:0] st;

    reg [7:0] req [0:2047];
    integer   req_len;

    reg [7:0] comp0 [0:31];
    reg [7:0] comp1 [0:31];
    reg [7:0] comp2 [0:31];
    reg [7:0] lmk   [0:31];

    reg [7:0] e4p [0:159];     // Qx Qy digest R S: SigVer, resultado P
    reg [7:0] e4f [0:159];     // idem, resultado F (S changed)
    reg [7:0] e4k [0:159];     // chave publica fora da curva (PKV)
    reg [7:0] e2kb  [0:271];   // key block de uma chave do SigGen, sob a LMK
    reg [7:0] e2aes [0:143];   // key block AES D0, sob a mesma LMK
    reg [7:0] e2v   [0:95];    // digest(32) e a chave publica Qx Qy(64)
    reg [7:0] sig   [0:127];   // r e s devolvidos pelo E2, em hex

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
                $display("[tb_ecdsa] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_ecdsa] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_ecdsa] FAIL: %0s -- erro %c%c, esperado %0d",
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
                $display("[tb_ecdsa] FAIL: CRC da resposta do console invalido");
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
                    $display("[tb_ecdsa] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_ecdsa] FAIL: SET_STATE -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #2000000000; #2000000000; #2000000000; #2000000000;     // 8 s
        $display("[tb_ecdsa] FAIL: timeout");
        $display("[tb_ecdsa] FAIL");
        $finish;
    end

    // E4 com um dos tres vetores: 0 = P, 1 = F, 2 = fora da curva.
    task pede_e4(input integer qual);
        integer k;
        begin
            inicio("E", "4");
            for (k = 0; k < 160; k = k + 1)
                case (qual)
                    0: poe_hex(e4p[k]);
                    1: poe_hex(e4f[k]);
                    default: poe_hex(e4k[k]);
                endcase
            ascii_troca();
        end
    endtask

    // E2: key block (o de ECDSA ou o AES) . digest. `troca` != 0 muda um
    // digito hex do corpo do bloco, que passa a nao fechar o MAC.
    task pede_e2(input integer aes, input integer troca);
        integer k, nb;
        reg [7:0] b;
        begin
            inicio("E", "2");
            nb = aes ? 144 : 272;
            for (k = 0; k < nb; k = k + 1) begin
                b = aes ? e2aes[k] : e2kb[k];
                if (troca && k == 100) b = (b == "0") ? "1" : "0";
                poe(b);
            end
            for (k = 0; k < 32; k = k + 1)
                poe_hex(e2v[k]);
            ascii_troca();
        end
    endtask

    initial begin
        $display("[tb_ecdsa] inicio");
        $readmemh("../vectors/ecdsa_e4_p.hex", e4p);
        $readmemh("../vectors/ecdsa_e4_f.hex", e4f);
        $readmemh("../vectors/ecdsa_e4_pkv.hex", e4k);
        $readmemh("../vectors/ecdsa_e2_bloco.hex", e2kb);
        $readmemh("../vectors/rsa_r2_aes.hex", e2aes);
        $readmemh("../vectors/ecdsa_e2.hex", e2v);
        if (e4p[0] === 8'hxx || e4f[0] === 8'hxx || e4k[0] === 8'hxx ||
            e2kb[0] === 8'hxx || e2aes[0] === 8'hxx || e2v[0] === 8'hxx) begin
            $display("[tb_ecdsa] FAIL: vetores nao carregados");
            $finish;
        end

        // LMK de teste, por tres componentes: a mesma do tb_rsa.
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
            $display("[tb_ecdsa] FAIL: o POST reprovou no boot");
            $finish;
        end
        limpa();
        console(CMD_GET_VERSION);

        inicio("E", "4");
        ascii_troca();
        confere("E", "5", 20, "E4 antes da cerimonia");

        cerimonia();
        $display("[tb_ecdsa] %0t ns: cerimonia feita", $time);

        erros_antes = errors;
        pede_e4(0);
        confere("E", "5", 0, "E4 assinatura valida");
        if (errors == erros_antes)
            $display("[tb_ecdsa] %0t ns: autoteste de primeiro uso passou, e a assinatura do CAVP confere", $time);

        pede_e4(1);
        confere("E", "5", 1, "E4 S adulterado");
        $display("[tb_ecdsa] %0t ns: assinatura adulterada do CAVP", $time);

        pede_e4(2);
        confere("E", "5", 16, "E4 chave fora da curva");

        inicio("E", "4");
        poe("A");
        ascii_troca();
        confere("E", "5", 22, "E4 curto");

        // ---- E2: assinar com uma chave do SigGen do CAVP ---------------
        erros_antes = errors;
        pede_e2(0, 0);
        confere("E", "3", 0, "E2 assinatura");
        $display("[tb_ecdsa] %0t ns: E2 respondeu", $time);
        if (resp_len != 8 + 128) begin
            $display("[tb_ecdsa] FAIL: E2 devolveu %0d bytes, esperado %0d",
                     resp_len, 8 + 128);
            errors = errors + 1;
        end else begin
            for (i = 0; i < 128; i = i + 1)
                sig[i] = resp[8 + i];
            // A assinatura de volta ao E4, com a chave publica do vetor.
            inicio("E", "4");
            for (i = 0; i < 64; i = i + 1) poe_hex(e2v[32 + i]);
            for (i = 0; i < 32; i = i + 1) poe_hex(e2v[i]);
            for (i = 0; i < 128; i = i + 1) poe(sig[i]);
            ascii_troca();
            confere("E", "5", 0, "E4 sobre o E2");
        end
        if (errors == erros_antes)
            $display("[tb_ecdsa] %0t ns: E2 assinou com a chave do CAVP, e o E4 aceitou a assinatura", $time);

        pede_e2(0, 1);
        confere("E", "3", 10, "E2 bloco adulterado");

        pede_e2(1, 0);
        confere("E", "3", 11, "E2 com key block AES");

        if (errors == 0) $display("[tb_ecdsa] PASS");
        else             $display("[tb_ecdsa] FAIL: %0d erro(s)", errors);
        $finish;
    end

endmodule
