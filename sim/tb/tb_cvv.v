`timescale 1ns/1ps
//
// tb_cvv -- CVV, CVV2 e iCVV: os comandos W0 e W2 (fase 8, etapa 8.6)
//
// sim-timeout: 14400
//
// Contra o firmware real no NEORV32. As chaves vem embrulhadas sob a LMK do
// tb pelo host/tr31.py (scripts/mkvectors.py).
//
//   1. W0 com as chaves e as entradas de TERCEIROS (vectors/cvv/cvv.rsp,
//      fixado por hash): o firmware tem de dar o CVV que a fonte publicou.
//      Um cartao da psec (codigo 111) e um do jmeter-iso8583 nos tres
//      codigos: CVV da tarja (101), CVV2 (000) e iCVV (999);
//   2. W0 com chave deste projeto e PAN inventado de 19 e de 12 digitos, que
//      as fontes nao cobrem: o CVV e o do host/cvv.py;
//   3. W2: o certo confere (00); o primeiro e o ultimo digito trocados, nao
//      (01). Os mesmos tres codigos de servico do mesmo cartao;
//   4. recusas: chave so de verificar no W0 e so de gerar no W2, chave
//      tripla, chave de outro uso (V2), todas 11; PAN de 11 digitos e letra
//      na validade, 16; key block adulterado, 10.
//
module tb_cvv;

    localparam real BIT_NS = 1000000000.0 / 115200.0;

    // Ver tb_uart_frame: clock nominal reduzido so para encolher o divisor
    // do debounce. O clock real continua sendo o de 100 MHz.
    localparam integer TB_CLK_HZ     = 100_000;
    localparam real    BTN_SETTLE_NS = 1000000.0;

    localparam [7:0] CMD_GET_VERSION = 8'h02;
    localparam [7:0] CMD_LMK_LOAD    = 8'h20;
    localparam [7:0] CMD_SET_STATE   = 8'h26;


    localparam [7:0] ST_OK        = 8'h00;

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

    reg [7:0] k1    [0:111];   // CVK da psec (valor de terceiros), modo C
    reg [7:0] k2    [0:111];   // CVK do jmeter-iso8583 (A = B), modo C
    reg [7:0] kp    [0:111];   // CVK deste projeto, modo C
    reg [7:0] kv    [0:111];   // a mesma, modo V: so verifica
    reg [7:0] kg    [0:111];   // a mesma, modo G: so gera
    reg [7:0] kt    [0:111];   // CVK de comprimento triplo: recusada
    reg [7:0] kpvk  [0:111];   // a mesma chave de kp, uso V2: recusada
    reg [7:0] cs    [0:185];   // 6 casos de 31 bytes: tamanho(2) . PAN(19)
                               // . validade(4) . codigo(3) . CVV(3)

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
                $display("[tb_cvv] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_cvv] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_cvv] FAIL: %0s -- erro %c%c, esperado %0d",
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
                $display("[tb_cvv] FAIL: CRC da resposta do console invalido");
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
                    $display("[tb_cvv] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_cvv] FAIL: SET_STATE -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #2000000000;     // 2 s
        $display("[tb_cvv] FAIL: timeout");
        $display("[tb_cvv] FAIL");
        $finish;
    end

    // A chave: 1 = k1, 2 = k2, 3 = kp, 4 = kv, 5 = kg, 6 = kt, 7 = kpvk.
    // `mexe` 1 troca um bit no meio do key block.
    task poe_chave(input integer q, input integer mexe);
        integer k;
        reg [7:0] b;
        begin
            for (k = 0; k < 112; k = k + 1) begin
                case (q)
                    1: b = k1[k];
                    2: b = k2[k];
                    3: b = kp[k];
                    4: b = kv[k];
                    5: b = kg[k];
                    6: b = kt[k];
                    default: b = kpvk[k];
                endcase
                if (mexe == 1 && k == 60) b = (b == "0") ? "1" : "0";
                poe(b);
            end
        end
    endtask

    // W0 (gerar = 1) ou W2, com a chave `q` e o caso `n`. `troca`: -1, ou o
    // indice do digito do CVV que vai trocado. `forma`: 0 normal, 1 PAN com o
    // ultimo digito cortado (11 digitos no caso de 12), 2 letra na validade.
    task pede(input integer gerar, input integer q, input integer n,
              input integer troca, input integer forma, input integer mexe);
        integer k, pn;
        reg [7:0] b;
        begin
            inicio("W", gerar ? "0" : "2");
            poe_chave(q, mexe);
            pn = (cs[31*n] - 8'd48) * 10 + (cs[31*n + 1] - 8'd48);
            if (forma == 1) pn = pn - 1;
            poe(8'd48 + pn / 10); poe(8'd48 + pn % 10);
            for (k = 0; k < pn; k = k + 1) poe(cs[31*n + 2 + k]);
            for (k = 0; k < 4; k = k + 1)
                poe((forma == 2 && k == 2) ? "A" : cs[31*n + 21 + k]);
            for (k = 0; k < 3; k = k + 1) poe(cs[31*n + 25 + k]);
            if (!gerar)
                for (k = 0; k < 3; k = k + 1) begin
                    b = cs[31*n + 28 + k];
                    if (k == troca) b = (b == "9") ? "0" : (b + 8'd1);
                    poe(b);
                end
            ascii_troca();
        end
    endtask

    // W0 e confere os 3 digitos com o caso `n`.
    task gera_confere(input integer q, input integer n, input [8*24-1:0] nome);
        integer k;
        begin
            pede(1, q, n, -1, 0, 0);
            confere("W", "1", 0, nome);
            if (resp_len != 8 + 3) begin
                $display("[tb_cvv] FAIL: %0s -- %0d bytes", nome, resp_len);
                errors = errors + 1;
            end else
                for (k = 0; k < 3; k = k + 1)
                    if (resp[8 + k] !== cs[31*n + 28 + k]) begin
                        $display("[tb_cvv] FAIL: %0s, digito %0d: %c, esperado %c",
                                 nome, k, resp[8 + k], cs[31*n + 28 + k]);
                        errors = errors + 1;
                    end
        end
    endtask

    initial begin
        $display("[tb_cvv] inicio");
        $readmemh("../vectors/cvv_k1.hex", k1);
        $readmemh("../vectors/cvv_k2.hex", k2);
        $readmemh("../vectors/cvv_kp.hex", kp);
        $readmemh("../vectors/cvv_kv.hex", kv);
        $readmemh("../vectors/cvv_kg.hex", kg);
        $readmemh("../vectors/cvv_kt.hex", kt);
        $readmemh("../vectors/cvv_pvk.hex", kpvk);
        $readmemh("../vectors/cvv_casos.hex", cs);
        if (k1[0] === 8'hxx || k2[0] === 8'hxx || kp[0] === 8'hxx ||
            kv[0] === 8'hxx || kg[0] === 8'hxx || kt[0] === 8'hxx ||
            kpvk[0] === 8'hxx || cs[0] === 8'hxx || cs[185] === 8'hxx) begin
            $display("[tb_cvv] FAIL: vetores nao carregados");
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
            $display("[tb_cvv] FAIL: o POST reprovou no boot");
            $finish;
        end
        limpa();
        console(CMD_GET_VERSION);

        cerimonia();
        $display("[tb_cvv] %0t ns: cerimonia feita", $time);

        // ---- 1. valores de terceiros ------------------------------------
        // O primeiro pedido com chave 3DES roda o autoteste de primeiro uso.
        erros_antes = errors;
        gera_confere(1, 0, "W0 psec, codigo 111");
        gera_confere(2, 1, "W0 jmeter, CVV (101)");
        gera_confere(2, 2, "W0 jmeter, CVV2 (000)");
        gera_confere(2, 3, "W0 jmeter, iCVV (999)");
        if (errors == erros_antes)
            $display("[tb_cvv] %0t ns: W0 da os 4 valores de terceiros", $time);

        // ---- 2. PAN de 19 e de 12 digitos -------------------------------
        erros_antes = errors;
        gera_confere(3, 4, "W0 PAN de 19");
        gera_confere(3, 5, "W0 PAN de 12");
        if (errors == erros_antes)
            $display("[tb_cvv] %0t ns: W0 com PAN de 19 e de 12, igual ao do Python", $time);

        // ---- 3. W2 ------------------------------------------------------
        erros_antes = errors;
        for (c = 1; c < 4; c = c + 1) begin
            pede(0, 2, c, -1, 0, 0);
            confere("W", "3", 0, "W2 certo");
        end
        pede(0, 2, 2, 0, 0, 0);
        confere("W", "3", 1, "W2 primeiro digito");
        pede(0, 2, 2, 2, 0, 0);
        confere("W", "3", 1, "W2 ultimo digito");
        pede(0, 4, 4, -1, 0, 0);
        confere("W", "3", 0, "W2 chave so de verificar");
        if (errors == erros_antes)
            $display("[tb_cvv] %0t ns: W2, certo confere e errado nao", $time);

        // ---- 4. recusas -------------------------------------------------
        erros_antes = errors;
        pede(1, 4, 4, -1, 0, 0);
        confere("W", "1", 11, "W0 chave so de verificar");
        pede(0, 5, 4, -1, 0, 0);
        confere("W", "3", 11, "W2 chave so de gerar");
        pede(1, 6, 4, -1, 0, 0);
        confere("W", "1", 11, "W0 chave tripla");
        pede(1, 7, 4, -1, 0, 0);
        confere("W", "1", 11, "W0 chave de uso V2");
        pede(1, 3, 5, -1, 1, 0);
        confere("W", "1", 16, "W0 PAN de 11");
        pede(1, 3, 4, -1, 2, 0);
        confere("W", "1", 16, "W0 letra na validade");
        pede(1, 3, 4, -1, 0, 1);
        confere("W", "1", 10, "W0 key block adulterado");
        if (errors == erros_antes)
            $display("[tb_cvv] %0t ns: recusas conferidas", $time);

        if (errors == 0) $display("[tb_cvv] PASS");
        else             $display("[tb_cvv] FAIL: %0d erro(s)", errors);
        $finish;
    end

endmodule
