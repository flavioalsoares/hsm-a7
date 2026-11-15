`timescale 1ns/1ps
//
// tb_pinv -- verificacao de PIN: metodo do offset e PVV, e a tabela de
//            decimalizacao autorizada (fase 8, etapa 8.5)
//
// sim-timeout: 14400
//
// Contra o firmware real no NEORV32. As chaves, o PIN block, o offset, o PVV
// e o MAC da tabela vem do host/pinverif.py, do host/pinblock.py e do
// host/tr31.py (scripts/mkvectors.py). O PIN e 48213, e o PAN e inventado.
//
//   1. TABELA_AUTORIZA sem os botoes: NOT_AUTHORIZED. Com os botoes: a
//      tabela volta com o MAC, e o MAC e o que o Python calculou com a LMK e
//      o KCV da chave de verificacao;
//   2. V0 com a tabela que o console devolveu: o offset e o do Python;
//   3. V2: o offset certo confere (00); com um digito trocado, nao (01);
//      com um digito a menos, nao (01);
//   4. a tabela so vale com o MAC dela: tabela trocada num digito, MAC
//      trocado num bit, e o MAC da mesma tabela autorizada para OUTRA chave,
//      erro 17. E a defesa contra o ataque de decimalizacao;
//   5. V4: o PVV e o do Python. V6: o certo confere, o errado nao;
//   6. chave de verificacao de modo 'V' nao gera (11); chave do offset nao
//      calcula PVV (11); PIN block adulterado (14);
//   7. o PIN block no formato 4, com chave AES: o mesmo PVV confere.
//
module tb_pinv;

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

    localparam [7:0] CMD_TABELA      = 8'h80;

    localparam [7:0] ST_OK        = 8'h00;
    localparam [7:0] ST_NOT_AUTH  = 8'h21;
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

    reg [7:0] ko    [0:143];   // key block da chave de origem, P0
    reg [7:0] dados [0:63];    // PAN(16) . PIN block(16) . campo PAN(16) . campo PIN(16)
    reg [7:0] ko3   [0:111];   // key block da chave 3DES de origem, P0
    reg [7:0] f0    [0:15];    // PIN block formato 0 sob ko3 (8) . esperado sob kd3 (8)
    reg [7:0] v1    [0:111];   // chave de verificacao do offset, V1, modo C
    reg [7:0] v1v   [0:111];   // a mesma, modo V: so verifica
    reg [7:0] v2    [0:111];   // chave de verificacao do PVV, V2, modo C
    reg [7:0] pv    [0:54];    // tabela(16) . MAC(8) . dados(8) . offset(5) . PVV(4)
                               // . KCV v1(3) . KCV v2(3) . MAC da tabela para v2(8)
    reg [7:0] tabm  [0:23];    // a tabela autorizada que o CONSOLE devolveu

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
                $display("[tb_pinv] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_pinv] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_pinv] FAIL: %0s -- erro %c%c, esperado %0d",
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
                $display("[tb_pinv] FAIL: CRC da resposta do console invalido");
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
                    $display("[tb_pinv] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_pinv] FAIL: SET_STATE -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #2000000000;     // 2 s
        $display("[tb_pinv] FAIL: timeout");
        $display("[tb_pinv] FAIL");
        $finish;
    end

    // COMUM de todo pedido: chave de PIN . chave de verificacao . formato .
    // PAN . PIN block. `qp`: 3 = ko3 (3DES, formato 0), 0 = ko (AES, formato
    // 4). `qv`: 1 = v1, 2 = v1v, 3 = v2. `mexe`: 1 troca um bit do PIN block.
    task poe_comum(input integer qp, input integer qv, input integer mexe);
        integer k;
        reg [7:0] b;
        begin
            if (qp == 3) for (k = 0; k < 112; k = k + 1) poe(ko3[k]);
            else         for (k = 0; k < 144; k = k + 1) poe(ko[k]);
            case (qv)
                1: for (k = 0; k < 112; k = k + 1) poe(v1[k]);
                2: for (k = 0; k < 112; k = k + 1) poe(v1v[k]);
                default: for (k = 0; k < 112; k = k + 1) poe(v2[k]);
            endcase
            poe((qp == 3) ? "0" : "4");
            poe("1"); poe("6");
            for (k = 0; k < 16; k = k + 1) poe(dados[k]);
            for (k = 0; k < ((qp == 3) ? 8 : 16); k = k + 1) begin
                b = (qp == 3) ? f0[k] : dados[16 + k];
                if (mexe == 1 && k == 0) b = b ^ 8'h01;
                poe_hex(b);
            end
        end
    endtask

    // A tabela autorizada, como o console a devolveu. `mexe`: 1 troca um
    // digito da tabela, 2 troca um bit do MAC, 3 manda o MAC que o Python fez
    // para a mesma tabela e a chave do PVV (outro KCV).
    task poe_tabela(input integer mexe);
        integer k;
        reg [7:0] b;
        begin
            for (k = 0; k < 16; k = k + 1) begin
                b = tabm[k];
                if (mexe == 1 && k == 10) b = "1";      // era '0'
                poe(b);
            end
            for (k = 0; k < 8; k = k + 1) begin
                b = (mexe == 3) ? pv[47 + k] : tabm[16 + k];
                if (mexe == 2 && k == 7) b = b ^ 8'h01;
                poe_hex(b);
            end
            for (k = 0; k < 8; k = k + 1) poe_hex(pv[24 + k]);
        end
    endtask

    // V0. `qv` e `mexe_tab` como acima.
    task pede_v0(input integer qv, input integer mexe_tab);
        begin
            inicio("V", "0");
            poe_comum(3, qv, 0);
            poe_tabela(mexe_tab);
            ascii_troca();
        end
    endtask

    // V2. `n`: quantos digitos de offset vao; `troca`: -1, ou o indice do
    // digito que vai trocado.
    task pede_v2(input integer mexe_bloco, input integer mexe_tab,
                 input integer n, input integer troca);
        integer k;
        reg [7:0] b;
        begin
            inicio("V", "2");
            poe_comum(3, 1, mexe_bloco);
            poe_tabela(mexe_tab);
            poe("0"); poe(8'd48 + n);
            for (k = 0; k < n; k = k + 1) begin
                b = pv[32 + k];
                if (k == troca) b = (b == "9") ? "0" : (b + 8'd1);
                poe(b);
            end
            ascii_troca();
        end
    endtask

    // V4 (gerar = 1) ou V6. `qp` e `qv` como no poe_comum; `troca` como no
    // pede_v2.
    task pede_pvv(input integer gerar, input integer qp, input integer qv,
                  input integer troca);
        integer k;
        reg [7:0] b;
        begin
            inicio("V", gerar ? "4" : "6");
            poe_comum(qp, qv, 0);
            poe("1");
            if (!gerar)
                for (k = 0; k < 4; k = k + 1) begin
                    b = pv[37 + k];
                    if (k == troca) b = (b == "9") ? "0" : (b + 8'd1);
                    poe(b);
                end
            ascii_troca();
        end
    endtask

    initial begin
        $display("[tb_pinv] inicio");
        $readmemh("../vectors/pin_ko.hex", ko);
        $readmemh("../vectors/pin_dados.hex", dados);
        $readmemh("../vectors/pin0_ko.hex", ko3);
        $readmemh("../vectors/pin0_dados.hex", f0);
        $readmemh("../vectors/pinv_v1.hex", v1);
        $readmemh("../vectors/pinv_v1v.hex", v1v);
        $readmemh("../vectors/pinv_v2.hex", v2);
        $readmemh("../vectors/pinv_dados.hex", pv);
        if (ko[0] === 8'hxx || dados[0] === 8'hxx || ko3[0] === 8'hxx ||
            f0[0] === 8'hxx || v1[0] === 8'hxx || v1v[0] === 8'hxx ||
            v2[0] === 8'hxx || pv[0] === 8'hxx) begin
            $display("[tb_pinv] FAIL: vetores nao carregados");
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
            $display("[tb_pinv] FAIL: o POST reprovou no boot");
            $finish;
        end
        limpa();
        console(CMD_GET_VERSION);

        cerimonia();
        $display("[tb_pinv] %0t ns: cerimonia feita", $time);

        // ---- 1. a tabela autorizada -------------------------------------
        // Pedido: tabela(16) . KCV da chave do offset(3). Resposta: status .
        // tabela(16) . KCV(3) . MAC(8).
        erros_antes = errors;
        soltar();
        limpa();
        for (i = 0; i < 16; i = i + 1) poe(pv[i]);
        for (i = 0; i < 3; i = i + 1) poe(pv[41 + i]);
        console(CMD_TABELA);
        if (st !== ST_NOT_AUTH) begin
            $display("[tb_pinv] FAIL: TABELA_AUTORIZA sem botoes -> 0x%02h", st);
            errors = errors + 1;
        end
        // forma errada: recusada ANTES de gastar o aperto
        apertar();
        limpa();
        for (i = 0; i < 16; i = i + 1) poe((i == 3) ? "A" : pv[i]);
        for (i = 0; i < 3; i = i + 1) poe(pv[41 + i]);
        console(CMD_TABELA);
        if (st !== ST_BAD_PARAM) begin
            $display("[tb_pinv] FAIL: tabela com letra -> 0x%02h", st);
            errors = errors + 1;
        end
        limpa();
        for (i = 0; i < 16; i = i + 1) poe(pv[i]);
        console(CMD_TABELA);
        if (st !== ST_BAD_PARAM) begin
            $display("[tb_pinv] FAIL: tabela sem KCV -> 0x%02h", st);
            errors = errors + 1;
        end
        limpa();
        for (i = 0; i < 16; i = i + 1) poe(pv[i]);
        for (i = 0; i < 3; i = i + 1) poe(pv[41 + i]);
        console(CMD_TABELA);
        soltar();
        if (st !== ST_OK || resp_len != 28) begin
            $display("[tb_pinv] FAIL: TABELA_AUTORIZA -> 0x%02h, %0d bytes", st, resp_len);
            errors = errors + 1;
        end else begin
            for (i = 0; i < 16; i = i + 1) begin
                tabm[i] = resp[1 + i];
                if (resp[1 + i] !== pv[i]) begin
                    $display("[tb_pinv] FAIL: tabela devolvida, byte %0d", i);
                    errors = errors + 1;
                end
            end
            for (i = 0; i < 3; i = i + 1)
                if (resp[17 + i] !== pv[41 + i]) begin
                    $display("[tb_pinv] FAIL: KCV devolvido, byte %0d", i);
                    errors = errors + 1;
                end
            for (i = 0; i < 8; i = i + 1) begin
                tabm[16 + i] = resp[20 + i];
                if (resp[20 + i] !== pv[16 + i]) begin
                    $display("[tb_pinv] FAIL: MAC, byte %0d: %02h, esperado %02h",
                             i, resp[20 + i], pv[16 + i]);
                    errors = errors + 1;
                end
            end
        end
        if (errors == erros_antes)
            $display("[tb_pinv] %0t ns: tabela autorizada, MAC igual ao do Python", $time);
        else begin
            $display("[tb_pinv] FAIL: sem tabela autorizada o resto nao diz nada");
            $finish;
        end

        // ---- 2. V0: o offset --------------------------------------------
        // O primeiro pedido com chave 3DES roda o autoteste de primeiro uso.
        erros_antes = errors;
        pede_v0(1, 0);
        confere("V", "1", 0, "V0");
        if (resp_len != 8 + 2 + 5 || resp[8] !== "0" || resp[9] !== "5") begin
            $display("[tb_pinv] FAIL: V0 -- %0d bytes", resp_len);
            errors = errors + 1;
        end else
            for (i = 0; i < 5; i = i + 1)
                if (resp[10 + i] !== pv[32 + i]) begin
                    $display("[tb_pinv] FAIL: offset, digito %0d: %c, esperado %c",
                             i, resp[10 + i], pv[32 + i]);
                    errors = errors + 1;
                end
        if (errors == erros_antes)
            $display("[tb_pinv] %0t ns: V0, offset igual ao do Python", $time);

        // ---- 3. V2 ------------------------------------------------------
        erros_antes = errors;
        pede_v2(0, 0, 5, -1);
        confere("V", "3", 0, "V2 offset certo");
        pede_v2(0, 0, 5, 4);
        confere("V", "3", 1, "V2 ultimo digito trocado");
        pede_v2(0, 0, 5, 0);
        confere("V", "3", 1, "V2 primeiro digito trocado");
        pede_v2(0, 0, 4, -1);
        confere("V", "3", 1, "V2 offset de 4 para PIN de 5");
        if (errors == erros_antes)
            $display("[tb_pinv] %0t ns: V2, certo confere e errado nao", $time);

        // ---- 4. a tabela so vale com o MAC dela -------------------------
        erros_antes = errors;
        pede_v2(0, 1, 5, -1);
        confere("V", "3", 17, "V2 tabela trocada");
        pede_v0(1, 2);
        confere("V", "1", 17, "V0 MAC trocado");
        pede_v0(1, 3);
        confere("V", "1", 17, "V0 MAC de outra chave");
        if (errors == erros_antes)
            $display("[tb_pinv] %0t ns: tabela sem o MAC dela, ou de outra chave, recusada", $time);

        // ---- 5. PVV -----------------------------------------------------
        erros_antes = errors;
        pede_pvv(1, 3, 3, -1);
        confere("V", "5", 0, "V4");
        if (resp_len != 8 + 4) begin
            $display("[tb_pinv] FAIL: V4 -- %0d bytes", resp_len);
            errors = errors + 1;
        end else
            for (i = 0; i < 4; i = i + 1)
                if (resp[8 + i] !== pv[37 + i]) begin
                    $display("[tb_pinv] FAIL: PVV, digito %0d: %c, esperado %c",
                             i, resp[8 + i], pv[37 + i]);
                    errors = errors + 1;
                end
        pede_pvv(0, 3, 3, -1);
        confere("V", "7", 0, "V6 PVV certo");
        pede_pvv(0, 3, 3, 2);
        confere("V", "7", 1, "V6 PVV errado");
        if (errors == erros_antes)
            $display("[tb_pinv] %0t ns: V4 igual ao do Python, V6 confere", $time);

        // ---- 6. recusas -------------------------------------------------
        erros_antes = errors;
        pede_v0(2, 0);
        confere("V", "1", 11, "V0 com chave so de verificar");
        pede_pvv(1, 3, 1, -1);
        confere("V", "5", 11, "V4 com chave do offset");
        pede_v2(1, 0, 5, -1);
        confere("V", "3", 14, "V2 PIN block adulterado");
        if (errors == erros_antes)
            $display("[tb_pinv] %0t ns: recusas conferidas", $time);

        // ---- 7. o mesmo PIN, no formato 4 -------------------------------
        erros_antes = errors;
        pede_pvv(0, 0, 3, -1);
        confere("V", "7", 0, "V6 formato 4");
        if (errors == erros_antes)
            $display("[tb_pinv] %0t ns: V6 com PIN block formato 4", $time);

        if (errors == 0) $display("[tb_pinv] PASS");
        else             $display("[tb_pinv] FAIL: %0d erro(s)", errors);
        $finish;
    end

endmodule
