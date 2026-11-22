`timescale 1ns/1ps
//
// tb_kek3 -- chave de troca 3DES e key block versao B (fase 8, etapa 8.7)
//
// sim-timeout: 36000
//
// Contra o firmware real no NEORV32.
//
//   1. a KEK 3DES nasce por COMPONENTES no console (0x2C com algoritmo 'T',
//      dois componentes de 16 bytes, dual control a cada um): o KCV de cada
//      componente e o do 3DES, e a chave montada tem o KCV da KBPK de um
//      bloco de terceiros. Componente 3DES de 32 bytes e recusado sem
//      gastar o aperto;
//   2. religar: a KEK 3DES volta da flash no mesmo handle, com o mesmo KCV
//      (o registro guarda um bloco de 112 caracteres numa entrada de 144);
//   3. K6 com os blocos versao B de TERCEIROS (vectors/tr31/x9143_B_TDES.rsp,
//      fixado por hash): sob a KEK montada (bloco 3) e sob KEKs embrulhadas
//      pelo Python (blocos 1, dupla, e 2, tripla), o firmware acha a chave
//      publicada, conferida pelo KCV;
//   4. K4 da chave do bloco 3 sob a KEK: sai um bloco versao B, e o K6 dele
//      devolve o mesmo KCV. Chave tripla sob KEK tripla sai;
//   5. recusas: K4 de chave AES e de chave tripla sob KEK dupla (13); K6 do
//      bloco de DES simples, do bloco com blocos opcionais, de um bloco
//      adulterado e de um bloco sob outra KEK (10).
//
module tb_kek3;

    localparam real BIT_NS = 1000000000.0 / 115200.0;

    // Ver tb_uart_frame: clock nominal reduzido so para encolher o divisor
    // do debounce. O clock real continua sendo o de 100 MHz.
    localparam integer TB_CLK_HZ     = 100_000;
    localparam real    BTN_SETTLE_NS = 1000000.0;

    localparam [7:0] CMD_GET_VERSION = 8'h02;
    localparam [7:0] CMD_LMK_LOAD    = 8'h20;
    localparam [7:0] CMD_SET_STATE   = 8'h26;
    localparam [7:0] CMD_EXPORT_KEY  = 8'h23;
    localparam [7:0] CMD_KEY_INFO    = 8'h25;
    localparam [7:0] CMD_KEY_FROM_COMPONENTS = 8'h2C;


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

    reg [7:0] k2    [0:111];   // KEK 3DES dupla (KBPK do bloco 1), sob a LMK
    reg [7:0] k3    [0:111];   // KEK 3DES tripla (KBPK do bloco 2), sob a LMK
    reg [7:0] kaes  [0:143];   // chave AES-256 de dados, sob a LMK
    reg [7:0] kt3   [0:111];   // chave 3DES tripla de dados, sob a LMK
    reg [7:0] blb   [0:519];   // blocos B 0..4 de terceiros, 104 bytes cada
    reg [7:0] cmp   [0:31];    // componentes 0 e 1 da KEK, 16 bytes cada
    reg [7:0] kcvs  [0:17];    // KCVs: chave 1/2, chave 3, KEK, comp0, comp1, t3
    reg [7:0] kekc  [0:111];   // a KEK montada, exportada pelo console
    reg [7:0] kb3   [0:111];   // a chave do bloco 3, sob a LMK (resposta do K6)
    reg [7:0] bb    [0:79];    // a chave do bloco 3 sob a KEK, versao B (K4)
    integer   bl_n [0:4];
    reg [7:0] h_kek;

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
                $display("[tb_kek3] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_kek3] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_kek3] FAIL: %0s -- erro %c%c, esperado %0d",
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
                $display("[tb_kek3] FAIL: CRC da resposta do console invalido");
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
                    $display("[tb_kek3] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_kek3] FAIL: SET_STATE -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #1500000000; #1500000000;   // 3 s: o teste termina perto de 2,25 s simulados
        $display("[tb_kek3] FAIL: timeout");
        $display("[tb_kek3] FAIL");
        $finish;
    end

    // ------------------------------------------------------------------
    task poe_arr(input integer q, input integer n, input integer mexe);
        integer k;
        reg [7:0] b;
        begin
            for (k = 0; k < n; k = k + 1) begin
                case (q)
                    1: b = k2[k];
                    2: b = k3[k];
                    3: b = kaes[k];
                    4: b = kt3[k];
                    5: b = kekc[k];
                    6: b = kb3[k];
                    default: b = bb[k];
                endcase
                if (mexe == 1 && k == 40) b = (b == "0") ? "1" : "0";
                poe(b);
            end
        end
    endtask

    task poe_blb(input integer i);
        integer k;
        begin
            for (k = 0; k < bl_n[i]; k = k + 1) poe(blb[104*i + k]);
        end
    endtask

    // Confere os 6 hex do KCV no fim da resposta com kcvs[3*q .. 3*q+2].
    task confere_kcv(input integer q, input [8*24-1:0] nome);
        integer k;
        begin
            for (k = 0; k < 3; k = k + 1)
                if ((resp[resp_len - 6 + 2*k] !== hexdig(kcvs[3*q + k][7:4])) ||
                    (resp[resp_len - 5 + 2*k] !== hexdig(kcvs[3*q + k][3:0]))) begin
                    $display("[tb_kek3] FAIL: %0s -- KCV byte %0d", nome, k);
                    errors = errors + 1;
                end
        end
    endtask

    // KEY_INFO da KEK montada: K0, T, B, E, 16 bytes, KCV da KBPK.
    task info_kek(input [8*24-1:0] nome);
        begin
            limpa(); poe(h_kek);
            console(CMD_KEY_INFO);
            if (st !== ST_OK || resp[1] !== "K" || resp[2] !== "0" ||
                resp[3] !== "T" || resp[4] !== "B" || resp[5] !== "E" ||
                resp[6] !== 8'd16 || resp[7] !== kcvs[6] ||
                resp[8] !== kcvs[7] || resp[9] !== kcvs[8]) begin
                $display("[tb_kek3] FAIL: %0s -- KEY_INFO st=%02h %c%c %c %c %c len=%0d kcv=%02h%02h%02h",
                         nome, st, resp[1], resp[2], resp[3], resp[4], resp[5],
                         resp[6], resp[7], resp[8], resp[9]);
                errors = errors + 1;
            end
        end
    endtask

    // Um componente da KEK 3DES: n de 2, 16 bytes.
    task componente(input integer n);
        integer k;
        begin
            soltar(); apertar();
            limpa(); poe(n[7:0]); poe(8'd2); poe("K"); poe("0"); poe("T"); poe("B"); poe("E");
            for (k = 0; k < 16; k = k + 1) poe(cmp[16*n + k]);
            console(CMD_KEY_FROM_COMPONENTS);
            soltar();
            if (st !== ST_OK || resp[1] !== kcvs[9 + 3*n] || resp[2] !== kcvs[10 + 3*n] ||
                resp[3] !== kcvs[11 + 3*n] || resp[4] !== n[7:0] + 8'd1 || resp[5] !== 8'd2) begin
                $display("[tb_kek3] FAIL: componente %0d -- st=%02h kcv=%02h%02h%02h %0d de %0d",
                         n, st, resp[1], resp[2], resp[3], resp[4], resp[5]);
                errors = errors + 1;
            end
        end
    endtask

    initial begin
        $display("[tb_kek3] inicio");
        $readmemh("../vectors/kek3_k2.hex", k2);
        $readmemh("../vectors/kek3_k3.hex", k3);
        $readmemh("../vectors/kek3_aes.hex", kaes);
        $readmemh("../vectors/kek3_t3.hex", kt3);
        $readmemh("../vectors/kek3_blocos.hex", blb);
        $readmemh("../vectors/kek3_comp.hex", cmp);
        $readmemh("../vectors/kek3_kcv.hex", kcvs);
        if (k2[0] === 8'hxx || k3[0] === 8'hxx || kaes[143] === 8'hxx ||
            kt3[0] === 8'hxx || blb[519] === 8'hxx || cmp[31] === 8'hxx ||
            kcvs[17] === 8'hxx) begin
            $display("[tb_kek3] FAIL: vetores nao carregados");
            $finish;
        end
        bl_n[0] = 96; bl_n[1] = 96; bl_n[2] = 96; bl_n[3] = 80; bl_n[4] = 104;

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
            $display("[tb_kek3] FAIL: o POST reprovou no boot");
            $finish;
        end
        limpa();
        console(CMD_GET_VERSION);

        cerimonia();
        $display("[tb_kek3] %0t ns: cerimonia feita", $time);

        // ---- 1. KEK 3DES por componentes ---------------------------------
        erros_antes = errors;
        // 32 bytes com algoritmo T: recusado antes do dual control, sem aperto
        limpa(); poe(8'd0); poe(8'd2); poe("K"); poe("0"); poe("T"); poe("B"); poe("E");
        for (i = 0; i < 32; i = i + 1) poe(comp0[i]);
        console(CMD_KEY_FROM_COMPONENTS);
        if (st !== ST_BAD_PARAM) begin
            $display("[tb_kek3] FAIL: componente 3DES de 32 bytes -> 0x%02h", st);
            errors = errors + 1;
        end
        componente(0);
        componente(1);
        h_kek = resp[6];
        if (h_kek == 8'd0) begin
            $display("[tb_kek3] FAIL: a KEK montada nao foi instalada");
            errors = errors + 1;
        end
        info_kek("KEK montada");
        if (errors == erros_antes)
            $display("[tb_kek3] %0t ns: KEK 3DES por componentes, KCV 3DES de cada um e da KEK", $time);

        // ---- 2. religar ---------------------------------------------------
        erros_antes = errors;
        rst_n = 1'b0;
        #2000;
        rst_n = 1'b1;
        #5000;
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));
        #1000;
        if (led[4] === 1'b0) begin
            $display("[tb_kek3] FAIL: o boot depois de religar foi para TAMPERED");
            errors = errors + 1;
        end
        info_kek("KEK depois de religar");
        if (errors == erros_antes)
            $display("[tb_kek3] %0t ns: religado, a KEK 3DES voltou da flash", $time);

        // A KEK sai do console sob a LMK, para a porta host.
        limpa(); poe(h_kek);
        console(CMD_EXPORT_KEY);
        if (st !== ST_OK || resp_len != 1 + 112 || resp[1] !== "D") begin
            $display("[tb_kek3] FAIL: EXPORT_KEY da KEK -> 0x%02h, %0d bytes", st, resp_len);
            errors = errors + 1;
        end
        for (i = 0; i < 112; i = i + 1) kekc[i] = resp[1 + i];

        // ---- 3. K6 com os blocos de terceiros ----------------------------
        erros_antes = errors;
        inicio("K", "6"); poe_arr(5, 112, 0); poe_blb(3); ascii_troca();
        confere("K", "7", 0, "K6 bloco 3, KEK montada");
        if (resp_len != 8 + 112 + 6) begin
            $display("[tb_kek3] FAIL: K6 bloco 3 -- %0d bytes", resp_len);
            errors = errors + 1;
        end
        confere_kcv(1, "K6 bloco 3");
        for (i = 0; i < 112; i = i + 1) kb3[i] = resp[8 + i];
        inicio("K", "6"); poe_arr(1, 112, 0); poe_blb(1); ascii_troca();
        confere("K", "7", 0, "K6 bloco 1, KEK dupla");
        confere_kcv(0, "K6 bloco 1");
        inicio("K", "6"); poe_arr(2, 112, 0); poe_blb(2); ascii_troca();
        confere("K", "7", 0, "K6 bloco 2, KEK tripla");
        confere_kcv(0, "K6 bloco 2");
        if (errors == erros_antes)
            $display("[tb_kek3] %0t ns: K6 abre os 3 blocos B de terceiros", $time);

        // ---- 4. K4 e volta --------------------------------------------------
        erros_antes = errors;
        inicio("K", "4"); poe_arr(5, 112, 0); poe_arr(6, 112, 0); ascii_troca();
        confere("K", "5", 0, "K4 sob a KEK 3DES");
        if (resp_len != 8 + 80 + 6 || resp[8] !== "B") begin
            $display("[tb_kek3] FAIL: K4 -- %0d bytes, versao %c", resp_len, resp[8]);
            errors = errors + 1;
        end
        confere_kcv(1, "K4");
        for (i = 0; i < 80; i = i + 1) bb[i] = resp[8 + i];
        inicio("K", "6"); poe_arr(5, 112, 0); poe_arr(7, 80, 0); ascii_troca();
        confere("K", "7", 0, "K6 do bloco do K4");
        confere_kcv(1, "K6 do bloco do K4");
        inicio("K", "4"); poe_arr(2, 112, 0); poe_arr(4, 112, 0); ascii_troca();
        confere("K", "5", 0, "K4 tripla sob tripla");
        if (resp[8] !== "B") begin
            $display("[tb_kek3] FAIL: K4 tripla -- versao %c", resp[8]);
            errors = errors + 1;
        end
        confere_kcv(5, "K4 tripla");
        if (errors == erros_antes)
            $display("[tb_kek3] %0t ns: K4 da bloco B, e o K6 dele volta com o mesmo KCV", $time);

        // ---- 5. recusas ----------------------------------------------------
        erros_antes = errors;
        inicio("K", "4"); poe_arr(5, 112, 0); poe_arr(3, 144, 0); ascii_troca();
        confere("K", "5", 13, "K4 chave AES sob KEK 3DES");
        inicio("K", "4"); poe_arr(5, 112, 0); poe_arr(4, 112, 0); ascii_troca();
        confere("K", "5", 13, "K4 tripla sob dupla");
        inicio("K", "6"); poe_arr(1, 112, 0); poe_blb(0); ascii_troca();
        confere("K", "7", 10, "K6 bloco de DES simples");
        inicio("K", "6"); poe_arr(5, 112, 0); poe_blb(4); ascii_troca();
        confere("K", "7", 10, "K6 blocos opcionais");
        inicio("K", "6"); poe_arr(5, 112, 0); poe_arr(7, 80, 1); ascii_troca();
        confere("K", "7", 10, "K6 bloco adulterado");
        inicio("K", "6"); poe_arr(1, 112, 0); poe_blb(3); ascii_troca();
        confere("K", "7", 10, "K6 sob outra KEK");
        if (errors == erros_antes)
            $display("[tb_kek3] %0t ns: recusas conferidas", $time);

        if (errors == 0) $display("[tb_kek3] PASS");
        else             $display("[tb_kek3] FAIL: %0d erro(s)", errors);
        $finish;
    end

endmodule
