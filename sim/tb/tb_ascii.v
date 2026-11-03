`timescale 1ns/1ps
//
// tb_ascii -- a porta HOST: command set ASCII (fase 5)
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// O que este teste prende, contra o firmware real rodando no NEORV32:
//
//   1. os dois protocolos dividem a UART: frames binarios (console) e
//      mensagens ASCII (host) se alternam sem se atrapalhar;
//   2. o estado manda: antes da cerimonia, so o diagnostico responde;
//   3. K0 gera chave e a devolve SO embrulhada, e K2 confere o bloco com o
//      mesmo KCV;
//   4. o bloco gerado pela porta host abre no CONSOLE (IMPORT_KEY) com o
//      mesmo KCV, e o ENCRYPT do console cifra IDENTICO ao C0 -- os dois
//      caminhos concordam sobre a mesma chave;
//   5. C0 -> C2 volta ao texto; M0 -> M2 confere, e com um bit trocado nao;
//   6. o `modo` do bloco manda: chave de cifra nao autentica, chave de MAC
//      nao cifra (erro 11);
//   7. bloco adulterado e recusado (erro 10), e mensagem malformada,
//      comando desconhecido e campo sobrando tambem;
//   8. KEK: K4 exporta a chave de cifra sob uma KEK gerada pelo K0 (uso
//      K0), e K6 a importa de volta -- mesmo KCV e o C0 com o bloco
//      reimportado cifra IDENTICO ao do passo 4. O bloco sob a KEK nao
//      abre sob a LMK. Recusas: chave 'N' nao sai (12), chave de dados nao
//      serve de KEK (13), KEK so-'E' nao importa (11), bloco adulterado ou
//      feito sob a LMK no lugar da KEK (10);
//   9. NADA sobra no slot efemero entre comandos: o KEY_INFO do console no
//      handle 17 encontra o slot vazio.
//
// O que ele NAO prova: que o C0 esta certo em termos absolutos. A chave e
// aleatoria e nao ha vetor para ela; o que se prova aqui e que a porta
// host e o console concordam. A conferencia contra uma implementacao
// independente (Python + `cryptography`) e na bancada, com a LMK em maos.
//
module tb_ascii;

    localparam real BIT_NS = 1000000000.0 / 115200.0;

    // Ver tb_uart_frame: clock nominal reduzido so para encolher o divisor
    // do debounce. O clock real continua sendo o de 100 MHz.
    localparam integer TB_CLK_HZ     = 100_000;
    localparam real    BTN_SETTLE_NS = 100000.0;

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

    reg [7:0] resp [0:511];
    integer   resp_len;
    reg [7:0] st;

    reg [7:0] req [0:511];
    integer   req_len;

    reg [7:0] comp0 [0:31];
    reg [7:0] comp1 [0:31];
    reg [7:0] comp2 [0:31];
    reg [7:0] lmk   [0:31];

    // Os dois blocos gerados pela porta host, e o que se sabe deles.
    reg [7:0] bloco_c [0:143];      // chave de cifra, modo B
    reg [7:0] bloco_m [0:143];      // chave de MAC,   modo C
    reg [7:0] kcv_c   [0:5];        // KCV em hex, como veio no K1
    reg [7:0] bloco_k [0:143];      // KEK, uso K0 modo B
    reg [7:0] bloco_e [0:143];      // KEK so de embrulhar, modo E
    reg [7:0] bloco_x [0:143];      // bloco_c exportado sob a KEK
    reg [7:0] bloco_l [0:143];      // bloco_x reimportado, sob a LMK
    reg [7:0] iv      [0:15];
    reg [7:0] texto   [0:31];
    reg [7:0] cifra   [0:31];
    reg [7:0] tag     [0:15];

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
                $display("[tb_ascii] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_ascii] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_ascii] FAIL: %0s -- erro %c%c, esperado %0d",
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
                $display("[tb_ascii] FAIL: CRC da resposta do console invalido");
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
                    $display("[tb_ascii] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_ascii] FAIL: SET_STATE -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #900000000;                     // 900 ms
        $display("[tb_ascii] FAIL: timeout");
        $display("[tb_ascii] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_ascii] inicio");

        // LMK = ECBKeySbox256 do CAVP, KCV 46F2FB -- a mesma de tb_zeroize.
        lmk[ 0]=8'hC4; lmk[ 1]=8'h7B; lmk[ 2]=8'h02; lmk[ 3]=8'h94;
        lmk[ 4]=8'hDB; lmk[ 5]=8'hBB; lmk[ 6]=8'hEE; lmk[ 7]=8'h0F;
        lmk[ 8]=8'hEC; lmk[ 9]=8'h47; lmk[10]=8'h57; lmk[11]=8'hF2;
        lmk[12]=8'h2F; lmk[13]=8'hFE; lmk[14]=8'hEE; lmk[15]=8'h35;
        lmk[16]=8'h87; lmk[17]=8'hCA; lmk[18]=8'h47; lmk[19]=8'h30;
        lmk[20]=8'hC3; lmk[21]=8'hD3; lmk[22]=8'h3B; lmk[23]=8'h69;
        lmk[24]=8'h1D; lmk[25]=8'hF3; lmk[26]=8'h8B; lmk[27]=8'hAB;
        lmk[28]=8'h07; lmk[29]=8'h6B; lmk[30]=8'hC5; lmk[31]=8'h58;
        for (i = 0; i < 32; i = i + 1) begin
            comp0[i] = 8'h10 + i[7:0];
            comp1[i] = 8'h5A ^ (i[7:0] * 8'h07);
            comp2[i] = lmk[i] ^ comp0[i] ^ comp1[i];
            texto[i] = 8'hA0 + i[7:0];
        end
        for (i = 0; i < 16; i = i + 1)
            iv[i] = 8'h0F - i[7:0];

        #200;
        rst_n = 1'b1;
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));
        #1000;
        if (led[4] === 1'b0) begin
            $display("[tb_ascii] FAIL: o POST reprovou no boot");
            $display("[tb_ascii] FAIL");
            $finish;
        end

        // Prova de que o laco principal roda (ver tb_zeroize, passo 1).
        limpa();
        console(CMD_GET_VERSION);

        // ---- 1. antes da cerimonia -----------------------------------
        erros_antes = errors;
        inicio("D", "0");
        ascii_troca();
        confere("D", "1", 0, "D0 em UNINITIALIZED");
        if (resp_len !== 21 || resp[8] !== "0" ||
            resp[9] !== "0" || resp[14] !== "0") begin
            $display("[tb_ascii] FAIL: D0 em UNINITIALIZED -- len=%0d estado=%c", resp_len, resp[8]);
            errors = errors + 1;
        end
        inicio("K", "0"); poe("D"); poe("0"); poe("B"); poe("E");
        ascii_troca();
        confere("K", "1", 20, "K0 em UNINITIALIZED");
        if (resp_len !== 8) begin
            $display("[tb_ascii] FAIL: K0 recusado trouxe campos (len=%0d)", resp_len);
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_ascii] antes da cerimonia: D0 responde (estado 0), K0 recusado com 20");

        // ---- 2. cerimonia pelo console, e a porta host ve -----------
        erros_antes = errors;
        cerimonia();
        inicio("D", "0");
        ascii_troca();
        confere("D", "1", 0, "D0 em OPERATIONAL");
        if (resp[8] !== "2" || resp[9] !== "4" || resp[10] !== "6" ||
            resp[11] !== "F" || resp[12] !== "2" || resp[13] !== "F" || resp[14] !== "B") begin
            $display("[tb_ascii] FAIL: D0 -- estado %c, KCV %c%c%c%c%c%c (esperado 2 / 46F2FB)",
                     resp[8], resp[9], resp[10], resp[11], resp[12], resp[13], resp[14]);
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_ascii] cerimonia pelo console; D0: estado 2, KCV da LMK 46F2FB");

        // ---- 3. K0 + K2 -----------------------------------------------
        erros_antes = errors;
        inicio("K", "0"); poe("D"); poe("0"); poe("B"); poe("E");
        ascii_troca();
        confere("K", "1", 0, "K0 cifra");
        if (resp_len !== 8 + 144 + 6) begin
            $display("[tb_ascii] FAIL: K1 com %0d bytes, esperado 158", resp_len);
            errors = errors + 1;
        end
        for (i = 0; i < 144; i = i + 1) bloco_c[i] = resp[8 + i];
        for (i = 0; i < 6; i = i + 1)   kcv_c[i]   = resp[152 + i];
        if (bloco_c[0] !== "D" || bloco_c[1] !== "0" || bloco_c[2] !== "1" ||
            bloco_c[3] !== "4" || bloco_c[4] !== "4" || bloco_c[5] !== "D" ||
            bloco_c[6] !== "0" || bloco_c[8] !== "B" || bloco_c[11] !== "E") begin
            $display("[tb_ascii] FAIL: cabecalho do bloco gerado inesperado");
            errors = errors + 1;
        end

        inicio("K", "2");
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        ascii_troca();
        confere("K", "3", 0, "K2");
        if (resp_len !== 19 || resp[8] !== "D" || resp[9] !== "0" || resp[10] !== "A" ||
            resp[11] !== "B" || resp[12] !== "E" ||
            resp[13] !== kcv_c[0] || resp[14] !== kcv_c[1] || resp[15] !== kcv_c[2] ||
            resp[16] !== kcv_c[3] || resp[17] !== kcv_c[4] || resp[18] !== kcv_c[5]) begin
            $display("[tb_ascii] FAIL: K3 nao confere com o K1");
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_ascii] K0 gerou bloco de 144; K2 confere: D0 A B E, mesmo KCV %c%c%c%c%c%c",
                     kcv_c[0], kcv_c[1], kcv_c[2], kcv_c[3], kcv_c[4], kcv_c[5]);

        // ---- 4. C0 -> C2 ----------------------------------------------
        erros_antes = errors;
        inicio("C", "0");
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        for (i = 0; i < 16; i = i + 1)  poe_hex(iv[i]);
        poe_dec4(32);
        for (i = 0; i < 32; i = i + 1)  poe_hex(texto[i]);
        ascii_troca();
        confere("C", "1", 0, "C0");
        if (resp_len !== 8 + 4 + 64) begin
            $display("[tb_ascii] FAIL: C1 com %0d bytes", resp_len);
            errors = errors + 1;
        end
        for (i = 0; i < 32; i = i + 1)
            cifra[i] = hexbyte(resp[12 + 2*i], resp[13 + 2*i]);

        inicio("C", "2");
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        for (i = 0; i < 16; i = i + 1)  poe_hex(iv[i]);
        poe_dec4(32);
        for (i = 0; i < 32; i = i + 1)  poe_hex(cifra[i]);
        ascii_troca();
        confere("C", "3", 0, "C2");
        for (i = 0; i < 32; i = i + 1)
            if (hexbyte(resp[12 + 2*i], resp[13 + 2*i]) !== texto[i]) begin
                if (errors == erros_antes)
                    $display("[tb_ascii] FAIL: C2 nao devolveu o texto (byte %0d)", i);
                errors = errors + 1;
            end
        if (errors == erros_antes)
            $display("[tb_ascii] C0 -> C2 devolve os 32 bytes");

        // ---- 5. o console concorda ------------------------------------
        //
        // O bloco feito pela porta host entra pelo IMPORT_KEY do console:
        // mesmo KCV, e o ENCRYPT do console cifra identico ao C0.
        erros_antes = errors;
        limpa();
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        console(CMD_IMPORT_KEY);
        if (st !== ST_OK || resp_len !== 5 ||
            {hexdig(resp[2][7:4]), hexdig(resp[2][3:0])} !== {kcv_c[0], kcv_c[1]} ||
            {hexdig(resp[3][7:4]), hexdig(resp[3][3:0])} !== {kcv_c[2], kcv_c[3]} ||
            {hexdig(resp[4][7:4]), hexdig(resp[4][3:0])} !== {kcv_c[4], kcv_c[5]}) begin
            $display("[tb_ascii] FAIL: IMPORT_KEY do bloco da porta host -> 0x%02h", st);
            errors = errors + 1;
        end else begin
            limpa();
            poe(resp[1]);                           // handle
            for (i = 0; i < 16; i = i + 1) poe(iv[i]);
            for (i = 0; i < 32; i = i + 1) poe(texto[i]);
            console(CMD_ENCRYPT);
            if (st !== ST_OK || resp_len !== 33) begin
                $display("[tb_ascii] FAIL: ENCRYPT do console -> 0x%02h", st);
                errors = errors + 1;
            end else
                for (i = 0; i < 32; i = i + 1)
                    if (resp[1 + i] !== cifra[i]) begin
                        if (errors == erros_antes)
                            $display("[tb_ascii] FAIL: console e porta host cifram diferente (byte %0d)", i);
                        errors = errors + 1;
                    end
        end
        if (errors == erros_antes)
            $display("[tb_ascii] console: IMPORT_KEY do bloco da porta host, mesmo KCV, ENCRYPT identico ao C0");

        // ---- 6. MAC --------------------------------------------------
        erros_antes = errors;
        inicio("K", "0"); poe("D"); poe("0"); poe("C"); poe("N");
        ascii_troca();
        confere("K", "1", 0, "K0 MAC");
        for (i = 0; i < 144; i = i + 1) bloco_m[i] = resp[8 + i];

        inicio("M", "0");
        for (i = 0; i < 144; i = i + 1) poe(bloco_m[i]);
        poe_dec4(20);
        for (i = 0; i < 20; i = i + 1) poe_hex(texto[i]);
        ascii_troca();
        confere("M", "1", 0, "M0");
        if (resp_len !== 8 + 32) begin
            $display("[tb_ascii] FAIL: M1 com %0d bytes", resp_len);
            errors = errors + 1;
        end
        for (i = 0; i < 16; i = i + 1)
            tag[i] = hexbyte(resp[8 + 2*i], resp[9 + 2*i]);

        inicio("M", "2");
        for (i = 0; i < 144; i = i + 1) poe(bloco_m[i]);
        for (i = 0; i < 16; i = i + 1)  poe_hex(tag[i]);
        poe_dec4(20);
        for (i = 0; i < 20; i = i + 1) poe_hex(texto[i]);
        ascii_troca();
        confere("M", "3", 0, "M2 confere");

        inicio("M", "2");
        for (i = 0; i < 144; i = i + 1) poe(bloco_m[i]);
        for (i = 0; i < 16; i = i + 1)  poe_hex(tag[i] ^ ((i == 7) ? 8'h01 : 8'h00));
        poe_dec4(20);
        for (i = 0; i < 20; i = i + 1) poe_hex(texto[i]);
        ascii_troca();
        confere("M", "3", 1, "M2 bit trocado");
        if (resp_len !== 8) begin
            $display("[tb_ascii] FAIL: M3 trouxe campos (len=%0d)", resp_len);
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_ascii] M0 -> M2 confere (00); um bit da tag trocado -> 01");

        // ---- 7. modo de uso ------------------------------------------
        erros_antes = errors;
        inicio("C", "0");
        for (i = 0; i < 144; i = i + 1) poe(bloco_m[i]);
        for (i = 0; i < 16; i = i + 1)  poe_hex(iv[i]);
        poe_dec4(16);
        for (i = 0; i < 16; i = i + 1)  poe_hex(texto[i]);
        ascii_troca();
        confere("C", "1", 11, "C0 com chave de MAC");

        inicio("M", "0");
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        poe_dec4(4);
        for (i = 0; i < 4; i = i + 1) poe_hex(texto[i]);
        ascii_troca();
        confere("M", "1", 11, "M0 com chave de cifra");
        if (errors == erros_antes)
            $display("[tb_ascii] modo: chave de MAC nao cifra, chave de cifra nao autentica (11)");

        // ---- 8. bloco adulterado e mensagens ruins --------------------
        erros_antes = errors;
        inicio("K", "2");
        for (i = 0; i < 144; i = i + 1)
            poe((i == 40) ? ((bloco_c[i] == "0") ? "1" : "0") : bloco_c[i]);
        ascii_troca();
        confere("K", "3", 10, "K2 corpo trocado");

        inicio("K", "2");
        for (i = 0; i < 144; i = i + 1)
            poe((i == 11) ? "N" : bloco_c[i]);   // exportabilidade E -> N
        ascii_troca();
        confere("K", "3", 10, "K2 cabecalho trocado");

        inicio("X", "8");
        ascii_troca();
        confere("X", "9", 21, "comando desconhecido");

        inicio("D", "0"); poe("Z");
        ascii_troca();
        confere("D", "1", 22, "D0 com campo sobrando");

        inicio("C", "0");
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        for (i = 0; i < 16; i = i + 1)  poe_hex(iv[i]);
        poe_dec4(15);
        for (i = 0; i < 15; i = i + 1)  poe_hex(texto[i]);
        ascii_troca();
        confere("C", "1", 15, "C0 com 15 bytes");

        limpa(); poe("T"); poe("B"); poe("0");
        ascii_troca();
        if (resp_len !== 8 || resp[0] !== "T" || resp[1] !== "B" || resp[2] !== "0" ||
            resp[3] !== "0" || resp[4] !== "Z" || resp[5] !== "Z" ||
            resp[6] !== "2" || resp[7] !== "2") begin
            $display("[tb_ascii] FAIL: mensagem de 3 bytes -- resposta len=%0d", resp_len);
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_ascii] recusados: corpo (10), cabecalho do bloco (10), comando (21), sobra (22), dados (15), curta (ZZ22)");

        // ---- 8b. KEK: exportar e importar -------------------------------
        //
        // Sem AES no testbench, a prova e a volta: o que o K4 embrulhou sob
        // a KEK, o K6 desembrulha e devolve sob a LMK com o MESMO KCV, e o
        // C0 com o bloco de volta cifra identico ao do passo 4. A conferencia
        // independente (o Python abrindo o bloco sob a KEK) e na bancada.
        erros_antes = errors;
        inicio("K", "0"); poe("K"); poe("0"); poe("B"); poe("E");
        ascii_troca();
        confere("K", "1", 0, "K0 KEK");
        for (i = 0; i < 144; i = i + 1) bloco_k[i] = resp[8 + i];

        inicio("K", "4");
        for (i = 0; i < 144; i = i + 1) poe(bloco_k[i]);
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        ascii_troca();
        confere("K", "5", 0, "K4");
        if (resp_len !== 8 + 144 + 6) begin
            $display("[tb_ascii] FAIL: K5 com %0d bytes, esperado 158", resp_len);
            errors = errors + 1;
        end
        for (i = 0; i < 144; i = i + 1) bloco_x[i] = resp[8 + i];
        for (i = 0; i < 6; i = i + 1)
            if (resp[152 + i] !== kcv_c[i]) begin
                if (errors == erros_antes)
                    $display("[tb_ascii] FAIL: K5 com KCV diferente do K1");
                errors = errors + 1;
            end
        for (i = 0; i < 16; i = i + 1)
            if (bloco_x[i] !== bloco_c[i]) begin
                if (errors == erros_antes)
                    $display("[tb_ascii] FAIL: K4 mudou o cabecalho (posicao %0d)", i);
                errors = errors + 1;
            end

        // sob a KEK, o bloco nao abre sob a LMK
        inicio("K", "2");
        for (i = 0; i < 144; i = i + 1) poe(bloco_x[i]);
        ascii_troca();
        confere("K", "3", 10, "K2 de bloco sob a KEK");

        inicio("K", "6");
        for (i = 0; i < 144; i = i + 1) poe(bloco_k[i]);
        for (i = 0; i < 144; i = i + 1) poe(bloco_x[i]);
        ascii_troca();
        confere("K", "7", 0, "K6");
        for (i = 0; i < 144; i = i + 1) bloco_l[i] = resp[8 + i];
        for (i = 0; i < 6; i = i + 1)
            if (resp[152 + i] !== kcv_c[i]) begin
                if (errors == erros_antes)
                    $display("[tb_ascii] FAIL: K7 com KCV diferente do K1");
                errors = errors + 1;
            end

        inicio("C", "0");
        for (i = 0; i < 144; i = i + 1) poe(bloco_l[i]);
        for (i = 0; i < 16; i = i + 1)  poe_hex(iv[i]);
        poe_dec4(32);
        for (i = 0; i < 32; i = i + 1)  poe_hex(texto[i]);
        ascii_troca();
        confere("C", "1", 0, "C0 com bloco reimportado");
        for (i = 0; i < 32; i = i + 1)
            if (hexbyte(resp[12 + 2*i], resp[13 + 2*i]) !== cifra[i]) begin
                if (errors == erros_antes)
                    $display("[tb_ascii] FAIL: bloco reimportado cifra diferente (byte %0d)", i);
                errors = errors + 1;
            end

        // recusas
        inicio("K", "4");                                  // 'N' nao sai
        for (i = 0; i < 144; i = i + 1) poe(bloco_k[i]);
        for (i = 0; i < 144; i = i + 1) poe(bloco_m[i]);
        ascii_troca();
        confere("K", "5", 12, "K4 de chave N");

        inicio("K", "4");                                  // dado nao e KEK
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        ascii_troca();
        confere("K", "5", 13, "K4 sob chave de dados");

        inicio("K", "0"); poe("K"); poe("0"); poe("E"); poe("E");
        ascii_troca();
        confere("K", "1", 0, "K0 KEK so E");
        for (i = 0; i < 144; i = i + 1) bloco_e[i] = resp[8 + i];
        inicio("K", "6");                                  // so embrulha
        for (i = 0; i < 144; i = i + 1) poe(bloco_e[i]);
        for (i = 0; i < 144; i = i + 1) poe(bloco_x[i]);
        ascii_troca();
        confere("K", "7", 11, "K6 com KEK so E");

        inicio("K", "6");                                  // adulterado
        for (i = 0; i < 144; i = i + 1) poe(bloco_k[i]);
        for (i = 0; i < 144; i = i + 1)
            poe((i == 60) ? ((bloco_x[i] == "0") ? "1" : "0") : bloco_x[i]);
        ascii_troca();
        confere("K", "7", 10, "K6 bloco adulterado");

        inicio("K", "6");                                  // sob a LMK, nao a KEK
        for (i = 0; i < 144; i = i + 1) poe(bloco_k[i]);
        for (i = 0; i < 144; i = i + 1) poe(bloco_c[i]);
        ascii_troca();
        confere("K", "7", 10, "K6 bloco sob a LMK");
        if (errors == erros_antes)
            $display("[tb_ascii] KEK: K4 -> K6 volta com o mesmo KCV e cifra identico; recusas 12, 13, 11, 10, 10");

        // ---- 9. nada sobra no slot efemero ----------------------------
        //
        // Handle 17 e o slot efemero. Depois de tudo isso, o console tem de
        // encontra-lo VAZIO: a chave de cada comando ASCII foi apagada no
        // fim dele.
        erros_antes = errors;
        limpa(); poe(8'd17);
        console(CMD_KEY_INFO);
        if (st !== ST_BAD_PARAM) begin
            $display("[tb_ascii] FAIL: KEY_INFO(17) -> 0x%02h, o slot efemero nao esta vazio", st);
            errors = errors + 1;
        end else
            $display("[tb_ascii] slot efemero vazio entre comandos (KEY_INFO 17 -> BAD_PARAM)");

        if (errors == 0)
            $display("[tb_ascii] PASS");
        else
            $display("[tb_ascii] FAIL: %0d erro(s)", errors);
        $finish;
    end

endmodule
