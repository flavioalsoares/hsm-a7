`timescale 1ns/1ps
//
// tb_persist -- fase 4: desligar e religar sem perder a LMK nem as chaves
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// O modelo da flash (sim/models/spi_flash_model.v) guarda a memoria
// atraves do reset do DUT. Derrubar o rst_n e soltar de novo e, para o
// firmware, um boot do zero -- a BRAM e reinicializada pelo crt0 e pelo
// keystore_init() -- enquanto a flash continua com o que foi gravado. E
// assim que este teste "desliga a placa".
//
// O que ele prende:
//
//   1. boot com a flash vazia: UNINITIALIZED, e o log ja tem o registro
//      de boot;
//   2. comando fora de hora entra no log COM o resultado (WRONG_STATE);
//   3. cerimonia + ativacao + chaves (geradas e por componentes) + apagar;
//   4. a flash: a LMK esta la (decisao de 2026-10-15, a flash e tratada
//      como memoria segura), a chave de trabalho montada por componentes
//      NAO esta em claro em lugar nenhum (vai embrulhada), e nenhuma
//      escrita tocou abaixo de 4 MB;
//   5. religar: OPERATIONAL sem cerimonia, LMK com o KCV do vetor do
//      CAVP, cada chave no MESMO handle com o MESMO KCV, o slot apagado
//      continua vazio;
//   6. o log: sequencia continua atravessando o boot, cada comando com
//      resultado, nenhum pendente;
//   7. copia mais nova corrompida: o boot cai na anterior;
//   8. ZEROIZE apaga a flash -- religa em UNINITIALIZED -- e o log fica.
//
module tb_persist;

    localparam real BIT_NS = 1000000000.0 / 115200.0;
    localparam integer TB_CLK_HZ     = 100_000;
    localparam real    BTN_SETTLE_NS = 100000.0;

    localparam [7:0] CMD_GET_VERSION = 8'h02;
    localparam [7:0] CMD_LMK_LOAD    = 8'h20;
    localparam [7:0] CMD_LMK_STATUS  = 8'h21;
    localparam [7:0] CMD_GEN_KEY     = 8'h22;
    localparam [7:0] CMD_KEY_INFO    = 8'h25;
    localparam [7:0] CMD_SET_STATE   = 8'h26;
    localparam [7:0] CMD_DELETE_KEY  = 8'h2B;
    localparam [7:0] CMD_KEY_COMP    = 8'h2C;
    localparam [7:0] CMD_AUDIT_READ  = 8'h2D;
    localparam [7:0] CMD_ZEROIZE     = 8'h2F;

    localparam [7:0] ST_OK          = 8'h00;
    localparam [7:0] ST_BAD_PARAM   = 8'h11;
    localparam [7:0] ST_WRONG_STATE = 8'h20;

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
    integer i, j, k, n;

    reg [7:0] resp [0:299];
    integer   resp_len;
    reg [7:0] st;

    reg [7:0] req_pl [0:63];
    integer   req_plen;

    reg [7:0] comp0 [0:31];
    reg [7:0] comp1 [0:31];
    reg [7:0] comp2 [0:31];
    reg [7:0] lmk   [0:31];
    reg [7:0] k2    [0:31];   // chave de trabalho montada por componentes
    reg [7:0] p0    [0:31];   // as duas partes dela
    reg [7:0] p1    [0:31];

    reg [23:0] kcv_h1, kcv_h2, kcv_h3, kcv_hc, kcv_tmp;
    reg [7:0]  h1, h2, h3, hc;
    integer    boots_vistos, pendentes, wrong_state_logado, seq_esperada;
    reg [31:0] proximo, continuar, seq;
    reg [31:0] cont_a, cont_b;
    integer    achou_lmk, achou_k2, base;

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
    // CRC32 IEEE 802.3 refletido -- implementacao independente do firmware
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

    // Pedido com payload em req_pl[0..req_plen-1]. Verilog-2001 nao passa
    // array por argumento de task; nao e elegancia, e a linguagem.
    task send_cmd_pl;
        input [7:0]  opcode;
        reg   [31:0] crc;
        reg   [15:0] len;
        integer      k;
        begin
            len = req_plen + 1;
            crc = 32'hFFFFFFFF;
            crc = crc32_update(crc, len[15:8]);
            crc = crc32_update(crc, len[7:0]);
            crc = crc32_update(crc, opcode);
            for (k = 0; k < req_plen; k = k + 1)
                crc = crc32_update(crc, req_pl[k]);
            crc = ~crc;

            uart_put(len[15:8]);
            uart_put(len[7:0]);
            uart_put(opcode);
            for (k = 0; k < req_plen; k = k + 1)
                uart_put(req_pl[k]);
            uart_put(crc[31:24]); uart_put(crc[23:16]);
            uart_put(crc[15:8]);  uart_put(crc[7:0]);
        end
    endtask

    task get_response;
        reg [15:0] len;
        reg [31:0] crc, crc_rx;
        reg [7:0]  b;
        integer    k;
        begin
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
                $display("[tb_persist] FAIL: CRC da resposta invalido");
                errors = errors + 1;
            end
            st = resp[0];
        end
    endtask

    // Botoes ATIVOS BAIXOS no pino: 0 = pressionado. O toplevel inverte, e
    // o firmware ve 1 = pressionado.
    task apertar; begin btn_a = 1'b0; btn_b = 1'b0; #(BTN_SETTLE_NS); end endtask
    task soltar;  begin btn_a = 1'b1; btn_b = 1'b1; #(BTN_SETTLE_NS); end endtask

    // Um aperto NOVO: e o gesto que o firmware exige entre autorizacoes.
    task aperto_novo; begin soltar(); apertar(); end endtask

    task prepara_componente;
        input integer n;
        integer k;
        begin
            req_pl[0] = n[7:0];
            for (k = 0; k < 32; k = k + 1) begin
                case (n)
                    0: req_pl[1 + k] = comp0[k];
                    1: req_pl[1 + k] = comp1[k];
                    default: req_pl[1 + k] = comp2[k];
                endcase
            end
            req_plen = 33;
        end
    endtask

    // A cerimonia inteira: tres componentes, cada um com aperto novo.
    task cerimonia;
        integer n;
        begin
            for (n = 0; n < 3; n = n + 1) begin
                aperto_novo();
                prepara_componente(n);
                send_cmd_pl(CMD_LMK_LOAD);
                get_response();
                if (st !== ST_OK) begin
                    $display("[tb_persist] FAIL: componente %0d -> status 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar();
        end
    endtask

    // LMK_STATUS, e confere contra o esperado.
    task confere_lmk;
        input integer n_esperado;
        input         completa_esperada;
        input         kcv_do_vetor;   // 1 = 46F2FB, 0 = tres zeros
        begin
            req_plen = 0;
            send_cmd_pl(CMD_LMK_STATUS);
            get_response();

            if (st !== ST_OK || resp_len !== 6) begin
                $display("[tb_persist] FAIL: LMK_STATUS status=0x%02h len=%0d", st, resp_len);
                errors = errors + 1;
            end else if (resp[1] !== n_esperado[7:0] ||
                         resp[2] !== {7'd0, completa_esperada}) begin
                $display("[tb_persist] FAIL: %0d componentes (completa=%0d), esperado %0d (%0d)",
                         resp[1], resp[2], n_esperado, completa_esperada);
                errors = errors + 1;
            end else if (kcv_do_vetor) begin
                if (resp[3] !== 8'h46 || resp[4] !== 8'hF2 || resp[5] !== 8'hFB) begin
                    $display("[tb_persist] FAIL: KCV = %02h%02h%02h, esperado 46F2FB",
                             resp[3], resp[4], resp[5]);
                    errors = errors + 1;
                end
            end else begin
                if (resp[3] !== 8'h00 || resp[4] !== 8'h00 || resp[5] !== 8'h00) begin
                    $display("[tb_persist] FAIL: KCV = %02h%02h%02h com a LMK apagada, esperado zeros",
                             resp[3], resp[4], resp[5]);
                    errors = errors + 1;
                end
            end
        end
    endtask

    task confere_estado;
        input [7:0] esperado;
        begin
            req_plen = 0;
            send_cmd_pl(CMD_GET_VERSION);
            get_response();
            if (st !== ST_OK || resp_len !== 5) begin
                $display("[tb_persist] FAIL: GET_VERSION status=0x%02h", st);
                errors = errors + 1;
            end else if (resp[4] !== esperado) begin
                $display("[tb_persist] FAIL: estado=%0d, esperado %0d", resp[4], esperado);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    // "Desligar e religar": reset do DUT, a flash fica.
    // ------------------------------------------------------------------
    task religa;
        begin
            rst_n = 1'b0;
            #2000;
            rst_n = 1'b1;
            #5000;
            wait ((led[1] === 1'b0) || (led[4] === 1'b0));
            #1000;
            if (led[4] === 1'b0) begin
                $display("[tb_persist] FAIL: o POST reprovou no boot");
                errors = errors + 1;
            end
        end
    endtask

    task gen_key;
        input [15:0] uso;
        input [7:0]  modo;
        input [7:0]  exp;
        output [7:0] h;
        output [23:0] kcv;
        begin
            req_pl[0] = uso[15:8]; req_pl[1] = uso[7:0];
            req_pl[2] = "A"; req_pl[3] = modo; req_pl[4] = exp;
            req_plen = 5;
            send_cmd_pl(CMD_GEN_KEY);
            get_response();
            if (st !== ST_OK) begin
                $display("[tb_persist] FAIL: GEN_KEY -> 0x%02h", st);
                errors = errors + 1;
            end
            h   = resp[1];
            kcv = {resp[2], resp[3], resp[4]};
        end
    endtask

    // KEY_INFO: devolve o status e o KCV (resp[7..9])
    task key_info;
        input  [7:0]  h;
        output [23:0] kcv;
        begin
            req_pl[0] = h; req_plen = 1;
            send_cmd_pl(CMD_KEY_INFO);
            get_response();
            kcv = {resp[7], resp[8], resp[9]};
        end
    endtask

    task confere_slot;
        input [7:0]  h;
        input [23:0] kcv_esperado;
        reg   [23:0] kcv;
        begin
            key_info(h, kcv);
            if (st !== ST_OK) begin
                $display("[tb_persist] FAIL: KEY_INFO %0d -> 0x%02h", h, st);
                errors = errors + 1;
            end else if (kcv !== kcv_esperado) begin
                $display("[tb_persist] FAIL: handle %0d com KCV %06h, esperado %06h",
                         h, kcv, kcv_esperado);
                errors = errors + 1;
            end
        end
    endtask

    // Procura uma sequencia de 32 bytes na janela modelada da flash.
    function integer procura;
        input integer qual;   // 0 = lmk, 1 = k2
        integer a, b, ok;
        begin
            procura = 0;
            for (a = 0; a <= 32'h80000 - 32; a = a + 1) begin
                ok = 1;
                for (b = 0; (b < 32) && ok; b = b + 1)
                    if (flash.mem[a + b] !== ((qual == 0) ? lmk[b] : k2[b])) ok = 0;
                if (ok) procura = procura + 1;
            end
        end
    endfunction

    // ------------------------------------------------------------------
    initial begin
        #900000000;                     // 900 ms
        $display("[tb_persist] FAIL: timeout");
        $display("[tb_persist] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_persist] inicio");

        // LMK = ECBKeySbox256 do CAVP, KCV 46F2FB (ver tb_zeroize).
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
            // chave de trabalho: qualquer valor conhecido e distinto da LMK
            k2[i] = 8'hA0 ^ (i[7:0] * 8'h0D);
            p0[i] = 8'h33 + (i[7:0] * 8'h05);
            p1[i] = k2[i] ^ p0[i];
        end

        #200;
        rst_n = 1'b1;
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));
        #1000;
        if (led[4] === 1'b0) begin
            $display("[tb_persist] FAIL: o POST reprovou no boot");
            $display("[tb_persist] FAIL");
            $finish;
        end

        // ---- 1. flash vazia ---------------------------------------------
        confere_estado(8'd0);
        if (flash.programas == 0) begin
            $display("[tb_persist] FAIL: o boot nao gravou o registro de boot");
            errors = errors + 1;
        end
        $display("[tb_persist] boot 1: flash vazia, UNINITIALIZED");

        // ---- 2. tentativa fora de hora -----------------------------------
        req_pl[0] = "D"; req_pl[1] = "0"; req_pl[2] = "A";
        req_pl[3] = "B"; req_pl[4] = "E"; req_plen = 5;
        send_cmd_pl(CMD_GEN_KEY);
        get_response();
        if (st !== ST_WRONG_STATE) begin
            $display("[tb_persist] FAIL: GEN_KEY em UNINITIALIZED -> 0x%02h", st);
            errors = errors + 1;
        end

        // ---- 3. cerimonia, ativacao, chaves ------------------------------
        cerimonia();
        confere_lmk(3, 1'b1, 1'b1);
        aperto_novo();
        req_pl[0] = 8'd2; req_plen = 1;
        send_cmd_pl(CMD_SET_STATE);
        get_response();
        soltar();
        if (st !== ST_OK) begin
            $display("[tb_persist] FAIL: SET_STATE -> 0x%02h", st);
            errors = errors + 1;
        end

        gen_key("D0", "B", "E", h1, kcv_h1);
        gen_key("M0", "C", "N", h2, kcv_h2);
        gen_key("K0", "B", "E", h3, kcv_h3);

        // chave por componentes, em duas partes
        for (n = 0; n < 2; n = n + 1) begin
            aperto_novo();
            req_pl[0] = n; req_pl[1] = 8'd2;
            req_pl[2] = "D"; req_pl[3] = "0"; req_pl[4] = "A";
            req_pl[5] = "B"; req_pl[6] = "N";
            for (k = 0; k < 32; k = k + 1)
                req_pl[7 + k] = (n == 0) ? p0[k] : p1[k];
            req_plen = 39;
            send_cmd_pl(CMD_KEY_COMP);
            get_response();
            if (st !== ST_OK) begin
                $display("[tb_persist] FAIL: KEY_FROM_COMPONENTS %0d -> 0x%02h", n, st);
                errors = errors + 1;
            end
        end
        soltar();
        hc = resp[6];
        key_info(hc, kcv_hc);

        req_pl[0] = h2; req_plen = 1;
        send_cmd_pl(CMD_DELETE_KEY);
        get_response();
        if (st !== ST_OK) begin
            $display("[tb_persist] FAIL: DELETE_KEY -> 0x%02h", st);
            errors = errors + 1;
        end
        $display("[tb_persist] handles %0d e %0d gerados, %0d por componentes, %0d apagado",
                 h1, h3, hc, h2);

        // ---- 4. o que esta na flash --------------------------------------
        achou_lmk = procura(0);
        achou_k2  = procura(1);
        if (achou_lmk == 0) begin
            $display("[tb_persist] FAIL: a LMK nao esta na flash -- nao ha como religar com ela");
            errors = errors + 1;
        end
        if (achou_k2 != 0) begin
            $display("[tb_persist] FAIL: a chave de trabalho esta EM CLARO na flash (%0d vezes)",
                     achou_k2);
            errors = errors + 1;
        end
        if (flash.violacoes != 0) begin
            $display("[tb_persist] FAIL: %0d escrita(s) abaixo de 4 MB", flash.violacoes);
            errors = errors + 1;
        end
        if ((achou_lmk != 0) && (achou_k2 == 0) && (flash.violacoes == 0))
            $display("[tb_persist] flash: LMK presente, chave de trabalho so embrulhada, 0 escritas abaixo de 4 MB");

        // ---- 5. religar --------------------------------------------------
        religa();
        erros_antes = errors;
        confere_estado(8'd2);
        confere_lmk(3, 1'b1, 1'b1);
        confere_slot(h1, kcv_h1);
        confere_slot(h3, kcv_h3);
        confere_slot(hc, kcv_hc);
        key_info(h2, kcv_tmp);
        if (st !== ST_BAD_PARAM) begin
            $display("[tb_persist] FAIL: slot apagado %0d voltou (status 0x%02h)", h2, st);
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_persist] boot 2: OPERATIONAL sem cerimonia, KCV 46F2FB, as tres chaves nos mesmos handles");

        // ---- 6. o log ----------------------------------------------------
        boots_vistos = 0; pendentes = 0; wrong_state_logado = 0;
        seq_esperada = 0;
        seq = 0;
        proximo = 1;
        while (seq < proximo) begin
            req_pl[0] = seq[31:24]; req_pl[1] = seq[23:16];
            req_pl[2] = seq[15:8];  req_pl[3] = seq[7:0];
            req_plen = 4;
            send_cmd_pl(CMD_AUDIT_READ);
            get_response();
            if (st !== ST_OK) begin
                $display("[tb_persist] FAIL: AUDIT_READ -> 0x%02h", st);
                errors = errors + 1;
                proximo = 0;
            end else begin
                proximo   = {resp[1], resp[2], resp[3], resp[4]};
                continuar = {resp[5], resp[6], resp[7], resp[8]};
                for (j = 0; j < (resp_len - 9) / 16; j = j + 1) begin
                    base = 9 + j * 16;
                    if ({resp[base], resp[base+1], resp[base+2], resp[base+3]} !== seq_esperada) begin
                        $display("[tb_persist] FAIL: log com buraco em %0d", seq_esperada);
                        errors = errors + 1;
                    end
                    seq_esperada = seq_esperada + 1;
                    if (resp[base+4] === 8'h00) boots_vistos = boots_vistos + 1;
                    if (resp[base+7] === 8'hFF) pendentes = pendentes + 1;
                    if ((resp[base+4] === CMD_GEN_KEY) && (resp[base+5] === 8'd0) &&
                        (resp[base+7] === ST_WRONG_STATE))
                        wrong_state_logado = 1;
                end
                seq = continuar;
            end
        end
        erros_antes = errors;
        if (boots_vistos != 2) begin
            $display("[tb_persist] FAIL: %0d registros de boot, esperado 2", boots_vistos);
            errors = errors + 1;
        end
        if (pendentes != 0) begin
            $display("[tb_persist] FAIL: %0d registro(s) sem resultado", pendentes);
            errors = errors + 1;
        end
        if (!wrong_state_logado) begin
            $display("[tb_persist] FAIL: o GEN_KEY recusado em UNINITIALIZED nao esta no log");
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_persist] log: %0d registros em sequencia, 2 boots, a recusa registrada, nenhum pendente",
                     proximo);

        // ---- 7. copia mais nova corrompida -------------------------------
        cont_a = {flash.mem[8],  flash.mem[9],  flash.mem[10],  flash.mem[11]};
        cont_b = {flash.mem[32'h1008], flash.mem[32'h1009], flash.mem[32'h100A], flash.mem[32'h100B]};
        if (cont_a > cont_b) flash.mem[100] = ~flash.mem[100];
        else                 flash.mem[32'h1000 + 100] = ~flash.mem[32'h1000 + 100];
        religa();
        // a copia anterior e a de ANTES do DELETE_KEY: o slot apagado volta
        erros_antes = errors;
        confere_estado(8'd2);
        key_info(h2, kcv_tmp);
        if (st !== ST_OK) begin
            $display("[tb_persist] FAIL: com a copia nova corrompida, o boot nao caiu na anterior");
            errors = errors + 1;
        end else if (kcv_tmp !== kcv_h2) begin
            $display("[tb_persist] FAIL: o slot %0d voltou com KCV %06h, esperado %06h",
                     h2, kcv_tmp, kcv_h2);
            errors = errors + 1;
        end
        confere_slot(h1, kcv_h1);
        if (errors == erros_antes)
            $display("[tb_persist] copia nova corrompida: o boot usou a anterior (o slot %0d de antes do DELETE voltou)", h2);

        // ---- 8. ZEROIZE apaga a flash; o log fica -------------------------
        aperto_novo();
        req_plen = 0;
        send_cmd_pl(CMD_ZEROIZE);
        get_response();
        soltar();
        if (st !== ST_OK) begin
            $display("[tb_persist] FAIL: ZEROIZE -> 0x%02h", st);
            errors = errors + 1;
        end
        religa();
        erros_antes = errors;
        confere_estado(8'd0);
        confere_lmk(0, 1'b0, 1'b0);
        if (procura(0) != 0) begin
            $display("[tb_persist] FAIL: a LMK continua na flash depois do ZEROIZE");
            errors = errors + 1;
        end
        req_pl[0] = 0; req_pl[1] = 0; req_pl[2] = 0; req_pl[3] = 0; req_plen = 4;
        send_cmd_pl(CMD_AUDIT_READ);
        get_response();
        if ({resp[1], resp[2], resp[3], resp[4]} <= proximo) begin
            $display("[tb_persist] FAIL: o log nao sobreviveu ao ZEROIZE");
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_persist] ZEROIZE: religa em UNINITIALIZED, LMK fora da flash, log intacto");

        if (flash.violacoes != 0) begin
            $display("[tb_persist] FAIL: %0d escrita(s) abaixo de 4 MB", flash.violacoes);
            errors = errors + 1;
        end

        if (errors == 0)
            $display("[tb_persist] PASS");
        else
            $display("[tb_persist] FAIL: %0d erro(s)", errors);
        $finish;
    end

endmodule
