`timescale 1ns/1ps
//
// tb_tamper -- fase 6: ambiente fora da faixa apaga tudo, sem pedir licenca
//
// tb_xadc prova que cada limite dispara no modelo do XADC. Este prova a
// corrente inteira, com o firmware real, e o estimulo vem da curva
// sim/stim/tb_tamper.txt: a temperatura sobe para 90 C em T_ALARME, sem
// comando nenhum e sem botao.
//
//   1. boot nominal: ENV_READ responde, nenhum alarme
//   2. cerimonia, ativacao, chave: a LMK esta na flash
//   3. a temperatura sobe: D5 acende sozinho, TAMPERED, comando recusado
//   4. a flash nao tem mais a LMK, e ENV_READ diz a causa
//   5. o log tem o registro 0x0F, com a causa e sem pendencia
//   6. SELFTEST em TAMPERED nao devolve nada
//   7. reset (SW1) com o ambiente ja normal: continua TAMPERED
//   8. "desligar" (limpa a retencao, so o testbench consegue): sobe em
//      UNINITIALIZED, com o log intacto
//   9. o clock de entrada para: o reset vem, e o boot acha a perda de lock
//
module tb_tamper;

    localparam real BIT_NS = 1000000000.0 / 115200.0;
    localparam integer TB_CLK_HZ     = 100_000;
    localparam real    BTN_SETTLE_NS = 1000000.0;

    localparam [7:0] CMD_GET_VERSION = 8'h02;
    localparam [7:0] CMD_LMK_LOAD    = 8'h20;
    localparam [7:0] CMD_LMK_STATUS  = 8'h21;
    localparam [7:0] CMD_GEN_KEY     = 8'h22;
    localparam [7:0] CMD_KEY_INFO    = 8'h25;
    localparam [7:0] CMD_SET_STATE   = 8'h26;
    localparam [7:0] CMD_DELETE_KEY  = 8'h2B;
    localparam [7:0] CMD_KEY_COMP    = 8'h2C;
    localparam [7:0] CMD_AUDIT_READ  = 8'h2D;
    localparam [7:0] CMD_ENV_READ    = 8'h2E;
    localparam [7:0] CMD_SELFTEST    = 8'h15;

    localparam [7:0] ST_OK          = 8'h00;
    localparam [7:0] ST_BAD_PARAM   = 8'h11;
    localparam [7:0] ST_WRONG_STATE = 8'h20;

    reg  sys_clk = 1'b0;
    reg  clk_parado = 1'b0;
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

    always #10 if (!clk_parado) sys_clk = ~sys_clk;
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
                $display("[tb_tamper] FAIL: CRC da resposta invalido");
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
                    $display("[tb_tamper] FAIL: componente %0d -> status 0x%02h", n, st);
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
                $display("[tb_tamper] FAIL: LMK_STATUS status=0x%02h len=%0d", st, resp_len);
                errors = errors + 1;
            end else if (resp[1] !== n_esperado[7:0] ||
                         resp[2] !== {7'd0, completa_esperada}) begin
                $display("[tb_tamper] FAIL: %0d componentes (completa=%0d), esperado %0d (%0d)",
                         resp[1], resp[2], n_esperado, completa_esperada);
                errors = errors + 1;
            end else if (kcv_do_vetor) begin
                if (resp[3] !== 8'h46 || resp[4] !== 8'hF2 || resp[5] !== 8'hFB) begin
                    $display("[tb_tamper] FAIL: KCV = %02h%02h%02h, esperado 46F2FB",
                             resp[3], resp[4], resp[5]);
                    errors = errors + 1;
                end
            end else begin
                if (resp[3] !== 8'h00 || resp[4] !== 8'h00 || resp[5] !== 8'h00) begin
                    $display("[tb_tamper] FAIL: KCV = %02h%02h%02h com a LMK apagada, esperado zeros",
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
                $display("[tb_tamper] FAIL: GET_VERSION status=0x%02h", st);
                errors = errors + 1;
            end else if (resp[4] !== esperado) begin
                $display("[tb_tamper] FAIL: estado=%0d, esperado %0d", resp[4], esperado);
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
                $display("[tb_tamper] FAIL: o POST reprovou no boot");
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
                $display("[tb_tamper] FAIL: GEN_KEY -> 0x%02h", st);
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

    localparam real T_ALARME = 300000000.0;   // 300 ms, em sim/stim/tb_tamper.txt

    `define XADC_STICKY dut.u_soc.u_neorv32.io_system.neorv32_cfs_enabled.neorv32_cfs_inst.u_core.u_xadc.sticky

    task espera_led_tamper;
        begin
            wait (led[4] === 1'b0);
            #1000;
        end
    endtask

    // Procura no log, a partir de `seq`, um registro `op` com argumento
    // `arg`. Le direto pelo comando, que tem de responder em TAMPERED.
    integer log_achou, log_pend;
    reg [7:0] log_res;
    task procura_log;
        input [7:0] op;
        input [7:0] arg;
        integer a;
        begin
            log_achou = 0; log_pend = 0; log_res = 8'hEE;
            seq = 0; proximo = 1;
            while (seq < proximo) begin
                req_pl[0] = seq[31:24]; req_pl[1] = seq[23:16];
                req_pl[2] = seq[15:8];  req_pl[3] = seq[7:0]; req_plen = 4;
                send_cmd_pl(CMD_AUDIT_READ);
                get_response();
                if (st !== ST_OK) begin
                    $display("[tb_tamper] FAIL: AUDIT_READ -> 0x%02h", st);
                    errors = errors + 1;
                    proximo = 0;
                end else begin
                    proximo = {resp[1], resp[2], resp[3], resp[4]};
                    continuar = {resp[5], resp[6], resp[7], resp[8]};
                    for (a = 9; a < resp_len; a = a + 16) begin
                        if (resp[a + 7] === 8'hFF) log_pend = log_pend + 1;
                        if (resp[a + 4] === op && resp[a + 6] === arg) begin
                            log_achou = log_achou + 1;
                            log_res = resp[a + 7];
                        end
                    end
                    seq = continuar;
                end
            end
        end
    endtask

    task le_env;
        begin
            req_plen = 0;
            send_cmd_pl(CMD_ENV_READ);
            get_response();
            if (st !== ST_OK || resp_len !== 12) begin
                $display("[tb_tamper] FAIL: ENV_READ status=0x%02h len=%0d", st, resp_len);
                errors = errors + 1;
            end
        end
    endtask

    task confere_recusa;
        begin
            req_plen = 0;
            send_cmd_pl(CMD_GET_VERSION);
            get_response();
            if (st !== ST_WRONG_STATE) begin
                $display("[tb_tamper] FAIL: GET_VERSION em TAMPERED -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    initial begin
        #2000000000;
        $display("[tb_tamper] FAIL: timeout");
        $finish;
    end

    initial begin
        $display("[tb_tamper] inicio");
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
            $display("[tb_tamper] FAIL: subiu em TAMPERED com ambiente nominal");
            $finish;
        end

        // ---- 1. nominal ---------------------------------------------------
        confere_estado(8'd0);
        le_env();
        if (resp[1] !== 8'h00 || resp[2] !== 8'h00 || resp[3] !== 8'h01) begin
            $display("[tb_tamper] FAIL: ENV_READ nominal retido=%02h agora=%02h valido=%02h",
                     resp[1], resp[2], resp[3]);
            errors = errors + 1;
        end
        // 36 C = codigo 2513; tolerancia de 8 codigos (1 C)
        if ({resp[4], resp[5]} < 16'd2505 || {resp[4], resp[5]} > 16'd2521) begin
            $display("[tb_tamper] FAIL: temperatura nominal, codigo %0d", {resp[4], resp[5]});
            errors = errors + 1;
        end
        $display("[tb_tamper] boot nominal, ENV_READ sem alarme");

        // ---- 2. cerimonia e chave ------------------------------------------
        cerimonia();
        aperto_novo();
        req_pl[0] = 8'd2; req_plen = 1;
        send_cmd_pl(CMD_SET_STATE);
        get_response();
        soltar();
        gen_key("D0", "B", "E", h1, kcv_h1);
        confere_estado(8'd2);
        if (procura(0) == 0) begin
            $display("[tb_tamper] FAIL: a LMK nao foi para a flash");
            errors = errors + 1;
        end
        $display("[tb_tamper] OPERATIONAL em t = %0d ms, LMK na flash", $time / 1000000);
        if ($realtime >= T_ALARME) begin
            $display("[tb_tamper] FAIL: a preparacao passou de T_ALARME");
            errors = errors + 1;
        end

        // ---- 3. a temperatura sobe ------------------------------------------
        espera_led_tamper();
        $display("[tb_tamper] D5 aceso em t = %0d ms, sem comando", $time / 1000000);
        if ($realtime < T_ALARME) begin
            $display("[tb_tamper] FAIL: disparou antes do degrau");
            errors = errors + 1;
        end
        #300000000;      // apagar dois setores: da tempo a resposta terminar
        confere_recusa();

        // ---- 4. a flash e a causa --------------------------------------------
        if (procura(0) != 0) begin
            $display("[tb_tamper] FAIL: a LMK continua na flash");
            errors = errors + 1;
        end
        le_env();
        if (resp[1] !== 8'h01) begin
            $display("[tb_tamper] FAIL: causa retida %02h, esperado 01", resp[1]);
            errors = errors + 1;
        end
        $display("[tb_tamper] TAMPERED, LMK fora da flash, causa: temperatura alta");

        // ---- 5. o log -----------------------------------------------------------
        procura_log(8'h0F, 8'h01);
        if (log_achou !== 1 || log_res !== ST_OK || log_pend !== 0) begin
            $display("[tb_tamper] FAIL: log achou=%0d resultado=%02h pendentes=%0d",
                     log_achou, log_res, log_pend);
            errors = errors + 1;
        end
        $display("[tb_tamper] log: registro 0x0F com a causa e sem pendencia");

        // ---- 6. SELFTEST em TAMPERED -----------------------------------------
        req_plen = 0;
        send_cmd_pl(CMD_SELFTEST);
        get_response();
        confere_recusa();
        $display("[tb_tamper] SELFTEST nao tira de TAMPERED");

        // ---- 7. reset, com a temperatura ja normal ----------------------------
        rst_n = 1'b0; #2000; rst_n = 1'b1; #5000;
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));
        #30000000;
        espera_led_tamper();
        confere_recusa();
        le_env();
        if (resp[1] !== 8'h01 || resp[2] !== 8'h00) begin
            $display("[tb_tamper] FAIL: depois do reset retido=%02h agora=%02h", resp[1], resp[2]);
            errors = errors + 1;
        end
        $display("[tb_tamper] reset nao apaga a prova: continua TAMPERED");

        // ---- 8. desligar ---------------------------------------------------------
        force `XADC_STICKY = 6'd0;
        rst_n = 1'b0; #2000; rst_n = 1'b1; #5000;
        release `XADC_STICKY;
        wait (led[1] === 1'b0);
        #30000000;
        confere_estado(8'd0);
        procura_log(8'h0F, 8'h01);
        if (log_achou < 1) begin
            $display("[tb_tamper] FAIL: o log perdeu o registro de violacao");
            errors = errors + 1;
        end
        $display("[tb_tamper] religado: UNINITIALIZED, log intacto");

        // ---- 9. o clock de entrada para ---------------------------------------
        // De novo com a LMK na flash: e ela que a resposta tem de apagar, e
        // aqui o caminho e o do boot, nao o do laco principal.
        cerimonia();
        aperto_novo();
        req_pl[0] = 8'd2; req_plen = 1;
        send_cmd_pl(CMD_SET_STATE);
        get_response();
        soltar();
        confere_estado(8'd2);
        if (procura(0) == 0) begin
            $display("[tb_tamper] FAIL: a segunda LMK nao foi para a flash");
            errors = errors + 1;
        end
        clk_parado = 1'b1;
        #5000;
        clk_parado = 1'b0;
        espera_led_tamper();    // o MMCM tem de voltar sem ninguem apertar nada
        $display("[tb_tamper] D5 aceso em t = %0d ms, sem comando", $time / 1000000);
        #300000000;
        confere_recusa();
        if (procura(0) != 0) begin
            $display("[tb_tamper] FAIL: a perda de lock deixou a LMK na flash");
            errors = errors + 1;
        end
        le_env();
        if (resp[1] !== 8'h40) begin
            $display("[tb_tamper] FAIL: causa %02h, esperado 40", resp[1]);
            errors = errors + 1;
        end
        $display("[tb_tamper] perda de lock: TAMPERED, LMK fora da flash, causa no ENV_READ");

        if (errors == 0) $display("[tb_tamper] PASS");
        else             $display("[tb_tamper] FAIL: %0d erros", errors);
        $finish;
    end

endmodule
