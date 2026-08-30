`timescale 1ns/1ps
//
// tb_zeroize -- apagar toda chave, e PROVAR que apagou
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// ---------------------------------------------------------------------
// O PROBLEMA DE TESTAR ZEROIZACAO
//
// "Chamei a funcao de apagar" nao e a mesma coisa que "apagou", e a
// diferenca e invisivel de fora: um `wipe()` que o compilador eliminou,
// um campo novo que ninguem acrescentou ao laco, um slot fora do
// intervalo -- os tres falham em SILENCIO, e os tres deixam chave viva
// num dispositivo que se anuncia limpo.
//
// O firmware tem a sua propria prova (`keystore_prova_zeroizacao()`, que
// varre a regiao byte a byte e roda no POST). Mas ela e AUTO-ATESTACAO:
// e o mesmo codigo dizendo que o mesmo codigo funcionou.
//
// ---------------------------------------------------------------------
// A PROVA INDEPENDENTE USADA AQUI: O KCV
//
// A LMK se acumula por XOR. Se a zeroizacao deixasse residuo em `g_lmk`,
// a cerimonia seguinte acumularia sobre o residuo -- e o KCV resultante
// **nao** seria o dos componentes, seria o dos componentes XOR residuo.
//
// Entao o teste e: cerimonia, KCV 46F2FB. ZEROIZE. Cerimonia com os
// MESMOS componentes, KCV 46F2FB de novo. Um unico bit sobrevivente na
// regiao da LMK muda o KCV completamente, e o valor esperado nao e "o que
// o firmware devolveu da outra vez" -- e vetor oficial do NIST
// (ECBKeySbox256, cujo PLAINTEXT e um bloco de zeros, o que faz o
// criptograma dele SER o KCV daquela chave).
//
// Isso e criptografia provando memoria. Nao alcanca os 16 slots -- so a
// LMK -- e isso esta dito, nao escondido: a varredura byte a byte dos
// slots continua sendo o teste de funcao critica do POST.
//
// ⚠ Por que nao ler a Block RAM diretamente. O array de memoria e um
// `signal spram : ram_t` VHDL dentro de neorv32_prim_spram, e este
// testbench e Verilog. O xsim ja recusou `force` atravessando essa
// fronteira em tb_post_tamper (XSIM 43-4289); ler um tipo composto VHDL
// de Verilog tem a mesma natureza. Registrar o limite importa: um
// testbench que se descrevesse como "varri a BRAM" quando na verdade
// perguntou ao dispositivo mentiria sobre a propria cobertura.
//
// ---------------------------------------------------------------------
// E O DEFEITO QUE ESTE TESTE FIXA NO LUGAR
//
// O autoteste sob demanda e DESTRUTIVO: o teste de funcao critica do key
// store instala e apaga chaves, e termina zerando o store inteiro, LMK
// inclusive. Antes de 2026-08-29 o dispositivo continuava dizendo
// OPERATIONAL depois disso -- estado e realidade divergindo. O teste 4
// abaixo prende o comportamento correto.
//
module tb_zeroize;

    localparam real BIT_NS = 1000000000.0 / 115200.0;

    // Ver tb_uart_frame: clock nominal reduzido so para encolher o divisor
    // do debounce. O clock real continua sendo o de 100 MHz.
    localparam integer TB_CLK_HZ     = 100_000;
    localparam real    BTN_SETTLE_NS = 100000.0;

    localparam [7:0] CMD_GET_VERSION = 8'h02;
    localparam [7:0] CMD_SELFTEST    = 8'h15;
    localparam [7:0] CMD_LMK_LOAD    = 8'h20;
    localparam [7:0] CMD_LMK_STATUS  = 8'h21;
    localparam [7:0] CMD_SET_STATE   = 8'h26;
    localparam [7:0] CMD_ZEROIZE     = 8'h2F;

    localparam [7:0] ST_OK            = 8'h00;
    localparam [7:0] ST_NOT_AUTH      = 8'h21;
    localparam [7:0] ST_SELFTEST_FAIL = 8'h30;

    // Veredito do RCT dentro do coprocessador -- mesmo caminho de
    // tb_post_tamper. Usado so no fim, para alcancar TAMPERED.
    `define RCT_FAIL dut.u_soc.u_neorv32.io_system.neorv32_cfs_enabled.neorv32_cfs_inst.u_core.u_health.rct_fail_o

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

    reg [7:0] resp [0:31];
    integer   resp_len;
    reg [7:0] st;

    reg [7:0] req_pl [0:63];
    integer   req_plen;

    reg [7:0] comp0 [0:31];
    reg [7:0] comp1 [0:31];
    reg [7:0] comp2 [0:31];
    reg [7:0] lmk   [0:31];

    always #10 sys_clk = ~sys_clk;

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
        .seg_an_o   (seg_an)
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
                $display("[tb_zeroize] FAIL: CRC da resposta invalido");
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
                    $display("[tb_zeroize] FAIL: componente %0d -> status 0x%02h", n, st);
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
                $display("[tb_zeroize] FAIL: LMK_STATUS status=0x%02h len=%0d", st, resp_len);
                errors = errors + 1;
            end else if (resp[1] !== n_esperado[7:0] ||
                         resp[2] !== {7'd0, completa_esperada}) begin
                $display("[tb_zeroize] FAIL: %0d componentes (completa=%0d), esperado %0d (%0d)",
                         resp[1], resp[2], n_esperado, completa_esperada);
                errors = errors + 1;
            end else if (kcv_do_vetor) begin
                if (resp[3] !== 8'h46 || resp[4] !== 8'hF2 || resp[5] !== 8'hFB) begin
                    $display("[tb_zeroize] FAIL: KCV = %02h%02h%02h, esperado 46F2FB",
                             resp[3], resp[4], resp[5]);
                    errors = errors + 1;
                end
            end else begin
                if (resp[3] !== 8'h00 || resp[4] !== 8'h00 || resp[5] !== 8'h00) begin
                    $display("[tb_zeroize] FAIL: KCV = %02h%02h%02h com a LMK apagada, esperado zeros",
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
                $display("[tb_zeroize] FAIL: GET_VERSION status=0x%02h", st);
                errors = errors + 1;
            end else if (resp[4] !== esperado) begin
                $display("[tb_zeroize] FAIL: estado=%0d, esperado %0d", resp[4], esperado);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #400000000;                     // 400 ms
        $display("[tb_zeroize] FAIL: timeout");
        $display("[tb_zeroize] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_zeroize] inicio");

        // Chave alvo = ECBKeySbox256 do CAVP (DECRYPT COUNT=0). O KCV dela
        // e 46F2FB porque o PLAINTEXT daquele vetor e um bloco de zeros --
        // entao o criptograma E o KCV, e nao ha vetor novo a inventar.
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
        end

        #200;
        rst_n = 1'b1;

        // Espera QUALQUER desfecho do POST, nao so o bom: esperar so pelo
        // LED de atividade trava para sempre se o POST reprovar, e um
        // teste que trava nao reprova -- ele deixa de existir.
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));
        #1000;
        if (led[4] === 1'b0) begin
            $display("[tb_zeroize] FAIL: o POST reprovou no boot");
            $display("[tb_zeroize] FAIL");
            $finish;
        end
        $display("[tb_zeroize] POST verde em %.2f ms", $realtime / 1000000.0);

        // ---- 1. cerimonia, e o dispositivo em servico ------------------
        erros_antes = errors;
        cerimonia();
        confere_lmk(3, 1'b1, 1'b1);
        if (errors == erros_antes)
            $display("[tb_zeroize] LMK carregada, KCV 46F2FB (vetor do CAVP)");

        aperto_novo();
        req_pl[0] = 8'd2;  req_plen = 1;      // OPERATIONAL
        send_cmd_pl(CMD_SET_STATE);
        get_response();
        soltar();
        if (st !== ST_OK) begin
            $display("[tb_zeroize] FAIL: SET_STATE -> 0x%02h", st);
            errors = errors + 1;
        end
        confere_estado(8'd2);

        // ---- 2. ZEROIZE sem botoes tem de ser recusado -----------------
        //
        // E a recusa NAO pode gastar o rearme: se gastasse, um host hostil
        // impediria a zeroizacao chamando o comando em laco -- transformando
        // o dual control numa forma de PROTEGER a chave de quem tem direito
        // de apaga-la.
        soltar();
        req_plen = 0;
        send_cmd_pl(CMD_ZEROIZE);
        get_response();
        if (st !== ST_NOT_AUTH) begin
            $display("[tb_zeroize] FAIL: ZEROIZE sem botoes -> 0x%02h, esperado 0x21", st);
            errors = errors + 1;
        end else begin
            $display("[tb_zeroize] ZEROIZE sem botoes -> NOT_AUTHORIZED");
        end

        // ---- 3. ZEROIZE com botoes -------------------------------------
        //
        // Sem soltar de novo: os botoes ja estao soltos desde a recusa, e
        // e justamente isso que se quer provar -- a recusa acima deixou o
        // rearme intacto.
        apertar();
        req_plen = 0;
        send_cmd_pl(CMD_ZEROIZE);
        get_response();
        soltar();

        if (st !== ST_OK || resp_len !== 2) begin
            $display("[tb_zeroize] FAIL: ZEROIZE -> status 0x%02h len=%0d", st, resp_len);
            errors = errors + 1;
        end else if (resp[1] !== 8'd0) begin
            $display("[tb_zeroize] FAIL: apos ZEROIZE estado=%0d, esperado 0", resp[1]);
            errors = errors + 1;
        end else begin
            $display("[tb_zeroize] ZEROIZE -> OK, e a recusa anterior nao gastou o rearme");
        end

        erros_antes = errors;
        confere_estado(8'd0);
        confere_lmk(0, 1'b0, 1'b0);
        if (errors == erros_antes)
            $display("[tb_zeroize] LMK zerada: 0 de 3, KCV em zeros");

        // ---- 4. A PROVA ------------------------------------------------
        //
        // Mesma cerimonia, mesmos componentes. Se a zeroizacao tivesse
        // deixado um unico bit em `g_lmk`, o XOR acumularia sobre ele e o
        // KCV nao seria 46F2FB -- seria outra coisa qualquer, porque o KCV
        // e AES da chave inteira.
        //
        // Criptografia provando memoria: nao ha como o firmware "passar"
        // aqui sem que a regiao estivesse realmente zerada.
        erros_antes = errors;
        cerimonia();
        confere_lmk(3, 1'b1, 1'b1);
        if (errors == erros_antes) begin
            $display("[tb_zeroize] PROVA: recarregada, KCV 46F2FB de novo --");
            $display("[tb_zeroize]   nenhum bit da LMK anterior sobreviveu ao ZEROIZE");
        end else begin
            // Anunciar sucesso ao lado de um FAIL e como um teste engana
            // quem le o log em diagonal. Descoberto por sabotagem em
            // 2026-08-29: o KCV vinha dc95c0 e a linha seguinte dizia que
            // nada sobrevivera.
            $display("[tb_zeroize]   ^ e A PROVA: sobrou material da LMK anterior");
        end

        // ---- 5. o autoteste sob demanda e DESTRUTIVO -------------------
        //
        // Nao e efeito colateral escondido: o teste de funcao critica do
        // key store instala e apaga chaves de verdade, e termina com o
        // store vazio. O que este teste prende e que o ESTADO acompanha.
        // Ate 2026-08-29 o dispositivo continuava dizendo AUTHORIZED com o
        // key store vazio, e estado que mente sobre a realidade e a pior
        // coisa que uma maquina de estados pode fazer.
        confere_estado(8'd1);                 // AUTHORIZED apos a cerimonia
        req_plen = 0;
        send_cmd_pl(CMD_SELFTEST);
        get_response();
        if (st !== ST_OK) begin
            $display("[tb_zeroize] FAIL: SELFTEST -> 0x%02h", st);
            errors = errors + 1;
        end else if (resp[1] !== 8'h00) begin
            $display("[tb_zeroize] FAIL: mascara do POST = 0x%02h", resp[1]);
            errors = errors + 1;
        end

        erros_antes = errors;
        confere_estado(8'd0);
        confere_lmk(0, 1'b0, 1'b0);
        if (errors == erros_antes)
            $display("[tb_zeroize] SELFTEST apagou a LMK -- e o estado voltou a UNINITIALIZED");

        // ---- 6. ZEROIZE em TAMPERED ------------------------------------
        //
        // O unico comando permitido em todo estado. Em TAMPERED e onde ele
        // MAIS precisa existir: e exatamente quando se quer apagar.
        //
        // Injecao pelo veredito do RCT, como em tb_post_tamper -- o xsim
        // nao suporta `force` sobre a amostra bruta atravessando a
        // fronteira VHDL/Verilog. O elo "fonte travada -> RCT reprovado"
        // e provado por tb_trng_health, na amostra exata.
        erros_antes = errors;
        cerimonia();
        confere_lmk(3, 1'b1, 1'b1);
        if (errors != erros_antes)
            $display("[tb_zeroize]   (cerimonia antes do TAMPERED ja falhou)");

        force `RCT_FAIL = 1'b1;
        req_plen = 0;
        send_cmd_pl(CMD_SELFTEST);
        get_response();
        if (st !== ST_SELFTEST_FAIL) begin
            $display("[tb_zeroize] FAIL: SELFTEST com RCT reprovado -> 0x%02h", st);
            errors = errors + 1;
        end else if (resp[1] !== 8'h10) begin
            $display("[tb_zeroize] FAIL: mascara = 0x%02h, esperado 0x10 (TRNG)", resp[1]);
            errors = errors + 1;
        end

        // Em TAMPERED nao se pergunta o estado pelo GET_VERSION: ele NAO
        // responde ali, e essa e a resposta certa -- a mascara dele e
        // ST_NORMAL, e um dispositivo comprometido responde o minimo
        // possivel. A recusa vale mais como assercao do que o byte de
        // estado valeria: prova que a maquina de estados esta em TAMPERED
        // *e* que a tabela de comandos age sobre isso.
        req_plen = 0;
        send_cmd_pl(CMD_GET_VERSION);
        get_response();
        if (st !== 8'h20) begin
            $display("[tb_zeroize] FAIL: GET_VERSION em TAMPERED -> 0x%02h, esperado 0x20", st);
            errors = errors + 1;
        end else begin
            $display("[tb_zeroize] dispositivo em TAMPERED (GET_VERSION recusado com WRONG_STATE)");
        end

        aperto_novo();
        req_plen = 0;
        send_cmd_pl(CMD_ZEROIZE);
        get_response();
        soltar();

        if (st !== ST_OK || resp_len !== 2) begin
            $display("[tb_zeroize] FAIL: ZEROIZE em TAMPERED -> 0x%02h len=%0d", st, resp_len);
            errors = errors + 1;
        end else if (resp[1] !== 8'd3) begin
            $display("[tb_zeroize] FAIL: apos ZEROIZE em TAMPERED, estado=%0d -- de TAMPERED NAO se sai",
                     resp[1]);
            errors = errors + 1;
        end else begin
            $display("[tb_zeroize] ZEROIZE em TAMPERED: apagou, e continua TAMPERED");
        end

        release `RCT_FAIL;

        if (errors == 0)
            $display("[tb_zeroize] PASS");
        else
            $display("[tb_zeroize] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
