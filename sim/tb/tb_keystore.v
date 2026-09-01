`timescale 1ns/1ps
//
// tb_keystore -- os quatro comandos de chave, ponta a ponta
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// ---------------------------------------------------------------------
// O QUE ESTE TESTE PROVA
//
// O criterio de aceitacao da fase que mais importa depois da fronteira:
// **gerar chave -> exportar -> reimportar -> a mesma chave de volta**,
// com o dispositivo real, pela UART, sem nunca ver material em claro.
//
// A igualdade e conferida pelo KCV, e vale dizer por que isso basta: o
// KCV e AES da chave inteira sobre um bloco de zeros. Duas chaves
// diferentes com o mesmo KCV exigem uma colisao em 2^24 -- e aqui nao ha
// adversario escolhendo as chaves, elas vem do CTR_DRBG do dispositivo.
// Um erro de importacao (um byte trocado, um deslocamento, um
// comprimento errado) muda o KCV inteiro.
//
// E prova as duas propriedades que fazem a fase 3 valer alguma coisa:
//
//   `exportabilidade='N'` recusa sair, e recusa pelo UNICO caminho que
//   existe -- nao ha segunda porta para os bytes.
//
//   um bit trocado no key block invalida a importacao, porque o
//   cabecalho X9.143 esta DENTRO do MAC. Sem isso, promover uma chave de
//   'N' para 'E' seria edicao de texto.
//
// ---------------------------------------------------------------------
// O QUE ELE NAO PROVA, E QUEM PROVA
//
// O acordo entre o firmware C e o parser Python sobre blocos de verdade.
// Isso e do `hsmtool keycycle`, que precisa da LMK no host -- coisa que
// um testbench nao tem como fazer melhor. Aqui as duas pontas do
// ida-e-volta sao o mesmo firmware, e isso esta dito em vez de
// subentendido: um teste que se descrevesse como "duas implementacoes
// concordam" rodando so uma mentiria sobre a propria cobertura.
//
module tb_keystore;

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

    reg [7:0] resp [0:255];
    integer   resp_len;
    reg [7:0] st;

    // 256, e nao 64: o maior pedido desta suite NAO e o componente de LMK
    // (33 bytes) -- e o key block do IMPORT_KEY, 144 caracteres. Um buffer
    // curto nao estoura com barulho: o frame sai com CRC errado e o
    // dispositivo responde BAD_CRC, que parece defeito do firmware.
    reg [7:0] req_pl [0:255];
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
                $display("[tb_keystore] FAIL: CRC da resposta invalido");
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
                    $display("[tb_keystore] FAIL: componente %0d -> status 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar();
        end
    endtask

    // Confere um campo de resposta e conta o erro.
    task espera_status;
        input [8*12-1:0] nome;
        input [7:0]      esperado;
        begin
            if (st !== esperado) begin
                $display("[tb_keystore] FAIL: %0s -> status 0x%02h, esperado 0x%02h",
                         nome, st, esperado);
                errors = errors + 1;
            end
        end
    endtask

    // GEN_KEY: uso(2) || algoritmo(1) || modo(1) || exportabilidade(1)
    task gera_chave;
        input [7:0] modo;
        input [7:0] exp;
        begin
            req_pl[0] = "D"; req_pl[1] = "0";
            req_pl[2] = "A";
            req_pl[3] = modo;
            req_pl[4] = exp;
            req_plen  = 5;
            send_cmd_pl(8'h22);
            get_response();
        end
    endtask

    reg [7:0] bloco  [0:255];
    reg [7:0] bloco2 [0:255];
    integer   bloco_n, bloco2_n;
    reg [7:0] kcv_e [0:2];
    reg [7:0] h_nao, h_sim, h_imp, h_cifra;
    reg [7:0] ct_a [0:15];
    reg [7:0] ct_b [0:15];
    integer   k, difs;

    // ⚠ Este e o testbench mais LENTO da suite, e a razao e aritmetica: ele
    // manda e recebe varios key blocks de 144 caracteres a 115200 baud, e
    // cada frame desses custa ~13 ms de tempo simulado. Sao ~140 ms no
    // total, contra ~40 ms do tb_zeroize.
    //
    // Nao da para acelerar encolhendo o clock nominal como se faz com o
    // debounce: o baud rate do NEORV32 sai da frequencia real do dominio,
    // nao do generic. Entao o custo e do protocolo, e nao ha o que apertar
    // sem trocar o que esta sendo testado.
    initial begin
        #300000000;                     // 300 ms
        $display("[tb_keystore] FAIL: timeout");
        $display("[tb_keystore] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_keystore] inicio");

        // Chave alvo da cerimonia = ECBKeySbox256 do CAVP.
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
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));
        #1000;
        if (led[4] === 1'b0) begin
            $display("[tb_keystore] FAIL: o POST reprovou no boot");
            $display("[tb_keystore] FAIL");
            $finish;
        end

        // ---- 1. antes de OPERATIONAL, nenhum deles responde -----------
        //
        // Nao ha linha de codigo recusando: e a mascara da tabela. Sem
        // LMK nao ha como embrulhar chave, entao gerar uma seria produzir
        // material que morre no desligamento sem ter servido.
        gera_chave("B", "E");
        espera_status("GEN_KEY cedo", 8'h20);        // WRONG_STATE

        req_pl[0] = 8'd1; req_plen = 1;
        send_cmd_pl(8'h23);
        get_response();
        espera_status("EXPORT cedo", 8'h20);

        // ---- 2. cerimonia e ativacao ----------------------------------
        cerimonia();
        aperto_novo();
        req_pl[0] = 8'd2; req_plen = 1;
        send_cmd_pl(8'h26);
        get_response();
        soltar();
        espera_status("SET_STATE", 8'h00);
        $display("[tb_keystore] dispositivo em OPERATIONAL");

        // ---- 3. chave NAO exportavel ----------------------------------
        gera_chave("B", "N");
        espera_status("GEN_KEY N", 8'h00);
        h_nao = resp[1];

        req_pl[0] = h_nao; req_plen = 1;
        send_cmd_pl(8'h23);
        get_response();
        if (st !== 8'h22) begin
            $display("[tb_keystore] FAIL: slot 'N' exportou (status 0x%02h) -- a chave saiu", st);
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] exportabilidade 'N': recusado com NOT_EXPORTABLE");
        end

        // ---- 4. chave exportavel, e o ida-e-volta ---------------------
        gera_chave("B", "E");
        espera_status("GEN_KEY E", 8'h00);
        h_sim    = resp[1];
        kcv_e[0] = resp[2]; kcv_e[1] = resp[3]; kcv_e[2] = resp[4];
        $display("[tb_keystore] chave gerada no dispositivo: handle %0d, KCV %02h%02h%02h",
                 h_sim, kcv_e[0], kcv_e[1], kcv_e[2]);

        req_pl[0] = h_sim; req_plen = 1;
        send_cmd_pl(8'h23);
        get_response();
        espera_status("EXPORT_KEY", 8'h00);

        bloco_n = resp_len - 1;
        for (k = 0; k < bloco_n; k = k + 1) bloco[k] = resp[1 + k];

        // O cabecalho e ASCII legivel, e conferi-lo byte a byte pega
        // erro de serializacao que o MAC nao pegaria -- o MAC so diz que
        // o que esta la esta integro, nao que e o que devia estar.
        if (bloco_n !== 144) begin
            $display("[tb_keystore] FAIL: key block com %0d caracteres, esperado 144", bloco_n);
            errors = errors + 1;
        end else if (bloco[0] !== "D" || bloco[1] !== "0" || bloco[2] !== "1" ||
                     bloco[3] !== "4" || bloco[4] !== "4" ||
                     bloco[5] !== "D" || bloco[6] !== "0" || bloco[7] !== "A" ||
                     bloco[8] !== "B" || bloco[11] !== "E") begin
            $display("[tb_keystore] FAIL: cabecalho = %0s%0s%0s%0s%0s%0s%0s%0s%0s...",
                     bloco[0], bloco[1], bloco[2], bloco[3], bloco[4],
                     bloco[5], bloco[6], bloco[7], bloco[8]);
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] key block D0144D0AB00E0000... (144 caracteres)");
        end

        // ---- 5. reimportar tem de devolver A MESMA chave --------------
        for (k = 0; k < bloco_n; k = k + 1) req_pl[k] = bloco[k];
        req_plen = bloco_n;
        send_cmd_pl(8'h24);
        get_response();
        espera_status("IMPORT_KEY", 8'h00);
        h_imp = resp[1];

        if (resp[2] !== kcv_e[0] || resp[3] !== kcv_e[1] || resp[4] !== kcv_e[2]) begin
            $display("[tb_keystore] FAIL: reimportada com KCV %02h%02h%02h, esperado %02h%02h%02h",
                     resp[2], resp[3], resp[4], kcv_e[0], kcv_e[1], kcv_e[2]);
            errors = errors + 1;
        end else if (h_imp === h_sim) begin
            $display("[tb_keystore] FAIL: importou por cima do slot de origem");
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] IDA E VOLTA: handle %0d tem o mesmo KCV do %0d --",
                     h_imp, h_sim);
            $display("[tb_keystore]   gerar -> exportar -> reimportar devolveu a MESMA chave");
        end

        // ---- 5b. O CRITERIO DE ACEITACAO DA FASE ---------------------
        //
        // "gerar -> exportar -> reimportar -> USAR EM AES: resultado
        // identico". Ate os comandos por handle existirem, o ida-e-volta
        // era provado so pelo KCV -- que e forte (AES da chave inteira
        // sobre um bloco de zeros) mas nao e USAR.
        //
        // Aqui as duas chaves cifram o MESMO bloco com o MESMO IV. Se os
        // criptogramas baterem, a chave que voltou e a mesma bit a bit --
        // e nao apenas "tem o mesmo KCV", que seria 24 bits de evidencia.
        req_pl[0] = h_sim;
        for (k = 0; k < 16; k = k + 1) req_pl[1 + k]      = 8'hA5 ^ k[7:0];
        for (k = 0; k < 16; k = k + 1) req_pl[1 + 16 + k] = 8'h5A ^ k[7:0];
        req_plen = 33;
        send_cmd_pl(8'h27);
        get_response();
        espera_status("ENCRYPT origem", 8'h00);
        for (k = 0; k < 16; k = k + 1) ct_a[k] = resp[1 + k];

        req_pl[0] = h_imp;
        req_plen = 33;
        send_cmd_pl(8'h27);
        get_response();
        espera_status("ENCRYPT reimportada", 8'h00);
        for (k = 0; k < 16; k = k + 1) ct_b[k] = resp[1 + k];

        difs = 0;
        for (k = 0; k < 16; k = k + 1)
            if (ct_a[k] !== ct_b[k]) difs = difs + 1;

        if (difs != 0) begin
            $display("[tb_keystore] FAIL: os dois handles cifraram DIFERENTE em %0d bytes",
                     difs);
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] CRITERIO: gerar -> exportar -> reimportar -> USAR");
            $display("[tb_keystore]   os dois handles cifram identico -- e a mesma chave");
        end

        // Decifrar tem de devolver o texto claro. Fecha o outro sentido.
        req_pl[0] = h_imp;
        for (k = 0; k < 16; k = k + 1) req_pl[1 + k]      = 8'hA5 ^ k[7:0];
        for (k = 0; k < 16; k = k + 1) req_pl[1 + 16 + k] = ct_a[k];
        req_plen = 33;
        send_cmd_pl(8'h28);
        get_response();
        espera_status("DECRYPT", 8'h00);

        difs = 0;
        for (k = 0; k < 16; k = k + 1)
            if (resp[1 + k] !== (8'h5A ^ k[7:0])) difs = difs + 1;
        if (difs != 0) begin
            $display("[tb_keystore] FAIL: decifrar nao devolveu o texto claro (%0d bytes)",
                     difs);
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] decifrar devolve o texto claro");
        end

        // ---- 5c. separacao de uso: 'E' recusa decifrar ----------------
        //
        // Confusao de tipo de chave e a origem de uma familia inteira de
        // ataques de API (manual, secao 15). A checagem vive DENTRO do
        // keystore, num lugar so -- nao no handler.
        gera_chave("E", "E");            // modo 'E' = so cifrar
        espera_status("GEN_KEY modo E", 8'h00);
        h_cifra = resp[1];

        req_pl[0] = h_cifra;
        for (k = 0; k < 32; k = k + 1) req_pl[1 + k] = 8'h00;
        req_plen = 33;
        send_cmd_pl(8'h27);
        get_response();
        espera_status("ENCRYPT com modo E", 8'h00);

        req_pl[0] = h_cifra;
        req_plen = 33;
        send_cmd_pl(8'h28);
        get_response();
        if (st !== 8'h24) begin
            $display("[tb_keystore] FAIL: chave so-de-cifrar DECIFROU (status 0x%02h)", st);
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] chave marcada 'E' recusa decifrar: BAD_KEY_USE");
        end

        // ---- 6. um bit trocado invalida ------------------------------
        //
        // Na posicao 11, a EXPORTABILIDADE -- o campo que um atacante
        // mais quer editar, e o que o MAC existe para proteger.
        for (k = 0; k < bloco_n; k = k + 1) req_pl[k] = bloco[k];
        req_pl[11] = (bloco[11] === "E") ? "N" : "E";
        req_plen = bloco_n;
        send_cmd_pl(8'h24);
        get_response();
        if (st === 8'h00) begin
            $display("[tb_keystore] FAIL: ACEITOU bloco com a exportabilidade reescrita");
            errors = errors + 1;
        end else if (st !== 8'h11) begin
            // Recusou, mas pelo motivo errado. Chamar isso de "aceitou"
            // manda procurar o bug no lugar errado -- foi o que aconteceu
            // aqui, com um BAD_CRC de buffer curto do proprio testbench.
            $display("[tb_keystore] FAIL: recusou com 0x%02h, esperado 0x11 (BAD_PARAM)", st);
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] exportabilidade reescrita a mao: recusado");
        end

        // Um bit no CORPO, para nao provar so o cabecalho.
        for (k = 0; k < bloco_n; k = k + 1) req_pl[k] = bloco[k];
        req_pl[40] = bloco[40] ^ 8'h01;
        req_plen = bloco_n;
        send_cmd_pl(8'h24);
        get_response();
        if (st === 8'h00) begin
            $display("[tb_keystore] FAIL: ACEITOU bloco com 1 bit trocado no corpo");
            errors = errors + 1;
        end else if (st !== 8'h11) begin
            $display("[tb_keystore] FAIL: recusou com 0x%02h, esperado 0x11 (BAD_PARAM)", st);
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] 1 bit trocado no corpo: recusado");
        end

        // ---- 7. exportar duas vezes da blocos DIFERENTES --------------
        //
        // Nao e capricho: dois blocos identicos denunciariam que a mesma
        // chave foi exportada duas vezes. O enchimento aleatorio existe
        // para isso.
        req_pl[0] = h_sim; req_plen = 1;
        send_cmd_pl(8'h23);
        get_response();
        bloco2_n = resp_len - 1;
        for (k = 0; k < bloco2_n; k = k + 1) bloco2[k] = resp[1 + k];

        difs = 0;
        for (k = 0; k < bloco_n; k = k + 1)
            if (bloco[k] !== bloco2[k]) difs = difs + 1;

        if (difs == 0) begin
            $display("[tb_keystore] FAIL: duas exportacoes deram o MESMO bloco");
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] duas exportacoes da mesma chave diferem em %0d caracteres",
                     difs);
        end

        // ---- 8. KEY_INFO ---------------------------------------------
        req_pl[0] = h_sim; req_plen = 1;
        send_cmd_pl(8'h25);
        get_response();
        espera_status("KEY_INFO", 8'h00);

        if (resp_len !== 14) begin
            $display("[tb_keystore] FAIL: KEY_INFO com %0d bytes, esperado 14", resp_len);
            errors = errors + 1;
        end else if (resp[1] !== "D" || resp[2] !== "0" || resp[3] !== "A" ||
                     resp[4] !== "B" || resp[5] !== "E" || resp[6] !== 8'd32) begin
            $display("[tb_keystore] FAIL: KEY_INFO = %0s%0s alg=%0s modo=%0s exp=%0s len=%0d",
                     resp[1], resp[2], resp[3], resp[4], resp[5], resp[6]);
            errors = errors + 1;
        end else if (resp[7] !== kcv_e[0] || resp[8] !== kcv_e[1] || resp[9] !== kcv_e[2]) begin
            $display("[tb_keystore] FAIL: KCV do KEY_INFO diverge do que o GEN_KEY devolveu");
            errors = errors + 1;
        end else begin
            $display("[tb_keystore] KEY_INFO: D0 A B E, 32 bytes, KCV confere");
        end

        // Handle 0 e slot vazio: MESMO codigo. Separar permitiria mapear
        // o key store sem instalar nada.
        req_pl[0] = 8'd0; req_plen = 1;
        send_cmd_pl(8'h25);
        get_response();
        espera_status("KEY_INFO(0)", 8'h11);

        req_pl[0] = 8'd16; req_plen = 1;
        send_cmd_pl(8'h25);
        get_response();
        espera_status("KEY_INFO vazio", 8'h11);
        $display("[tb_keystore] handle invalido e slot vazio: mesmo codigo");

        if (errors == 0)
            $display("[tb_keystore] PASS");
        else
            $display("[tb_keystore] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
