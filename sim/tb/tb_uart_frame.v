`timescale 1ns/1ps
//
// tb_uart_frame -- protocolo de comandos, ponta a ponta
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// Roda o firmware de verdade (fw/, embutido na IMEM) no SoC de verdade, e
// conversa com ele pela UART a 115200 baud, byte a byte, como o host fara.
//
//   pedido    LEN(2) | CMD(1)    | PAYLOAD | CRC32(4)
//   resposta  LEN(2) | STATUS(1) | PAYLOAD | CRC32(4)
//
// big-endian; LEN cobre CMD/STATUS + PAYLOAD; CRC32 (IEEE 802.3 refletido,
// igual ao zlib.crc32) cobre tudo menos os proprios 4 bytes de CRC.
//
// O CRC e calculado AQUI de forma independente do firmware. Se as duas
// implementacoes divergirem, o teste falha -- que e o ponto.
//
// A segunda metade e a CERIMONIA DE LMK da fase 3, com os dois botoes de
// dual control acionados pelos pinos do toplevel. E o unico teste do
// projeto em que a autorizacao vem de fora do link do host -- e por isso o
// unico capaz de reprovar um dual control que so finge existir.
//
module tb_uart_frame;

    localparam real BIT_NS = 1000000000.0 / 115200.0;   // 8680.6 ns

    // Clock nominal do SoC reduzido SO para o divisor do debounce.
    //
    // hsm_top escala DEBOUNCE_CYCLES = CLK_HZ/100; com os 100 MHz reais
    // isso da 10 ms por transicao de botao, e a cerimonia sozinha custaria
    // quase 100 ms de simulacao. Com 100 kHz nominais o debounce cai para
    // 1000 ciclos (10 us de tempo simulado, ja que o clock continua sendo
    // o de verdade).
    //
    // O que isto NAO faz: encolher o debounce nao enfraquece nada aqui,
    // porque quem verifica o filtro de ressalto e tb_debounce, com o
    // parametro no valor de producao. Este testbench verifica o que vem
    // DEPOIS do filtro -- a politica de autorizacao no firmware.
    //
    // O que muda tambem: o divisor do heartbeat. led[0] nao e usado aqui.
    localparam integer TB_CLK_HZ = 100_000;

    // Tempo para o debounce assentar e o laco principal enxergar o novo
    // nivel. 1000 ciclos de 10 ns = 10 us; 100 us da uma ordem de grandeza
    // de folga sem custar simulacao perceptivel.
    localparam real BTN_SETTLE_NS = 100000.0;

    // Boot do firmware ate estar pronto para receber. Medido com folga:
    // o banner do bootloader comecava em ~690 us, e este firmware faz bem
    // menos que aquele.
    localparam real BOOT_WAIT_NS = 1500000.0;           // 1,5 ms

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;      // linha do host -> HSM (idle alto)
    reg  btn_a   = 1'b1;
    reg  btn_b   = 1'b1;

    wire       uart_tx;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;

    integer errors = 0;
    integer i;

    reg [7:0] resp [0:31];
    integer   resp_len;
    reg [7:0] st;

    // Payload do pedido. 33 bytes e o maior desta suite (LMK_LOAD_COMPONENT:
    // indice + componente de 32).
    reg [7:0] req_pl [0:63];
    integer   req_plen;

    // Componentes da cerimonia e o KCV esperado -- montados em `initial`
    // mais abaixo, onde da para explicar de onde o valor esperado vem.
    reg [7:0] comp0 [0:31];
    reg [7:0] comp1 [0:31];
    reg [7:0] comp2 [0:31];
    reg [7:0] lmk   [0:31];
    reg [7:0] kcv_c0 [0:2];
    reg [7:0] kcv_c1 [0:2];
    reg [7:0] kcv_c2 [0:2];

    always #10 sys_clk = ~sys_clk;   // 50 MHz

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
                if (c[0])
                    c = (c >> 1) ^ 32'hEDB88320;
                else
                    c = c >> 1;
            end
            crc32_update = c;
        end
    endfunction

    // ------------------------------------------------------------------
    // UART
    // ------------------------------------------------------------------
    task uart_put(input [7:0] b);
        integer k;
        begin
            uart_rx = 1'b0;              // start
            #(BIT_NS);
            for (k = 0; k < 8; k = k + 1) begin
                uart_rx = b[k];          // LSB primeiro
                #(BIT_NS);
            end
            uart_rx = 1'b1;              // stop
            #(BIT_NS);
        end
    endtask

    // Com validacao de start bit no meio do periodo -- ver tb_soc_boot.
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

    // ------------------------------------------------------------------
    // Envia um frame de comando completo, com CRC correto ou corrompido
    // ------------------------------------------------------------------
    task send_cmd;
        input [7:0]  opcode;
        input        corrupt_crc;
        reg   [31:0] crc;
        reg   [15:0] len;
        begin
            len = 16'd1;                 // so o opcode, sem payload
            crc = 32'hFFFFFFFF;
            crc = crc32_update(crc, len[15:8]);
            crc = crc32_update(crc, len[7:0]);
            crc = crc32_update(crc, opcode);
            crc = ~crc;

            if (corrupt_crc) crc = crc ^ 32'h00000001;

            uart_put(len[15:8]);
            uart_put(len[7:0]);
            uart_put(opcode);
            uart_put(crc[31:24]);
            uart_put(crc[23:16]);
            uart_put(crc[15:8]);
            uart_put(crc[7:0]);
        end
    endtask

    // Mesma coisa, com payload -- o pedido sai de req_pl[0..req_plen-1].
    //
    // Verilog-2001 nao passa array por argumento de task, entao o payload
    // vive num buffer de modulo. Nao e elegancia; e a linguagem.
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
            uart_put(crc[31:24]);
            uart_put(crc[23:16]);
            uart_put(crc[15:8]);
            uart_put(crc[7:0]);
        end
    endtask

    // ------------------------------------------------------------------
    // Botoes de dual control
    //
    // ATIVOS BAIXOS no pino: 0 = pressionado. O toplevel inverte, e o
    // firmware ve 1 = pressionado. Errar essa dupla inversao inverteria o
    // dual control em silencio -- o comando passaria com os botoes soltos.
    // ------------------------------------------------------------------
    task apertar;
        begin
            btn_a = 1'b0;
            btn_b = 1'b0;
            #(BTN_SETTLE_NS);
        end
    endtask

    task soltar;
        begin
            btn_a = 1'b1;
            btn_b = 1'b1;
            #(BTN_SETTLE_NS);
        end
    endtask

    // Um aperto NOVO: solta, espera o rearme, aperta de novo. E o gesto que
    // o firmware exige entre duas autorizacoes (fw/include/dualctl.h).
    task aperto_novo;
        begin
            soltar();
            apertar();
        end
    endtask

    // Recebe um frame de resposta e confere o CRC de forma independente
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
                $display("[tb_uart_frame] FAIL: CRC da resposta invalido (calc=%08h rx=%08h)",
                         crc, crc_rx);
                errors = errors + 1;
            end

            st = resp[0];
        end
    endtask

    // Monta o payload de LMK_LOAD_COMPONENT para o componente `n`.
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

    initial begin
        #150000000;                      // 150 ms
        $display("[tb_uart_frame] FAIL: timeout");
        $display("[tb_uart_frame] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_uart_frame] inicio -- 115200 baud");

        #200;
        rst_n = 1'b1;

        // Espera o POST terminar antes de falar com o dispositivo.
        //
        // Nao e cortesia: antes do POST passar o firmware nao esta no laco
        // de comandos, e um PING nesse instante nao seria respondido. O
        // sinal de pronto e o LED de atividade (led[1], ativo baixo), que
        // main() acende exatamente ao sair do POST -- o mesmo indicador que
        // tb_soc_silent usa.
        //
        // Esperar por um TEMPO FIXO seria pior: o custo do POST muda quando
        // se acrescenta um vetor, e o teste passaria a reprovar por atraso
        // em vez de por defeito.
        // Espera QUALQUER um dos dois desfechos, nao so o bom: se o POST
        // reprovar, led[1] nunca desce e esperar so por ele trava aqui para
        // sempre. Um teste que trava nao reprova -- ele deixa de existir.
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));

        if (led[4] === 1'b0) begin
            $display("[tb_uart_frame] FAIL: POST reprovou -- LED de tamper aceso em %.2f ms",
                     $realtime / 1000000.0);
            $display("[tb_uart_frame] FAIL");
            $finish;
        end
        $display("[tb_uart_frame] POST concluido em %.2f ms", $realtime / 1000000.0);
        #(BOOT_WAIT_NS);

        // ---- 1. PING -> PONG ------------------------------------------
        send_cmd(8'h01, 1'b0);
        get_response();

        if (st !== 8'h00) begin
            $display("[tb_uart_frame] FAIL: PING status=0x%02h, esperado 0x00", st);
            errors = errors + 1;
        end else if (resp_len !== 5) begin
            $display("[tb_uart_frame] FAIL: PING len=%0d, esperado 5", resp_len);
            errors = errors + 1;
        end else if (resp[1] !== "P" || resp[2] !== "O" ||
                     resp[3] !== "N" || resp[4] !== "G") begin
            $display("[tb_uart_frame] FAIL: PING payload = %c%c%c%c, esperado PONG",
                     resp[1], resp[2], resp[3], resp[4]);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] PING -> PONG");
        end

        // ---- 2. GET_VERSION -------------------------------------------
        send_cmd(8'h02, 1'b0);
        get_response();

        if (st !== 8'h00 || resp_len !== 5) begin
            $display("[tb_uart_frame] FAIL: GET_VERSION status=0x%02h len=%0d",
                     st, resp_len);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] GET_VERSION -> v%0d.%0d.%0d estado=%0d",
                     resp[1], resp[2], resp[3], resp[4]);
            // Fase 1: o dispositivo nasce e fica em UNINITIALIZED (0)
            if (resp[4] !== 8'd0) begin
                $display("[tb_uart_frame] FAIL: estado=%0d, esperado 0 (UNINITIALIZED)",
                         resp[4]);
                errors = errors + 1;
            end
        end

        // ---- 2b. GET_DNA ----------------------------------------------
        //
        // O caminho inteiro numa tacada: host -> UART -> parser -> tabela
        // de comandos -> driver do CFS -> registrador -> DNA_PORT. Nenhum
        // outro testbench cobre essa cadeia toda.
        //
        // O valor esperado e o SIM_DNA_VALUE de rtl/crypto/hsm_cfs.v. Sao
        // 57 bits em 8 bytes big-endian, entao os 7 bits mais altos do
        // primeiro byte tem de vir zerados -- e e justamente ali que um
        // erro de deslocamento apareceria.
        send_cmd(8'h03, 1'b0);
        get_response();

        if (st !== 8'h00 || resp_len !== 9) begin
            $display("[tb_uart_frame] FAIL: GET_DNA status=0x%02h len=%0d (esperado 0x00, 9)",
                     st, resp_len);
            errors = errors + 1;
        end else if ({resp[1], resp[2], resp[3], resp[4],
                      resp[5], resp[6], resp[7], resp[8]} !== 64'h00123456789ABCDE) begin
            $display("[tb_uart_frame] FAIL: GET_DNA = %02h%02h%02h%02h%02h%02h%02h%02h",
                     resp[1], resp[2], resp[3], resp[4],
                     resp[5], resp[6], resp[7], resp[8]);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] GET_DNA -> %02h%02h%02h%02h%02h%02h%02h%02h",
                     resp[1], resp[2], resp[3], resp[4],
                     resp[5], resp[6], resp[7], resp[8]);
        end

        // ---- 3. CRC corrompido -> STATUS_BAD_CRC ----------------------
        send_cmd(8'h01, 1'b1);
        get_response();

        if (st !== 8'h01) begin
            $display("[tb_uart_frame] FAIL: CRC ruim -> status=0x%02h, esperado 0x01", st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] CRC corrompido -> STATUS_BAD_CRC");
        end

        // ---- 4. opcode desconhecido -> STATUS_UNKNOWN_CMD -------------
        send_cmd(8'hAA, 1'b0);
        get_response();

        if (st !== 8'h10) begin
            $display("[tb_uart_frame] FAIL: opcode 0xAA -> status=0x%02h, esperado 0x10", st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] opcode desconhecido -> STATUS_UNKNOWN_CMD");
        end

        // ---- 4b. AES com chave no payload nao existe mais ------------
        //
        // 0x10 AES_ENC e 0x11 AES_DEC recebiam a chave no pedido. Foram
        // REMOVIDOS, e nao apenas restringidos por mascara: material de
        // chave atravessando a fronteira e errado em TODO estado, entao
        // mascara nenhuma conserta.
        //
        // Este teste roda em UNINITIALIZED, que era justamente o unico
        // estado em que eles respondiam. Se alguem os trouxer de volta
        // "so para bring-up", reprova aqui.
        for (i = 0; i < 2; i = i + 1) begin
            if (i == 0) send_cmd(8'h10, 1'b0);
            else        send_cmd(8'h11, 1'b0);
            get_response();
            if (st !== 8'h10) begin
                $display("[tb_uart_frame] FAIL: AES com chave no payload ainda responde (status=0x%02h)",
                         st);
                errors = errors + 1;
            end
        end
        $display("[tb_uart_frame] 0x10/0x11 (chave no payload) -> UNKNOWN_CMD");

        // ---- 4c. o HMAC AINDA existe, e isso e deliberado -------------
        //
        // Ele tem o mesmo defeito -- chave no payload -- e fica ate haver
        // um MAC por HANDLE que o substitua. Remove-lo antes deixaria o
        // dispositivo SEM SERVICO DE MAC nenhum, o que afasta do padrao
        // da categoria em vez de aproximar.
        //
        // Este teste existe para que a divida seja VISIVEL: no dia em que
        // o 0x29 MAC nascer e o 0x13 for removido, ele reprova e obriga
        // quem removeu a vir aqui apagar a divida junto.
        //
        // ⚠ Enquanto ele passar, o criterio "a captura da UART nao contem
        // nenhum byte de chave em claro" NAO pode passar.
        req_pl[0] = 8'd1;        // klen = 1
        req_pl[1] = 8'hAB;       // a chave -- em claro na linha, e o ponto
        req_pl[2] = 8'h00;       // mensagem de 1 byte
        req_plen  = 3;
        send_cmd_pl(8'h13);
        get_response();
        if (st !== 8'h00 || resp_len !== 33) begin
            $display("[tb_uart_frame] FAIL: HMAC -> status=0x%02h len=%0d, esperado 0x00/33",
                     st, resp_len);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] 0x13 HMAC ainda responde -- DIVIDA CONHECIDA,");
            $display("[tb_uart_frame]   ate existir um MAC por handle");
        end

        // ---- 5. o dispositivo continua vivo depois dos erros ----------
        // Este e o criterio que importa (PLANO.md secao 2): frame malformado
        // nunca trava a maquina de estados. Se o parser tivesse ficado preso
        // num dos casos acima, este PING nao voltaria.
        send_cmd(8'h01, 1'b0);
        get_response();

        if (st !== 8'h00 || resp[1] !== "P") begin
            $display("[tb_uart_frame] FAIL: dispositivo nao respondeu apos os erros");
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] recuperou: PING responde depois dos frames ruins");
        end

        // ================================================================
        // 6. Cerimonia de LMK -- fase 3
        //
        // Tres componentes por XOR, dual control pelos dois botoes, e a
        // escada de estados UNINITIALIZED -> AUTHORIZED -> OPERATIONAL.
        //
        // De onde vem o valor esperado do KCV, que e o que sustenta este
        // teste inteiro:
        //
        //   KCV e AES-ECB da chave sobre um bloco de ZEROS. O vetor
        //   ECBKeySbox256 do CAVP tem PLAINTEXT = 0, entao o criptograma
        //   dele E o bloco cifrado de zeros sob aquela chave, e os tres
        //   primeiros bytes sao o KCV -- 46 F2 FB.
        //
        //   Os componentes sao escolhidos para que comp0^comp1^comp2 de
        //   exatamente aquela chave. Assim o valor esperado nao e "o que o
        //   firmware devolveu da outra vez": e um vetor oficial do NIST,
        //   com procedencia em vectors/MANIFEST.txt.
        // ================================================================
        $display("[tb_uart_frame] --- cerimonia de LMK ---");

        // Chave alvo = kat_aes1_key (ECBKeySbox256, DECRYPT COUNT=0).
        lmk[ 0]=8'hC4; lmk[ 1]=8'h7B; lmk[ 2]=8'h02; lmk[ 3]=8'h94;
        lmk[ 4]=8'hDB; lmk[ 5]=8'hBB; lmk[ 6]=8'hEE; lmk[ 7]=8'h0F;
        lmk[ 8]=8'hEC; lmk[ 9]=8'h47; lmk[10]=8'h57; lmk[11]=8'hF2;
        lmk[12]=8'h2F; lmk[13]=8'hFE; lmk[14]=8'hEE; lmk[15]=8'h35;
        lmk[16]=8'h87; lmk[17]=8'hCA; lmk[18]=8'h47; lmk[19]=8'h30;
        lmk[20]=8'hC3; lmk[21]=8'hD3; lmk[22]=8'h3B; lmk[23]=8'h69;
        lmk[24]=8'h1D; lmk[25]=8'hF3; lmk[26]=8'h8B; lmk[27]=8'hAB;
        lmk[28]=8'h07; lmk[29]=8'h6B; lmk[30]=8'hC5; lmk[31]=8'h58;

        // Componentes 0 e 1 arbitrarios mas DISTINTOS entre si e da chave;
        // o 2 fecha o XOR. Nenhum dos tres pode ser zero nem igual a outro,
        // ou o teste passaria a tolerar um componente ignorado.
        for (i = 0; i < 32; i = i + 1) begin
            comp0[i] = 8'h10 + i[7:0];
            comp1[i] = 8'h5A ^ (i[7:0] * 8'h07);
            comp2[i] = lmk[i] ^ comp0[i] ^ comp1[i];
        end

        // ---- 6a. LMK_STATUS antes de tudo ------------------------------
        req_plen = 0;
        send_cmd_pl(8'h21);
        get_response();

        if (st !== 8'h00 || resp_len !== 6) begin
            $display("[tb_uart_frame] FAIL: LMK_STATUS status=0x%02h len=%0d (esperado 0x00, 6)",
                     st, resp_len);
            errors = errors + 1;
        end else if (resp[1] !== 8'd0 || resp[2] !== 8'd0) begin
            $display("[tb_uart_frame] FAIL: LMK_STATUS inicial = %0d comp, completa=%0d",
                     resp[1], resp[2]);
            errors = errors + 1;
        end else if (resp[3] !== 8'h00 || resp[4] !== 8'h00 || resp[5] !== 8'h00) begin
            // KCV zerado enquanto incompleta. Se sair diferente de zero
            // aqui, algo esta devolvendo o acumulado parcial -- que e o
            // comeco de um oraculo sobre componentes ja carregados.
            $display("[tb_uart_frame] FAIL: LMK_STATUS incompleta devolveu KCV %02h%02h%02h",
                     resp[3], resp[4], resp[5]);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] LMK_STATUS -> 0 componentes, KCV zerado");
        end

        // ---- 6b. SEM os botoes -> STATUS_NOT_AUTHORIZED ----------------
        //
        // Este e o criterio de aceitacao da fase (PLANO.md secao 4). E o
        // unico teste da suite cuja condicao de falha nao esta no link do
        // host: o frame e valido, o CRC confere, o estado permite, o
        // payload esta certo. So faltam os dedos.
        soltar();
        prepara_componente(0);
        send_cmd_pl(8'h20);
        get_response();

        if (st !== 8'h21) begin
            $display("[tb_uart_frame] FAIL: LMK_LOAD sem botoes -> status=0x%02h, esperado 0x21 (NOT_AUTHORIZED)",
                     st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] LMK_LOAD sem botoes -> STATUS_NOT_AUTHORIZED");
        end

        // Recusar nao pode ter carregado nada.
        req_plen = 0;
        send_cmd_pl(8'h21);
        get_response();
        if (resp[1] !== 8'd0) begin
            $display("[tb_uart_frame] FAIL: recusa por dual control carregou componente (%0d)",
                     resp[1]);
            errors = errors + 1;
        end

        // ---- 6c. componente 0, com os dois botoes ----------------------
        apertar();
        prepara_componente(0);
        send_cmd_pl(8'h20);
        get_response();

        if (st !== 8'h00 || resp_len !== 6) begin
            $display("[tb_uart_frame] FAIL: LMK_LOAD[0] status=0x%02h len=%0d", st, resp_len);
            errors = errors + 1;
        end else if (resp[4] !== 8'd1) begin
            $display("[tb_uart_frame] FAIL: LMK_LOAD[0] carregados=%0d, esperado 1", resp[4]);
            errors = errors + 1;
        end else if (resp[5] !== 8'd0) begin
            $display("[tb_uart_frame] FAIL: estado=%0d apos 1 componente, esperado 0", resp[5]);
            errors = errors + 1;
        end else begin
            kcv_c0[0] = resp[1]; kcv_c0[1] = resp[2]; kcv_c0[2] = resp[3];
            $display("[tb_uart_frame] LMK_LOAD[0] -> KCV %02h%02h%02h, 1 componente",
                     resp[1], resp[2], resp[3]);
        end

        // ---- 6d. SEGURANDO os botoes -> ainda recusa -------------------
        //
        // O ponto do "aperto novo" (fw/include/dualctl.h): sem ele, fita
        // adesiva sobre os dois botoes carregaria a LMK inteira sozinha.
        // Aqui os botoes continuam pressionados desde 6c, e o comando tem
        // de ser recusado assim mesmo.
        prepara_componente(1);
        send_cmd_pl(8'h20);
        get_response();

        if (st !== 8'h21) begin
            $display("[tb_uart_frame] FAIL: botao SEGURADO autorizou (status=0x%02h) -- dual control derrotado por fita adesiva",
                     st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] botao segurado -> STATUS_NOT_AUTHORIZED (exige aperto novo)");
        end

        // ---- 6e. componentes 1 e 2, cada um com aperto novo ------------
        aperto_novo();
        prepara_componente(1);
        send_cmd_pl(8'h20);
        get_response();

        if (st !== 8'h00 || resp[4] !== 8'd2) begin
            $display("[tb_uart_frame] FAIL: LMK_LOAD[1] status=0x%02h carregados=%0d",
                     st, resp[4]);
            errors = errors + 1;
        end else begin
            kcv_c1[0] = resp[1]; kcv_c1[1] = resp[2]; kcv_c1[2] = resp[3];
            $display("[tb_uart_frame] LMK_LOAD[1] -> KCV %02h%02h%02h, 2 componentes",
                     resp[1], resp[2], resp[3]);
        end

        // Fora de ordem: o componente 1 de novo, quando o firmware espera o
        // 2. Tem de ser BAD_PARAM, e -- importante -- NAO pode gastar o
        // aperto: o operador ja soltou e apertou por este componente.
        aperto_novo();
        prepara_componente(1);
        send_cmd_pl(8'h20);
        get_response();

        if (st !== 8'h11) begin
            $display("[tb_uart_frame] FAIL: componente fora de ordem -> status=0x%02h, esperado 0x11",
                     st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] componente fora de ordem -> STATUS_BAD_PARAM");
        end

        // O aperto NAO foi consumido pela recusa acima: mesmo sem soltar,
        // o componente certo passa. Se este passo falhar, um host hostil
        // consegue negar a cerimonia chamando o comando em laco.
        prepara_componente(2);
        send_cmd_pl(8'h20);
        get_response();

        if (st !== 8'h00 || resp_len !== 6) begin
            $display("[tb_uart_frame] FAIL: LMK_LOAD[2] status=0x%02h len=%0d", st, resp_len);
            errors = errors + 1;
        end else begin
            kcv_c2[0] = resp[1]; kcv_c2[1] = resp[2]; kcv_c2[2] = resp[3];
            if (resp[4] !== 8'd3) begin
                $display("[tb_uart_frame] FAIL: carregados=%0d apos o terceiro", resp[4]);
                errors = errors + 1;
            end
            // AUTHORIZED = 1. A transicao acontece no mesmo comando que
            // completa a chave, e nao num comando separado: "tenho LMK" e
            // "estou em AUTHORIZED" tem de ser a mesma afirmacao.
            if (resp[5] !== 8'd1) begin
                $display("[tb_uart_frame] FAIL: estado=%0d apos completar a LMK, esperado 1 (AUTHORIZED)",
                         resp[5]);
                errors = errors + 1;
            end
            $display("[tb_uart_frame] LMK_LOAD[2] -> KCV %02h%02h%02h, 3 componentes, estado AUTHORIZED",
                     resp[1], resp[2], resp[3]);
        end

        soltar();

        // ---- 6f. KCV da LMK contra o vetor oficial ---------------------
        req_plen = 0;
        send_cmd_pl(8'h21);
        get_response();

        if (st !== 8'h00 || resp_len !== 6) begin
            $display("[tb_uart_frame] FAIL: LMK_STATUS final status=0x%02h len=%0d", st, resp_len);
            errors = errors + 1;
        end else if (resp[1] !== 8'd3 || resp[2] !== 8'd1) begin
            $display("[tb_uart_frame] FAIL: LMK_STATUS final = %0d comp, completa=%0d",
                     resp[1], resp[2]);
            errors = errors + 1;
        end else if (resp[3] !== 8'h46 || resp[4] !== 8'hF2 || resp[5] !== 8'hFB) begin
            // Valor de vetor oficial. Se este byte nao bate, o XOR dos
            // componentes ou a ordem de bytes estao errados -- nao o vetor.
            $display("[tb_uart_frame] FAIL: KCV da LMK = %02h%02h%02h, esperado 46F2FB",
                     resp[3], resp[4], resp[5]);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] KCV da LMK = 46F2FB (ECBKeySbox256, CAVP)");
        end

        // O KCV que sai a cada componente e do COMPONENTE, nunca do
        // acumulado. Se algum deles fosse igual ao final, o comando estaria
        // vazando um oraculo sobre a chave mestra em construcao.
        if (kcv_c0[0] === 8'h46 && kcv_c0[1] === 8'hF2 && kcv_c0[2] === 8'hFB) begin
            $display("[tb_uart_frame] FAIL: KCV do componente 0 == KCV da LMK");
            errors = errors + 1;
        end
        if (kcv_c1[0] === 8'h46 && kcv_c1[1] === 8'hF2 && kcv_c1[2] === 8'hFB) begin
            $display("[tb_uart_frame] FAIL: KCV do componente 1 == KCV da LMK");
            errors = errors + 1;
        end
        if (kcv_c2[0] === 8'h46 && kcv_c2[1] === 8'hF2 && kcv_c2[2] === 8'hFB) begin
            $display("[tb_uart_frame] FAIL: KCV do componente 2 == KCV da LMK");
            errors = errors + 1;
        end
        if (kcv_c0[0] === kcv_c1[0] && kcv_c0[1] === kcv_c1[1] && kcv_c0[2] === kcv_c1[2]) begin
            $display("[tb_uart_frame] FAIL: componentes distintos com o mesmo KCV");
            errors = errors + 1;
        end

        // ---- 6g. um comando com chave em claro morre sozinho -----------
        //
        // A propriedade: um comando que recebe chave em claro tem mascara
        // ST_UNINIT, entao com LMK carregada o dispositivo saiu de
        // UNINITIALIZED e ele para de responder -- sem uma linha de codigo
        // desligando nada. O payload vai vazio de proposito: a checagem de
        // estado acontece ANTES do handler, entao nem chega a ser lido.
        //
        // ⚠ O SUJEITO DESTE TESTE MUDOU em 2026-09-01. Era o AES_ENC
        // (0x10); ele foi REMOVIDO e hoje devolve UNKNOWN_CMD em qualquer
        // estado, o que nao demonstra nada sobre mascara. Passou a ser o
        // HMAC (0x13), o unico comando com chave em claro que resta.
        //
        // ⚠ E quando o HMAC tambem for removido -- assim que existir um
        // MAC por handle -- este teste vai reprovar, e a reprovacao sera
        // CORRETA: nao havera mais nenhum comando que demonstre a
        // propriedade, porque nao havera mais nenhum comando com chave em
        // claro. Que e o objetivo. Quem chegar aqui nesse dia deve apagar
        // o teste, nao consertar a expectativa.
        req_pl[0] = 8'd1;
        req_pl[1] = 8'hAB;
        req_pl[2] = 8'h00;
        req_plen  = 3;
        send_cmd_pl(8'h13);
        get_response();

        if (st !== 8'h20) begin
            $display("[tb_uart_frame] FAIL: HMAC com LMK -> status=0x%02h, esperado 0x20 (WRONG_STATE)",
                     st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] HMAC (chave em claro) -> STATUS_WRONG_STATE");
        end

        // E o AES_ENC, que foi removido, nao responde em estado nenhum.
        send_cmd(8'h10, 1'b0);
        get_response();
        if (st !== 8'h10) begin
            $display("[tb_uart_frame] FAIL: AES_ENC removido -> status=0x%02h, esperado 0x10",
                     st);
            errors = errors + 1;
        end

        // E a propria cerimonia nao se repete: nao ha caminho para trocar a
        // chave mestra por cima da existente.
        send_cmd(8'h20, 1'b0);
        get_response();

        if (st !== 8'h20) begin
            $display("[tb_uart_frame] FAIL: LMK_LOAD apos completa -> status=0x%02h, esperado 0x20",
                     st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] LMK_LOAD apos completa -> STATUS_WRONG_STATE");
        end

        // ---- 6h. ativacao: AUTHORIZED -> OPERATIONAL -------------------
        req_pl[0] = 8'd2;                 // HSM_OPERATIONAL
        req_plen  = 1;
        send_cmd_pl(8'h26);
        get_response();

        if (st !== 8'h21) begin
            $display("[tb_uart_frame] FAIL: SET_STATE sem botoes -> status=0x%02h, esperado 0x21",
                     st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] SET_STATE sem botoes -> STATUS_NOT_AUTHORIZED");
        end

        // Alvo invalido: so OPERATIONAL e aceito. Voltar para UNINITIALIZED
        // por comando deixaria a LMK viva com o estado dizendo que nao ha
        // chave -- o estado deixaria de ser verdade sobre o dispositivo.
        apertar();
        req_pl[0] = 8'd0;                 // HSM_UNINITIALIZED
        req_plen  = 1;
        send_cmd_pl(8'h26);
        get_response();

        if (st !== 8'h11) begin
            $display("[tb_uart_frame] FAIL: SET_STATE(UNINITIALIZED) -> status=0x%02h, esperado 0x11",
                     st);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] SET_STATE(UNINITIALIZED) -> STATUS_BAD_PARAM");
        end

        req_pl[0] = 8'd2;
        req_plen  = 1;
        send_cmd_pl(8'h26);
        get_response();

        if (st !== 8'h00 || resp_len !== 2 || resp[1] !== 8'd2) begin
            $display("[tb_uart_frame] FAIL: SET_STATE(OPERATIONAL) status=0x%02h estado=%0d",
                     st, resp[1]);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] SET_STATE -> OPERATIONAL");
        end

        soltar();

        // ---- 6i. o estado sobrevive, e o dispositivo continua vivo -----
        send_cmd(8'h02, 1'b0);
        get_response();

        if (st !== 8'h00 || resp[4] !== 8'd2) begin
            $display("[tb_uart_frame] FAIL: GET_VERSION apos ativacao, estado=%0d, esperado 2",
                     resp[4]);
            errors = errors + 1;
        end else begin
            $display("[tb_uart_frame] GET_VERSION -> estado OPERATIONAL");
        end

        if (errors == 0)
            $display("[tb_uart_frame] PASS");
        else
            $display("[tb_uart_frame] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
