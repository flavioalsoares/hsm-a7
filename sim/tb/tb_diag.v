`timescale 1ns/1ps
//
// tb_diag -- verifica o bitstream de diagnostico de bancada.
//
// Regra 4 do CLAUDE.md vale aqui com forca dobrada: este design e um
// INSTRUMENTO DE MEDIDA. Um instrumento errado nao produz "nenhum
// resultado", produz um resultado errado com cara de certo -- e a gente
// ia gravar na placa e concluir "a UART esta rompida" quando na verdade
// o transmissor e que estava.
//
// O que este testbench prova:
//   1. a mensagem periodica sai correta em 8N1, byte a byte
//   2. o contador de sequencia anda entre duas mensagens
//   3. um byte recebido volta ecoado, com o valor certo
//      (o eco e o unico teste do sentido de ENTRADA, T15)
//   4. a luz corrida acende os quatro LEDs, um por vez, sem pular nenhum
//
// Divisores encolhidos por parametro -- ver hsm_diag_top.
//
module tb_diag;

    // BAUD_DIV pequeno o bastante para simular rapido, grande o bastante
    // para o sincronizador de 3 estagios do RX nao comer o bit de start.
    localparam integer BAUD_DIV = 16;

    // NAO multiplo de BAUD_DIV, de proposito.
    //
    // Com 8000 (= 500 x 16) a mensagem comecava sempre em fase com o
    // contador de baud e o bit de start saia com a largura certa por
    // acidente. O testbench passava e o hardware transmitia lixo. Um
    // periodo primo em relacao ao baud forca o carregamento a cair em
    // fase arbitraria, que e o caso real.
    localparam integer MSG_DIV  = 8007;
    localparam integer HB_DIV   = 600;
    localparam integer WALK_DIV = 300;

    // O clk interno vem do MMCM: 50 MHz na entrada -> 100 MHz, 10 ns.
    localparam real CLK_NS = 10.0;
    localparam real BIT_NS = BAUD_DIV * CLK_NS;

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  rxd     = 1'b1;

    wire       txd;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;

    always #10 sys_clk = ~sys_clk;      // 50 MHz na entrada do MMCM

    hsm_diag_top #(
        .CLK_HZ    (100_000_000),
        .BAUD_RATE (115_200),
        .HB_DIV    (HB_DIV),
        .WALK_DIV  (WALK_DIV),
        .MSG_DIV   (MSG_DIV),
        .BAUD_DIV  (BAUD_DIV)
    ) dut (
        .sys_clk_i  (sys_clk),
        .rst_n_i    (rst_n),
        .uart_rxd_i (rxd),
        .uart_txd_o (txd),
        .btn_a_i    (1'b1),
        .btn_b_i    (1'b1),
        .led_o      (led),
        .seg_o      (seg),
        .seg_an_o   (seg_an)
    );

    integer erros = 0;

    // ------------------------------------------------------------------
    // Receptor CONTINUO, em background, com fila.
    //
    // Chamar uma task de recepcao sob demanda nao funciona aqui: entre o
    // fim de uma leitura e o inicio da proxima o DUT pode ja ter comecado
    // a transmitir, e a task engata numa transicao no MEIO do quadro. O
    // sintoma e um byte deslocado de um bit -- 0xA5 chegando como 0xD2 --
    // e a conclusao errada seria "o receptor do DUT esta quebrado".
    //
    // Este processo nunca solta a linha: termina um byte no meio do stop e
    // ja volta a esperar a proxima borda de start. Assim funciona tanto
    // com bytes colados (mensagem) quanto com bytes isolados (eco).
    // ------------------------------------------------------------------
    reg [7:0] fila [0:255];
    integer   fila_wr = 0;
    integer   fila_rd = 0;

    initial begin : receptor
        reg [7:0] b;
        integer   i;
        forever begin
            @(negedge txd);

            // Largura do bit de start. Nao e preciosismo: um start curto
            // nao e reconhecido pelo receptor do outro lado, que engata na
            // proxima borda de descida e le o quadro deslocado de um bit.
            // Amostrar so no centro dos bits NAO pega isso -- o quadro
            // continua decodificando certo aqui e chega errado na placa.
            #(BIT_NS * 0.9);
            if (txd !== 1'b0) begin
                $display("[tb_diag] ERRO: bit de start encurtado (linha ja subiu em 0,9 T)");
                erros = erros + 1;
            end

            #(BIT_NS * 0.6);          // total 1,5 T = centro do bit 0
            for (i = 0; i < 8; i = i + 1) begin
                b[i] = txd;
                #(BIT_NS);
            end
            fila[fila_wr % 256] = b;
            fila_wr = fila_wr + 1;
            // Estamos no meio do stop. Voltar ao topo do laco deixa o
            // processo esperando a proxima borda de start sem perde-la.
        end
    end

    // Tira um byte da fila, esperando se preciso.
    task uart_get(output [7:0] b);
        begin
            while (fila_wr == fila_rd) #(BIT_NS / 4);
            b = fila[fila_rd % 256];
            fila_rd = fila_rd + 1;
        end
    endtask

    // Transmite um byte para o DUT.
    task uart_put(input [7:0] b);
        integer i;
        begin
            rxd = 1'b0;  #(BIT_NS);              // start
            for (i = 0; i < 8; i = i + 1) begin
                rxd = b[i];  #(BIT_NS);
            end
            rxd = 1'b1;  #(BIT_NS);              // stop
        end
    endtask

    reg [15:0] er_lido, ew_lido;
    reg [31:0] z_lido;

    // Le a mensagem inteira e devolve o campo de sequencia.
    task ler_mensagem(output [15:0] seq_lida, input integer verifica_texto);
        reg [7:0] c;
        reg [7:0] esperado [0:8];
        integer i;
        integer v;
        begin
            esperado[0]="H"; esperado[1]="S"; esperado[2]="M"; esperado[3]="-";
            esperado[4]="D"; esperado[5]="I"; esperado[6]="A"; esperado[7]="G";
            esperado[8]=" ";

            for (i = 0; i < 9; i = i + 1) begin
                uart_get(c);
                if (verifica_texto && (c !== esperado[i])) begin
                    $display("[tb_diag] ERRO: caractere %0d = 0x%02x, esperado 0x%02x",
                             i, c, esperado[i]);
                    erros = erros + 1;
                end
            end

            seq_lida = 16'd0;
            for (i = 0; i < 4; i = i + 1) begin
                uart_get(c);
                if (c >= "0" && c <= "9")      v = c - "0";
                else if (c >= "A" && c <= "F") v = c - "A" + 10;
                else begin
                    $display("[tb_diag] ERRO: digito hex invalido 0x%02x", c);
                    erros = erros + 1;
                    v = 0;
                end
                seq_lida = (seq_lida << 4) | v[3:0];
            end

            // " R" + 4 hex + " W" + 4 hex -- placar do teste de Block RAM
            le_placar("R", er_lido);
            le_placar("W", ew_lido);
            le_palavra32("Z", z_lido);

            uart_get(c);
            if (c !== 8'h0D) begin
                $display("[tb_diag] ERRO: esperava CR, veio 0x%02x", c);
                erros = erros + 1;
            end
            uart_get(c);
            if (c !== 8'h0A) begin
                $display("[tb_diag] ERRO: esperava LF, veio 0x%02x", c);
                erros = erros + 1;
            end
        end
    endtask

    // Mesma coisa com 8 digitos -- a primeira palavra lida da ROM.
    task le_palavra32(input [7:0] marca, output [31:0] valor);
        reg [7:0] c;
        integer i, v;
        begin
            uart_get(c);
            if (c !== " ") begin
                $display("[tb_diag] ERRO: esperava espaco antes de %0s", marca);
                erros = erros + 1;
            end
            uart_get(c);
            if (c !== marca) begin
                $display("[tb_diag] ERRO: esperava marca %0s, veio 0x%02x", marca, c);
                erros = erros + 1;
            end
            valor = 32'd0;
            for (i = 0; i < 8; i = i + 1) begin
                uart_get(c);
                if (c >= "0" && c <= "9")      v = c - "0";
                else if (c >= "A" && c <= "F") v = c - "A" + 10;
                else begin
                    $display("[tb_diag] ERRO: hex invalido em %0s: 0x%02x", marca, c);
                    erros = erros + 1;
                    v = 0;
                end
                valor = (valor << 4) | v[3:0];
            end
        end
    endtask

    task le_placar(input [7:0] marca, output [15:0] valor);
        reg [7:0] c;
        integer i, v;
        begin
            uart_get(c);
            if (c !== " ") begin
                $display("[tb_diag] ERRO: esperava espaco antes de %0s, veio 0x%02x", marca, c);
                erros = erros + 1;
            end
            uart_get(c);
            if (c !== marca) begin
                $display("[tb_diag] ERRO: esperava marca %0s, veio 0x%02x", marca, c);
                erros = erros + 1;
            end
            valor = 16'd0;
            for (i = 0; i < 4; i = i + 1) begin
                uart_get(c);
                if (c >= "0" && c <= "9")      v = c - "0";
                else if (c >= "A" && c <= "F") v = c - "A" + 10;
                else begin
                    $display("[tb_diag] ERRO: hex invalido no placar %0s: 0x%02x", marca, c);
                    erros = erros + 1;
                    v = 0;
                end
                valor = (valor << 4) | v[3:0];
            end
        end
    endtask

    // ------------------------------------------------------------------
    // Luz corrida: observa em paralelo e anota quais LEDs chegaram a
    // acender, e se em algum instante houve mais de um aceso.
    // ------------------------------------------------------------------
    reg [3:0] vistos      = 4'b0000;
    reg       mais_de_um  = 1'b0;

    // LEDs sao ativos baixos: o aceso e o bit em zero.
    wire [3:0] acesos = ~led[4:1];

    always @(posedge dut.clk) begin
        if (rst_n) begin
            vistos <= vistos | acesos;
            if (acesos != 4'b0001 && acesos != 4'b0010 &&
                acesos != 4'b0100 && acesos != 4'b1000)
                mais_de_um <= 1'b1;
        end
    end

    // ------------------------------------------------------------------
    reg [15:0] s1, s2;
    reg [7:0]  eco;

    initial begin
        $display("[tb_diag] inicio");

        rst_n = 1'b0;
        repeat (200) @(posedge sys_clk);
        rst_n = 1'b1;

        // 1 e 2 -- duas mensagens seguidas, com o contador andando
        ler_mensagem(s1, 1);
        $display("[tb_diag] mensagem 1 ok, seq=%04x", s1);

        ler_mensagem(s2, 1);
        $display("[tb_diag] mensagem 2 ok, seq=%04x", s2);

        // Em simulacao a Block RAM funciona sempre. Se o placar nao vier
        // zerado, o defeito e do proprio hsm_memtest -- e um instrumento
        // que acusa falha onde nao ha e pior que nenhum instrumento: ele
        // manda trocar hardware bom.
        if (er_lido !== 16'd0 || ew_lido !== 16'd0) begin
            $display("[tb_diag] ERRO: placar de BRAM nao zerou em simulacao (R=%04x W=%04x)",
                     er_lido, ew_lido);
            erros = erros + 1;
        end else begin
            $display("[tb_diag] placar de Block RAM zerado, como tem de ser em simulacao");
        end

        // A primeira palavra da ROM tem de ser a semente. E esta a medida
        // que nao depende de hipotese de latencia: em hardware ela separa
        // "inicializacao nao pegou" de "comparador desalinhado".
        // Quinta leitura valida = rom[4]. Ver o cabecalho de hsm_memtest:
        // a primeira nao serve porque zero e ambiguo entre "inicializacao
        // nao pegou" e "um ciclo de latencia a mais".
        if (z_lido !== 32'h2345_678B) begin
            $display("[tb_diag] ERRO: palavra da ROM = %08x, esperado 2345678B", z_lido);
            erros = erros + 1;
        end

        if (s2 !== (s1 + 16'd1)) begin
            $display("[tb_diag] ERRO: contador nao andou (%04x -> %04x)", s1, s2);
            erros = erros + 1;
        end

        // 3 -- eco. Logo depois de uma mensagem terminar ha uma janela
        // larga ate a proxima, entao o proximo byte a sair e o eco.
        //
        // Com o receptor rodando em background, basta enviar e depois
        // tirar da fila: nenhuma borda se perde no intervalo.
        uart_put(8'h5A);
        uart_get(eco);
        if (eco !== 8'h5A) begin
            $display("[tb_diag] ERRO: eco devolveu 0x%02x, esperado 0x5A", eco);
            erros = erros + 1;
        end else begin
            $display("[tb_diag] eco de 0x5A ok -- caminho de entrada vivo");
        end

        uart_put(8'hA5);
        uart_get(eco);
        if (eco !== 8'hA5) begin
            $display("[tb_diag] ERRO: eco devolveu 0x%02x, esperado 0xA5", eco);
            erros = erros + 1;
        end else begin
            $display("[tb_diag] eco de 0xA5 ok");
        end

        // 4 -- controle do display pelo host
        //
        // E o instrumento que fecha o [TBD] da polaridade do 7-seg. Se ele
        // estiver errado, a medida em hardware vira palpite com cara de
        // resultado -- exatamente o que ja aconteceu duas vezes nesta
        // bancada.
        if (seg !== 8'hFF || seg_an !== 3'b111) begin
            $display("[tb_diag] ERRO: display nao nasceu em repouso (seg=%02h an=%b)",
                     seg, seg_an);
            erros = erros + 1;
        end

        uart_put(8'hAA);   // marca
        uart_put(8'h7E);   // seg
        uart_put(8'h05);   // an
        #(BIT_NS * 2);
        if (seg !== 8'h7E || seg_an !== 3'b101) begin
            $display("[tb_diag] ERRO: seg=%02h an=%b, esperado 7E / 101", seg, seg_an);
            erros = erros + 1;
        end else begin
            $display("[tb_diag] display: host escreveu seg=7E an=101");
        end

        // Um byte solto NAO pode mexer no display -- se mexesse, o eco de
        // qualquer teste anterior teria apagado o padrao sob observacao.
        uart_put(8'h3C);
        #(BIT_NS * 2);
        if (seg !== 8'h7E) begin
            $display("[tb_diag] ERRO: byte solto alterou o display (seg=%02h)", seg);
            erros = erros + 1;
        end

        // 5 -- luz corrida: deu tempo de sobra para as quatro posicoes
        if (vistos !== 4'b1111) begin
            $display("[tb_diag] ERRO: LEDs que nunca acenderam, mascara=%b", vistos);
            erros = erros + 1;
        end else begin
            $display("[tb_diag] luz corrida acendeu D2..D5, um por vez");
        end

        if (mais_de_um) begin
            $display("[tb_diag] ERRO: houve instante com != 1 LED aceso");
            erros = erros + 1;
        end

        if (erros == 0) $display("[tb_diag] PASS");
        else            $display("[tb_diag] FAIL -- %0d erro(s)", erros);

        $finish;
    end

    // Rede de seguranca: se o DUT nunca transmitir, o testbench trava em
    // @(negedge txd) para sempre. Melhor reprovar do que pendurar.
    initial begin
        #5_000_000;
        $display("[tb_diag] FAIL -- timeout: o DUT nao transmitiu");
        $finish;
    end

endmodule
