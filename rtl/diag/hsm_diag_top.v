`timescale 1ns/1ps
//
// hsm_diag_top.v -- bitstream de diagnostico de bancada. NAO E O HSM.
//
// ---------------------------------------------------------------------
// PARA QUE ISTO EXISTE
//
// Sintoma que motivou o arquivo: o FPGA configura com Done = 0x1, sem CRC
// error, EOS = 1 e MMCM travado -- e o dispositivo fica mudo na UART. Ja
// aconteceu antes nesta bancada (ver CLAUDE.md) e custou uma sessao
// inteira, porque com o SoC no meio existem dezenas de explicacoes:
// firmware travado, CFS ausente, reset, IMEM, baud, pinagem, cabo.
//
// Este design remove TODAS de uma vez. Nao ha CPU, nao ha NEORV32, nao ha
// firmware, nao ha memoria. So contadores e um transmissor serial de
// trinta linhas. Se ele fala, o caminho fisico esta inteiro e a culpa e
// do SoC. Se ele nao fala, o caminho fisico esta rompido e nao adianta
// olhar RTL, sintese ou timing.
//
// Um teste so vale pelo que ele consegue REPROVAR. Este reprova o
// caminho de I/O inteiro sem nenhuma ajuda de software.
//
// ---------------------------------------------------------------------
// O QUE OBSERVAR
//
//   D1              pisca a 1 Hz          -> MMCM travado, 100 MHz vivo
//   D2..D5          luz corrida, ~4 Hz    -> cada pino de LED, um a um
//   UART 115200 8N1 "HSM-DIAG nnnn\r\n"   -> T14 + CP2102 + host
//                   a cada ~500 ms
//   qualquer byte recebido volta ecoado   -> T15 (o sentido de entrada)
//
// A luz corrida importa: ela acende os quatro LEDs de firmware SEPARADOS
// no tempo. Um pino morto aparece como um buraco na sequencia, e um
// buraco e visivel de longe. Acender todos juntos esconderia exatamente
// isso.
//
// O contador na mensagem tambem importa: prova que a UART esta viva
// AGORA e nao que sobrou lixo num buffer de alguem.
//
// ---------------------------------------------------------------------
// Mesmas portas e mesma pinagem do hsm_top -- usa o XDC sem alteracao.
// Ver constraints/qmtech_a35t.xdc e doc/pinout.md.
//
// LEDs e botoes sao ATIVOS BAIXOS na daughterboard; a inversao fica toda
// aqui, como no toplevel de verdade.
//
module hsm_diag_top #(
    parameter integer CLK_HZ    = 100_000_000,
    parameter integer BAUD_RATE = 115_200,

    // Divisores derivados, mas SOBRESCRITIVEIS: o testbench encolhe todos
    // para nao simular meio segundo de tempo real. Em hardware ficam nos
    // valores calculados a partir de CLK_HZ.
    parameter integer HB_DIV   = CLK_HZ / 2,          // 1 Hz
    parameter integer WALK_DIV = CLK_HZ / 4,          // ~4 Hz
    parameter integer MSG_DIV  = CLK_HZ / 2,          // ~500 ms
    parameter integer BAUD_DIV = CLK_HZ / BAUD_RATE   // 868 @ 100M/115200
)(
    input  wire       sys_clk_i,    // N11, 50 MHz
    input  wire       rst_n_i,      // B7 (SW1), ativo baixo

    input  wire       uart_rxd_i,   // T15
    output wire       uart_txd_o,   // T14

    input  wire       btn_a_i,      // M6 (SW2)
    input  wire       btn_b_i,      // P6 (SW5)

    output wire [4:0] led_o,        // D1..D5, ativos baixos

    output wire [7:0] seg_o,
    output wire [2:0] seg_an_o
);

    // ------------------------------------------------------------------
    // Clock e reset -- o MESMO gerador do toplevel de verdade.
    //
    // Deliberado: se o MMCM ou a sequencia de reset for o problema, este
    // diagnostico tem de falhar do mesmo jeito. Trocar por um clock
    // direto tornaria o teste incapaz de reprovar o que ele precisa
    // reprovar.
    // ------------------------------------------------------------------
    wire clk, rst_n, mmcm_locked;

    clk_rst_gen #(
        .RST_HOLD_CYCLES (64)
    ) u_clk_rst (
        .clk_in_i (sys_clk_i),
        .rst_n_i  (rst_n_i),
        .clk_o    (clk),
        .rst_n_o  (rst_n),
        .locked_o (mmcm_locked)
    );

    // ------------------------------------------------------------------
    // Heartbeat de 1 Hz -- identico ao do hsm_top
    // ------------------------------------------------------------------
    reg [31:0] hb_cnt    = 32'd0;
    reg        heartbeat = 1'b0;

    always @(posedge clk) begin
        if (!rst_n) begin
            hb_cnt    <= 32'd0;
            heartbeat <= 1'b0;
        end else if (hb_cnt == (HB_DIV - 1)) begin
            hb_cnt    <= 32'd0;
            heartbeat <= ~heartbeat;
        end else begin
            hb_cnt <= hb_cnt + 32'd1;
        end
    end

    // ------------------------------------------------------------------
    // Luz corrida em D2..D5, ~4 Hz, um LED aceso por vez
    // ------------------------------------------------------------------
    reg [31:0] walk_cnt = 32'd0;
    reg [1:0]  walk_idx = 2'd0;

    always @(posedge clk) begin
        if (!rst_n) begin
            walk_cnt <= 32'd0;
            walk_idx <= 2'd0;
        end else if (walk_cnt == (WALK_DIV - 1)) begin
            walk_cnt <= 32'd0;
            walk_idx <= walk_idx + 2'd1;
        end else begin
            walk_cnt <= walk_cnt + 32'd1;
        end
    end

    wire [3:0] walk = (4'b0001 << walk_idx);

    assign led_o = ~{walk, heartbeat};   // led_o[0] = D1 = heartbeat

    // ------------------------------------------------------------------
    // UART -- transmissor e receptor minimos, 8N1
    //
    // Escritos aqui em vez de reaproveitar o NEORV32 porque o objetivo e
    // justamente NAO depender do SoC. Trinta linhas que sao faceis de ler
    // valem mais, neste arquivo, do que reuso.
    // ------------------------------------------------------------------
    reg [15:0] baud_cnt = 16'd0;
    wire       baud_tick = (baud_cnt == (BAUD_DIV - 1));

    // ---- transmissor: declarado antes do contador porque o contador
    //      precisa saber a hora do carregamento ----
    reg [9:0] tx_sr   = 10'h3FF;   // {stop, dados, start}; repouso = tudo 1
    reg [3:0] tx_bits = 4'd0;
    reg [7:0] tx_data = 8'd0;
    reg       tx_load = 1'b0;
    wire      tx_busy = (tx_bits != 4'd0);

    wire tx_carrega = tx_load & ~tx_busy;

    // O contador de baud REALINHA no carregamento.
    //
    // Sem isto ele corre livre e o byte entra em fase arbitraria: o bit de
    // start dura o que sobrou do periodo corrente, de um ciclo a BAUD_DIV.
    // Um start de 10 ns nao e visto pelo receptor do outro lado, que entao
    // engata na proxima borda de descida e le o quadro inteiro deslocado de
    // um bit -- 0x48 chegando como 0xA4.
    //
    // Custou uma medida em hardware para aparecer, e nao apareceu em
    // simulacao porque la MSG_DIV era multiplo de BAUD_DIV e a fase caia
    // certa por acidente. O testbench agora usa um MSG_DIV que NAO e
    // multiplo, e confere a largura do start.
    always @(posedge clk) begin
        if (!rst_n)            baud_cnt <= 16'd0;
        else if (tx_carrega)   baud_cnt <= 16'd0;
        else if (baud_tick)    baud_cnt <= 16'd0;
        else                   baud_cnt <= baud_cnt + 16'd1;
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            tx_sr   <= 10'h3FF;
            tx_bits <= 4'd0;
        end else if (tx_carrega) begin
            tx_sr   <= {1'b1, tx_data, 1'b0};
            tx_bits <= 4'd10;
        end else if (baud_tick && tx_busy) begin
            tx_sr   <= {1'b1, tx_sr[9:1]};
            tx_bits <= tx_bits - 4'd1;
        end
    end

    assign uart_txd_o = tx_sr[0];

    // ---- receptor: so o suficiente para ecoar ----
    //
    // Amostra no meio do bit. Sem sincronizador de dois estagios seria um
    // CDC descuidado -- a linha e assincrona em relacao ao nosso clock.
    (* ASYNC_REG = "TRUE" *) reg [2:0] rx_sync = 3'b111;

    always @(posedge clk) begin
        if (!rst_n) rx_sync <= 3'b111;
        else        rx_sync <= {rx_sync[1:0], uart_rxd_i};
    end

    wire rx_line = rx_sync[2];

    reg [3:0]  rx_bits    = 4'd0;
    reg [15:0] rx_cnt     = 16'd0;
    reg [7:0]  rx_sr      = 8'd0;
    reg [7:0]  rx_byte    = 8'd0;
    reg        rx_valid   = 1'b0;
    wire       rx_busy    = (rx_bits != 4'd0);

    // 1,5 tempo de bit a partir da borda de start cai no MEIO do bit 0.
    // Esperar so meio bit cairia no meio do START, e o start seria
    // amostrado como se fosse dado -- todo byte voltaria deslocado, e um
    // eco deslocado se parece com "RX quebrado". Um diagnostico que erra
    // assim reprova o que esta bom.
    localparam integer RX_FIRST = (3 * BAUD_DIV) / 2 - 1;

    always @(posedge clk) begin
        rx_valid <= 1'b0;

        if (!rst_n) begin
            rx_bits <= 4'd0;
            rx_cnt  <= 16'd0;
        end else if (!rx_busy) begin
            if (!rx_line) begin              // borda de start
                rx_bits <= 4'd9;             // 8 bits de dado + o stop
                rx_cnt  <= RX_FIRST[15:0];
            end
        end else if (rx_cnt == 16'd0) begin
            rx_cnt  <= BAUD_DIV[15:0] - 16'd1;
            rx_bits <= rx_bits - 4'd1;
            if (rx_bits == 4'd1) begin
                // Instante do STOP. O byte so e entregue aqui, e nao no
                // ultimo bit de dado: entregar antes faz o eco comecar a
                // sair enquanto o quadro de entrada ainda esta na linha.
                // Nao conferimos o VALOR do stop -- isto e um diagnostico
                // de fio, nao um validador de enquadramento.
                rx_byte  <= rx_sr;
                rx_valid <= 1'b1;
            end else begin
                rx_sr <= {rx_line, rx_sr[7:1]};   // LSB primeiro
            end
        end else begin
            rx_cnt <= rx_cnt - 16'd1;
        end
    end

    // ------------------------------------------------------------------
    // Mensagem periodica + eco
    //
    // "HSM-DIAG nnnn\r\n" a cada ~500 ms, com nnnn em hexadecimal
    // crescente. O contador prova que a mensagem e nova.
    //
    // O eco tem prioridade: se chegar um byte, ele volta imediatamente.
    // Assim o teste do sentido de entrada (T15) nao depende de acertar a
    // janela entre duas mensagens.
    // ------------------------------------------------------------------
    reg [31:0] msg_cnt = 32'd0;
    reg [5:0]  msg_idx = 6'd0;
    reg        msg_run = 1'b0;
    reg [15:0] seq     = 16'd0;

    // "HSM-DIAG nnnn Rrrrr Wwwww" + CR + LF
    //   nnnn  contador de sequencia
    //   rrrr  erros da BRAM inicializada pelo bitstream (o caso da IMEM)
    //   wwww  erros de escrita/leitura em BRAM
    // Os dois placares em zero e a prova de que a Block RAM esta boa.
    localparam integer MSG_LEN = 37;

    wire        mem_done;
    wire [15:0] mem_erros_rom, mem_erros_rw;
    wire [31:0] mem_primeira;

    hsm_memtest #(.N (512)) u_memtest (
        .clk_i       (clk),
        .rstn_i      (rst_n),
        .done_o      (mem_done),
        .erros_rom_o (mem_erros_rom),
        .erros_rw_o  (mem_erros_rw),
        .primeira_o  (mem_primeira)
    );

    function [7:0] hexdig(input [3:0] v);
        hexdig = (v < 4'd10) ? (8'd48 + {4'd0, v}) : (8'd55 + {4'd0, v});
    endfunction

    function [7:0] msg_char(input [5:0] i, input [15:0] s,
                            input [15:0] er, input [15:0] ew,
                            input [31:0] z);
        case (i)
            6'd0:  msg_char = "H";
            6'd1:  msg_char = "S";
            6'd2:  msg_char = "M";
            6'd3:  msg_char = "-";
            6'd4:  msg_char = "D";
            6'd5:  msg_char = "I";
            6'd6:  msg_char = "A";
            6'd7:  msg_char = "G";
            6'd8:  msg_char = " ";
            6'd9:  msg_char = hexdig(s[15:12]);
            6'd10: msg_char = hexdig(s[11:8]);
            6'd11: msg_char = hexdig(s[7:4]);
            6'd12: msg_char = hexdig(s[3:0]);
            6'd13: msg_char = " ";
            6'd14: msg_char = "R";
            6'd15: msg_char = hexdig(er[15:12]);
            6'd16: msg_char = hexdig(er[11:8]);
            6'd17: msg_char = hexdig(er[7:4]);
            6'd18: msg_char = hexdig(er[3:0]);
            6'd19: msg_char = " ";
            6'd20: msg_char = "W";
            6'd21: msg_char = hexdig(ew[15:12]);
            6'd22: msg_char = hexdig(ew[11:8]);
            6'd23: msg_char = hexdig(ew[7:4]);
            6'd24: msg_char = hexdig(ew[3:0]);
            6'd25: msg_char = " ";
            6'd26: msg_char = "Z";
            6'd27: msg_char = hexdig(z[31:28]);
            6'd28: msg_char = hexdig(z[27:24]);
            6'd29: msg_char = hexdig(z[23:20]);
            6'd30: msg_char = hexdig(z[19:16]);
            6'd31: msg_char = hexdig(z[15:12]);
            6'd32: msg_char = hexdig(z[11:8]);
            6'd33: msg_char = hexdig(z[7:4]);
            6'd34: msg_char = hexdig(z[3:0]);
            6'd35: msg_char = 8'h0D;
            default: msg_char = 8'h0A;
        endcase
    endfunction

    // Eco pendente. rx_valid dura um ciclo so; se o transmissor estiver
    // ocupado nesse ciclo o byte se perderia, e um eco perdido se parece
    // com "T15 rompido" -- outro falso negativo no proprio teste.
    reg       echo_pend = 1'b0;
    reg [7:0] echo_byte = 8'd0;

    always @(posedge clk) begin
        tx_load <= 1'b0;

        if (!rst_n) begin
            msg_cnt   <= 32'd0;
            msg_idx   <= 6'd0;
            msg_run   <= 1'b0;
            seq       <= 16'd0;
            echo_pend <= 1'b0;
        end else begin
            if (rx_valid) begin
                echo_byte <= rx_byte;
                echo_pend <= 1'b1;
            end

            if (msg_cnt == (MSG_DIV - 1)) begin
                msg_cnt <= 32'd0;
                if (!msg_run) begin
                    msg_run <= 1'b1;
                    msg_idx <= 6'd0;
                end
            end else begin
                msg_cnt <= msg_cnt + 32'd1;
            end

            if (!tx_busy && !tx_load) begin
                if (echo_pend) begin
                    // eco tem prioridade
                    tx_data   <= echo_byte;
                    tx_load   <= 1'b1;
                    echo_pend <= 1'b0;
                end else if (msg_run) begin
                    tx_data <= msg_char(msg_idx, seq, mem_erros_rom, mem_erros_rw, mem_primeira);
                    tx_load <= 1'b1;
                    if (msg_idx == (MSG_LEN - 1)) begin
                        msg_run <= 1'b0;
                        seq     <= seq + 16'd1;
                    end else begin
                        msg_idx <= msg_idx + 6'd1;
                    end
                end
            end
        end
    end

    // ------------------------------------------------------------------
    // Nao usados. Amarrados para o XDC continuar valendo sem alteracao.
    // ------------------------------------------------------------------
    wire _unused = &{1'b0, btn_a_i, btn_b_i, mmcm_locked, mem_done, 1'b0};

    // ------------------------------------------------------------------
    // Display de 7 segmentos -- CONTROLE DIRETO PELO HOST
    //
    // Existe para fechar um [TBD] que arrasta desde a fase 1: nao se sabe
    // se o display e anodo ou catodo comum, nem qual bit de seg_o vai para
    // qual segmento fisico. Os PINOS estao certos (vieram do esquematico);
    // a tabela de fontes e que nao pode ser escrita de palpite.
    //
    // Varredura fixa em RTL resolveria devagar e as cegas: cada hipotese
    // custaria um bitstream novo. Aqui o host manda os valores CRUS e quem
    // olha responde -- o ciclo de experimento cai de vinte minutos para
    // dois segundos.
    //
    // Protocolo, sobre a mesma UART do eco:
    //
    //     0xAA  <seg>  <an>     ->  seg_o = seg, seg_an_o = an
    //
    // Qualquer outro byte segue ecoando normalmente. 0xAA foi escolhido
    // porque nenhum teste existente o envia, e porque 10101010 e facil de
    // reconhecer num analisador.
    //
    // Repouso: tudo em 1. Se o display for anodo comum (ativo baixo em
    // seg_o) isso o deixa apagado; se for catodo comum, aceso. Qual dos
    // dois acontece na energizacao ja e a primeira medida.
    // ------------------------------------------------------------------
    reg [7:0] seg_manual = 8'hFF;
    reg [2:0] an_manual  = 3'b111;
    reg [1:0] seg_st     = 2'd0;

    always @(posedge clk) begin
        if (!rst_n) begin
            seg_manual <= 8'hFF;
            an_manual  <= 3'b111;
            seg_st     <= 2'd0;
        end else if (rx_valid) begin
            case (seg_st)
                2'd0: if (rx_byte == 8'hAA) seg_st <= 2'd1;
                2'd1: begin seg_manual <= rx_byte; seg_st <= 2'd2; end
                default: begin an_manual <= rx_byte[2:0]; seg_st <= 2'd0; end
            endcase
        end
    end

    assign seg_o    = seg_manual;
    assign seg_an_o = an_manual;

endmodule
