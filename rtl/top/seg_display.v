`timescale 1ns/1ps
//
// seg_display.v -- estado do HSM no display de 7 segmentos
//
// Tres digitos multiplexados soletram o estado da maquina (PLANO secao 4):
//
//     Uni   UNINITIALIZED    sem chave mestra
//     Aut   AUTHORIZED       LMK carregada, ainda nao em servico
//     OPE   OPERATIONAL      em servico
//     tPr   TAMPERED         reprovou, e nao sai daqui por software
//
// POR QUE ISTO E PECA DE OPERACAO, E NAO ENFEITE
//
// Os cinco LEDs desta placa sao todos VERMELHOS (doc/pinout.md). A cor nao
// distingue nada, entao o requisito "LED vermelho para TAMPERED" esta
// atendido e vazio -- quem carrega informacao de estado e este display.
//
// E ha um segundo trabalho, que nasceu de uma pergunta de bancada: "que
// botoes?". O PONTO DECIMAL acende quando o dual control esta satisfeito
// neste instante. O operador aperta e ve o dispositivo concordar, sem
// depender de ler silkscreen no meio de uma cerimonia.
//
// Isso nao vaza nada: quem esta apertando os botoes ja esta na frente da
// placa, e nao ha observador remoto para quem a informacao seja nova.
//
// FRONTEIRA: fora. Este modulo recebe dois bits de estado e um bit de
// autorizacao, e nao tem caminho nenhum para material de chave. Nao pode
// passar a ter -- um display que mostrasse KCV seria um canal lateral
// otico, e otico e o unico canal que nao aparece em captura de UART.
//
module seg_display #(
    // Frequencia do dominio. Parametrizado para o testbench nao precisar
    // simular a varredura em tempo real.
    parameter integer CLK_HZ = 100_000_000,

    // Taxa de troca de digito. 600 Hz => quadro completo a 200 Hz, bem
    // acima do limiar de cintilacao e bem abaixo de qualquer preocupacao
    // com o tempo de subida do driver.
    parameter integer MUX_HZ = 600,

    // Polaridades -- VERIFICADAS EM HARDWARE 2026-08-09 (doc/pinout.md).
    // Nao sao palpite: as quatro combinacoes foram medidas uma a uma com o
    // controle direto do rtl/diag/.
    parameter SEG_ACTIVE_LOW = 1'b1,   // segmento acende com 0
    parameter AN_ACTIVE_LOW  = 1'b0,   // digito habilita com 1

    // Qual anodo e o digito da ESQUERDA. MEDIDO 2026-08-26: e o [0].
    //
    // 1 = seg_an_o[0] fica a esquerda e [2] a direita.
    // 0 = o contrario.
    //
    // Trocado, "Uni" aparece como "inU": legivel, errado, e imediatamente
    // obvio para quem olha -- mas INVISIVEL em simulacao, porque a ordem
    // fisica e fato do cobre e nao do RTL. Por isso um unico parametro
    // resolve, em vez de fiacao condicional espalhada.
    parameter DIGITO0_A_ESQUERDA = 1'b1
)(
    input  wire       clk_i,
    input  wire       rst_n_i,      // sincrono, ativo baixo

    input  wire [1:0] estado_i,     // hsm_state_t: 0=Uni 1=Aut 2=OPE 3=tPr
    input  wire       dual_ok_i,    // dual control satisfeito AGORA

    output wire [7:0] seg_o,        // a,b,c,d,e,f,g,dp -- ja na polaridade
    output wire [2:0] seg_an_o      // varredura -- ja na polaridade
);

    // ------------------------------------------------------------------
    // Glifos
    //
    // bit0=a bit1=b bit2=c bit3=d bit4=e bit5=f bit6=g bit7=dp,
    // ATIVO ALTO aqui dentro. A polaridade da placa e aplicada uma vez so,
    // na saida -- misturar as duas convencoes no meio da logica e como se
    // inverte um segmento sem perceber.
    //
    //      aaa
    //     f   b
    //      ggg
    //     e   c
    //      ddd
    // ------------------------------------------------------------------
    localparam [7:0] GL_U = 8'b0011_1110;   // b c d e f
    localparam [7:0] GL_n = 8'b0101_0100;   // c e g
    localparam [7:0] GL_i = 8'b0000_0100;   // c
    localparam [7:0] GL_A = 8'b0111_0111;   // a b c e f g
    localparam [7:0] GL_u = 8'b0001_1100;   // c d e
    localparam [7:0] GL_t = 8'b0111_1000;   // d e f g
    localparam [7:0] GL_O = 8'b0011_1111;   // a b c d e f
    localparam [7:0] GL_P = 8'b0111_0011;   // a b e f g
    localparam [7:0] GL_E = 8'b0111_1001;   // a d e f g
    localparam [7:0] GL_r = 8'b0101_0000;   // e g

    localparam [7:0] GL_DP = 8'b1000_0000;

    // ------------------------------------------------------------------
    // Palavra do estado, sempre na ordem de LEITURA:
    // indice 0 = caractere da esquerda.
    // ------------------------------------------------------------------
    reg [7:0] car0, car1, car2;

    always @(*) begin
        case (estado_i)
            2'd0: begin car0 = GL_U; car1 = GL_n; car2 = GL_i; end  // Uni
            2'd1: begin car0 = GL_A; car1 = GL_u; car2 = GL_t; end  // Aut
            2'd2: begin car0 = GL_O; car1 = GL_P; car2 = GL_E; end  // OPE
            // 2'd3 e o unico default de proposito: um estado_i corrompido
            // deve mostrar TAMPERED, nao apagar nem mostrar Uni. Falhar
            // para o lado seguro tambem vale para o painel.
            default: begin car0 = GL_t; car1 = GL_P; car2 = GL_r; end
        endcase
    end

    // ------------------------------------------------------------------
    // Varredura
    // ------------------------------------------------------------------
    localparam integer MUX_DIV_RAW = CLK_HZ / MUX_HZ;
    localparam integer MUX_DIV     = (MUX_DIV_RAW < 4) ? 4 : MUX_DIV_RAW;

    // Apagamento entre digitos. Sem isto o digito seguinte acende antes de
    // o anterior descarregar e aparece um "fantasma" fraco no vizinho --
    // num display que soletra estado, fantasma vira leitura ambigua.
    localparam integer BLANK_CYC = (MUX_DIV / 16 < 1) ? 1 : MUX_DIV / 16;

    reg [31:0] cnt;
    reg [1:0]  digito;    // 0,1,2 na ordem de leitura

    always @(posedge clk_i) begin
        if (!rst_n_i) begin
            cnt    <= 32'd0;
            digito <= 2'd0;
        end else if (cnt == (MUX_DIV - 1)) begin
            cnt    <= 32'd0;
            digito <= (digito == 2'd2) ? 2'd0 : (digito + 2'd1);
        end else begin
            cnt <= cnt + 32'd1;
        end
    end

    wire apagando = (cnt < BLANK_CYC);

    // ------------------------------------------------------------------
    // Seleção do caractere e do anodo
    // ------------------------------------------------------------------
    reg [7:0] car;
    always @(*) begin
        case (digito)
            2'd0:    car = car0;
            2'd1:    car = car1;
            default: car = car2;
        endcase
    end

    // Ponto decimal no ULTIMO caractere -- o da direita na leitura. Um so,
    // e nao os tres: tres pontos acesos parecem defeito, um ponto parece
    // sinal.
    wire [7:0] car_dp = car | ((dual_ok_i && (digito == 2'd2)) ? GL_DP : 8'h00);

    // Anodo one-hot na ordem de leitura, com o mapeamento fisico aplicado
    // aqui e em nenhum outro lugar.
    reg [2:0] an;
    always @(*) begin
        case (digito)
            2'd0:    an = DIGITO0_A_ESQUERDA ? 3'b001 : 3'b100;
            2'd1:    an = 3'b010;
            default: an = DIGITO0_A_ESQUERDA ? 3'b100 : 3'b001;
        endcase
    end

    // ------------------------------------------------------------------
    // Saidas -- unica aplicacao de polaridade
    //
    // Em reset o display fica apagado pelos DOIS caminhos ao mesmo tempo,
    // segmentos desligados E digitos desabilitados. Qualquer um bastaria;
    // os dois juntos mantem o display apagado mesmo se um parametro de
    // polaridade for trocado por engano.
    // ------------------------------------------------------------------
    wire        ligado   = rst_n_i && !apagando;
    wire [7:0]  seg_alto = ligado ? car_dp : 8'h00;
    wire [2:0]  an_alto  = ligado ? an     : 3'b000;

    assign seg_o    = SEG_ACTIVE_LOW ? ~seg_alto : seg_alto;
    assign seg_an_o = AN_ACTIVE_LOW  ? ~an_alto  : an_alto;

endmodule
