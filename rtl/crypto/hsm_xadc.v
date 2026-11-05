`timescale 1ns/1ps
//
// hsm_xadc.v -- sensores de ambiente: temperatura e tensoes do proprio die
//
// Fase 6. O mecanismo de protecao contra falhas ambientais: um dispositivo
// fora da faixa de operacao nao garante que calcula certo, e condicao
// ambiental fora da faixa e como se induz falha de proposito.
//
// ---------------------------------------------------------------------
// FRONTEIRA CRIPTOGRAFICA
//
// Dentro. Nao toca material de chave: ve tensao e temperatura, nada mais.
//
// ---------------------------------------------------------------------
// DIVISAO ENTRE HARDWARE E FIRMWARE -- a mesma do TRNG
//
// O hardware DETECTA e RETEM. O firmware RESPONDE: apaga, registra, vai
// para TAMPERED. As chaves moram na DMEM, que este bloco nao alcanca, e e
// bom que nao alcance.
//
//   * Os limites sao atributos INIT do primitivo. DWE esta amarrado em
//     zero: nao existe caminho de escrita para o DRP, entao nenhuma linha
//     de firmware afrouxa um limite. O JTAG alcanca o DRP por outro lado,
//     e isso esta anotado em doc/fase6-notas.md.
//   * `sticky_o` NAO tem reset, so o valor inicial da configuracao. Quem
//     saiu da faixa e apertou o SW1 nao apaga a prova: o firmware a
//     encontra no boot seguinte. So reconfigurar o FPGA limpa -- e isso,
//     nesta placa, e desligar ou regravar. E a excecao deliberada a
//     convencao de reset sincrono do projeto.
//
// ---------------------------------------------------------------------
// LIMITES -- de onde vem
//
// Chip desta placa: XC7A35T-1FTG256C (manual do core board QMTECH), grau
// comercial. Faixas: DS181 v1.27, Tabela 2, condicoes recomendadas.
//
//   Tj       0 .. 85 C
//   VCCINT   0,95 .. 1,05 V
//   VCCAUX   1,71 .. 1,89 V
//   VCCBRAM  0,95 .. 1,05 V
//
// Codigos: UG480 v1.9, Figuras 2-9 e 2-10, registradores 16 bits com o
// valor de 12 bits justificado a esquerda.
//
//   Temp(C) = codigo * 503,975 / 4096 - 273,15
//   V       = codigo * 3 / 4096
//
// O erro dos sensores (DS181, Tabela 65) e de +-4 C e +-1%. Nao ha margem
// somada aos limites: o limite e o da folha de dados.
//
// O QUE O XADC NAO COBRE, E FICA AQUI: o alarme de temperatura so olha
// para cima. O registrador 54h e o limite de REARME, nao um limite
// inferior. Frio e o ataque classico de remanencia de memoria, entao o
// piso de 0 C e uma comparacao deste bloco sobre a leitura.
//
// ---------------------------------------------------------------------
// BITS DE sticky_o / live_o
//
//   0  temperatura acima de 85 C     ALM[0]
//   1  VCCINT fora da faixa          ALM[1]
//   2  VCCAUX fora da faixa          ALM[2]
//   3  VCCBRAM fora da faixa         ALM[3]
//   4  temperatura abaixo de 0 C     comparacao local
//   5  sensor parado                 sem EOS por WD_CICLOS
//
module hsm_xadc #(
    // Sem fim de sequencia por este tempo, o sensor parou. 2^24 ciclos de
    // 100 MHz = 168 ms, contra uma sequencia de ~100 us. Testbench usa menos.
    parameter integer WD_BITS = 24
)(
    input  wire        clk_i,        // 100 MHz, tambem e o DCLK do XADC
    input  wire        rstn_i,

    // Valores iniciais: sticky_o nao tem reset, entao um X aqui grudaria.
    output reg         valid_o = 1'b0,    // leituras reais disponiveis
    output wire [5:0]  sticky_o,     // retido ate reconfigurar
    output wire [5:0]  live_o,       // condicao AGORA
    output reg  [11:0] temp_o = 12'd0,
    output reg  [11:0] vccint_o = 12'd0,
    output reg  [11:0] vccaux_o = 12'd0,
    output reg  [11:0] vccbram_o = 12'd0
);

    // 0 C: 273,15 * 4096 / 503,975 = 2220,03
    localparam [11:0] COD_0C = 12'd2220;

    // Enderecos de status do DRP (UG480, Figura 3-1)
    localparam [6:0] DRP_TEMP = 7'h00, DRP_VCCINT  = 7'h01,
                     DRP_VCCAUX = 7'h02, DRP_VCCBRAM = 7'h06;

    wire [7:0]  alm;
    wire [15:0] drp_do;
    wire        drp_rdy;
    wire        eos;
    reg  [6:0]  drp_addr = DRP_TEMP;
    reg         drp_en   = 1'b0;

    XADC #(
        .INIT_40 (16'h9000),  // sem media nos coeficientes; media de 16
        .INIT_41 (16'h2EF0),  // sequencia continua, ALM[3:0] ligados, calibra
        .INIT_42 (16'h0400),  // DCLK/4 = 25 MHz (ADCCLK maximo: 26 MHz)
        .INIT_48 (16'h4701),  // calibracao, temp, VCCINT, VCCAUX, VCCBRAM
        .INIT_49 (16'h0000),  // nenhuma entrada externa
        .INIT_4A (16'h4700),  // media nos quatro sensores
        .INIT_4B (16'h0000),
        .INIT_4C (16'h0000),
        .INIT_4D (16'h0000),
        .INIT_4E (16'h0000),
        .INIT_4F (16'h0000),
        .INIT_50 (16'hB5ED),  // temperatura, sobe em 85 C
        .INIT_51 (16'h5999),  // VCCINT  maximo 1,05 V
        .INIT_52 (16'hA147),  // VCCAUX  maximo 1,89 V
        .INIT_53 (16'h0000),  // OT: 125 C padrao, sem desligamento automatico
        .INIT_54 (16'hA93A),  // temperatura, rearma em 60 C
        .INIT_55 (16'h5111),  // VCCINT  minimo 0,95 V
        .INIT_56 (16'h91EB),  // VCCAUX  minimo 1,71 V
        .INIT_57 (16'hAE4E),  // OT, rearme
        .INIT_58 (16'h5999),  // VCCBRAM maximo 1,05 V
        .INIT_5C (16'h5111),  // VCCBRAM minimo 0,95 V
        // scripts/sim.sh copia a curva do testbench para este nome.
        .SIM_MONITOR_FILE ("xadc_stim.txt")
    ) u_xadc (
        .CONVST       (1'b0),
        .CONVSTCLK    (1'b0),
        .DADDR        (drp_addr),
        .DCLK         (clk_i),
        .DEN          (drp_en),
        .DI           (16'd0),
        .DWE          (1'b0),      // ver o cabecalho: sem caminho de escrita
        .RESET        (1'b0),
        .VAUXN        (16'd0),
        .VAUXP        (16'd0),
        .VN           (1'b0),
        .VP           (1'b0),
        .ALM          (alm),
        .BUSY         (),
        .CHANNEL      (),
        .DO           (drp_do),
        .DRDY         (drp_rdy),
        .EOC          (),
        .EOS          (eos),
        .JTAGBUSY     (),
        .JTAGLOCKED   (),
        .JTAGMODIFIED (),
        .MUXADDR      (),
        .OT           ()
    );

    // ------------------------------------------------------------------
    // Varredura: le os quatro sensores em rodizio.
    //
    // Antes do primeiro fim de sequencia os registradores de status ainda
    // nao tem medida, e uma leitura zero pareceria -273 C. Por isso valid_o
    // so sobe depois de um EOS e de uma volta completa depois dele.
    // ------------------------------------------------------------------
    localparam [1:0] V_PEDE = 2'd0, V_ESPERA = 2'd1;

    reg [1:0]         v_st    = V_PEDE;
    reg [1:0]         v_idx   = 2'd0;
    reg               viu_eos = 1'b0;
    reg               volta   = 1'b0;   // volta completa iniciada apos o EOS
    reg [WD_BITS-1:0] wd      = {WD_BITS{1'b0}};

    wire wd_estourou = &wd;

    always @(posedge clk_i) begin
        drp_en <= 1'b0;

        if (!rstn_i) begin
            v_st    <= V_PEDE;
            v_idx   <= 2'd0;
            viu_eos <= 1'b0;
            volta   <= 1'b0;
            valid_o <= 1'b0;
            wd      <= {WD_BITS{1'b0}};
        end else begin
            if (eos) begin
                viu_eos <= 1'b1;
                wd      <= {WD_BITS{1'b0}};
            end else if (!wd_estourou) begin
                wd      <= wd + 1'b1;
            end

            case (v_st)
                V_PEDE: begin
                    case (v_idx)
                        2'd0:    drp_addr <= DRP_TEMP;
                        2'd1:    drp_addr <= DRP_VCCINT;
                        2'd2:    drp_addr <= DRP_VCCAUX;
                        default: drp_addr <= DRP_VCCBRAM;
                    endcase
                    drp_en <= 1'b1;
                    v_st   <= V_ESPERA;
                    if (v_idx == 2'd0 && viu_eos) begin
                        volta <= 1'b1;
                    end
                end
                default: begin
                    if (drp_rdy) begin
                        case (v_idx)
                            2'd0:    temp_o    <= drp_do[15:4];
                            2'd1:    vccint_o  <= drp_do[15:4];
                            2'd2:    vccaux_o  <= drp_do[15:4];
                            default: vccbram_o <= drp_do[15:4];
                        endcase
                        if (v_idx == 2'd3 && volta) begin
                            valid_o <= 1'b1;
                        end
                        v_idx <= v_idx + 2'd1;
                        v_st  <= V_PEDE;
                    end
                end
            endcase
        end
    end

    // ------------------------------------------------------------------
    // Condicao agora, e a retencao
    // ------------------------------------------------------------------
    wire frio = valid_o & (temp_o < COD_0C);

    // O watchdog vale mesmo sem valid_o: sensor que nunca respondeu tambem
    // e sensor parado.
    assign live_o = { wd_estourou, frio,
                      alm[3] & valid_o, alm[2] & valid_o,
                      alm[1] & valid_o, alm[0] & valid_o };

    // Sincronismo: ALM vem do DCLK, que e clk_i. Nao ha cruzamento.
    reg [5:0] sticky = 6'd0;      // SEM reset, de proposito

    always @(posedge clk_i) begin
        sticky <= sticky | live_o;
    end

    assign sticky_o = sticky;

endmodule
