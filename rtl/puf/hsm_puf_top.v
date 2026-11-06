`timescale 1ns/1ps
//
// hsm_puf_top.v -- experimento de RO-PUF (fase 6). NAO E O HSM.
//
// Bitstream separado, sem CPU e sem chave nenhuma. Mede a frequencia de 64
// aneis, um de cada vez, e entrega as contagens. Formar bits, escolher pares e
// calcular as metricas fica em host/puf.py. Ver doc/puf-experimento.md.
//
// Sem CPU nao ha IMEM, entao ele carrega por JTAG, na SRAM, e nao toca a flash.
//
// Protocolo, UART 115200 8N1. Um byte de comando, resposta de tamanho fixo:
//
//   'V'      -> "PUF1"
//   'T'      -> 'T' TEMP(2) ESTADO
//   'U'      -> 'U' VCCINT(2) ESTADO
//   'C' n    -> 'K' NIVEL TEMP(2): liga n bancos de carga (0..8)
//   'S'      -> 'S' TEMP(2) 64, 64 x CONTAGEM(3), 'E' TEMP(2) ESTADO
//
// TEMP e VCCINT sao codigos de 12 bits do XADC. ESTADO: bit 0 temperatura boa,
// bit 1 um limite foi atingido desde o ultimo 'T', bit 2 MMCM travado, bit 3
// VCCINT boa.
//
// SEGURANCA (doc/puf-experimento.md, secao 3): um anel ligado por vez, janela
// de 1 ms, e nada liga sem leitura valida abaixo de 70 C. Acima disso a carga
// desliga, e a varredura devolve FFFFFF sem ligar o anel. Com VCCINT abaixo de
// 0,95 V, o piso do DS181, a carga tambem desliga. A guarda fica aqui, no
// hardware, e nao depende do host.
//
module hsm_puf_top #(
    parameter integer BAUD_DIV = 868,        // 100 MHz / 115200
    parameter integer JANELA   = 100_000,    // 1 ms
    parameter integer ASSENTA  = 64,         // ciclos ate a contagem parar
    parameter integer WD_BITS  = 24
)(
    input  wire       sys_clk_i,
    input  wire       rst_n_i,
    input  wire       uart_rxd_i,
    output wire       uart_txd_o,
    input  wire       btn_a_i,
    input  wire       btn_b_i,
    output wire [4:0] led_o,
    output wire [7:0] seg_o,
    output wire [2:0] seg_an_o
);

    localparam integer N_RO = 64;

    // (70 + 273,15) * 4096 / 503,975 = 2788,96
    localparam [11:0] COD_LIMITE = 12'd2789;

    // 0,95 * 4096 / 3 = 1297,07
    localparam [11:0] COD_VCC_MIN = 12'd1297;

    wire clk, rst_n, locked, lock_perdido;

    clk_rst_gen u_clk (
        .clk_in_i       (sys_clk_i),
        .rst_n_i        (rst_n_i),
        .clk_o          (clk),
        .rst_n_o        (rst_n),
        .locked_o       (locked),
        .lock_perdido_o (lock_perdido)
    );

    // ---- temperatura ----------------------------------------------------
    wire        xadc_ok;
    wire [11:0] temp;
    wire [11:0] vccint;
    wire [5:0]  xadc_agora;

    hsm_xadc #(.WD_BITS(WD_BITS)) u_xadc (
        .clk_i     (clk),
        .rstn_i    (rst_n),
        .valid_o   (xadc_ok),
        .sticky_o  (),
        .live_o    (xadc_agora),
        .temp_o    (temp),
        .vccint_o  (vccint),
        .vccaux_o  (),
        .vccbram_o ()
    );

    // Sensor parado conta como temperatura ruim: a ultima leitura envelheceu.
    wire temp_boa = xadc_ok && !xadc_agora[5] && (temp < COD_LIMITE);
    wire vcc_boa  = xadc_ok && !xadc_agora[5] && (vccint >= COD_VCC_MIN);
    wire pode_carga = temp_boa && vcc_boa;

    // ---- aneis e contador -----------------------------------------------
    reg  [N_RO-1:0] en = {N_RO{1'b0}};
    wire [N_RO-1:0] ro;

    genvar i;
    generate
        for (i = 0; i < N_RO; i = i + 1) begin : g_ro
            puf_ro #(.IDX(i)) u_ro (.en_i(en[i]), .ro_o(ro[i]));
        end
    endgenerate

    // Com um anel ligado, o OR e esse anel. A contagem so e lida depois de o
    // anel parar e de ASSENTA ciclos, entao o dado cruza de dominio parado.
    wire ro_clk;
`ifdef HSM_PUF_SIM
    assign ro_clk = |ro;
`else
    BUFG u_ro_bufg (.I(|ro), .O(ro_clk));
`endif

    reg         limpa = 1'b1;
    reg  [23:0] conta = 24'd0;

    always @(posedge ro_clk or posedge limpa) begin
        if (limpa) conta <= 24'd0;
        else       conta <= conta + 24'd1;
    end

    // ---- carga ----------------------------------------------------------
    reg  [3:0] nivel = 4'd0;
    reg  [7:0] carga_en = 8'd0;
    wire       carga_vivo;

    always @(posedge clk) begin
        case (nivel)
            4'd0:    carga_en <= 8'h00;
            4'd1:    carga_en <= 8'h01;
            4'd2:    carga_en <= 8'h03;
            4'd3:    carga_en <= 8'h07;
            4'd4:    carga_en <= 8'h0F;
            4'd5:    carga_en <= 8'h1F;
            4'd6:    carga_en <= 8'h3F;
            4'd7:    carga_en <= 8'h7F;
            default: carga_en <= 8'hFF;
        endcase
    end

    puf_carga u_carga (.clk_i(clk), .en_i(carga_en), .vivo_o(carga_vivo));

    // ---- UART -----------------------------------------------------------
    (* ASYNC_REG = "TRUE" *) reg [2:0] rx_sync = 3'b111;
    reg [3:0]  rx_bits = 4'd0;
    reg [15:0] rx_cnt  = 16'd0;
    reg [7:0]  rx_sr   = 8'd0;
    reg [7:0]  rx_byte = 8'd0;
    reg        rx_ok   = 1'b0;

    always @(posedge clk) begin
        rx_sync <= {rx_sync[1:0], uart_rxd_i};
        rx_ok   <= 1'b0;

        if (!rst_n) begin
            rx_bits <= 4'd0;
        end else if (rx_bits == 4'd0) begin
            if (!rx_sync[2]) begin
                rx_bits <= 4'd9;
                rx_cnt  <= (3 * BAUD_DIV) / 2 - 1;
            end
        end else if (rx_cnt != 16'd0) begin
            rx_cnt <= rx_cnt - 16'd1;
        end else begin
            rx_cnt  <= BAUD_DIV - 1;
            rx_bits <= rx_bits - 4'd1;
            if (rx_bits == 4'd1) begin
                rx_byte <= rx_sr;
                rx_ok   <= 1'b1;
            end else begin
                rx_sr <= {rx_sync[2], rx_sr[7:1]};
            end
        end
    end

    reg [9:0]  tx_sr   = 10'h3FF;
    reg [3:0]  tx_bits = 4'd0;
    reg [15:0] tx_cnt  = 16'd0;
    reg        tx_vai  = 1'b0;
    reg [7:0]  tx_byte = 8'd0;
    wire       tx_livre = (tx_bits == 4'd0);

    always @(posedge clk) begin
        if (!rst_n) begin
            tx_sr   <= 10'h3FF;
            tx_bits <= 4'd0;
        end else if (tx_livre) begin
            if (tx_vai) begin
                tx_sr   <= {1'b1, tx_byte, 1'b0};
                tx_bits <= 4'd10;
                tx_cnt  <= BAUD_DIV - 1;
            end
        end else if (tx_cnt != 16'd0) begin
            tx_cnt <= tx_cnt - 16'd1;
        end else begin
            tx_cnt  <= BAUD_DIV - 1;
            tx_sr   <= {1'b1, tx_sr[9:1]};
            tx_bits <= tx_bits - 4'd1;
        end
    end

    assign uart_txd_o = tx_sr[0];

    // ---- controle -------------------------------------------------------
    localparam [3:0] E_LIVRE = 4'd0, E_NIVEL = 4'd1, E_ENVIA = 4'd2,
                     E_ESPERA_TX = 4'd3, E_ANEL = 4'd4, E_LIGA = 4'd5,
                     E_JANELA = 4'd6, E_ASSENTA = 4'd7;

    reg [3:0]  estado  = E_LIVRE;
    reg [3:0]  depois  = E_LIVRE;
    reg [31:0] fila    = 32'd0;
    reg [2:0]  n_fila  = 3'd0;
    reg [6:0]  idx     = 7'd0;
    reg [23:0] tempo   = 24'd0;
    reg        atingiu = 1'b0;

    wire [15:0] temp16 = {4'd0, temp};
    wire [15:0] vcc16  = {4'd0, vccint};
    wire [7:0]  situacao = {4'd0, vcc_boa, locked, atingiu, temp_boa};

    always @(posedge clk) begin
        tx_vai <= 1'b0;

        if (!rst_n) begin
            estado  <= E_LIVRE;
            en      <= {N_RO{1'b0}};
            limpa   <= 1'b1;
            nivel   <= 4'd0;
            atingiu <= 1'b0;
        end else begin
            // A guarda vale em qualquer estado.
            if (xadc_ok && !pode_carga) begin
                nivel   <= 4'd0;
                atingiu <= 1'b1;
            end

            case (estado)
                E_LIVRE: begin
                    if (rx_ok) begin
                        case (rx_byte)
                            "V": begin
                                fila <= "PUF1"; n_fila <= 3'd4;
                                depois <= E_LIVRE; estado <= E_ENVIA;
                            end
                            "T": begin
                                fila <= {"T", temp16, situacao}; n_fila <= 3'd4;
                                atingiu <= !pode_carga;
                                depois <= E_LIVRE; estado <= E_ENVIA;
                            end
                            "U": begin
                                fila <= {"U", vcc16, situacao}; n_fila <= 3'd4;
                                depois <= E_LIVRE; estado <= E_ENVIA;
                            end
                            "C": estado <= E_NIVEL;
                            "S": begin
                                fila <= {"S", temp16, 8'd64}; n_fila <= 3'd4;
                                idx <= 7'd0;
                                depois <= E_ANEL; estado <= E_ENVIA;
                            end
                            default: ;
                        endcase
                    end
                end

                E_NIVEL: begin
                    if (rx_ok) begin
                        // A guarda acima vence esta atribuicao no ciclo
                        // seguinte, se a temperatura nao estiver boa.
                        if (pode_carga)
                            nivel <= (rx_byte > 8'd8) ? 4'd8 : rx_byte[3:0];
                        fila <= {"K", 4'd0, (pode_carga ? ((rx_byte > 8'd8) ? 4'd8 : rx_byte[3:0]) : 4'd0),
                                 temp16};
                        n_fila <= 3'd4;
                        depois <= E_LIVRE; estado <= E_ENVIA;
                    end
                end

                E_ENVIA: begin
                    if (n_fila == 3'd0) begin
                        estado <= depois;
                    end else if (tx_livre && !tx_vai) begin
                        tx_byte <= fila[31:24];
                        tx_vai  <= 1'b1;
                        fila    <= {fila[23:0], 8'd0};
                        n_fila  <= n_fila - 3'd1;
                        estado  <= E_ESPERA_TX;
                    end
                end

                E_ESPERA_TX: begin
                    if (!tx_livre) estado <= E_ENVIA;
                end

                E_ANEL: begin
                    if (idx == N_RO) begin
                        fila <= {"E", temp16, situacao}; n_fila <= 3'd4;
                        depois <= E_LIVRE; estado <= E_ENVIA;
                    end else if (!temp_boa) begin
                        fila <= {24'hFFFFFF, 8'd0}; n_fila <= 3'd3;
                        idx <= idx + 7'd1;
                        depois <= E_ANEL; estado <= E_ENVIA;
                    end else begin
                        limpa  <= 1'b1;
                        tempo  <= ASSENTA;
                        estado <= E_LIGA;
                    end
                end

                E_LIGA: begin
                    if (tempo != 24'd0) begin
                        tempo <= tempo - 24'd1;
                    end else begin
                        limpa   <= 1'b0;
                        en[idx[5:0]] <= 1'b1;
                        tempo   <= JANELA - 1;
                        estado  <= E_JANELA;
                    end
                end

                E_JANELA: begin
                    if (tempo != 24'd0 && temp_boa) begin
                        tempo <= tempo - 24'd1;
                    end else begin
                        en     <= {N_RO{1'b0}};
                        tempo  <= ASSENTA;
                        estado <= E_ASSENTA;
                    end
                end

                E_ASSENTA: begin
                    if (tempo != 24'd0) begin
                        tempo <= tempo - 24'd1;
                    end else begin
                        fila <= {conta, 8'd0}; n_fila <= 3'd3;
                        idx  <= idx + 7'd1;
                        depois <= E_ANEL; estado <= E_ENVIA;
                    end
                end

                default: estado <= E_LIVRE;
            endcase
        end
    end

    // ---- painel ---------------------------------------------------------
    reg [25:0] pisca = 26'd0;
    always @(posedge clk) pisca <= pisca + 26'd1;

    // D1 vivo, D2 varrendo, D3 carga ligada, D4 limite atingido, D5 ponta da
    // carga: mantem a carga viva na sintese. Ativos baixos.
    assign led_o = ~{carga_vivo & (nivel != 4'd0), atingiu, nivel != 4'd0,
                     |en, pisca[25]};

    assign seg_o    = 8'hFF;
    assign seg_an_o = 3'b111;

    wire nao_usados = btn_a_i | btn_b_i | lock_perdido;

endmodule
