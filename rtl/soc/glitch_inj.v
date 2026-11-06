`timescale 1ns/1ps
//
// glitch_inj.v -- injetor de falha de clock (fase 6, so no bitstream de ataque)
//
// Faz o papel do equipamento externo de quem ataca: escuta a linha RX e, numa
// contagem de bytes escolhida, troca o clock do SoC por um mais rapido durante
// alguns ciclos. Fica fora do bitstream de producao (`HSM_ATAQUE`), e nao fala
// com a CPU: o firmware atacado e o mesmo que vai para a placa.
//
// Configura-se por um frame com opcode desconhecido, que o firmware recusa:
//
//   CMD 0xF7 | 'G' | 'L' | ATRASO(3) | LARGURA(1) | BYTES(2)
//
// Depois do CRC desse frame ele fica armado. No fim do byte numero BYTES do
// proximo pedido espera ATRASO ciclos e liga o clock rapido por LARGURA ciclos
// desse clock. Dispara uma vez e desarma.
//
module glitch_inj #(
    parameter integer BIT_CICLOS = 868     // 100 MHz / 115200
)(
    input  wire clk_i,
    input  wire rstn_i,
    input  wire rxd_i,
    output reg  glitch_o = 1'b0
);

    // ---- receptor 8N1 ---------------------------------------------------
    (* ASYNC_REG = "TRUE" *) reg [1:0] rx_q = 2'b11;
    reg [10:0] tempo = 11'd0;
    reg [3:0]  bits  = 4'd0;      // 0 = parado; 1..8 dados; 9 stop
    reg [7:0]  dado  = 8'd0;
    reg        byte_ok = 1'b0;

    always @(posedge clk_i) begin
        rx_q    <= {rx_q[0], rxd_i};
        byte_ok <= 1'b0;

        if (!rstn_i) begin
            bits <= 4'd0;
        end else if (bits == 4'd0) begin
            if (!rx_q[1]) begin
                bits  <= 4'd1;
                tempo <= (BIT_CICLOS * 3 / 2) - 1;   // meio do primeiro dado
            end
        end else if (tempo != 11'd0) begin
            tempo <= tempo - 11'd1;
        end else if (bits == 4'd9) begin
            byte_ok <= 1'b1;                         // meio do stop
            bits    <= 4'd0;
        end else begin
            dado  <= {rx_q[1], dado[7:1]};
            bits  <= bits + 4'd1;
            tempo <= BIT_CICLOS - 1;
        end
    end

    // ---- configuracao e disparo ----------------------------------------
    localparam [1:0] E_LIVRE = 2'd0, E_CRC = 2'd1, E_ARMADO = 2'd2, E_ATRASO = 2'd3;

    reg [1:0]  estado  = E_LIVRE;
    reg [63:0] janela  = 64'd0;   // ultimos 8 bytes
    reg [2:0]  crc_cnt = 3'd0;
    reg [23:0] atraso  = 24'd0;
    reg [7:0]  largura = 8'd0;
    reg [15:0] alvo    = 16'd0;
    reg [15:0] vistos  = 16'd0;
    reg [7:0]  ligado  = 8'd0;

    wire [71:0] com_novo = {janela, dado};

    always @(posedge clk_i) begin
        if (!rstn_i) begin
            estado   <= E_LIVRE;
            janela   <= 64'd0;
            ligado   <= 8'd0;
            glitch_o <= 1'b0;
        end else begin
            if (byte_ok) janela <= com_novo[63:0];

            // A contagem de largura corre no proprio clock rapido.
            if (ligado != 8'd0) begin
                ligado <= ligado - 8'd1;
                if (ligado == 8'd1) glitch_o <= 1'b0;
            end

            case (estado)
                E_LIVRE: begin
                    if (byte_ok && com_novo[71:48] == {8'hF7, "GL"}) begin
                        atraso  <= com_novo[47:24];
                        largura <= com_novo[23:16];
                        alvo    <= com_novo[15:0];
                        crc_cnt <= 3'd4;
                        estado  <= E_CRC;
                    end
                end
                E_CRC: begin
                    if (byte_ok) begin
                        crc_cnt <= crc_cnt - 3'd1;
                        if (crc_cnt == 3'd1) begin
                            vistos <= 16'd0;
                            estado <= E_ARMADO;
                        end
                    end
                end
                E_ARMADO: begin
                    if (byte_ok) begin
                        vistos <= vistos + 16'd1;
                        if (vistos + 16'd1 == alvo) estado <= E_ATRASO;
                    end
                end
                default: begin
                    if (atraso != 24'd0) begin
                        atraso <= atraso - 24'd1;
                    end else begin
                        if (largura != 8'd0) begin
                            glitch_o <= 1'b1;
                            ligado   <= largura;
                        end
                        estado <= E_LIVRE;
                    end
                end
            endcase
        end
    end

endmodule
