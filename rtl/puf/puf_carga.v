`timescale 1ns/1ps
//
// puf_carga.v -- carga termica: aneis de flip-flops com todo bit alternando
//
// Aquece o die para a medida de deriva (doc/puf-experimento.md, secao 5). Cada
// banco liga por um bit de en_i. DONT_TOUCH impede a sintese de fundir os
// flip-flops iguais, e shreg_extract impede de virar SRL, que nao aqueceria.
//
module puf_carga #(
    parameter integer BANCOS = 8,
    parameter integer LARGURA = 2560
)(
    input  wire              clk_i,
    input  wire [BANCOS-1:0] en_i,
    output wire              vivo_o
);

    wire [BANCOS-1:0] pontas;

    genvar b;
    generate
        for (b = 0; b < BANCOS; b = b + 1) begin : g_banco
            (* DONT_TOUCH = "true", shreg_extract = "no" *)
            reg [LARGURA-1:0] r = {(LARGURA/2){2'b10}};
            reg en_q = 1'b0;

            always @(posedge clk_i) begin
                en_q <= en_i[b];
                if (en_q) r <= {r[LARGURA-2:0], r[LARGURA-1]};
            end

            assign pontas[b] = r[0];
        end
    endgenerate

    assign vivo_o = ^pontas;

endmodule
