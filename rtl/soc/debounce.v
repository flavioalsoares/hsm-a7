`timescale 1ns/1ps
//
// debounce.v -- filtro de ressalto para contato mecanico
//
// A entrada precisa chegar JA SINCRONIZADA ao dominio de clk_i. Este
// modulo nao faz sincronizacao; ele so exige estabilidade.
//
// Regra: a saida so acompanha a entrada depois que ela ficou diferente
// da saida por STABLE_CYCLES ciclos CONSECUTIVOS. Qualquer transicao no
// meio zera a contagem.
//
// Por que isto e um modulo de seguranca, e nao um detalhe de UX: os dois
// botoes autorizam LMK_LOAD_COMPONENT (dual control, PLANO secao 4). Um
// ressalto de contato lido como pressionamento vale por uma autorizacao
// que ninguem deu. O custodiante que soltou o botao nao consentiu com o
// segundo pulso.
//
module debounce #(
    // Ciclos de estabilidade exigidos. 10 ms a 100 MHz cobre com folga o
    // ressalto tipico de tactile switch (1 a 5 ms).
    parameter integer STABLE_CYCLES = 1_000_000
)(
    input  wire clk_i,
    input  wire rst_n_i,     // sincrono, ativo baixo
    input  wire d_i,         // ja sincronizado, ativo alto
    output reg  q_o
);

    reg [31:0] cnt = 32'd0;

    initial q_o = 1'b0;

    always @(posedge clk_i) begin
        if (!rst_n_i) begin
            cnt <= 32'd0;
            q_o <= 1'b0;
        end else if (d_i == q_o) begin
            // entrada concorda com a saida: nada a fazer
            cnt <= 32'd0;
        end else if (cnt == (STABLE_CYCLES - 1)) begin
            // ficou diferente tempo suficiente: aceita a mudanca
            cnt <= 32'd0;
            q_o <= d_i;
        end else begin
            cnt <= cnt + 32'd1;
        end
    end

endmodule
