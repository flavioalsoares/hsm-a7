`timescale 1ns/1ps
//
// ro_puf.v -- oscilador em anel para o experimento de PUF (fase 6)
// EXPERIMENTAL / EDUCACIONAL. Nao usar como fonte de chave.
// Ver doc/puf-experimento.md
//
// REGRA DE SEGURANCA: apenas o par sob medicao pode ter en_i ativo.
// Nunca habilitar todos os anéis simultaneamente (calor + ruido de alimentacao).
//
module ro_cell #(
    parameter STAGES = 7          // impar, 5..9
)(
    input  wire en_i,
    output wire osc_o
);
    (* DONT_TOUCH = "TRUE" *) wire [STAGES:0] chain;

    // primeiro estagio: AND de enable fecha o anel
    (* DONT_TOUCH = "TRUE" *) LUT2 #(.INIT(4'b0100)) u_gate (
        .O(chain[0]), .I0(chain[STAGES]), .I1(en_i)
    );

    genvar i;
    generate
      for (i = 0; i < STAGES; i = i + 1) begin : g_inv
        (* DONT_TOUCH = "TRUE" *) LUT1 #(.INIT(2'b01)) u_inv (
            .O(chain[i+1]), .I0(chain[i])
        );
      end
    endgenerate

    assign osc_o = chain[STAGES];
endmodule

//
// TODO: contador de janela, MUX de selecao de par, comparador.
// TODO: LOC/pblock identicos por instancia -- sem isso o experimento mede
//       assimetria de roteamento, nao variacao de silicio.
//
