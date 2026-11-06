`timescale 1ns/1ps
//
// puf_ro.v -- um oscilador em anel: NAND de enable + seis inversores
//
// Sete inversoes, numero impar: o anel oscila enquanto en_i estiver alto. Com
// en_i baixo ele para, e s[1] fica em zero, o que deixa juntar as saidas de
// todos os aneis com um OR. Com o tampao, o anel ocupa os oito LUTs de um CLB.
//
// Cada estagio e um LUT explicito com DONT_TOUCH. Sem isso a sintese colapsa a
// cadeia. Quem posiciona os LUTs e scripts/build-puf.tcl.
//
// Simulacao RTL nao tem atraso de porta: um laco destes travaria o simulador.
// O modelo com HSM_PUF_SIM tem meio periodo proprio por anel, e prova o
// contador e o protocolo. Ele nao diz nada sobre o silicio.
//
module puf_ro #(
    parameter integer IDX = 0
)(
    input  wire en_i,
    output wire ro_o
);

`ifdef HSM_PUF_SIM

    localparam integer MEIO_PS = 3000 + ((IDX * 37) % 53);

    reg r = 1'b0;

    always @(posedge en_i) begin : oscila
        while (en_i) begin
            #(MEIO_PS / 1000.0) r = ~r;
        end
        r = 1'b0;
    end

    assign ro_o = r;

`else

    (* DONT_TOUCH = "true" *) wire [6:0] s;

    (* DONT_TOUCH = "true" *)
    LUT2 #(.INIT(4'b0111)) u_nand (.O(s[0]), .I0(en_i), .I1(s[6]));

    genvar k;
    generate
        for (k = 1; k < 7; k = k + 1) begin : g_inv
            (* DONT_TOUCH = "true" *)
            LUT1 #(.INIT(2'b01)) u_inv (.O(s[k]), .I0(s[k-1]));
        end
    endgenerate

    // Tampao: o caminho ate o OR varia de anel para anel e fica fora do laco.
    // O laco de todos os aneis ve a mesma carga.
    (* DONT_TOUCH = "true" *)
    LUT1 #(.INIT(2'b10)) u_tap (.O(ro_o), .I0(s[1]));

`endif

endmodule
