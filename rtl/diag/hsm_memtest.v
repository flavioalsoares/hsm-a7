`timescale 1ns/1ps
//
// hsm_memtest.v -- teste de Block RAM para o bitstream de diagnostico.
//
// ---------------------------------------------------------------------
// A HIPOTESE QUE ELE EXISTE PARA REPROVAR
//
// O bitstream de diagnostico fala pela UART e pisca os cinco LEDs, e
// mesmo assim o hsm_top fica mudo com a CPU sem executar uma instrucao.
// A diferenca estrutural entre os dois designs e curta:
//
//   hsm_diag_top   0 Block RAM
//   hsm_top        4 Block RAM  <- IMEM (ROM de instrucao) e DMEM
//
// Se a Block RAM nao guardar o valor inicial que o bitstream escreveu, a
// CPU busca lixo, executa lixo, e o dispositivo fica mudo. E o
// diagnostico anterior nao pegaria isso, porque nao usa BRAM nenhuma.
//
// O detalhe importante: a CONFIGURACAO continuaria perfeita. O CRC do
// bitstream cobre os dados transmitidos, nao o estado das celulas depois
// de gravadas. Done = 1 e No CRC error convivem sem problema com uma
// BRAM que nao reteve o conteudo -- que e exatamente o sintoma que
// estamos perseguindo.
//
// ---------------------------------------------------------------------
// O QUE ELE MEDE, E POR QUE SAO DOIS TESTES E NAO UM
//
//   ROM  le uma memoria INICIALIZADA PELO BITSTREAM e compara com o
//        mesmo valor recalculado em logica combinacional (LUT). Testa
//        justamente o que a IMEM depende: o conteudo inicial ter chegado.
//
//   RW   escreve e le de volta em tempo de execucao. Testa a celula como
//        memoria, sem depender da inicializacao.
//
// Separar importa: ROM falhando com RW passando significa que a celula
// funciona e a INICIALIZACAO e que nao pegou -- outro defeito, outro
// conserto. Um teste so nao distingue os dois, e a distincao aqui e a
// diferenca entre "troque a placa" e "o fluxo de build esta errado".
//
// A comparacao e contra LUT de proposito: comparar BRAM com BRAM passaria
// com as duas igualmente corrompidas.
//
module hsm_memtest #(
    parameter integer N = 512          // palavras de 32 bits em cada memoria
)(
    input  wire        clk_i,
    input  wire        rstn_i,
    output reg         done_o,
    output reg  [15:0] erros_rom_o,
    output reg  [15:0] erros_rw_o
);

    // Gerador do padrao. Constante de Knuth; qualquer sequencia serve,
    // desde que NAO seja trivial: um padrao de zeros passaria numa BRAM
    // que devolve zero por estar morta.
    function [31:0] padrao(input [31:0] i);
        padrao = (i * 32'h9E37_79B9) ^ {i[15:0], ~i[15:0]};
    endfunction

    localparam integer AW = $clog2(N);

    (* rom_style = "block" *) reg [31:0] rom [0:N-1];
    (* ram_style = "block" *) reg [31:0] ram [0:N-1];

    integer k;
    initial begin
        for (k = 0; k < N; k = k + 1)
            rom[k] = padrao(k[31:0]);
    end

    reg [AW:0]  addr;
    reg [1:0]   fase;
    reg [31:0]  rom_q, ram_q;
    reg [31:0]  addr_d1;
    reg         valida;

    localparam [1:0] F_ROM = 2'd0, F_ESCREVE = 2'd1, F_LE = 2'd2, F_FIM = 2'd3;

    always @(posedge clk_i) begin
        if (!rstn_i) begin
            addr        <= {(AW+1){1'b0}};
            fase        <= F_ROM;
            done_o      <= 1'b0;
            erros_rom_o <= 16'd0;
            erros_rw_o  <= 16'd0;
            valida      <= 1'b0;
        end else begin
            // Leitura sincrona: o dado chega um ciclo depois do endereco,
            // entao a comparacao anda atrasada de um ciclo junto com ele.
            rom_q   <= rom[addr[AW-1:0]];
            ram_q   <= ram[addr[AW-1:0]];
            addr_d1 <= {{(32-AW){1'b0}}, addr[AW-1:0]};

            case (fase)
                F_ROM: begin
                    valida <= 1'b1;
                    if (valida && (rom_q !== padrao(addr_d1)))
                        erros_rom_o <= erros_rom_o + 16'd1;
                    if (addr == N) begin
                        addr   <= {(AW+1){1'b0}};
                        fase   <= F_ESCREVE;
                        valida <= 1'b0;
                    end else begin
                        addr <= addr + 1'b1;
                    end
                end

                F_ESCREVE: begin
                    ram[addr[AW-1:0]] <= ~padrao({{(32-AW){1'b0}}, addr[AW-1:0]});
                    if (addr == N - 1) begin
                        addr <= {(AW+1){1'b0}};
                        fase <= F_LE;
                    end else begin
                        addr <= addr + 1'b1;
                    end
                end

                F_LE: begin
                    valida <= 1'b1;
                    if (valida && (ram_q !== ~padrao(addr_d1)))
                        erros_rw_o <= erros_rw_o + 16'd1;
                    if (addr == N) begin
                        fase   <= F_FIM;
                        valida <= 1'b0;
                    end else begin
                        addr <= addr + 1'b1;
                    end
                end

                default: done_o <= 1'b1;   // F_FIM: para e mantem o placar
            endcase
        end
    end

endmodule
