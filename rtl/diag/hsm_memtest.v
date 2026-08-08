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
//   hsm_diag_top   0 Block RAM (antes deste arquivo)
//   hsm_top        4 Block RAM  <- IMEM (ROM de instrucao) e DMEM
//
// Se a Block RAM nao guardar o valor inicial que o bitstream escreveu, a
// CPU busca lixo, executa lixo, e o dispositivo fica mudo.
//
// O detalhe importante: a CONFIGURACAO continuaria perfeita. O CRC do
// bitstream cobre os dados transmitidos, nao o estado das celulas depois
// de gravadas. Done = 1 e No CRC error convivem sem problema com uma
// BRAM que nao reteve o conteudo.
//
// ---------------------------------------------------------------------
// DOIS TESTES, E POR QUE NAO UM
//
//   ROM  le memoria INICIALIZADA PELO BITSTREAM e compara com o valor
//        recalculado fora dela. E o que a IMEM depende: o conteudo
//        inicial ter chegado.
//
//   RW   escreve e le de volta em tempo de execucao. Testa a celula como
//        memoria, sem depender da inicializacao.
//
// ROM falhando com RW passando = a celula funciona e a INICIALIZACAO nao
// pegou. Sao defeitos diferentes com consertos diferentes, e a distincao
// separa "troque a placa" de "o fluxo de build esta errado".
//
// ---------------------------------------------------------------------
// POR QUE O PADRAO E UM LFSR, E NAO UMA FUNCAO DO ENDERECO
//
// A primeira versao preenchia a ROM com f(endereco) -- um produto e um
// XOR. O Vivado percebeu que a memoria era uma funcao calculavel, JOGOU
// A MEMORIA FORA e passou a computar o valor com um DSP, que absorveu um
// registrador a mais e desalinhou a comparacao em um ciclo. Resultado em
// hardware: 512 erros de 512, com a BRAM perfeitamente sadia.
//
// O instrumento acusou defeito onde nao havia -- que e a pior falha
// possivel num instrumento, porque manda trocar hardware bom. E nao
// aparecia em simulacao, onde nao existe otimizacao de sintese.
//
// Sequencia de LFSR nao tem forma fechada em funcao do indice: para
// substituir a memoria por logica a ferramenta teria de desenrolar 512
// passos. Entao ela mantem a memoria, que e o que precisamos testar.
//
// O comparador guarda o SEU proprio LFSR, em registrador, andando em
// travamento com o endereco. Compara BRAM contra flip-flop -- nunca BRAM
// contra BRAM, que passaria com as duas igualmente corrompidas.
//
module hsm_memtest #(
    parameter integer N    = 512,              // palavras de 32 bits
    parameter [31:0]  SEED = 32'h1234_5678     // semente do padrao
)(
    input  wire        clk_i,
    input  wire        rstn_i,
    output reg         done_o,
    output reg  [15:0] erros_rom_o,
    output reg  [15:0] erros_rw_o,

    // Uma palavra da ROM, crua, capturada na QUINTA leitura valida.
    //
    // Nao e a primeira de proposito. A primeira nao decide nada: se a
    // memoria tiver um ciclo de latencia a mais que o esperado, a
    // primeira captura pega o valor de RESET do registrador de saida --
    // zero -- e zero tambem e o que uma inicializacao que nao pegou
    // produz. Dois defeitos opostos, mesmo numero.
    //
    // Na quinta leitura o valor de reset ja saiu do pipeline. Entao:
    //   valor da sequencia (rom[3] ou rom[4]) -> memoria BOA, comparador
    //                                            desalinhado
    //   zero                                  -> inicializacao NAO pegou
    output reg  [31:0] primeira_o
);

    localparam integer AW = $clog2(N);

    // Um passo do LFSR de 32 bits, polinomio maximal x^32+x^22+x^2+x+1.
    function [31:0] passo(input [31:0] s);
        passo = {s[30:0], s[31] ^ s[21] ^ s[1] ^ s[0]};
    endfunction

    (* rom_style = "block" *) reg [31:0] rom [0:N-1];
    (* ram_style = "block" *) reg [31:0] ram [0:N-1];

    integer k;
    reg [31:0] semeia;
    initial begin
        semeia = SEED;
        for (k = 0; k < N; k = k + 1) begin
            rom[k] = semeia;
            semeia = passo(semeia);
        end
    end

    reg [AW:0]  addr;
    reg [1:0]   fase;
    reg [31:0]  rom_q, ram_q;
    reg [31:0]  lfsr, esperado_d1;
    reg         valida;
    reg         capturou;
    reg [2:0]   nleituras;

    localparam [1:0] F_ROM = 2'd0, F_ESCREVE = 2'd1, F_LE = 2'd2, F_FIM = 2'd3;

    always @(posedge clk_i) begin
        if (!rstn_i) begin
            addr        <= {(AW+1){1'b0}};
            fase        <= F_ROM;
            done_o      <= 1'b0;
            erros_rom_o <= 16'd0;
            erros_rw_o  <= 16'd0;
            lfsr        <= SEED;
            esperado_d1 <= 32'd0;
            valida      <= 1'b0;
            primeira_o  <= 32'd0;
            capturou    <= 1'b0;
            nleituras   <= 3'd0;
        end else begin
            // Leitura sincrona: o dado sai um ciclo depois do endereco.
            // esperado_d1 anda junto, para a comparacao casar em fase.
            rom_q       <= rom[addr[AW-1:0]];
            ram_q       <= ram[addr[AW-1:0]];
            esperado_d1 <= lfsr;

            case (fase)
                F_ROM: begin
                    valida <= 1'b1;
                    if (valida && !capturou) begin
                        if (nleituras == 3'd4) begin
                            primeira_o <= rom_q;
                            capturou   <= 1'b1;
                        end else begin
                            nleituras <= nleituras + 3'd1;
                        end
                    end
                    if (valida && (rom_q !== esperado_d1))
                        erros_rom_o <= erros_rom_o + 16'd1;

                    if (addr == N) begin
                        addr   <= {(AW+1){1'b0}};
                        lfsr   <= SEED;
                        fase   <= F_ESCREVE;
                        valida <= 1'b0;
                    end else begin
                        addr <= addr + 1'b1;
                        lfsr <= passo(lfsr);
                    end
                end

                F_ESCREVE: begin
                    // Grava o COMPLEMENTO do padrao: se a celula devolvesse
                    // o valor inicial em vez do escrito, a fase de leitura
                    // acusaria -- um teste que escreve o mesmo valor que ja
                    // esta la nao prova escrita nenhuma.
                    ram[addr[AW-1:0]] <= ~lfsr;
                    if (addr == N - 1) begin
                        addr <= {(AW+1){1'b0}};
                        lfsr <= SEED;
                        fase <= F_LE;
                    end else begin
                        addr <= addr + 1'b1;
                        lfsr <= passo(lfsr);
                    end
                end

                F_LE: begin
                    valida <= 1'b1;
                    if (valida && (ram_q !== ~esperado_d1))
                        erros_rw_o <= erros_rw_o + 16'd1;

                    if (addr == N) begin
                        fase   <= F_FIM;
                        valida <= 1'b0;
                    end else begin
                        addr <= addr + 1'b1;
                        lfsr <= passo(lfsr);
                    end
                end

                default: done_o <= 1'b1;   // F_FIM: para e mantem o placar
            endcase
        end
    end

endmodule
