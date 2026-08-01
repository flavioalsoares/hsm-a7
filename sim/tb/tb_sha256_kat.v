`timescale 1ns/1ps
//
// tb_sha256_kat -- SHA-256 contra os vetores oficiais do NIST (CAVP/SHAVS)
//
// Regra do projeto: nada vai para a placa sem passar antes aqui. E a regra
// inviolavel numero 5: se um KAT falha, o bug esta no codigo, nao no vetor.
//
// 65 mensagens de SHA256ShortMsg.rsp, de 0 a 512 bits, cobrindo mensagem
// vazia, mensagens de um bloco e mensagens que transbordam para dois blocos
// por causa do preenchimento.
//
// DIVISAO DE RESPONSABILIDADE, e ela importa: o sha256_core opera sobre
// blocos de 512 bits ja preenchidos e NAO implementa padding. Quem preenche
// e quem chama -- aqui, scripts/mkvectors.py; no dispositivo, o firmware.
// Testar o core com o padding embutido misturaria duas coisas que falham
// por motivos diferentes.
//
// O caso da mensagem vazia e o mais instrutivo: ela vira um bloco inteiro
// de padding, e o digest esperado e o e3b0c442... conhecido. Se o padding
// estiver errado, e esse o primeiro vetor a cair.
//
`include "counts.vh"

module tb_sha256_kat;

    localparam CLK_HALF = 5;          // 100 MHz

    // 74 blocos para as 65 mensagens (algumas ocupam dois).
    localparam MAX_BLOCOS = 256;

    reg          clk = 1'b0;
    reg          reset_n = 1'b0;

    reg          init = 1'b0;
    reg          next = 1'b0;
    reg          mode = 1'b1;         // 1 = SHA-256 (0 seria SHA-224)
    reg  [511:0] block;

    wire         ready;
    wire [255:0] digest;
    wire         digest_valid;

    integer erros = 0;
    integer i, b, base;

    always #CLK_HALF clk = ~clk;

    sha256_core dut (
        .clk          (clk),
        .reset_n      (reset_n),
        .init         (init),
        .next         (next),
        .mode         (mode),
        .block        (block),
        .ready        (ready),
        .digest       (digest),
        .digest_valid (digest_valid)
    );

    // ------------------------------------------------------------------
    reg [511:0] blocos  [0:MAX_BLOCOS-1];
    reg [31:0]  nblocos [0:`N_SHA256-1];
    reg [255:0] esperado[0:`N_SHA256-1];

    initial begin
        $readmemh("../vectors/sha256_blocks.hex",  blocos);
        $readmemh("../vectors/sha256_nblocks.hex", nblocos);
        $readmemh("../vectors/sha256_digest.hex",  esperado);
    end

    // Aguarda o core estar ocioso (antes de comandar).
    task espera_pronto;
        begin
            while (!ready) @(posedge clk);
        end
    endtask

    // Aguarda uma operacao COMECAR e depois TERMINAR.
    //
    // Esperar so por 'ready' alto nao basta: no ciclo seguinte ao comando o
    // core ainda nao baixou 'ready', entao a espera termina de imediato e se
    // le o digest da operacao ANTERIOR. O sintoma e caracteristico -- os
    // resultados saem corretos, mas deslocados de um.
    task espera_conclusao;
        begin
            while (ready)  @(posedge clk);   // saiu do ocioso
            while (!ready) @(posedge clk);   // voltou ao ocioso
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #100000000;
        $display("[tb_sha256_kat] FAIL: timeout");
        $display("[tb_sha256_kat] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_sha256_kat] inicio -- %0d mensagens", `N_SHA256);

        #1;
        if (esperado[0] === {256{1'bx}} || nblocos[0] === {32{1'bx}}) begin
            $display("[tb_sha256_kat] FAIL: vetores nao carregados -- rode scripts/mkvectors.py");
            $display("[tb_sha256_kat] FAIL");
            $finish;
        end

        repeat (4) @(posedge clk);
        reset_n = 1'b1;
        repeat (4) @(posedge clk);
        espera_pronto;

        base = 0;
        for (i = 0; i < `N_SHA256; i = i + 1) begin
            for (b = 0; b < nblocos[i]; b = b + 1) begin
                block = blocos[base + b];
                // Primeiro bloco inicializa o estado; os demais encadeiam.
                if (b == 0) init = 1'b1;
                else        next = 1'b1;
                @(posedge clk);
                init = 1'b0;
                next = 1'b0;
                espera_conclusao;
            end
            base = base + nblocos[i];

            if (digest !== esperado[i]) begin
                if (erros < 3)
                    $display("[tb_sha256_kat] FAIL msg %0d (%0d bloco(s)): obtido %064h esperado %064h",
                             i, nblocos[i], digest, esperado[i]);
                erros = erros + 1;
            end
        end

        if (erros == 0) begin
            $display("[tb_sha256_kat] %0d/%0d mensagens, %0d blocos",
                     `N_SHA256, `N_SHA256, base);
            $display("[tb_sha256_kat] PASS");
        end else begin
            $display("[tb_sha256_kat] FAIL: %0d de %0d mensagens", erros, `N_SHA256);
        end

        $finish;
    end

endmodule
