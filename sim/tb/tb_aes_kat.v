`timescale 1ns/1ps
//
// tb_aes_kat -- AES-256 contra os vetores oficiais do NIST (CAVP/AESAVS)
//
// Regra do projeto: nada vai para a placa sem passar antes aqui. E a regra
// inviolavel numero 5: se um KAT falha, o bug esta no codigo, nao no vetor.
//
// Cobre ECB e CBC, cifra e decifra, com os quatro tipos de vetor do AESAVS:
//
//   GFSbox   textos escolhidos, chave zero
//   KeySbox  chaves escolhidas, texto zero
//   VarKey   cada bit da chave ligado isoladamente (256 vetores)
//   VarTxt   cada bit do bloco ligado isoladamente (128 vetores)
//
// Os dois ultimos sao os que pegam erro estrutural: VarKey acha indexacao
// errada na expansao de chave, VarTxt acha ordem de byte e permutacao
// trocadas. Um core que passa so no GFSbox pode estar inteiro errado.
//
// O core (secworks/aes) faz ECB. O encadeamento de CBC e feito AQUI, no
// testbench, porque e assim que o firmware vai fazer -- e separar as duas
// responsabilidades e o ponto.
//
// Vetores gerados por scripts/mkvectors.py a partir de vectors/, que vem do
// NIST com hash conferido (vectors/MANIFEST.txt).
//
`include "counts.vh"

module tb_aes_kat;

    localparam CLK_HALF = 5;          // 100 MHz

    reg          clk = 1'b0;
    reg          reset_n = 1'b0;

    reg          encdec = 1'b0;
    reg          init = 1'b0;
    reg          next = 1'b0;
    wire         ready;

    reg  [255:0] key;
    reg          keylen = 1'b1;       // 1 = AES-256
    reg  [127:0] block;
    wire [127:0] result;
    wire         result_valid;

    integer erros = 0;
    integer i;

    always #CLK_HALF clk = ~clk;

    aes_core dut (
        .clk          (clk),
        .reset_n      (reset_n),
        .encdec       (encdec),
        .init         (init),
        .next         (next),
        .ready        (ready),
        .key          (key),
        .keylen       (keylen),
        .block        (block),
        .result       (result),
        .result_valid (result_valid)
    );

    // ------------------------------------------------------------------
    // Vetores. Caminho relativo a build/sim, que e o cwd imposto por
    // scripts/sim.sh.
    // ------------------------------------------------------------------
    reg [255:0] ecb_e_key [0:`N_AES_ECB-1];
    reg [127:0] ecb_e_in  [0:`N_AES_ECB-1];
    reg [127:0] ecb_e_out [0:`N_AES_ECB-1];
    reg [255:0] ecb_d_key [0:`N_AES_ECB-1];
    reg [127:0] ecb_d_in  [0:`N_AES_ECB-1];
    reg [127:0] ecb_d_out [0:`N_AES_ECB-1];

    reg [255:0] cbc_e_key [0:`N_AES_CBC-1];
    reg [127:0] cbc_e_iv  [0:`N_AES_CBC-1];
    reg [127:0] cbc_e_in  [0:`N_AES_CBC-1];
    reg [127:0] cbc_e_out [0:`N_AES_CBC-1];
    reg [255:0] cbc_d_key [0:`N_AES_CBC-1];
    reg [127:0] cbc_d_iv  [0:`N_AES_CBC-1];
    reg [127:0] cbc_d_in  [0:`N_AES_CBC-1];
    reg [127:0] cbc_d_out [0:`N_AES_CBC-1];

    initial begin
        $readmemh("../vectors/aes_ecb256_enc_key.hex", ecb_e_key);
        $readmemh("../vectors/aes_ecb256_enc_in.hex",  ecb_e_in);
        $readmemh("../vectors/aes_ecb256_enc_out.hex", ecb_e_out);
        $readmemh("../vectors/aes_ecb256_dec_key.hex", ecb_d_key);
        $readmemh("../vectors/aes_ecb256_dec_in.hex",  ecb_d_in);
        $readmemh("../vectors/aes_ecb256_dec_out.hex", ecb_d_out);

        $readmemh("../vectors/aes_cbc256_enc_key.hex", cbc_e_key);
        $readmemh("../vectors/aes_cbc256_enc_iv.hex",  cbc_e_iv);
        $readmemh("../vectors/aes_cbc256_enc_in.hex",  cbc_e_in);
        $readmemh("../vectors/aes_cbc256_enc_out.hex", cbc_e_out);
        $readmemh("../vectors/aes_cbc256_dec_key.hex", cbc_d_key);
        $readmemh("../vectors/aes_cbc256_dec_iv.hex",  cbc_d_iv);
        $readmemh("../vectors/aes_cbc256_dec_in.hex",  cbc_d_in);
        $readmemh("../vectors/aes_cbc256_dec_out.hex", cbc_d_out);
    end

    // ------------------------------------------------------------------
    task espera_pronto;
        begin
            while (!ready) @(posedge clk);
        end
    endtask

    // Aguarda a operacao COMECAR e depois TERMINAR.
    //
    // Esperar so por 'ready' alto nao basta: logo apos o comando o core
    // ainda nao baixou 'ready', a espera termina de imediato e se le o
    // resultado da operacao ANTERIOR. O sintoma e caracteristico -- tudo
    // correto, porem deslocado de um. Foi exatamente assim que o
    // tb_sha256_kat falhou na primeira versao.
    task espera_conclusao;
        begin
            while (ready)  @(posedge clk);
            while (!ready) @(posedge clk);
        end
    endtask

    task carrega_chave(input [255:0] k);
        begin
            key  = k;
            init = 1'b1;
            @(posedge clk);
            init = 1'b0;
            espera_conclusao;
        end
    endtask

    task processa(input dir, input [127:0] b, output [127:0] r);
        begin
            encdec = dir;              // 1 = cifra, 0 = decifra
            block  = b;
            next   = 1'b1;
            @(posedge clk);
            next   = 1'b0;
            espera_conclusao;
            r = result;
        end
    endtask

    // ------------------------------------------------------------------
    task roda_ecb;
        reg [127:0] r;
        integer n;
        begin
            n = 0;
            for (i = 0; i < `N_AES_ECB; i = i + 1) begin
                carrega_chave(ecb_e_key[i]);
                processa(1'b1, ecb_e_in[i], r);
                if (r !== ecb_e_out[i]) begin
                    if (n < 3)
                        $display("[tb_aes_kat] FAIL ECB-enc %0d: obtido %032h esperado %032h",
                                 i, r, ecb_e_out[i]);
                    n = n + 1;
                end
            end
            if (n) begin
                $display("[tb_aes_kat] FAIL: ECB cifra, %0d de %0d", n, `N_AES_ECB);
                erros = erros + n;
            end else
                $display("[tb_aes_kat] ECB cifra   : %0d/%0d", `N_AES_ECB, `N_AES_ECB);

            n = 0;
            for (i = 0; i < `N_AES_ECB; i = i + 1) begin
                carrega_chave(ecb_d_key[i]);
                processa(1'b0, ecb_d_in[i], r);
                if (r !== ecb_d_out[i]) begin
                    if (n < 3)
                        $display("[tb_aes_kat] FAIL ECB-dec %0d: obtido %032h esperado %032h",
                                 i, r, ecb_d_out[i]);
                    n = n + 1;
                end
            end
            if (n) begin
                $display("[tb_aes_kat] FAIL: ECB decifra, %0d de %0d", n, `N_AES_ECB);
                erros = erros + n;
            end else
                $display("[tb_aes_kat] ECB decifra : %0d/%0d", `N_AES_ECB, `N_AES_ECB);
        end
    endtask

    // CBC de um bloco: C = E(P xor IV) e P = D(C) xor IV
    task roda_cbc;
        reg [127:0] r;
        integer n;
        begin
            n = 0;
            for (i = 0; i < `N_AES_CBC; i = i + 1) begin
                carrega_chave(cbc_e_key[i]);
                processa(1'b1, cbc_e_in[i] ^ cbc_e_iv[i], r);
                if (r !== cbc_e_out[i]) begin
                    if (n < 3)
                        $display("[tb_aes_kat] FAIL CBC-enc %0d: obtido %032h esperado %032h",
                                 i, r, cbc_e_out[i]);
                    n = n + 1;
                end
            end
            if (n) begin
                $display("[tb_aes_kat] FAIL: CBC cifra, %0d de %0d", n, `N_AES_CBC);
                erros = erros + n;
            end else
                $display("[tb_aes_kat] CBC cifra   : %0d/%0d", `N_AES_CBC, `N_AES_CBC);

            n = 0;
            for (i = 0; i < `N_AES_CBC; i = i + 1) begin
                carrega_chave(cbc_d_key[i]);
                processa(1'b0, cbc_d_in[i], r);
                if ((r ^ cbc_d_iv[i]) !== cbc_d_out[i]) begin
                    if (n < 3)
                        $display("[tb_aes_kat] FAIL CBC-dec %0d: obtido %032h esperado %032h",
                                 i, r ^ cbc_d_iv[i], cbc_d_out[i]);
                    n = n + 1;
                end
            end
            if (n) begin
                $display("[tb_aes_kat] FAIL: CBC decifra, %0d de %0d", n, `N_AES_CBC);
                erros = erros + n;
            end else
                $display("[tb_aes_kat] CBC decifra : %0d/%0d", `N_AES_CBC, `N_AES_CBC);
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #200000000;
        $display("[tb_aes_kat] FAIL: timeout");
        $display("[tb_aes_kat] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_aes_kat] inicio -- %0d ECB + %0d CBC, cifra e decifra",
                 `N_AES_ECB, `N_AES_CBC);

        // Sem os arquivos de vetor, $readmemh deixa X e o teste passaria
        // "sem erros" sobre nada. Recusar e o comportamento certo.
        #1;
        if (ecb_e_key[0] === {256{1'bx}} || ecb_e_out[`N_AES_ECB-1] === {128{1'bx}}) begin
            $display("[tb_aes_kat] FAIL: vetores nao carregados -- rode scripts/mkvectors.py");
            $display("[tb_aes_kat] FAIL");
            $finish;
        end

        repeat (4) @(posedge clk);
        reset_n = 1'b1;
        repeat (4) @(posedge clk);
        espera_pronto;

        roda_ecb;
        roda_cbc;

        if (erros == 0)
            $display("[tb_aes_kat] PASS");
        else
            $display("[tb_aes_kat] FAIL: %0d vetor(es)", erros);

        $finish;
    end

endmodule
