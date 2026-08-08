`timescale 1ns/1ps
//
// tb_trng_health -- RCT e APT do hsm_health, contra as regras da
// SP 800-90B secao 4.4.
//
// Nao ha "vetores oficiais" para health tests: a norma da os ALGORITMOS e
// as formulas de cutoff, nao um arquivo de resposta. Entao o que se testa
// aqui e a norma escrita como sequencias construidas de proposito, e o
// que importa e testar as BORDAS -- reprovar na amostra exata, e nao uma
// antes nem uma depois.
//
// Um health test que dispara cedo demais desliga um HSM saudavel. Um que
// dispara tarde demais deixa passar entropia degradada e a semente ja
// nasceu ruim. Os dois erros sao caros e nenhum aparece em operacao
// normal, so em campo.
//
// Sequencias usadas:
//
//   travada        sempre o mesmo bit         -> RCT reprova
//   borda do RCT   exatamente C-1 repeticoes  -> RCT NAO reprova
//                  exatamente C repeticoes    -> RCT reprova
//   enviesada      periodo 8 com 7 zeros      -> APT reprova (896 > 793)
//                  e corridas de 7            -> RCT nao reprova
//   LFSR           equilibrada                -> nenhum reprova, e o teste
//                                                de partida conclui
//
// A sequencia enviesada e a mais instrutiva das quatro: ela VARIA o tempo
// todo, nunca repete mais que sete vezes, e passaria despercebida por
// qualquer teste de "a fonte travou?". So o APT a pega. E uma fonte assim
// -- viva mas enviesada -- e o que um oscilador em anel degradando de
// verdade produz.
//
module tb_trng_health;

    localparam integer RCT_CUTOFF = 41;
    localparam integer APT_WINDOW = 1024;
    localparam integer APT_CUTOFF = 793;
    localparam integer STARTUP_N  = 1024;

    reg clk  = 1'b0;
    reg rstn = 1'b0;
    reg en   = 1'b0;
    reg samp = 1'b0;
    reg vld  = 1'b0;

    wire        rct_fail, apt_fail, fail, startup_ok;
    wire [15:0] rct_count, apt_count;

    always #5 clk = ~clk;      // 100 MHz

    hsm_health #(
        .RCT_CUTOFF (RCT_CUTOFF),
        .APT_WINDOW (APT_WINDOW),
        .APT_CUTOFF (APT_CUTOFF),
        .STARTUP_N  (STARTUP_N)
    ) dut (
        .clk_i        (clk),
        .rstn_i       (rstn),
        .en_i         (en),
        .sample_i     (samp),
        .valid_i      (vld),
        .rct_fail_o   (rct_fail),
        .apt_fail_o   (apt_fail),
        .fail_o       (fail),
        .startup_ok_o (startup_ok),
        .rct_count_o  (rct_count),
        .apt_count_o  (apt_count)
    );

    integer erros = 0;

    task reinicia;
        begin
            en   = 1'b0;
            vld  = 1'b0;
            rstn = 1'b0;
            @(posedge clk); @(posedge clk);
            rstn = 1'b1;
            en   = 1'b1;
            @(posedge clk);
        end
    endtask

    // Uma amostra por ciclo, que e o regime real da fonte.
    task amostra(input b);
        begin
            samp = b;
            vld  = 1'b1;
            @(posedge clk);
            vld  = 1'b0;
        end
    endtask

    task confere(input esperado, input real_val, input [255:0] nome);
        begin
            if (esperado !== real_val) begin
                $display("[tb_trng_health] ERRO: %0s -- esperado %b, obtido %b",
                         nome, esperado, real_val);
                erros = erros + 1;
            end
        end
    endtask

    integer i;
    reg [31:0] lfsr;

    initial begin
        $display("[tb_trng_health] inicio -- RCT C=%0d, APT W=%0d C=%0d",
                 RCT_CUTOFF, APT_WINDOW, APT_CUTOFF);

        // --------------------------------------------------------------
        // 1. Fonte travada: o modo de falha catastrofico do oscilador
        // --------------------------------------------------------------
        reinicia;
        for (i = 0; i < 200; i = i + 1) amostra(1'b0);
        confere(1'b1, rct_fail, "fonte travada em 0 deveria reprovar no RCT");

        reinicia;
        for (i = 0; i < 200; i = i + 1) amostra(1'b1);
        confere(1'b1, rct_fail, "fonte travada em 1 deveria reprovar no RCT");

        // --------------------------------------------------------------
        // 2. Borda exata do RCT
        //
        // C = 41 significa reprovar na 41a amostra IGUAL, contando a
        // primeira. Com 40 iguais tem de passar.
        // --------------------------------------------------------------
        reinicia;
        for (i = 0; i < RCT_CUTOFF - 1; i = i + 1) amostra(1'b0);
        confere(1'b0, rct_fail, "C-1 repeticoes NAO podem reprovar");
        if (rct_count !== RCT_CUTOFF - 1) begin
            $display("[tb_trng_health] ERRO: contador RCT = %0d, esperado %0d",
                     rct_count, RCT_CUTOFF - 1);
            erros = erros + 1;
        end

        amostra(1'b0);              // a C-esima
        confere(1'b1, rct_fail, "C repeticoes DEVEM reprovar");
        $display("[tb_trng_health] RCT reprova exatamente na amostra %0d", RCT_CUTOFF);

        // --------------------------------------------------------------
        // 3. Falha e permanente
        //
        // Depois de reprovar, uma fonte que volta a parecer boa continua
        // reprovada. Health test que se auto-recupera nao serve: a saida
        // ruim ja virou semente.
        // --------------------------------------------------------------
        for (i = 0; i < 500; i = i + 1) amostra(i[0]);
        confere(1'b1, rct_fail, "falha do RCT tem de ser permanente");

        // --------------------------------------------------------------
        // 4. Fonte enviesada: viva, variando, e mesmo assim ruim
        //
        // Periodo 8 com sete zeros e um um: 896 zeros por janela de 1024,
        // acima do cutoff de 793. Corrida maxima de 7, muito abaixo do
        // cutoff do RCT -- entao SO o APT pega.
        // --------------------------------------------------------------
        reinicia;
        for (i = 0; i < APT_WINDOW; i = i + 1) amostra((i % 8) == 7);
        confere(1'b0, rct_fail, "fonte enviesada nao deveria reprovar no RCT");
        confere(1'b1, apt_fail, "fonte enviesada DEVE reprovar no APT");
        $display("[tb_trng_health] APT pegou o vies que o RCT nao pega");

        // --------------------------------------------------------------
        // 5. Fonte equilibrada: nada reprova, e a partida conclui
        // --------------------------------------------------------------
        reinicia;
        lfsr = 32'hACE1_2345;
        for (i = 0; i < STARTUP_N + APT_WINDOW; i = i + 1) begin
            // LFSR de 32 bits, polinomio maximal x^32+x^22+x^2+x+1
            lfsr = {lfsr[30:0], lfsr[31] ^ lfsr[21] ^ lfsr[1] ^ lfsr[0]};
            amostra(lfsr[0]);
        end
        confere(1'b0, rct_fail,   "fonte equilibrada nao pode reprovar no RCT");
        confere(1'b0, apt_fail,   "fonte equilibrada nao pode reprovar no APT");
        confere(1'b1, startup_ok, "teste de partida deveria ter concluido");
        $display("[tb_trng_health] fonte equilibrada passa, partida concluida");

        // --------------------------------------------------------------
        // 6. Desabilitar a fonte zera o estado
        //
        // Contagem de repeticao atravessando um desligamento nao significa
        // nada: as amostras nao sao consecutivas.
        // --------------------------------------------------------------
        reinicia;
        for (i = 0; i < RCT_CUTOFF - 1; i = i + 1) amostra(1'b0);
        en = 1'b0;  @(posedge clk);
        en = 1'b1;  @(posedge clk);
        for (i = 0; i < RCT_CUTOFF - 1; i = i + 1) amostra(1'b0);
        confere(1'b0, rct_fail, "contagem nao pode atravessar um desligamento");

        if (erros == 0) $display("[tb_trng_health] PASS");
        else            $display("[tb_trng_health] FAIL -- %0d erro(s)", erros);

        $finish;
    end

endmodule
