`timescale 1ns/1ps
//
// tb_seg -- display de 7 segmentos: glifos, varredura e ponto decimal
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// O que este testbench PODE verificar: que cada estado produz os tres
// glifos certos, na ordem certa, um digito de cada vez, com apagamento
// entre digitos e com o ponto decimal so onde e so quando devido.
//
// O que ele NAO PODE verificar, e vale dizer alto: se o digito de indice 0
// e fisicamente o da ESQUERDA na placa. Isso e um fato do cobre, nao do
// RTL -- aqui ele entra como o parametro DIGITO0_A_ESQUERDA, e o
// testbench so confere que o parametro faz o que promete. Trocado, "Uni"
// vira "inU": legivel, errado, e invisivel em simulacao.
//
// Os valores esperados de glifo NAO sao "o que o modulo devolveu": estao
// escritos aqui em binario, segmento a segmento, a partir do desenho de um
// display de sete segmentos. Sao a mesma informacao expressa duas vezes,
// de formas independentes -- que e o unico jeito de um teste de tabela
// valer alguma coisa.
//
module tb_seg;

    // Clock nominal reduzido so para encolher o divisor da varredura.
    // MUX_DIV = 100000/600 = 166 ciclos; BLANK = 10.
    localparam integer TB_CLK_HZ = 100_000;
    localparam integer MUX_HZ    = 600;
    localparam integer MUX_DIV   = TB_CLK_HZ / MUX_HZ;

    reg clk   = 1'b0;
    reg rst_n = 1'b0;
    reg [1:0] estado  = 2'd0;
    reg       dual_ok = 1'b0;

    wire [7:0] seg;
    wire [2:0] an;

    integer errors = 0;
    integer k;

    always #5 clk = ~clk;    // 100 MHz de verdade

    seg_display #(
        .CLK_HZ             (TB_CLK_HZ),
        .MUX_HZ             (MUX_HZ),
        .SEG_ACTIVE_LOW     (1'b1),
        .AN_ACTIVE_LOW      (1'b0),
        .DIGITO0_A_ESQUERDA (1'b1)
    ) dut (
        .clk_i     (clk),
        .rst_n_i   (rst_n),
        .estado_i  (estado),
        .dual_ok_i (dual_ok),
        .seg_o     (seg),
        .seg_an_o  (an)
    );

    // ------------------------------------------------------------------
    // Glifos esperados, ATIVO ALTO, escritos segmento a segmento.
    //
    //   bit0=a bit1=b bit2=c bit3=d bit4=e bit5=f bit6=g bit7=dp
    //
    //      aaa
    //     f   b
    //      ggg
    //     e   c
    //      ddd
    // ------------------------------------------------------------------
    localparam [7:0] E_U = 8'b0011_1110;   // b c d e f
    localparam [7:0] E_n = 8'b0101_0100;   // c e g
    localparam [7:0] E_i = 8'b0000_0100;   // c
    localparam [7:0] E_A = 8'b0111_0111;   // a b c e f g
    localparam [7:0] E_u = 8'b0001_1100;   // c d e
    localparam [7:0] E_t = 8'b0111_1000;   // d e f g
    localparam [7:0] E_O = 8'b0011_1111;   // a b c d e f
    localparam [7:0] E_P = 8'b0111_0011;   // a b e f g
    localparam [7:0] E_E = 8'b0111_1001;   // a d e f g
    localparam [7:0] E_r = 8'b0101_0000;   // e g

    // A placa acende segmento com 0 e habilita digito com 1. A inversao
    // acontece uma vez so, na saida do DUT -- aqui ela e desfeita uma vez
    // so tambem, para que o resto do teste raciocine em ativo alto.
    function [7:0] alto;
        input [7:0] pino;
        begin
            alto = ~pino;
        end
    endfunction

    // ------------------------------------------------------------------
    // Le o proximo digito aceso, amostrando no meio do slot.
    //
    // Ancorado no apagamento entre digitos, e nao num contador do
    // testbench: se o DUT mudar a divisao da varredura, este teste
    // continua valendo. Um testbench que conta ciclos por fora vira uma
    // segunda copia do DUT, e duas copias do mesmo erro concordam.
    // ------------------------------------------------------------------
    task le_digito;
        output [7:0] s_alto;
        output [2:0] a_val;
        begin
            while (an !== 3'b000) @(posedge clk);   // espera apagar
            while (an === 3'b000) @(posedge clk);   // espera acender
            repeat (MUX_DIV / 2) @(posedge clk);    // meio do slot
            s_alto = alto(seg);
            a_val  = an;
        end
    endtask

    // ------------------------------------------------------------------
    // Confere uma palavra inteira: tres digitos, glifo e anodo.
    // ------------------------------------------------------------------
    reg [7:0] s0, s1, s2;
    reg [2:0] a0, a1, a2;

    task confere_palavra;
        input [8*4-1:0] nome;
        input [7:0] g0, g1, g2;
        input       espera_dp;
        begin
            // Sincroniza no primeiro digito: gira ate o anodo 001 aparecer,
            // que e o inicio da palavra.
            a0 = 3'b000;
            k  = 0;
            while (a0 !== 3'b001 && k < 8) begin
                le_digito(s0, a0);
                k = k + 1;
            end

            if (a0 !== 3'b001) begin
                $display("[tb_seg] FAIL: %0s -- nunca vi o digito 0 (an=%b)", nome, a0);
                errors = errors + 1;
            end

            le_digito(s1, a1);
            le_digito(s2, a2);

            if (a1 !== 3'b010 || a2 !== 3'b100) begin
                $display("[tb_seg] FAIL: %0s -- varredura fora de ordem: %b %b %b",
                         nome, a0, a1, a2);
                errors = errors + 1;
            end

            // O ponto decimal so pode aparecer no ULTIMO digito. Se ele
            // vazar para os outros dois, o operador ve tres pontos e le
            // "defeito" em vez de "autorizado".
            if (s0[7] !== 1'b0 || s1[7] !== 1'b0) begin
                $display("[tb_seg] FAIL: %0s -- ponto decimal em digito que nao e o ultimo",
                         nome);
                errors = errors + 1;
            end

            if (s2[7] !== espera_dp) begin
                $display("[tb_seg] FAIL: %0s -- dp=%b no ultimo digito, esperado %b",
                         nome, s2[7], espera_dp);
                errors = errors + 1;
            end

            if (s0[6:0] !== g0[6:0] || s1[6:0] !== g1[6:0] || s2[6:0] !== g2[6:0]) begin
                $display("[tb_seg] FAIL: %0s -- glifos %b %b %b, esperado %b %b %b",
                         nome, s0[6:0], s1[6:0], s2[6:0], g0[6:0], g1[6:0], g2[6:0]);
                errors = errors + 1;
            end else begin
                $display("[tb_seg] %0s -- glifos e varredura OK%0s",
                         nome, espera_dp ? " (com ponto decimal)" : "");
            end
        end
    endtask

    initial begin
        #20000000;
        $display("[tb_seg] FAIL: timeout");
        $display("[tb_seg] FAIL");
        $finish;
    end

    initial begin
        $display("[tb_seg] inicio");

        // ---- 1. em reset, apagado pelos DOIS caminhos ------------------
        //
        // Segmentos desligados E digitos desabilitados. Qualquer um
        // bastaria; os dois juntos mantem o display apagado mesmo se um
        // parametro de polaridade for trocado por engano.
        repeat (20) @(posedge clk);
        if (seg !== 8'hFF || an !== 3'b000) begin
            $display("[tb_seg] FAIL: em reset seg=%h an=%b, esperado FF/000", seg, an);
            errors = errors + 1;
        end else begin
            $display("[tb_seg] reset -- display apagado pelos dois caminhos");
        end

        rst_n = 1'b1;
        @(posedge clk);

        // ---- 2. os quatro estados -------------------------------------
        estado  = 2'd0; dual_ok = 1'b0;
        confere_palavra("Uni ", E_U, E_n, E_i, 1'b0);

        estado  = 2'd1;
        confere_palavra("Aut ", E_A, E_u, E_t, 1'b0);

        estado  = 2'd2;
        confere_palavra("OPE ", E_O, E_P, E_E, 1'b0);

        estado  = 2'd3;
        confere_palavra("tPr ", E_t, E_P, E_r, 1'b0);

        // ---- 3. ponto decimal do dual control -------------------------
        //
        // O operador aperta os dois botoes e ve o dispositivo concordar.
        // E a resposta de bancada para "que botoes?", e nao vaza nada:
        // quem esta apertando ja esta na frente da placa.
        estado  = 2'd0;
        dual_ok = 1'b1;
        confere_palavra("Uni.", E_U, E_n, E_i, 1'b1);

        dual_ok = 1'b0;
        confere_palavra("Uni ", E_U, E_n, E_i, 1'b0);

        // ---- 4. um digito de cada vez ---------------------------------
        //
        // Dois anodos simultaneos misturariam os dois glifos no mesmo
        // display -- e a mistura de "Uni" com "tPr" nao se parece com
        // nenhum dos dois, entao o operador leria lixo sem saber que e
        // lixo.
        estado = 2'd2;
        for (k = 0; k < 30; k = k + 1) begin
            @(posedge clk);
            case (an)
                3'b000, 3'b001, 3'b010, 3'b100: ;   // apagado ou one-hot
                default: begin
                    $display("[tb_seg] FAIL: dois digitos acesos ao mesmo tempo (an=%b)", an);
                    errors = errors + 1;
                end
            endcase
        end

        // ---- 5. existe apagamento entre digitos -----------------------
        //
        // Sem ele, o digito seguinte acende antes de o anterior descarregar
        // e aparece um fantasma no vizinho. Verificar que a janela EXISTE:
        // se o apagamento sumir, `an` nunca vale 000 depois do reset e este
        // laco estoura.
        k = 0;
        while (an !== 3'b000 && k < 4 * MUX_DIV) begin
            @(posedge clk);
            k = k + 1;
        end
        if (an !== 3'b000) begin
            $display("[tb_seg] FAIL: nao ha apagamento entre digitos");
            errors = errors + 1;
        end else begin
            $display("[tb_seg] apagamento entre digitos presente");
        end

        // Durante o apagamento os segmentos tambem ficam desligados. Se so
        // o anodo apagasse, a carga residual ainda acenderia o vizinho.
        if (seg !== 8'hFF) begin
            $display("[tb_seg] FAIL: no apagamento seg=%h, esperado FF", seg);
            errors = errors + 1;
        end

        // ---- 6. volta ao reset ----------------------------------------
        rst_n = 1'b0;
        repeat (5) @(posedge clk);
        if (seg !== 8'hFF || an !== 3'b000) begin
            $display("[tb_seg] FAIL: reset nao apaga (seg=%h an=%b)", seg, an);
            errors = errors + 1;
        end

        if (errors == 0)
            $display("[tb_seg] PASS");
        else
            $display("[tb_seg] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
