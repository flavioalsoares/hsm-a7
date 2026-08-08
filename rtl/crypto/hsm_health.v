// =====================================================================
// hsm_health.v -- health tests continuos da fonte de entropia
//
// RCT (Repetition Count Test) e APT (Adaptive Proportion Test), conforme
// NIST SP 800-90B secao 4.4, sobre a AMOSTRA BRUTA da fonte de ruido.
//
// ---------------------------------------------------------------------
// POR QUE ISTO ESTA EM HARDWARE, E NAO EM FIRMWARE
//
// O PLANO.md previa os dois testes em firmware. Nao da, e o motivo e
// aritmetico: a SP 800-90B exige que os health tests continuos vejam
// TODA amostra produzida pela fonte ("continuous", secao 4.4). Nossa
// fonte digitaliza uma amostra por ciclo de 100 MHz. Uma CPU RISC-V de
// ciclo unico a 100 MHz nao consegue ler, comparar e contar 100 milhoes
// de amostras por segundo -- ela perderia a maioria, e um teste que ve
// uma amostra em cada mil nao e o teste da norma, e uma amostragem que
// nao detecta a falha que a norma quer detectar (uma fonte que travou
// entre duas leituras do firmware).
//
// Divisao adotada, que preserva a intencao do plano:
//
//   hardware  testes CONTINUOS, toda amostra, sem excecao (este arquivo)
//   firmware  testes de PARTIDA (secao 4.3) sobre um retrato de 1024
//             amostras BRUTAS CONSECUTIVAS que o hardware congela em um
//             buffer, mais toda a POLITICA: falha -> TAMPERED, DRBG
//             parado, LED vermelho
//
// O firmware continua dono da decisao, que e o que importa para a
// arquitetura do HSM. O hardware so e dono da contagem, que e o que ele
// faz melhor. E os dois testes ficam implementados duas vezes, de forma
// independente -- em Verilog aqui e em C no firmware -- o que e uma
// checagem cruzada de graca contra erro de interpretacao da norma.
//
// ---------------------------------------------------------------------
// DE ONDE VEM OS CUTOFFS
//
// Nao foram lembrados de tabela: foram calculados, e o calculo esta em
// scripts/health-cutoffs.py, que imprime a tabela e e a fonte destes
// defaults. Reproduzir com:  python3 scripts/health-cutoffs.py
//
//   alpha = 2^-20                       (SP 800-90B, secao 4.4)
//   H     = 0,5 bit por amostra bruta   HIPOTESE DE PROJETO, ver abaixo
//
//   RCT:  C = 1 + ceil(-log2(alpha)/H)  = 41        (secao 4.4.1)
//   APT:  W = 1024, C = menor inteiro com
//         P(X >= C) <= alpha, X ~ Bin(W, 2^-H) = 793 (secao 4.4.2)
//
// ATENCAO, e isto e o ponto didatico central deste modulo: H = 0,5 e uma
// HIPOTESE, nao uma medida. Uma validacao 90B de verdade estima H a
// partir de 1.000.000 de amostras brutas coletadas do hardware real,
// pelo track nao-IID da norma (ferramenta ea_non_iid do NIST). Enquanto
// H for chute, estes cutoffs sao chute -- e um cutoff frouxo demais
// deixa passar fonte degradada, um cutoff apertado demais desliga o HSM
// por acaso. E por isso que o buffer de retrato existe: ele e o caminho
// para coletar as amostras e um dia trocar a hipotese por um numero.
//
// Ver doc/fase2-notas.md.
//
// ---------------------------------------------------------------------
// A FALHA E PERMANENTE
//
// rct_fail_o e apt_fail_o sao sticky: sobem e so descem no reset. Health
// test que se auto-recupera nao serve para nada -- a fonte pode voltar a
// parecer boa depois de ter produzido saida ruim, e essa saida ja virou
// semente. Uma vez suspeita, sempre suspeita, ate intervencao.
// =====================================================================

`timescale 1ns/1ps

module hsm_health #(
    parameter integer RCT_CUTOFF = 41,     // secao 4.4.1
    parameter integer APT_WINDOW = 1024,   // secao 4.4.2, fonte binaria
    parameter integer APT_CUTOFF = 793,
    parameter integer STARTUP_N  = 1024    // secao 4.3, teste de partida
) (
    input  wire        clk_i,
    input  wire        rstn_i,     // reset sincrono, ativo baixo

    input  wire        en_i,       // fonte habilitada
    input  wire        sample_i,   // amostra bruta
    input  wire        valid_i,    // sample_i vale neste ciclo

    output reg         rct_fail_o, // sticky
    output reg         apt_fail_o, // sticky
    output wire        fail_o,
    output reg         startup_ok_o,  // STARTUP_N amostras sem falha

    // diagnostico -- o firmware le, e um retrato de saude, nao um veredito
    output wire [15:0] rct_count_o,
    output wire [15:0] apt_count_o
);

    // ------------------------------------------------------------------
    // RCT -- secao 4.4.1
    //
    //   A = amostra anterior, B = quantas vezes ela se repetiu
    //   nova amostra igual a A -> B++, e B >= C reprova
    //   nova amostra diferente -> A = nova, B = 1
    //
    // O que ele pega: fonte que travou em um valor. E a falha catastrofica
    // classica de oscilador em anel -- para de oscilar e a saida vira
    // constante, sem nenhum outro sintoma visivel.
    // ------------------------------------------------------------------
    reg        rct_a;
    reg [15:0] rct_b;
    reg        rct_seeded;   // ja vimos a primeira amostra?

    // ------------------------------------------------------------------
    // APT -- secao 4.4.2
    //
    //   a cada janela de W amostras: A = primeira amostra da janela,
    //   conta quantas das W sao iguais a A; >= C reprova
    //
    // O que ele pega: fonte que nao travou, mas ficou enviesada -- 90%
    // de zeros ainda "varia", passa no RCT e nao tem a entropia que a
    // gente assumiu ao dimensionar a semente.
    // ------------------------------------------------------------------
    reg        apt_a;
    reg [15:0] apt_b;
    reg [15:0] apt_i;        // posicao dentro da janela, 0 = referencia

    reg [15:0] startup_cnt;

    assign fail_o      = rct_fail_o | apt_fail_o;
    assign rct_count_o = rct_b;
    assign apt_count_o = apt_b;

    always @(posedge clk_i) begin
        if (!rstn_i || !en_i) begin
            // Fonte desligada zera o estado: a contagem de repeticao
            // atravessando um desligamento nao significa nada.
            rct_a        <= 1'b0;
            rct_b        <= 16'd0;
            rct_seeded   <= 1'b0;
            rct_fail_o   <= 1'b0;
            apt_a        <= 1'b0;
            apt_b        <= 16'd0;
            apt_i        <= 16'd0;
            apt_fail_o   <= 1'b0;
            startup_cnt  <= 16'd0;
            startup_ok_o <= 1'b0;
        end else if (valid_i) begin
            // ---------------- RCT ----------------
            if (!rct_seeded) begin
                rct_a      <= sample_i;
                rct_b      <= 16'd1;
                rct_seeded <= 1'b1;
            end else if (sample_i == rct_a) begin
                rct_b <= rct_b + 16'd1;
                if (rct_b + 16'd1 >= RCT_CUTOFF)
                    rct_fail_o <= 1'b1;
            end else begin
                rct_a <= sample_i;
                rct_b <= 16'd1;
            end

            // ---------------- APT ----------------
            if (apt_i == 16'd0) begin
                // primeira amostra da janela: vira a referencia
                apt_a <= sample_i;
                apt_b <= 16'd1;
                apt_i <= 16'd1;
                // Janela de uma amostra so nao existe; APT_WINDOW >= 2.
                if (16'd1 >= APT_CUTOFF)
                    apt_fail_o <= 1'b1;
            end else begin
                if (sample_i == apt_a) begin
                    apt_b <= apt_b + 16'd1;
                    if (apt_b + 16'd1 >= APT_CUTOFF)
                        apt_fail_o <= 1'b1;
                end
                apt_i <= (apt_i == APT_WINDOW - 1) ? 16'd0 : apt_i + 16'd1;
            end

            // ------------- teste de partida -------------
            // STARTUP_N amostras consecutivas sem reprovar em nenhum dos
            // dois. Enquanto nao terminar, a saida da fonte nao deve ser
            // usada -- quem impoe isso e o firmware.
            if (!startup_ok_o && !rct_fail_o && !apt_fail_o) begin
                if (startup_cnt == STARTUP_N - 1)
                    startup_ok_o <= 1'b1;
                else
                    startup_cnt <= startup_cnt + 16'd1;
            end
        end
    end

endmodule
