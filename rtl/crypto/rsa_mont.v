`timescale 1ns/1ps
// =====================================================================
// rsa_mont.v -- produto de Montgomery para RSA (fase 7)
//
// Calcula  dst = a * b * R^-1 mod N,  com R = 2^(16*len).
//
// Um comando por produto. Quem dirige a exponenciacao e o firmware: a
// politica fica em C, e o que custa ciclo fica aqui. Algoritmo FIOS, com
// limbs de 16 bits e dois multiplicadores, um para a*b e outro para m*N.
//
// ---------------------------------------------------------------------
// TEMPO CONSTANTE
//
// O numero de ciclos depende so de len. A subtracao final de N sempre
// acontece, e a escolha entre T e T-N e um mux na hora de gravar. Sem isso,
// o tempo do produto vazaria um bit por multiplicacao, que e o ataque de
// temporizacao classico contra RSA.
//
// ---------------------------------------------------------------------
// MEMORIA
//
//   rf    8 registradores de 128 limbs, uma RAMB18. limb 0 = menos
//         significativo. CPU le e escreve, com o core parado.
//   nmem  modulo. Escrita pela CPU, sem leitura: com CRT ele e um primo.
//   tmem  acumulador. Zerado antes e depois de cada produto.
//
// Tudo aqui esta dentro da fronteira criptografica. wipe_i apaga as tres
// memorias e os registradores do caminho de dados.
// =====================================================================
module rsa_mont (
    input  wire        clk_i,
    input  wire        rstn_i,

    input  wire        start_i,
    input  wire        wipe_i,
    input  wire [2:0]  dst_i,
    input  wire [2:0]  a_i,
    input  wire [2:0]  b_i,
    input  wire [7:0]  len_i,       // limbs, de 1 a 128
    input  wire [15:0] n0p_i,       // -N^-1 mod 2^16
    output wire        busy_o,

    // addr[10] = 1 escreve em nmem, com o limb em addr[6:0].
    // addr[10] = 0 acessa rf, com {reg, limb} em addr[9:0].
    // O dado lido vem no ciclo seguinte. Com o core ocupado, nada acontece.
    input  wire        host_en_i,
    input  wire        host_we_i,
    input  wire [10:0] host_addr_i,
    input  wire [15:0] host_wdata_i,
    output wire [15:0] host_rdata_o
);

    localparam [3:0] S_IDLE  = 4'd0,  S_CLR   = 4'd1,  S_ROW_A = 4'd2,
                     S_ROW_B = 4'd3,  S_ROW_C = 4'd4,  S_ROW_D = 4'd5,
                     S_ROW_E = 4'd6,  S_ROW_F = 4'd7,  S_FLUXO = 4'd8,
                     S_ESVAZ = 4'd9,  S_FIM   = 4'd10, S_CMP   = 4'd11,
                     S_SAIDA = 4'd12, S_LIMPA = 4'd13, S_WIPE  = 4'd14;

    reg [3:0] estado;
    assign busy_o = (estado != S_IDLE);

    reg [15:0] rf   [0:1023];
    reg [15:0] nmem [0:127];
    reg [15:0] tmem [0:127];

    integer k;
    initial begin
        for (k = 0; k < 1024; k = k + 1) rf[k] = 16'd0;
        for (k = 0; k < 128; k = k + 1) begin
            nmem[k] = 16'd0;
            tmem[k] = 16'd0;
        end
    end

    reg [2:0]  dst, ra, rb;
    reg [7:0]  len;
    reg [15:0] n0p;
    reg [7:0]  i;           // linha: limb de b
    reg [10:0] j;           // limb; ate 1023 no wipe

    // ---------------------------------------------------------- pipeline
    reg        v1, v2, v3, v4;
    reg [6:0]  j1, j2, j3, j4;
    reg [15:0] a_r, n_r, t_r, t2;
    reg [31:0] p1, p2;
    reg [33:0] q;
    reg [19:0] c;           // carry entre limbs
    reg [15:0] bi, a0, t0, u, m, tl;
    reg [31:0] mul1, mfull;
    reg        br, ge;      // borrow, e T >= N

    wire        v0   = (estado == S_FLUXO);
    wire [34:0] r    = {1'b0, q} + {15'd0, c};
    wire [20:0] fim  = {5'd0, tl} + {1'b0, c};
    wire [6:0]  ult  = len[6:0] - 7'd1;     // len = 128 vira 127 em 7 bits

    // leitura assincrona de tmem e nmem, num endereco so
    wire        na_saida = (estado == S_CMP) || (estado == S_SAIDA);
    wire [6:0]  rd   = na_saida ? j[6:0] : ((estado == S_ROW_B) ? 7'd0 : j1);
    wire [15:0] t_rd = tmem[rd];
    wire [15:0] n_rd = nmem[rd];
    wire [16:0] dif  = {1'b0, t_rd} - {1'b0, n_rd} - {16'd0, br};

    // ---------------------------------------------------------- portas rf
    wire        host_ok = host_en_i & ~busy_o;
    wire [9:0]  addr_a  = (estado == S_FLUXO) ? {ra, j[6:0]} : {ra, 7'd0};
    wire        grava   = (estado == S_SAIDA) || (estado == S_WIPE);
    wire [9:0]  addr_b  = (estado == S_SAIDA) ? {dst, j[6:0]} :
                          (estado == S_WIPE)  ? j[9:0] :
                          (estado == S_ROW_A) ? {rb, i[6:0]} : host_addr_i[9:0];
    wire [15:0] din_b   = (estado == S_SAIDA) ? (ge ? dif[15:0] : t_rd) :
                          (estado == S_WIPE)  ? 16'd0 : host_wdata_i;
    wire        we_b    = grava | (host_ok & host_we_i & ~host_addr_i[10]);

    reg [15:0] do_a, do_b;
    always @(posedge clk_i) do_a <= rf[addr_a];
    always @(posedge clk_i) begin
        if (we_b) rf[addr_b] <= din_b;
        do_b <= rf[addr_b];
    end
    assign host_rdata_o = do_b;

    // ---------------------------------------------------------- nmem
    wire        n_wipe = (estado == S_WIPE) && (j < 11'd128);
    always @(posedge clk_i) begin
        if (n_wipe)
            nmem[j[6:0]] <= 16'd0;
        else if (host_ok & host_we_i & host_addr_i[10])
            nmem[host_addr_i[6:0]] <= host_wdata_i;
    end

    // ---------------------------------------------------------- tmem
    wire        t_zera = (estado == S_CLR) || (estado == S_LIMPA) || n_wipe;
    wire        t_pipe = v4 && (j4 != 7'd0);
    always @(posedge clk_i) begin
        if (t_zera)
            tmem[j[6:0]] <= 16'd0;
        else if (estado == S_FIM)
            tmem[ult] <= fim[15:0];
        else if (t_pipe)
            tmem[j4 - 7'd1] <= r[15:0];
    end

    // ---------------------------------------------------------- dados
    always @(posedge clk_i) begin
        v1 <= v0;  j1 <= j[6:0];
        a_r <= do_a;  n_r <= n_rd;  t_r <= t_rd;
        v2 <= v1;  j2 <= j1;
        p1 <= a_r * bi;  p2 <= n_r * m;  t2 <= t_r;
        v3 <= v2;  j3 <= j2;
        q <= {2'b00, p1} + {2'b00, p2} + {18'd0, t2};
        v4 <= v3;  j4 <= j3;
    end

    // ---------------------------------------------------------- controle
    always @(posedge clk_i) begin
        if (!rstn_i) begin
            estado <= S_IDLE;
            c <= 20'd0;
            tl <= 16'd0;
            br <= 1'b0;
            ge <= 1'b0;
        end else begin
            if (v4) c <= r[34:16];

            // O wipe interrompe um produto em curso: apagar nao espera.
            if (wipe_i) begin
                j <= 11'd0;
                estado <= S_WIPE;
            end else
            case (estado)
            S_IDLE: begin
                j <= 11'd0;
                i <= 8'd0;
                if (start_i) begin
                    dst <= dst_i;  ra <= a_i;  rb <= b_i;
                    len <= len_i;  n0p <= n0p_i;
                    tl <= 16'd0;
                    estado <= S_CLR;
                end
            end

            S_CLR: begin
                if (j[6:0] == ult) begin
                    j <= 11'd0;
                    estado <= S_ROW_A;
                end else
                    j <= j + 11'd1;
            end

            S_ROW_A: estado <= S_ROW_B;     // endereca a[0] e b[i]

            S_ROW_B: begin
                bi <= do_b;  a0 <= do_a;  t0 <= t_rd;
                c <= 20'd0;
                estado <= S_ROW_C;
            end

            S_ROW_C: begin mul1  <= a0 * bi;       estado <= S_ROW_D; end
            S_ROW_D: begin u     <= t0 + mul1[15:0]; estado <= S_ROW_E; end
            S_ROW_E: begin mfull <= u * n0p;       estado <= S_ROW_F; end

            S_ROW_F: begin
                m <= mfull[15:0];
                j <= 11'd0;
                estado <= S_FLUXO;
            end

            S_FLUXO: begin
                if (j[6:0] == ult)
                    estado <= S_ESVAZ;
                else
                    j <= j + 11'd1;
            end

            S_ESVAZ: if (!v1 && !v2 && !v3 && !v4) estado <= S_FIM;

            S_FIM: begin
                tl <= {11'd0, fim[20:16]};
                if (i + 8'd1 == len) begin
                    j <= 11'd0;
                    br <= 1'b0;
                    estado <= S_CMP;
                end else begin
                    i <= i + 8'd1;
                    estado <= S_ROW_A;
                end
            end

            // Primeira passada: so descobre se T >= N.
            S_CMP: begin
                br <= dif[16];
                if (j[6:0] == ult) begin
                    ge <= (tl != 16'd0) | ~dif[16];
                    br <= 1'b0;
                    j <= 11'd0;
                    estado <= S_SAIDA;
                end else
                    j <= j + 11'd1;
            end

            // Segunda passada: subtrai sempre, e o mux escolhe.
            S_SAIDA: begin
                br <= dif[16];
                if (j[6:0] == ult) begin
                    j <= 11'd0;
                    estado <= S_LIMPA;
                end else
                    j <= j + 11'd1;
            end

            S_LIMPA: begin
                if (j[6:0] == ult) begin
                    tl <= 16'd0;  c <= 20'd0;  br <= 1'b0;  ge <= 1'b0;
                    estado <= S_IDLE;
                end else
                    j <= j + 11'd1;
            end

            S_WIPE: begin
                bi <= 16'd0;  a0 <= 16'd0;  t0 <= 16'd0;  u <= 16'd0;
                m <= 16'd0;  mul1 <= 32'd0;  mfull <= 32'd0;
                tl <= 16'd0;  c <= 20'd0;  br <= 1'b0;  ge <= 1'b0;
                n0p <= 16'd0;   // -p^-1 mod 2^16 no CRT: vem de um primo
                if (j == 11'd1023)
                    estado <= S_IDLE;
                else
                    j <= j + 11'd1;
            end

            default: estado <= S_IDLE;
            endcase
        end
    end

endmodule
