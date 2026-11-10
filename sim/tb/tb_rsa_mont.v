`timescale 1ns/1ps
//
// tb_rsa_mont -- produto de Montgomery e exponenciacao de 2048 bits
//
// Tres provas, da menor para a maior:
//
//   1. Produtos contra inteiros do Python, com len de 128, 64, 2 e 1 limbs,
//      incluindo 0, 1, N-1 e R mod N.
//   2. Tempo: o numero de ciclos de um produto so depende de len.
//   3. KAT do CAVP: S^e mod n dos 10 vetores SHA-256 do SigGen15 tem de dar o
//      EM de PKCS#1 v1.5. Aqui o laco de exponenciacao roda no testbench,
//      como rodara no firmware.
//
// Depois, o wipe: nada do que ficou nas memorias pode sobreviver a ele.
//
`include "../vectors/counts.vh"

module tb_rsa_mont;
    reg clk = 0, rstn = 0;
    always #5 clk = ~clk;

    reg         start = 0, wipe = 0;
    reg  [2:0]  dst = 0, ra = 0, rb = 0;
    reg  [7:0]  len = 0;
    reg  [15:0] n0p = 0;
    wire        busy;
    reg         hen = 0, hwe = 0;
    reg  [10:0] haddr = 0;
    reg  [15:0] hw = 0;
    wire [15:0] hr;

    rsa_mont dut (.clk_i(clk), .rstn_i(rstn), .start_i(start), .wipe_i(wipe),
                  .dst_i(dst), .a_i(ra), .b_i(rb), .len_i(len), .n0p_i(n0p),
                  .busy_o(busy), .host_en_i(hen), .host_we_i(hwe),
                  .host_addr_i(haddr), .host_wdata_i(hw), .host_rdata_o(hr));

    localparam NP = `N_RSA_MONT;
    localparam NK = `N_RSA_KAT;

    reg [15:0] prod [0:NP*512-1];
    reg [15:0] cfg  [0:NP*2-1];
    reg [15:0] kat  [0:(2+2*NK)*128-1];

    integer erros = 0;
    integer ciclos;
    integer ciclos_de [0:128];

    task escreve(input [10:0] a, input [15:0] d);
        begin
            @(negedge clk);
            hen = 1; hwe = 1; haddr = a; hw = d;
            @(negedge clk);
            hen = 0; hwe = 0;
        end
    endtask

    task le(input [10:0] a, output [15:0] d);
        begin
            @(negedge clk);
            hen = 1; hwe = 0; haddr = a;
            @(negedge clk);
            hen = 0;
            d = hr;
        end
    endtask

    task mont(input [2:0] d, input [2:0] a, input [2:0] b);
        begin
            @(negedge clk);
            dst = d; ra = a; rb = b; start = 1;
            @(negedge clk);
            start = 0;
            ciclos = 1;
            while (busy) begin
                @(negedge clk);
                ciclos = ciclos + 1;
            end
        end
    endtask

    task zera_reg(input [2:0] g);
        integer k;
        for (k = 0; k < 128; k = k + 1) escreve({1'b0, g, k[6:0]}, 16'd0);
    endtask

    // Registradores da exponenciacao: 0 base, 1 acumulador, 2 R^2, 3 um.
    task exponencia(input integer idx);
        integer k, bit_alto;
        reg [31:0] e;
        reg [15:0] v;
        integer dif;
        begin
            e = `RSA_E;
            for (k = 0; k < 128; k = k + 1)
                escreve({1'b0, 3'd0, k[6:0]}, kat[(2 + 2*idx)*128 + k]);
            mont(0, 0, 2);                      // base em forma de Montgomery
            bit_alto = 31;
            while (!e[bit_alto]) bit_alto = bit_alto - 1;
            mont(1, 0, 3);                      // acumulador = S
            mont(1, 1, 2);
            for (k = bit_alto - 1; k >= 0; k = k - 1) begin
                mont(1, 1, 1);
                if (e[k]) mont(1, 1, 0);
            end
            mont(1, 1, 3);                      // sai da forma de Montgomery
            dif = 0;
            for (k = 0; k < 128; k = k + 1) begin
                le({1'b0, 3'd1, k[6:0]}, v);
                if (v !== kat[(3 + 2*idx)*128 + k]) dif = dif + 1;
            end
            if (dif != 0) begin
                $display("[tb_rsa_mont] FAIL: KAT %0d, %0d limbs diferentes", idx, dif);
                erros = erros + 1;
            end
        end
    endtask

    integer c, k, dif;
    reg [15:0] v;

    initial begin
        $readmemh("../vectors/rsa_mont.hex", prod);
        $readmemh("../vectors/rsa_mont_cfg.hex", cfg);
        $readmemh("../vectors/rsa_kat.hex", kat);
        if (prod[0] === 16'hxxxx || kat[0] === 16'hxxxx) begin
            $display("[tb_rsa_mont] FAIL: vetores nao carregados");
            $finish;
        end
        for (k = 0; k <= 128; k = k + 1) ciclos_de[k] = -1;
        repeat (5) @(negedge clk);
        rstn = 1;
        repeat (2) @(negedge clk);

        // 1 e 2: produtos
        for (c = 0; c < NP; c = c + 1) begin
            len = cfg[2*c][7:0];
            n0p = cfg[2*c + 1];
            for (k = 0; k < 128; k = k + 1) begin
                escreve({1'b1, 3'd0, k[6:0]}, prod[c*512 + k]);
                escreve({1'b0, 3'd4, k[6:0]}, prod[c*512 + 128 + k]);
                escreve({1'b0, 3'd5, k[6:0]}, prod[c*512 + 256 + k]);
            end
            mont(6, 4, 5);
            if (ciclos_de[len] == -1)
                ciclos_de[len] = ciclos;
            else if (ciclos_de[len] != ciclos) begin
                $display("[tb_rsa_mont] FAIL: len %0d levou %0d e %0d ciclos", len,
                         ciclos_de[len], ciclos);
                erros = erros + 1;
            end
            dif = 0;
            for (k = 0; k < len; k = k + 1) begin
                le({1'b0, 3'd6, k[6:0]}, v);
                if (v !== prod[c*512 + 384 + k]) dif = dif + 1;
            end
            if (dif != 0) begin
                $display("[tb_rsa_mont] FAIL: produto %0d (len %0d), %0d limbs diferentes",
                         c, len, dif);
                erros = erros + 1;
            end
        end
        $display("[tb_rsa_mont] produtos: %0d casos; ciclos len 128 = %0d, 64 = %0d, 2 = %0d, 1 = %0d",
                 NP, ciclos_de[128], ciclos_de[64], ciclos_de[2], ciclos_de[1]);

        // 3: KAT do CAVP
        len = 128;
        n0p = `RSA_N0P;
        for (k = 0; k < 128; k = k + 1) begin
            escreve({1'b1, 3'd0, k[6:0]}, kat[k]);
            escreve({1'b0, 3'd2, k[6:0]}, kat[128 + k]);
            escreve({1'b0, 3'd3, k[6:0]}, (k == 0) ? 16'd1 : 16'd0);
        end
        for (c = 0; c < NK; c = c + 1) exponencia(c);
        $display("[tb_rsa_mont] KAT SigGen15: %0d vetores", NK);

        // wipe
        @(negedge clk);
        wipe = 1;
        @(negedge clk);
        wipe = 0;
        while (busy) @(negedge clk);
        dif = 0;
        for (k = 0; k < 1024; k = k + 1) begin
            le({1'b0, k[9:0]}, v);
            if (v !== 16'd0) dif = dif + 1;
        end
        for (k = 0; k < 128; k = k + 1)
            if (dut.nmem[k] !== 16'd0 || dut.tmem[k] !== 16'd0) dif = dif + 1;
        if (dif != 0) begin
            $display("[tb_rsa_mont] FAIL: wipe deixou %0d limbs", dif);
            erros = erros + 1;
        end
        // n0p = -N^-1 mod 2^16. Com CRT, N e um primo da chave.
        if (dut.n0p !== 16'd0) begin
            $display("[tb_rsa_mont] FAIL: wipe deixou n0p = %h", dut.n0p);
            erros = erros + 1;
        end

        if (erros == 0) $display("[tb_rsa_mont] PASS");
        else            $display("[tb_rsa_mont] FAIL: %0d erros", erros);
        $finish;
    end

    initial begin
        #2000000000;
        $display("[tb_rsa_mont] FAIL: timeout");
        $finish;
    end
endmodule
