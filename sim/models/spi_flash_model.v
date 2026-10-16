`timescale 1ns/1ps
//
// spi_flash_model.v -- modelo comportamental da MT25QL128, so o que o
// firmware usa
//
// NAO e o modelo do fabricante. E um modelo PROPRIO, escrito a partir do
// datasheet, e por isso tem o defeito classico: se eu tiver lido o
// datasheet errado, o modelo e o driver concordam no erro. O que fecha
// isso e a placa -- a validacao em hardware (doc/fase4-notas.md) e a
// prova, a simulacao e o filtro.
//
// O que ele modela, em SPI modo 0 e linha unica:
//
//   0x9F  READ ID              20 BA 18 (Micron, MT25QL, 128 Mbit)
//   0x05  READ STATUS          bit 0 = WIP, bit 1 = WEL
//   0x06  WRITE ENABLE         liga WEL
//   0x04  WRITE DISABLE        desliga WEL
//   0x03  READ                 endereco de 3 bytes, leitura continua
//   0x02  PAGE PROGRAM         ate 256 bytes, DA A VOLTA dentro da pagina
//   0x20  SUBSECTOR ERASE 4KB
//
// E as duas regras do datasheet que mais pegam driver:
//
//   - PROGRAMAR SO DESCE BITS. Gravar sobre o que nao foi apagado faz AND
//     com o conteudo; o modelo faz o mesmo, em vez de sobrescrever.
//   - PROGRAM e ERASE so executam se o CS subir num multiplo de 8 bits, e
//     so com WEL ligado. Depois deles, WEL desliga sozinho.
//
// O modelo guarda SO a janela a partir de 4 MB. Abaixo dela fica o
// bitstream, que o firmware nao pode tocar: qualquer PROGRAM ou ERASE la
// e contado em `violacoes`, e os testbenches exigem zero. E o teste da
// guarda de fw/src/flash.c.
//
// A memoria sobrevive ao reset do DUT -- e assim que os testbenches
// simulam desligar e religar a placa.
//
module spi_flash_model #(
    parameter integer BASE   = 32'h400000,   // inicio da janela modelada
    parameter integer TAM    = 32'h080000,   // 512 KB
    parameter integer T_PP   = 20_000,       // ns -- page program
    parameter integer T_SSE  = 200_000       // ns -- erase de 4 KB
)(
    input  wire sck,
    input  wire csn,
    input  wire mosi,
    output wire miso
);

    reg [7:0] mem [0:TAM-1];

    integer violacoes = 0;   // PROGRAM/ERASE abaixo de BASE
    integer programas = 0;   // contadores, para os testbenches
    integer apagamentos = 0;

    reg wel = 1'b0;
    reg wip = 1'b0;

    // estado da transacao
    reg  [7:0]  cmd;
    reg  [7:0]  sh_in;
    integer     nbits;          // bits recebidos desde o CS cair
    reg  [23:0] addr;
    reg  [7:0]  sh_out;
    reg         out_en;
    reg         miso_r;

    reg  [7:0]  pagebuf [0:255];
    reg  [255:0] pagevalid;
    reg  [7:0]  pp_col;         // coluna dentro da pagina

    integer i;

    initial begin
        for (i = 0; i < TAM; i = i + 1) mem[i] = 8'hFF;
        out_en = 1'b0;
        miso_r = 1'b0;
        nbits  = 0;
    end

    assign miso = out_en ? miso_r : 1'bz;

    function [7:0] le;
        input [23:0] a;
        begin
            if ((a >= BASE) && (a < BASE + TAM)) le = mem[a - BASE];
            else                                 le = 8'hA5;   // "bitstream"
        end
    endfunction

    // proximo byte a sair, conforme o comando
    function [7:0] proximo_byte;
        input integer nbyte;          // indice do byte de dados (0..)
        begin
            case (cmd)
                8'h9F: proximo_byte = (nbyte == 0) ? 8'h20 :
                                      (nbyte == 1) ? 8'hBA :
                                      (nbyte == 2) ? 8'h18 : 8'h00;
                8'h05: proximo_byte = {6'b0, wel, wip};
                8'h03: proximo_byte = le(addr + nbyte);
                default: proximo_byte = 8'hFF;
            endcase
        end
    endfunction

    integer nbyte_dados;

    always @(negedge csn) begin
        nbits     = 0;
        cmd       = 8'h00;
        addr      = 24'h0;
        out_en    = 1'b0;
        pagevalid = 256'b0;
    end

    // amostra na subida (modo 0)
    always @(posedge sck) begin
        if (!csn) begin
            sh_in = {sh_in[6:0], mosi};
            nbits = nbits + 1;

            if (nbits == 8) begin
                cmd = sh_in;
                if (wip && (cmd != 8'h05)) cmd = 8'h00;   // ocupada: so status
                if (cmd == 8'h06) wel = 1'b1;
                if (cmd == 8'h04) wel = 1'b0;
            end else if ((nbits > 8) && (nbits <= 32) && (nbits % 8 == 0) &&
                         ((cmd == 8'h03) || (cmd == 8'h02) || (cmd == 8'h20))) begin
                addr = {addr[15:0], sh_in};
                if (nbits == 32) pp_col = addr[7:0];
            end else if ((nbits > 32) && (nbits % 8 == 0) && (cmd == 8'h02)) begin
                pagebuf[pp_col]   = sh_in;
                pagevalid[pp_col] = 1'b1;
                pp_col = pp_col + 8'd1;     // da a volta na pagina
            end
        end
    end

    // muda a saida na descida (modo 0)
    always @(negedge sck) begin
        if (!csn) begin
            if (((cmd == 8'h9F) || (cmd == 8'h05)) && (nbits >= 8)) begin
                nbyte_dados = (nbits - 8) / 8;
                if ((nbits - 8) % 8 == 0) sh_out = proximo_byte(nbyte_dados);
                out_en = 1'b1;
                miso_r = sh_out[7 - ((nbits - 8) % 8)];
            end else if ((cmd == 8'h03) && (nbits >= 32)) begin
                nbyte_dados = (nbits - 32) / 8;
                if ((nbits - 32) % 8 == 0) sh_out = proximo_byte(nbyte_dados);
                out_en = 1'b1;
                miso_r = sh_out[7 - ((nbits - 32) % 8)];
            end
        end
    end

    // fim da transacao: PROGRAM e ERASE executam aqui
    integer k;
    reg [23:0] base_pag, base_sub;
    always @(posedge csn) begin
        out_en = 1'b0;
        if ((nbits % 8 == 0) && wel && !wip) begin
            if ((cmd == 8'h02) && (nbits > 32)) begin
                base_pag = {addr[23:8], 8'h00};
                if (base_pag < BASE) begin
                    violacoes = violacoes + 1;
                    $display("[spi_flash] VIOLACAO: PROGRAM em 0x%06h, abaixo da janela", addr);
                end else if (base_pag < BASE + TAM) begin
                    for (k = 0; k < 256; k = k + 1)
                        if (pagevalid[k])
                            mem[base_pag - BASE + k] = mem[base_pag - BASE + k] & pagebuf[k];
                end
                programas = programas + 1;
                wel = 1'b0;
                wip = 1'b1;
                wip <= #(T_PP) 1'b0;      // nao bloqueia o always
            end else if ((cmd == 8'h20) && (nbits == 32)) begin
                base_sub = {addr[23:12], 12'h000};
                if (base_sub < BASE) begin
                    violacoes = violacoes + 1;
                    $display("[spi_flash] VIOLACAO: ERASE em 0x%06h, abaixo da janela", addr);
                end else if (base_sub < BASE + TAM) begin
                    for (k = 0; k < 4096; k = k + 1)
                        mem[base_sub - BASE + k] = 8'hFF;
                end
                apagamentos = apagamentos + 1;
                wel = 1'b0;
                wip = 1'b1;
                wip <= #(T_SSE) 1'b0;
            end
        end
    end

endmodule
