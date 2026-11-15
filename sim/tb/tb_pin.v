`timescale 1ns/1ps
//
// tb_pin -- traducao de PIN block ISO 9564-1 formato 4, porta host (fase 8)
//
// O formato 0 e a traducao entre formatos estao no tb_pin0.
//
// sim-timeout: 14400
//
// Contra o firmware real no NEORV32. O PIN block de entrada e as chaves vem
// do host/pinblock.py e do host/tr31.py (scripts/mkvectors.py):
//
//   1. antes da cerimonia, P0 e recusado pelo estado (erro 20);
//   2. P0 da chave de origem para a de destino: P1 00 e 32 digitos hex;
//   3. o bloco traduzido e aberto pelo C2, com a chave de destino embrulhada
//      como chave de dados: D( D(bloco) ^ campo do PAN ) tem de dar o campo
//      do PIN que o Python montou, com os 8 bytes aleatorios TROCADOS;
//   4. o mesmo pedido de novo da um bloco diferente;
//   5. PIN block com um bit trocado: erro 14. PAN com um digito trocado:
//      erro 14;
//   6. chave de origem que nao e P0: erro 11. Idem a de destino;
//   7. formato desconhecido: erro 16. Pedido curto: erro 22. Key block
//      adulterado: erro 10.
//
module tb_pin;

    localparam real BIT_NS = 1000000000.0 / 115200.0;

    // Ver tb_uart_frame: clock nominal reduzido so para encolher o divisor
    // do debounce. O clock real continua sendo o de 100 MHz.
    localparam integer TB_CLK_HZ     = 100_000;
    localparam real    BTN_SETTLE_NS = 1000000.0;

    localparam [7:0] CMD_GET_VERSION = 8'h02;
    localparam [7:0] CMD_LMK_LOAD    = 8'h20;
    localparam [7:0] CMD_IMPORT_KEY  = 8'h24;
    localparam [7:0] CMD_KEY_INFO    = 8'h25;
    localparam [7:0] CMD_SET_STATE   = 8'h26;
    localparam [7:0] CMD_ENCRYPT     = 8'h27;

    localparam [7:0] ST_OK        = 8'h00;
    localparam [7:0] ST_BAD_PARAM = 8'h11;

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;
    reg  btn_a   = 1'b1;
    reg  btn_b   = 1'b1;

    wire       uart_tx;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;

    integer errors = 0;
    integer erros_antes;
    integer i;

    reg [7:0] resp [0:2047];
    integer   resp_len;
    reg [7:0] st;

    reg [7:0] req [0:2047];
    integer   req_len;

    reg [7:0] comp0 [0:31];
    reg [7:0] comp1 [0:31];
    reg [7:0] comp2 [0:31];
    reg [7:0] lmk   [0:31];

    reg [7:0] ko    [0:143];   // key block da chave de origem, P0
    reg [7:0] kd    [0:143];   // key block da chave de destino, P0
    reg [7:0] kd_d0 [0:143];   // a chave de destino embrulhada como D0
    reg [7:0] dados [0:63];    // PAN(16) . PIN block(16) . campo PAN(16) . campo PIN(16)
    reg [7:0] saida [0:15];    // o PIN block traduzido
    reg [7:0] meio  [0:15];
    reg [7:0] campo [0:15];
    integer   iguais;

    always #10 sys_clk = ~sys_clk;
    wire flash_csn, flash_mosi, flash_miso;

    hsm_top #(
        .CLK_HZ (TB_CLK_HZ)
    ) dut (
        .sys_clk_i  (sys_clk),
        .rst_n_i    (rst_n),
        .uart_rxd_i (uart_rx),
        .uart_txd_o (uart_tx),
        .btn_a_i    (btn_a),
        .btn_b_i    (btn_b),
        .led_o      (led),
        .seg_o      (seg),
        .seg_an_o   (seg_an),
        .flash_csn_o    (flash_csn),
        .flash_mosi_o   (flash_mosi),
        .flash_miso_i   (flash_miso),
        .flash_wp_n_o   (),
        .flash_hold_n_o ()
    );

    spi_flash_model flash (
        .sck  (dut.flash_sck),
        .csn  (flash_csn),
        .mosi (flash_mosi),
        .miso (flash_miso)
    );

    // ------------------------------------------------------------------
    // CRC32 IEEE 802.3 refletido -- so o console usa
    // ------------------------------------------------------------------
    function [31:0] crc32_update;
        input [31:0] crc;
        input [7:0]  b;
        integer k;
        reg [31:0] c;
        begin
            c = crc ^ {24'd0, b};
            for (k = 0; k < 8; k = k + 1) begin
                if (c[0]) c = (c >> 1) ^ 32'hEDB88320;
                else      c = c >> 1;
            end
            crc32_update = c;
        end
    endfunction

    function [7:0] hexdig;
        input [3:0] v;
        hexdig = (v < 10) ? (8'd48 + v) : (8'd55 + v);
    endfunction

    // Dois digitos hex -> um byte, numa chamada so, com nomes que nao
    // existem em nenhum outro escopo. A versao anterior -- {hexval(x),
    // hexval(y)} -- leu "47" como 4B nesta simulacao, enquanto o firmware
    // e o console concordavam em 47 (2026-11-03). Num modulo isolado a mesma
    // expressao funcionou; a causa no xsim nao foi isolada, e o padrao foi
    // trocado por este, que nao depende de duas chamadas da mesma funcao
    // estatica na mesma expressao.
    function [7:0] hexbyte;
        input [7:0] hb_hi;
        input [7:0] hb_lo;
        reg   [3:0] hb_a, hb_b;
        begin
            hb_a = (hb_hi >= 8'd65) ? (hb_hi - 8'd55) : (hb_hi - 8'd48);
            hb_b = (hb_lo >= 8'd65) ? (hb_lo - 8'd55) : (hb_lo - 8'd48);
            hexbyte = {hb_a, hb_b};
        end
    endfunction

    task uart_put(input [7:0] b);
        integer k;
        begin
            uart_rx = 1'b0;  #(BIT_NS);
            for (k = 0; k < 8; k = k + 1) begin
                uart_rx = b[k];  #(BIT_NS);
            end
            uart_rx = 1'b1;  #(BIT_NS);
        end
    endtask

    task uart_get(output [7:0] data);
        integer k;
        reg     valid;
        begin
            valid = 1'b0;
            while (!valid) begin
                @(negedge uart_tx);
                #(BIT_NS * 0.5);
                if (uart_tx === 1'b0) valid = 1'b1;
            end
            for (k = 0; k < 8; k = k + 1) begin
                #(BIT_NS);
                data[k] = uart_tx;
            end
            #(BIT_NS);
        end
    endtask

    // ---- montagem do pedido ------------------------------------------
    task limpa; begin req_len = 0; end endtask
    task poe(input [7:0] b); begin req[req_len] = b; req_len = req_len + 1; end endtask
    task poe_hex(input [7:0] b); begin poe(hexdig(b[7:4])); poe(hexdig(b[3:0])); end endtask
    task poe_dec4(input integer v);
        begin
            poe(8'd48 + (v / 1000) % 10); poe(8'd48 + (v / 100) % 10);
            poe(8'd48 + (v / 10) % 10);   poe(8'd48 + v % 10);
        end
    endtask
    // cabecalho fixo "TB01" + comando
    task inicio(input [7:0] c0, input [7:0] c1);
        begin limpa(); poe("T"); poe("B"); poe("0"); poe("1"); poe(c0); poe(c1); end
    endtask

    // ---- porta HOST: LEN(2) + mensagem, sem CRC ----------------------
    task ascii_troca;
        reg [15:0] len;
        reg [7:0]  b;
        integer    k;
        begin
            len = req_len;
            uart_put(len[15:8]);
            uart_put(len[7:0]);
            for (k = 0; k < req_len; k = k + 1)
                uart_put(req[k]);

            uart_get(b); len[15:8] = b;
            uart_get(b); len[7:0]  = b;
            resp_len = len;
            for (k = 0; k < len; k = k + 1) begin
                uart_get(b);
                resp[k] = b;
            end
        end
    endtask

    // Confere cabecalho devolvido, codigo de resposta e erro.
    task confere(input [7:0] r0, input [7:0] r1, input integer erro,
                 input [8*24-1:0] nome);
        begin
            if (resp_len < 8 ||
                resp[0] !== "T" || resp[1] !== "B" || resp[2] !== "0" || resp[3] !== "1") begin
                $display("[tb_pin] FAIL: %0s -- resposta curta ou cabecalho trocado (len=%0d)",
                         nome, resp_len);
                errors = errors + 1;
            end else if (resp[4] !== r0 || resp[5] !== r1) begin
                $display("[tb_pin] FAIL: %0s -- resposta %c%c, esperado %c%c",
                         nome, resp[4], resp[5], r0, r1);
                errors = errors + 1;
            end else if (((resp[6] - 8'd48) * 10 + (resp[7] - 8'd48)) !== erro) begin
                $display("[tb_pin] FAIL: %0s -- erro %c%c, esperado %0d",
                         nome, resp[6], resp[7], erro);
                errors = errors + 1;
            end
        end
    endtask

    // ---- console: o frame binario de sempre ---------------------------
    task console(input [7:0] opcode);
        reg [31:0] crc, crc_rx;
        reg [15:0] len;
        reg [7:0]  b;
        integer    k;
        begin
            len = req_len + 1;
            crc = 32'hFFFFFFFF;
            crc = crc32_update(crc, len[15:8]);
            crc = crc32_update(crc, len[7:0]);
            crc = crc32_update(crc, opcode);
            for (k = 0; k < req_len; k = k + 1)
                crc = crc32_update(crc, req[k]);
            crc = ~crc;

            uart_put(len[15:8]);
            uart_put(len[7:0]);
            uart_put(opcode);
            for (k = 0; k < req_len; k = k + 1)
                uart_put(req[k]);
            uart_put(crc[31:24]); uart_put(crc[23:16]);
            uart_put(crc[15:8]);  uart_put(crc[7:0]);

            uart_get(b); len[15:8] = b;
            uart_get(b); len[7:0]  = b;
            crc = 32'hFFFFFFFF;
            crc = crc32_update(crc, len[15:8]);
            crc = crc32_update(crc, len[7:0]);
            resp_len = len;
            for (k = 0; k < len; k = k + 1) begin
                uart_get(b);
                resp[k] = b;
                crc = crc32_update(crc, b);
            end
            crc = ~crc;
            uart_get(b); crc_rx[31:24] = b;
            uart_get(b); crc_rx[23:16] = b;
            uart_get(b); crc_rx[15:8]  = b;
            uart_get(b); crc_rx[7:0]   = b;
            if (crc !== crc_rx) begin
                $display("[tb_pin] FAIL: CRC da resposta do console invalido");
                errors = errors + 1;
            end
            st = resp[0];
        end
    endtask

    task apertar; begin btn_a = 1'b0; btn_b = 1'b0; #(BTN_SETTLE_NS); end endtask
    task soltar;  begin btn_a = 1'b1; btn_b = 1'b1; #(BTN_SETTLE_NS); end endtask

    task cerimonia;
        integer n, k;
        begin
            for (n = 0; n < 3; n = n + 1) begin
                soltar(); apertar();
                limpa();
                poe(n[7:0]);
                for (k = 0; k < 32; k = k + 1)
                    case (n)
                        0: poe(comp0[k]);
                        1: poe(comp1[k]);
                        default: poe(comp2[k]);
                    endcase
                console(CMD_LMK_LOAD);
                if (st !== ST_OK) begin
                    $display("[tb_pin] FAIL: componente %0d -> 0x%02h", n, st);
                    errors = errors + 1;
                end
            end
            soltar(); apertar();
            limpa(); poe(8'd2);
            console(CMD_SET_STATE);
            soltar();
            if (st !== ST_OK) begin
                $display("[tb_pin] FAIL: SET_STATE -> 0x%02h", st);
                errors = errors + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #2000000000;     // 2 s
        $display("[tb_pin] FAIL: timeout");
        $display("[tb_pin] FAIL");
        $finish;
    end

    // P0: origem . destino . formatos . PAN . PIN block. `qo`/`qd` escolhem
    // o key block (0 = ko, 1 = kd, 2 = kd como D0). `mexe`: 1 troca um bit
    // do PIN block, 2 troca um digito do PAN, 3 pede formato '1', 4 troca
    // um caractere do key block de origem.
    task pede_p0(input integer qo, input integer qd, input integer mexe);
        integer k;
        reg [7:0] b;
        begin
            inicio("P", "0");
            for (k = 0; k < 144; k = k + 1) begin
                b = (qo == 0) ? ko[k] : (qo == 1) ? kd[k] : kd_d0[k];
                if (mexe == 4 && k == 100) b = (b == "0") ? "1" : "0";
                poe(b);
            end
            for (k = 0; k < 144; k = k + 1)
                poe((qd == 0) ? ko[k] : (qd == 1) ? kd[k] : kd_d0[k]);
            poe((mexe == 3) ? "1" : "4"); poe("4");
            poe("1"); poe("6");
            for (k = 0; k < 16; k = k + 1) begin
                b = dados[k];
                if (mexe == 2 && k == 15) b = (b == "0") ? "1" : "0";
                poe(b);
            end
            for (k = 0; k < 16; k = k + 1) begin
                b = dados[16 + k];
                if (mexe == 1 && k == 0) b = b ^ 8'h01;
                poe_hex(b);
            end
            ascii_troca();
        end
    endtask

    // C2 de UM bloco com a chave de destino como D0 e IV zero: AES puro.
    // Entrada em `meio`, saida em `meio`.
    task decifra_meio;
        integer k;
        begin
            inicio("C", "2");
            for (k = 0; k < 144; k = k + 1) poe(kd_d0[k]);
            for (k = 0; k < 16; k = k + 1) poe_hex(8'h00);
            poe_dec4(16);
            for (k = 0; k < 16; k = k + 1) poe_hex(meio[k]);
            ascii_troca();
            confere("C", "3", 0, "C2 de conferencia");
            if (resp_len != 8 + 4 + 32) begin
                $display("[tb_pin] FAIL: C2 devolveu %0d bytes", resp_len);
                errors = errors + 1;
            end else
                for (k = 0; k < 16; k = k + 1)
                    meio[k] = hexbyte(resp[12 + 2*k], resp[13 + 2*k]);
        end
    endtask

    // Abre `saida` (sob a chave de destino) e deixa o campo do PIN em `campo`.
    task abre_saida;
        integer k;
        begin
            for (k = 0; k < 16; k = k + 1) meio[k] = saida[k];
            decifra_meio();
            for (k = 0; k < 16; k = k + 1) meio[k] = meio[k] ^ dados[32 + k];
            decifra_meio();
            for (k = 0; k < 16; k = k + 1) campo[k] = meio[k];
        end
    endtask

    task guarda_saida(input [8*24-1:0] nome);
        integer k;
        begin
            confere("P", "1", 0, nome);
            if (resp_len != 8 + 32) begin
                $display("[tb_pin] FAIL: %0s -- %0d bytes, esperado 40", nome, resp_len);
                errors = errors + 1;
            end else
                for (k = 0; k < 16; k = k + 1)
                    saida[k] = hexbyte(resp[8 + 2*k], resp[9 + 2*k]);
        end
    endtask

    initial begin
        $display("[tb_pin] inicio");
        $readmemh("../vectors/pin_ko.hex", ko);
        $readmemh("../vectors/pin_kd.hex", kd);
        $readmemh("../vectors/pin_kd_d0.hex", kd_d0);
        $readmemh("../vectors/pin_dados.hex", dados);
        if (ko[0] === 8'hxx || kd[0] === 8'hxx || kd_d0[0] === 8'hxx ||
            dados[0] === 8'hxx) begin
            $display("[tb_pin] FAIL: vetores nao carregados");
            $finish;
        end

        // LMK de teste, por tres componentes: a mesma do tb_rsa.
        for (i = 0; i < 32; i = i + 1) begin
            comp0[i] = 8'h10 + i[7:0];
            comp1[i] = 8'h5A ^ (i[7:0] * 8'h07);
            comp2[i] = 8'hC3 + i[7:0];
        end

        #200;
        rst_n = 1'b1;
        wait ((led[1] === 1'b0) || (led[4] === 1'b0));
        #1000;
        if (led[4] === 1'b0) begin
            $display("[tb_pin] FAIL: o POST reprovou no boot");
            $finish;
        end
        limpa();
        console(CMD_GET_VERSION);

        pede_p0(0, 1, 0);
        confere("P", "1", 20, "P0 antes da cerimonia");

        cerimonia();
        $display("[tb_pin] %0t ns: cerimonia feita", $time);

        // ---- a traducao, e a prova de que o PIN e o mesmo --------------
        erros_antes = errors;
        pede_p0(0, 1, 0);
        guarda_saida("P0 origem -> destino");
        abre_saida();
        iguais = 0;
        for (i = 0; i < 8; i = i + 1) begin
            if (campo[i] !== dados[48 + i]) begin
                $display("[tb_pin] FAIL: campo do PIN, byte %0d: %02h, esperado %02h",
                         i, campo[i], dados[48 + i]);
                errors = errors + 1;
            end
            if (campo[8 + i] === dados[56 + i]) iguais = iguais + 1;
        end
        if (iguais == 8) begin
            $display("[tb_pin] FAIL: os 8 bytes aleatorios nao foram trocados");
            errors = errors + 1;
        end
        if (errors == erros_antes)
            $display("[tb_pin] %0t ns: bloco traduzido, e o campo do PIN confere", $time);

        // ---- o mesmo pedido de novo: outro bloco -----------------------
        for (i = 0; i < 16; i = i + 1) meio[i] = saida[i];
        pede_p0(0, 1, 0);
        guarda_saida("P0 de novo");
        iguais = 0;
        for (i = 0; i < 16; i = i + 1)
            if (saida[i] === meio[i]) iguais = iguais + 1;
        if (iguais == 16) begin
            $display("[tb_pin] FAIL: dois pedidos iguais deram o mesmo bloco");
            errors = errors + 1;
        end

        // ---- recusas ---------------------------------------------------
        pede_p0(0, 1, 1);
        confere("P", "1", 14, "PIN block adulterado");
        pede_p0(0, 1, 2);
        confere("P", "1", 14, "PAN trocado");
        pede_p0(1, 0, 0);
        confere("P", "1", 14, "chave de origem errada");
        pede_p0(2, 1, 0);
        confere("P", "1", 11, "origem nao e P0");
        pede_p0(0, 2, 0);
        confere("P", "1", 11, "destino nao e P0");
        pede_p0(0, 1, 3);
        confere("P", "1", 16, "formato desconhecido");
        pede_p0(0, 1, 4);
        confere("P", "1", 10, "key block adulterado");
        inicio("P", "0");
        poe("A");
        ascii_troca();
        confere("P", "1", 22, "P0 curto");
        $display("[tb_pin] %0t ns: recusas conferidas", $time);

        if (errors == 0) $display("[tb_pin] PASS");
        else             $display("[tb_pin] FAIL: %0d erro(s)", errors);
        $finish;
    end

endmodule
