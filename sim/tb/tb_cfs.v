`timescale 1ns/1ps
//
// tb_cfs -- o coprocessador criptografico visto pelo barramento
//
// tb_aes_kat e tb_sha256_kat ja provaram que os CORES estao certos. Este
// testbench prova outra coisa, e e uma coisa diferente: que o CAMINHO entre
// a CPU e os cores esta certo.
//
// A distincao importa porque a classe de defeito e outra. Um core correto
// atras de um mapa de registradores com a ordem das palavras invertida
// produz resultados perfeitamente errados, e nenhum KAT de core pega isso.
// Por isso aqui os mesmos vetores do NIST sao replicados ATRAVES do
// barramento -- escrita de chave palavra a palavra, comando por CTRL,
// espera por STATUS, leitura de resultado palavra a palavra.
//
// Cobre:
//   1. ID do bloco
//   2. DNA_PORT -- 57 bits, ordem dos bits, contagem
//   3. AES-256 ECB, cifra e decifra, todos os vetores do AESAVS
//   4. SHA-256, todas as mensagens do SHAVS, inclusive multi-bloco
//   5. escrita-somente: leitura de chave e bloco devolve zero
//   6. WIPE: a chave EXPANDIDA e sobrescrita, nao so o registrador
//
// O item 6 e o que separa zeroizacao de teatro de zeroizacao. Zerar o
// registrador de chave e facil; provar que a chave expandida dentro do
// aes_key_mem sumiu exige medir o comportamento do core depois do wipe.
//
`include "counts.vh"

module tb_cfs;

    localparam CLK_HALF   = 5;      // 100 MHz
    localparam MAX_BLOCOS = 256;

    // Mapa de registradores -- espelha rtl/crypto/hsm_cfs.v
    localparam [15:0] R_ID     = 16'h000;
    localparam [15:0] R_STATUS = 16'h004;
    localparam [15:0] R_CTRL   = 16'h008;
    localparam [15:0] R_KEY    = 16'h020;   // 8 palavras
    localparam [15:0] R_BLOCK  = 16'h040;   // 4 palavras
    localparam [15:0] R_RESULT = 16'h050;   // 4 palavras
    localparam [15:0] R_SBLOCK = 16'h080;   // 16 palavras
    localparam [15:0] R_DIGEST = 16'h0C0;   // 8 palavras
    localparam [15:0] R_DNA_LO = 16'h100;
    localparam [15:0] R_DNA_HI = 16'h104;

    localparam [31:0] C_AES_INIT = 32'h01;
    localparam [31:0] C_AES_NEXT = 32'h02;
    localparam [31:0] C_AES_ENC  = 32'h04;
    localparam [31:0] C_SHA_INIT = 32'h08;
    localparam [31:0] C_SHA_NEXT = 32'h10;
    localparam [31:0] C_WIPE     = 32'h20;

    localparam [31:0] S_AES_BUSY  = 32'h01;
    localparam [31:0] S_AES_VALID = 32'h02;
    localparam [31:0] S_SHA_BUSY  = 32'h04;
    localparam [31:0] S_SHA_VALID = 32'h08;
    localparam [31:0] S_DNA_VALID = 32'h10;
    localparam [31:0] S_WIPE_BUSY = 32'h20;

    // Precisa bater com SIM_DNA_VALUE em rtl/crypto/hsm_cfs.v. Se um dos
    // dois mudar sem o outro, este testbench reprova -- que e o desejado.
    localparam [56:0] DNA_ESPERADO = 57'h0123456789ABCDE;

    reg         clk = 1'b0;
    reg         rstn = 1'b0;
    reg  [15:0] addr = 16'd0;
    reg  [31:0] wdata = 32'd0;
    reg         stb = 1'b0;
    reg         rw = 1'b0;
    wire [31:0] rdata;
    wire        ack;
    wire        irq;

    integer erros = 0;
    integer i, j, b, base, n;

    always #CLK_HALF clk = ~clk;

    // ------------------------------------------------------------------
    // Fonte de entropia SIMULADA.
    //
    // O hsm_entropy de verdade nao entra aqui: ele e um oscilador em anel,
    // e em simulacao um anel ou nao oscila ou oscila do jeito que o
    // simulador quiser. Nao da para REPRODUZIR "fonte travada" nem "fonte
    // enviesada" com ele -- e sao esses dois casos que precisam ser
    // testados.
    //
    // Entao a fonte e um LFSR sob controle do testbench, que sabe trocar
    // para travada quando quiser. Os health tests em si ja foram testados
    // isoladamente em tb_trng_health; o que se verifica AQUI e o caminho
    // pelo barramento: registradores, retrato e bits de status.
    // ------------------------------------------------------------------
    reg        ent_travada = 1'b0;
    reg [31:0] ent_lfsr    = 32'h1357_9BDF;
    wire       ent_en;
    reg        ent_raw     = 1'b0;
    reg        ent_rawv    = 1'b0;
    reg [7:0]  ent_byte    = 8'd0;
    reg        ent_bytev   = 1'b0;
    // Um byte a cada 64 ciclos, nao a cada 8.
    //
    // Nao e detalhe de conveniencia: com um byte a cada 8 ciclos, o byte
    // seguinte chega no MESMO ciclo da leitura e re-arma BYTE_VALID por
    // direito. O teste "a leitura consome" reprovava um RTL correto. E a
    // fonte real e mesmo lenta assim -- o von Neumann descarta os pares
    // 00 e 11, entao sobra menos de um bit a cada quatro amostras.
    reg [5:0]  ent_bcnt    = 6'd0;

    always @(posedge clk) begin
        if (!ent_en) begin
            ent_rawv  <= 1'b0;
            ent_bytev <= 1'b0;
            ent_bcnt  <= 6'd0;
        end else begin
            ent_lfsr <= {ent_lfsr[30:0],
                         ent_lfsr[31] ^ ent_lfsr[21] ^ ent_lfsr[1] ^ ent_lfsr[0]};
            ent_raw  <= ent_travada ? 1'b0 : ent_lfsr[0];
            ent_rawv <= 1'b1;

            // um byte a cada 8 amostras, so para exercitar o caminho
            ent_byte  <= {ent_byte[6:0], ent_travada ? 1'b0 : ent_lfsr[0]};
            ent_bcnt  <= ent_bcnt + 6'd1;
            ent_bytev <= (ent_bcnt == 6'd63);
        end
    end

    hsm_cfs dut (
        .clk_i   (clk),
        .rstn_i  (rstn),
        .addr_i  (addr),
        .wdata_i (wdata),
        .stb_i   (stb),
        .rw_i    (rw),
        .rdata_o (rdata),
        .ack_o   (ack),

        .ent_en_o         (ent_en),
        .ent_raw_i        (ent_raw),
        .ent_raw_valid_i  (ent_rawv),
        .ent_byte_i       (ent_byte),
        .ent_byte_valid_i (ent_bytev),

        .irq_o   (irq)
    );

    // ------------------------------------------------------------------
    // Vetores -- os mesmos arquivos dos testbenches de core, gerados por
    // scripts/mkvectors.py a partir de vectors/ (hash em MANIFEST.txt).
    // ------------------------------------------------------------------
    reg [255:0] ecb_e_key [0:`N_AES_ECB-1];
    reg [127:0] ecb_e_in  [0:`N_AES_ECB-1];
    reg [127:0] ecb_e_out [0:`N_AES_ECB-1];
    reg [255:0] ecb_d_key [0:`N_AES_ECB-1];
    reg [127:0] ecb_d_in  [0:`N_AES_ECB-1];
    reg [127:0] ecb_d_out [0:`N_AES_ECB-1];

    reg [511:0] blocos   [0:MAX_BLOCOS-1];
    reg [31:0]  nblocos  [0:`N_SHA256-1];
    reg [255:0] esperado [0:`N_SHA256-1];

    initial begin
        $readmemh("../vectors/aes_ecb256_enc_key.hex", ecb_e_key);
        $readmemh("../vectors/aes_ecb256_enc_in.hex",  ecb_e_in);
        $readmemh("../vectors/aes_ecb256_enc_out.hex", ecb_e_out);
        $readmemh("../vectors/aes_ecb256_dec_key.hex", ecb_d_key);
        $readmemh("../vectors/aes_ecb256_dec_in.hex",  ecb_d_in);
        $readmemh("../vectors/aes_ecb256_dec_out.hex", ecb_d_out);

        $readmemh("../vectors/sha256_blocks.hex",  blocos);
        $readmemh("../vectors/sha256_nblocks.hex", nblocos);
        $readmemh("../vectors/sha256_digest.hex",  esperado);
    end

    // ------------------------------------------------------------------
    // Barramento. Mesmo protocolo do NEORV32: stb por um ciclo, ack e
    // rdata no ciclo seguinte.
    //
    // O estimulo muda na BORDA DE DESCIDA. Nao e estetica: dirigir na
    // borda de subida, que e a mesma em que o DUT amostra, e uma corrida
    // -- o simulador pode executar a atribuicao do testbench antes ou
    // depois do always do DUT, e o resultado muda. A primeira versao deste
    // arquivo fazia isso e o xsim resolveu a favor do testbench: o DUT via
    // stb um ciclo cedo, respondia cedo, e TODAS as leituras chegavam sem
    // ACK. Estimulo na descida, amostragem na subida, e a corrida some.
    // ------------------------------------------------------------------
    task bus_wr(input [15:0] a, input [31:0] d);
        begin
            @(negedge clk);
            addr = a; wdata = d; rw = 1'b1; stb = 1'b1;
            @(negedge clk);
            stb = 1'b0; rw = 1'b0;
        end
    endtask

    task bus_rd(input [15:0] a, output [31:0] d);
        begin
            @(negedge clk);
            addr = a; rw = 1'b0; stb = 1'b1;
            @(negedge clk);          // o DUT ja amostrou: ack e rdata valem
            stb = 1'b0;
            if (ack !== 1'b1) begin
                $display("[tb_cfs] FAIL: sem ACK na leitura de 0x%03h", a);
                erros = erros + 1;
            end
            d = rdata;
        end
    endtask

    // ------------------------------------------------------------------
    // Um valor grande atravessa o barramento em palavras de 32 bits, a
    // mais significativa primeiro. E aqui que mora a classe de erro que
    // este testbench existe para pegar.
    // ------------------------------------------------------------------
    task wr_256(input [15:0] base_a, input [255:0] v);
        integer k;
        begin
            for (k = 0; k < 8; k = k + 1)
                bus_wr(base_a + k*4, v[255 - 32*k -: 32]);
        end
    endtask

    task wr_128(input [15:0] base_a, input [127:0] v);
        integer k;
        begin
            for (k = 0; k < 4; k = k + 1)
                bus_wr(base_a + k*4, v[127 - 32*k -: 32]);
        end
    endtask

    task wr_512(input [15:0] base_a, input [511:0] v);
        integer k;
        begin
            for (k = 0; k < 16; k = k + 1)
                bus_wr(base_a + k*4, v[511 - 32*k -: 32]);
        end
    endtask

    task rd_128(input [15:0] base_a, output [127:0] v);
        integer k;
        reg [31:0] w;
        begin
            for (k = 0; k < 4; k = k + 1) begin
                bus_rd(base_a + k*4, w);
                v[127 - 32*k -: 32] = w;
            end
        end
    endtask

    task rd_256(input [15:0] base_a, output [255:0] v);
        integer k;
        reg [31:0] w;
        begin
            for (k = 0; k < 8; k = k + 1) begin
                bus_rd(base_a + k*4, w);
                v[255 - 32*k -: 32] = w;
            end
        end
    endtask

    // ------------------------------------------------------------------
    // Espera por STATUS. E assim que o firmware vai fazer: um bit so, sem
    // o handshake fragil de 'ready' -- ver o cabecalho de hsm_cfs.v.
    // ------------------------------------------------------------------
    task espera(input [31:0] mascara);
        reg [31:0] s;
        integer guarda;
        begin
            guarda = 0;
            s = mascara;
            while ((s & mascara) != 32'd0) begin
                bus_rd(R_STATUS, s);
                guarda = guarda + 1;
                if (guarda > 10000) begin
                    $display("[tb_cfs] FAIL: STATUS travado em 0x%08h (mascara 0x%02h)",
                             s, mascara);
                    erros = erros + 1;
                    $display("[tb_cfs] FAIL");
                    $finish;
                end
            end
        end
    endtask

    task aes_carrega_chave(input [255:0] k);
        begin
            wr_256(R_KEY, k);
            bus_wr(R_CTRL, C_AES_INIT);
            espera(S_AES_BUSY);
        end
    endtask

    task aes_processa(input cifra, input [127:0] b_in, output [127:0] b_out);
        begin
            wr_128(R_BLOCK, b_in);
            bus_wr(R_CTRL, C_AES_NEXT | (cifra ? C_AES_ENC : 32'd0));
            espera(S_AES_BUSY);
            rd_128(R_RESULT, b_out);
        end
    endtask

    // ------------------------------------------------------------------
    task t_id;
        reg [31:0] v;
        begin
            bus_rd(R_ID, v);
            if (v !== 32'h48534d31) begin
                $display("[tb_cfs] FAIL: ID = 0x%08h, esperado 0x48534d31", v);
                erros = erros + 1;
            end else
                $display("[tb_cfs] ID          : \"HSM1\"");
        end
    endtask

    task t_dna;
        reg [31:0] lo, hi;
        reg [56:0] dna;
        begin
            bus_rd(R_STATUS, lo);
            if ((lo & S_DNA_VALID) == 32'd0) begin
                $display("[tb_cfs] FAIL: DNA_VALID nao subiu apos o reset");
                erros = erros + 1;
            end

            bus_rd(R_DNA_LO, lo);
            bus_rd(R_DNA_HI, hi);
            dna = {hi[24:0], lo};

            if (hi[31:25] !== 7'd0) begin
                $display("[tb_cfs] FAIL: DNA_HI com bits acima de 56 (0x%08h)", hi);
                erros = erros + 1;
            end
            if (dna !== DNA_ESPERADO) begin
                $display("[tb_cfs] FAIL: DNA = %015h, esperado %015h", dna, DNA_ESPERADO);
                erros = erros + 1;
            end else
                $display("[tb_cfs] DNA_PORT    : %015h (57 bits)", dna);
        end
    endtask

    task t_aes;
        reg [127:0] r;
        begin
            n = 0;
            for (i = 0; i < `N_AES_ECB; i = i + 1) begin
                aes_carrega_chave(ecb_e_key[i]);
                aes_processa(1'b1, ecb_e_in[i], r);
                if (r !== ecb_e_out[i]) begin
                    if (n < 3)
                        $display("[tb_cfs] FAIL AES-enc %0d: obtido %032h esperado %032h",
                                 i, r, ecb_e_out[i]);
                    n = n + 1;
                end
            end
            if (n) begin
                $display("[tb_cfs] FAIL: AES cifra, %0d de %0d", n, `N_AES_ECB);
                erros = erros + n;
            end else
                $display("[tb_cfs] AES cifra   : %0d/%0d", `N_AES_ECB, `N_AES_ECB);

            n = 0;
            for (i = 0; i < `N_AES_ECB; i = i + 1) begin
                aes_carrega_chave(ecb_d_key[i]);
                aes_processa(1'b0, ecb_d_in[i], r);
                if (r !== ecb_d_out[i]) begin
                    if (n < 3)
                        $display("[tb_cfs] FAIL AES-dec %0d: obtido %032h esperado %032h",
                                 i, r, ecb_d_out[i]);
                    n = n + 1;
                end
            end
            if (n) begin
                $display("[tb_cfs] FAIL: AES decifra, %0d de %0d", n, `N_AES_ECB);
                erros = erros + n;
            end else
                $display("[tb_cfs] AES decifra : %0d/%0d", `N_AES_ECB, `N_AES_ECB);
        end
    endtask

    task t_sha;
        reg [255:0] d;
        begin
            n = 0;
            base = 0;
            for (i = 0; i < `N_SHA256; i = i + 1) begin
                for (b = 0; b < nblocos[i]; b = b + 1) begin
                    wr_512(R_SBLOCK, blocos[base + b]);
                    // Primeiro bloco inicializa o estado; os demais encadeiam.
                    bus_wr(R_CTRL, (b == 0) ? C_SHA_INIT : C_SHA_NEXT);
                    espera(S_SHA_BUSY);
                end
                rd_256(R_DIGEST, d);
                if (d !== esperado[i]) begin
                    if (n < 3)
                        $display("[tb_cfs] FAIL SHA %0d (%0d bloco(s)): obtido %064h esperado %064h",
                                 i, nblocos[i], d, esperado[i]);
                    n = n + 1;
                end
                base = base + nblocos[i];
            end
            if (n) begin
                $display("[tb_cfs] FAIL: SHA-256, %0d de %0d", n, `N_SHA256);
                erros = erros + n;
            end else
                $display("[tb_cfs] SHA-256     : %0d/%0d mensagens, %0d blocos",
                         `N_SHA256, `N_SHA256, base);
        end
    endtask

    // Chave e bloco sao escrita-somente. Nao protege contra a CPU (ela
    // acabou de escrever a chave); evita criar um caminho de leitura que um
    // bug de firmware possa usar por acidente ao varrer o espaco de IO.
    task t_write_only;
        reg [255:0] k;
        reg [127:0] b128;
        reg [31:0]  w, w2;
        begin
            aes_carrega_chave(256'hffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff);
            wr_128(R_BLOCK, {4{32'hdeadbeef}});
            wr_512(R_SBLOCK, {16{32'hdeadbeef}});

            rd_256(R_KEY, k);
            rd_128(R_BLOCK, b128);
            bus_rd(R_SBLOCK, w);
            bus_rd(R_CTRL, w2);

            if (k !== 256'd0 || b128 !== 128'd0 || w !== 32'd0 || w2 !== 32'd0) begin
                $display("[tb_cfs] FAIL: chave/bloco legiveis (key=%064h block=%032h sblock=%08h ctrl=%08h)",
                         k, b128, w, w2);
                erros = erros + 1;
            end else
                $display("[tb_cfs] escrita-so  : chave e blocos leem zero");
        end
    endtask

    // ------------------------------------------------------------------
    // WIPE.
    //
    // O teste que vale: depois do wipe, cifrar um bloco SEM carregar chave
    // nenhuma tem de produzir o resultado sob a chave ZERO. Se a expansao
    // da chave anterior tivesse sobrevivido no aes_key_mem, sairia outra
    // coisa. Zerar o registrador visivel nao provaria nada disso.
    //
    // O vetor de referencia vem do proprio AESAVS: o GFSbox usa chave zero.
    // ------------------------------------------------------------------
    task t_wipe;
        reg [127:0] r;
        reg [31:0]  s;
        integer     vz;
        begin
            vz = -1;
            for (i = 0; i < `N_AES_ECB; i = i + 1)
                if (vz < 0 && ecb_e_key[i] === 256'd0) vz = i;

            if (vz < 0) begin
                $display("[tb_cfs] FAIL: nenhum vetor com chave zero -- t_wipe nao pode rodar");
                erros = erros + 1;
                disable t_wipe;
            end

            // Estado sujo: chave qualquer, resultado qualquer.
            aes_carrega_chave(ecb_e_key[`N_AES_ECB-1]);
            aes_processa(1'b1, ecb_e_in[`N_AES_ECB-1], r);

            bus_wr(R_CTRL, C_WIPE);

            // O wipe leva algumas centenas de ciclos: mexe nos cores.
            bus_rd(R_STATUS, s);
            if ((s & S_WIPE_BUSY) == 32'd0) begin
                $display("[tb_cfs] FAIL: WIPE_BUSY nao subiu");
                erros = erros + 1;
            end
            espera(S_WIPE_BUSY);

            // Sem carregar chave: o core tem de estar com a chave zero.
            aes_processa(1'b1, ecb_e_in[vz], r);
            if (r !== ecb_e_out[vz]) begin
                $display("[tb_cfs] FAIL: apos WIPE a chave expandida sobreviveu");
                $display("[tb_cfs]       obtido %032h esperado %032h (chave zero)",
                         r, ecb_e_out[vz]);
                erros = erros + 1;
            end else
                $display("[tb_cfs] WIPE        : chave expandida sobrescrita (vetor %0d)", vz);
        end
    endtask

    // ------------------------------------------------------------------
    initial begin
        #400000000;
        $display("[tb_cfs] FAIL: timeout");
        $display("[tb_cfs] FAIL");
        $finish;
    end

    // ------------------------------------------------------------------
    // TRNG pelo barramento.
    //
    // Nao se testa aqui a QUALIDADE da entropia -- isso nao se testa em
    // simulacao, e nem em bancada com um script: exige coleta de amostras
    // brutas e as ferramentas de estimativa da SP 800-90B. O que se testa
    // e o caminho: liga/desliga, retrato de amostras brutas, e os bits de
    // status refletindo o que os health tests decidiram.
    //
    // O caso da fonte travada e o mais importante: e o unico que prova
    // que o veredito do health test chega ate a CPU. Um RCT perfeito cujo
    // bit nao aparece no registrador de status e um RCT que nao existe.
    // ------------------------------------------------------------------
    localparam [15:0] R_TRNG_CTRL   = 16'h110;
    localparam [15:0] R_TRNG_STATUS = 16'h114;
    localparam [15:0] R_TRNG_BYTE   = 16'h118;
    localparam [15:0] R_TRNG_SNAP   = 16'h180;

    localparam [31:0] T_EN        = 32'h0000_0001;
    localparam [31:0] T_SNAP      = 32'h0000_0002;
    localparam [31:0] TS_EN       = 32'h0000_0001;
    localparam [31:0] TS_SRC_RDY  = 32'h0000_0002;
    localparam [31:0] TS_BYTE_VLD = 32'h0000_0004;
    localparam [31:0] TS_SNAP_BSY = 32'h0000_0008;
    localparam [31:0] TS_SNAP_RDY = 32'h0000_0010;
    localparam [31:0] TS_START_OK = 32'h0000_0020;
    localparam [31:0] TS_RCT_FAIL = 32'h0000_0040;

    task t_trng;
        reg [31:0] s, w;
        reg [31:0] snap [0:31];
        integer k, uns, espera_max;
        begin
            // --- desligado por padrao ---
            bus_rd(R_TRNG_STATUS, s);
            if ((s & TS_EN) !== 32'd0) begin
                $display("[tb_cfs] FAIL: TRNG nasceu ligado");
                erros = erros + 1;
            end

            // --- liga ---
            ent_travada = 1'b0;
            bus_wr(R_TRNG_CTRL, T_EN);
            repeat (20) @(posedge clk);
            bus_rd(R_TRNG_STATUS, s);
            if ((s & TS_EN) === 32'd0 || (s & TS_SRC_RDY) === 32'd0) begin
                $display("[tb_cfs] FAIL: TRNG nao ligou (status=%08h)", s);
                erros = erros + 1;
            end

            // --- byte condicionado aparece ---
            espera_max = 0;
            s = 32'd0;
            while (((s & TS_BYTE_VLD) === 32'd0) && (espera_max < 200)) begin
                bus_rd(R_TRNG_STATUS, s);
                espera_max = espera_max + 1;
            end
            if ((s & TS_BYTE_VLD) === 32'd0) begin
                $display("[tb_cfs] FAIL: TRNG nao produziu byte");
                erros = erros + 1;
            end else begin
                bus_rd(R_TRNG_BYTE, w);
                bus_rd(R_TRNG_STATUS, s);
                if ((s & TS_BYTE_VLD) !== 32'd0) begin
                    $display("[tb_cfs] FAIL: leitura de TRNG_BYTE nao consumiu");
                    erros = erros + 1;
                end
            end

            // --- retrato de 1024 amostras brutas ---
            bus_wr(R_TRNG_CTRL, T_EN | T_SNAP);
            espera_max = 0;
            s = 32'd0;
            while (((s & TS_SNAP_RDY) === 32'd0) && (espera_max < 4000)) begin
                bus_rd(R_TRNG_STATUS, s);
                espera_max = espera_max + 1;
            end
            if ((s & TS_SNAP_RDY) === 32'd0) begin
                $display("[tb_cfs] FAIL: retrato nao ficou pronto");
                erros = erros + 1;
            end else begin
                uns = 0;
                for (k = 0; k < 32; k = k + 1) begin
                    bus_rd(R_TRNG_SNAP + k*4, snap[k]);
                    for (j = 0; j < 32; j = j + 1)
                        if (snap[k][j]) uns = uns + 1;
                end
                // Fonte de LFSR: esperar algo perto de 512 em 1024. Faixa
                // larga de proposito -- o teste e "o retrato tem amostras
                // de verdade", nao "o LFSR e bom".
                if (uns < 300 || uns > 724) begin
                    $display("[tb_cfs] FAIL: retrato com %0d uns em 1024 -- nao parece amostra", uns);
                    erros = erros + 1;
                end else begin
                    $display("[tb_cfs] TRNG        : retrato de 1024 brutas, %0d uns", uns);
                end
            end

            // --- fonte travada tem de chegar ao status ---
            bus_wr(R_TRNG_CTRL, 32'd0);      // desliga: zera os health tests
            repeat (5) @(posedge clk);
            ent_travada = 1'b1;
            bus_wr(R_TRNG_CTRL, T_EN);

            espera_max = 0;
            s = 32'd0;
            while (((s & TS_RCT_FAIL) === 32'd0) && (espera_max < 400)) begin
                bus_rd(R_TRNG_STATUS, s);
                espera_max = espera_max + 1;
            end
            if ((s & TS_RCT_FAIL) === 32'd0) begin
                $display("[tb_cfs] FAIL: fonte travada nao levantou RCT_FAIL no status");
                erros = erros + 1;
            end else begin
                $display("[tb_cfs] TRNG        : fonte travada -> RCT_FAIL visivel pela CPU");
            end

            ent_travada = 1'b0;
            bus_wr(R_TRNG_CTRL, 32'd0);
        end
    endtask

    initial begin
        $display("[tb_cfs] inicio -- %0d vetores AES ECB, %0d mensagens SHA",
                 `N_AES_ECB, `N_SHA256);

        // Sem os arquivos de vetor, $readmemh deixa X e o teste passaria
        // "sem erros" sobre nada. Recusar e o comportamento certo.
        #1;
        if (ecb_e_key[0] === {256{1'bx}} || esperado[0] === {256{1'bx}}) begin
            $display("[tb_cfs] FAIL: vetores nao carregados -- rode scripts/mkvectors.py");
            $display("[tb_cfs] FAIL");
            $finish;
        end

        repeat (4) @(posedge clk);
        rstn = 1'b1;
        repeat (80) @(posedge clk);       // o DNA_PORT leva 57 ciclos

        t_id;
        t_dna;
        t_aes;
        t_sha;
        t_write_only;
        t_wipe;
        t_trng;

        if (irq !== 1'b0) begin
            $display("[tb_cfs] FAIL: irq_o nao ficou em zero");
            erros = erros + 1;
        end

        if (erros == 0)
            $display("[tb_cfs] PASS");
        else
            $display("[tb_cfs] FAIL: %0d erro(s)", erros);

        $finish;
    end

endmodule
