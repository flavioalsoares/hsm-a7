// =====================================================================
// hsm_cfs.v -- logica do Custom Functions Subsystem do HSM
//
// Este e o coprocessador criptografico do projeto: AES-256, SHA-256 e o
// DNA_PORT, ligados a CPU por um mapa de registradores.
//
// O CFS e o ponto de extensao PROJETADO do NEORV32 (doc/submodulos.md,
// grau 2 da escada): o upstream entrega um neorv32_cfs.vhd de exemplo
// feito para ser substituido. O build filtra o arquivo dele e compila o
// nosso no lugar, na mesma biblioteca VHDL. O submodulo continua byte a
// byte igual a tag v1.13.3 -- sem patch, sem fork.
//
// Divisao de arquivos:
//   neorv32_cfs.vhd  shim VHDL, so desempacota os records do barramento
//   hsm_cfs.v        este arquivo, onde esta a logica (Verilog-2001,
//                    convencao do projeto para codigo proprio)
//
// ---------------------------------------------------------------------
// FRONTEIRA CRIPTOGRAFICA
//
// Este modulo esta DENTRO da fronteira. Consequencias, e elas nao sao
// decorativas:
//
//   * cfs_out_o (unico fio do CFS que chega ao toplevel) fica em zero.
//     Regra 2 do CLAUDE.md: chave nunca vai para registrador exposto no
//     toplevel. O shim VHDL amarra; aqui nao existe sequer a porta.
//   * A leitura de AES_KEY e dos blocos devolve ZERO. Escrita-somente.
//     Nao e proteger contra a CPU (ela ja escreveu a chave); e nao criar
//     um caminho de leitura que um bug de firmware possa usar por
//     acidente ao varrer o espaco de IO.
//   * Existe CTRL.WIPE, e ele sobrescreve o estado interno dos cores --
//     nao so os registradores visiveis. Ver a secao do wipe.
//
// ---------------------------------------------------------------------
// MAPA DE REGISTRADORES  (base 0xFFEB0000, offsets em bytes)
//
//   0x000  ID        r   0x48534d31 = "HSM1"
//   0x004  STATUS    r   [0] AES_BUSY    [1] AES_VALID
//                        [2] SHA_BUSY    [3] SHA_VALID
//                        [4] DNA_VALID   [5] WIPE_BUSY
//   0x008  CTRL      w   [0] AES_INIT    expande a chave
//                        [1] AES_NEXT    processa um bloco
//                        [2] AES_ENCDEC  1 = cifra, 0 = decifra
//                        [3] SHA_INIT    primeiro bloco da mensagem
//                        [4] SHA_NEXT    bloco seguinte
//                        [5] WIPE        zeroiza (ignora os outros bits)
//
//   0x020..0x03C  AES_KEY[0..7]     w   256 bits, palavra 0 = bits 255:224
//   0x040..0x04C  AES_BLOCK[0..3]   w   128 bits
//   0x050..0x05C  AES_RESULT[0..3]  r   128 bits
//
//   0x080..0x0BC  SHA_BLOCK[0..15]  w   512 bits, ja preenchido
//   0x0C0..0x0DC  SHA_DIGEST[0..7]  r   256 bits
//
//   0x100  DNA_LO    r   DNA[31:0]
//   0x104  DNA_HI    r   {7'b0, DNA[56:32]}
//
//   0x110  TRNG_CTRL    w  [0] EN     liga a fonte de ruido
//                          [1] SNAP   congela 1024 amostras BRUTAS
//   0x114  TRNG_STATUS  r  [0] EN          [1] SRC_READY
//                          [2] BYTE_VALID  [3] SNAP_BUSY
//                          [4] SNAP_READY  [5] STARTUP_OK
//                          [6] RCT_FAIL    [7] APT_FAIL
//   0x118  TRNG_BYTE    r  [7:0] byte condicionado; a leitura CONSOME
//   0x11C  TRNG_DIAG    r  {APT_COUNT[15:0], RCT_COUNT[15:0]}
//   0x180..0x1FC  TRNG_SNAP[0..31]  r  1024 amostras brutas consecutivas
//                          palavra 0 = as 32 amostras MAIS ANTIGAS
//

// Ordem das palavras: a mais significativa primeiro, como nos vetores do
// NIST. O firmware roda em RISC-V little-endian e portanto PRECISA montar
// cada palavra de 32 bits a partir do vetor de bytes -- ver fw/src/hsm_cfs.c.
// Trocar isso por um memcpy passaria no compilador e falharia em todos os
// KAT, que e o melhor desfecho possivel para esse tipo de erro.
//
// Enderecos nao mapeados: escrita ignorada, leitura devolve zero, ACK
// sempre. Nao dar ACK causaria excecao de bus timeout na CPU.
//
// ---------------------------------------------------------------------
// O QUE ESTE BLOCO NAO FAZ, DE PROPOSITO
//
//   * ECB apenas. O encadeamento de CBC e do firmware -- mesma divisao de
//     responsabilidade dos testbenches de KAT (doc/fase2-notas.md).
//   * Padding do SHA e do firmware. O core recebe blocos de 512 bits
//     prontos.
//   * keylen fixo em AES-256. Nao ha caminho para AES-128: a hierarquia
//     de chaves da fase 3 e toda de 256 bits e um modo mais fraco
//     alcancavel por escrita em registrador e um downgrade de graca.
//   * Sem interrupcao. irq_o fica em zero: o caminho de comando do
//     firmware e sincrono e de passo unico (fw/src/main.c), e um handler
//     de IRQ mexendo nos mesmos buffers de chave e mais dificil de
//     auditar do que uma espera ocupada.
//
// ---------------------------------------------------------------------
// O BIT DE BUSY, E POR QUE ELE NAO E O 'ready' DO CORE
//
// Os cores da secworks sinalizam conclusao com 'ready' alto. Esperar por
// isso logo depois do comando NAO FUNCIONA: o core ainda nao baixou
// 'ready', a espera termina de imediato e le-se o resultado da operacao
// ANTERIOR. Foi exatamente assim que o tb_sha256_kat reprovou -- digests
// corretos, deslocados de um (doc/fase2-notas.md).
//
// La o conserto foi no testbench: esperar COMECAR e depois TERMINAR. Aqui
// o conserto e em hardware, e vale para todo mundo: o CFS mantem um bit de
// BUSY que sobe junto com o comando e so cai depois que o core comecou e
// terminou. O firmware poll um bit e nao tem como errar o handshake.
//
// Corrigir uma armadilha de temporizacao no lugar onde ela some para todos
// os clientes futuros e mais barato do que documenta-la.
// =====================================================================

`timescale 1ns/1ps

module hsm_cfs (
    input  wire        clk_i,
    input  wire        rstn_i,      // reset sincrono, ativo baixo

    // barramento, ja desempacotado pelo shim VHDL
    input  wire [15:0] addr_i,      // endereco de byte dentro do CFS
    input  wire [31:0] wdata_i,
    input  wire        stb_i,       // strobe, um ciclo
    input  wire        rw_i,        // 1 = escrita
    output reg  [31:0] rdata_o,
    output reg         ack_o,

    // Fonte de ruido. Fica em hsm_entropy.vhd porque a celula osciladora
    // que ela reaproveita e uma entidade VHDL do upstream; o shim liga os
    // dois. Ver o cabecalho daquele arquivo.
    output wire        ent_en_o,
    input  wire        ent_raw_i,        // amostra BRUTA, sem condicionar
    input  wire        ent_raw_valid_i,
    input  wire [7:0]  ent_byte_i,       // apos von Neumann
    input  wire        ent_byte_valid_i,

    output wire        irq_o
);

    localparam [31:0] ID_MAGIC = 32'h48534d31;   // "HSM1"

    // Endereco de palavra. 7 bits = 128 palavras = 512 bytes; o resto dos
    // 64 KB do CFS nao tem registrador fisico.
    wire [6:0] waddr = addr_i[8:2];

    localparam [6:0] A_ID     = 7'h00;   // 0x000
    localparam [6:0] A_STATUS = 7'h01;   // 0x004
    localparam [6:0] A_CTRL   = 7'h02;   // 0x008
    localparam [6:0] A_DNA_LO = 7'h40;   // 0x100
    localparam [6:0] A_DNA_HI = 7'h41;   // 0x104

    localparam [6:0] A_TRNG_CTRL   = 7'h44;   // 0x110
    localparam [6:0] A_TRNG_STATUS = 7'h45;   // 0x114
    localparam [6:0] A_TRNG_BYTE   = 7'h46;   // 0x118
    localparam [6:0] A_TRNG_DIAG   = 7'h47;   // 0x11C
    // TRNG_SNAP: 0x180..0x1FC -> waddr 7'h60..7'h7F, ou seja waddr[6:5]==11.
    // Faixa escolhida por ter prefixo limpo: decodificar por comparacao de
    // intervalo custa comparadores no caminho de leitura e e mais facil de
    // errar em uma palavra so.

    // ------------------------------------------------------------------
    // Registradores de dado
    // ------------------------------------------------------------------
    reg [255:0] aes_key;
    reg [127:0] aes_block;
    reg [511:0] sha_block;
    reg         aes_encdec;

    // pulsos de comando: uma fonte para o barramento, outra para o wipe
    reg  aes_init_bus,  aes_next_bus,  sha_init_bus,  sha_next_bus;
    reg  aes_init_wipe, aes_next_wipe, sha_init_wipe;

    wire aes_init = aes_init_bus | aes_init_wipe;
    wire aes_next = aes_next_bus | aes_next_wipe;
    wire sha_init = sha_init_bus | sha_init_wipe;
    wire sha_next = sha_next_bus;

    // ------------------------------------------------------------------
    // Cores (submodulos externos, fixados por SHA de commit)
    // ------------------------------------------------------------------
    wire         aes_ready;
    wire [127:0] aes_result;
    wire         aes_valid;

    aes_core u_aes (
        .clk          (clk_i),
        .reset_n      (rstn_i),
        .encdec       (aes_encdec),
        .init         (aes_init),
        .next         (aes_next),
        .ready        (aes_ready),
        .key          (aes_key),
        .keylen       (1'b1),          // AES-256, e so
        .block        (aes_block),
        .result       (aes_result),
        .result_valid (aes_valid)
    );

    wire         sha_ready;
    wire [255:0] sha_digest;
    wire         sha_valid;

    sha256_core u_sha (
        .clk          (clk_i),
        .reset_n      (rstn_i),
        .init         (sha_init),
        .next         (sha_next),
        .mode         (1'b1),          // 1 = SHA-256 (0 seria SHA-224)
        .block        (sha_block),
        .ready        (sha_ready),
        .digest       (sha_digest),
        .digest_valid (sha_valid)
    );

    // ------------------------------------------------------------------
    // Bit de BUSY -- ver o cabecalho
    //
    // Sobe com o comando e so cai depois que o core COMECOU (ready caiu) e
    // TERMINOU (ready voltou). O termo aes_init|aes_next no 'active' cobre
    // a janela de um ciclo entre o pulso e o busy registrado -- sem ele,
    // quem consultasse no ciclo seguinte veria "livre" antes da hora.
    // ------------------------------------------------------------------
    reg aes_busy, aes_started;
    reg sha_busy, sha_started;

    wire aes_active = aes_busy | aes_init | aes_next;
    wire sha_active = sha_busy | sha_init | sha_next;

    always @(posedge clk_i) begin
        if (!rstn_i) begin
            aes_busy <= 1'b0;  aes_started <= 1'b0;
            sha_busy <= 1'b0;  sha_started <= 1'b0;
        end else begin
            if (aes_init | aes_next) begin
                aes_busy    <= 1'b1;
                aes_started <= 1'b0;
            end else if (aes_busy) begin
                if (!aes_ready)              aes_started <= 1'b1;
                if (aes_started & aes_ready) aes_busy    <= 1'b0;
            end

            if (sha_init | sha_next) begin
                sha_busy    <= 1'b1;
                sha_started <= 1'b0;
            end else if (sha_busy) begin
                if (!sha_ready)              sha_started <= 1'b1;
                if (sha_started & sha_ready) sha_busy    <= 1'b0;
            end
        end
    end

    // ------------------------------------------------------------------
    // DNA_PORT -- identidade de fabrica, 57 bits
    //
    // O que e: um numero unico gravado em cada die na fabricacao. Serve
    // para o dispositivo dizer QUEM ele e, e e o que o comando GET_DNA
    // devolve.
    //
    // O que NAO e: segredo. O DNA e legivel por JTAG em qualquer placa e
    // nao tem protecao nenhuma. Usa-lo como chave, ou derivar chave dele,
    // e um erro classico -- ver a discussao de PUF no manual. Aqui ele e
    // identificador, nunca material criptografico.
    //
    // Protocolo do primitivo (modelo unisim DNA_PORT.v):
    //   posedge CLK com READ=1  -> carrega o valor, DOUT = bit 56
    //   posedge CLK com SHIFT=1 -> desloca, DOUT = proximo bit (MSB first)
    // Sao portanto 1 leitura + 56 deslocamentos = 57 bits.
    //
    // Roda no mesmo clock de 100 MHz do resto do SoC: um dominio so, sem
    // clock derivado e sem CDC. A leitura acontece uma vez, no reset.
    // ATENCAO REGISTRADA: o limite de frequencia do CLK do DNA_PORT (UG470)
    // nao foi conferido contra o documento oficial neste projeto. Se a
    // leitura vier inconsistente em hardware, o conserto e local -- dividir
    // o clock deste bloco -- e nao afeta mais nada.
    // ------------------------------------------------------------------
    reg [56:0] dna_sr    = 57'd0;
    reg [5:0]  dna_cnt   = 6'd0;
    reg [1:0]  dna_st    = 2'd0;
    reg        dna_read  = 1'b0;
    reg        dna_shift = 1'b0;
    reg        dna_valid = 1'b0;

    wire dna_dout;

    localparam [1:0] D_START = 2'd0, D_LOAD = 2'd1, D_SHIFT = 2'd2, D_DONE = 2'd3;

    DNA_PORT #(
        // Valor arbitrario e reconhecivel, usado APENAS em simulacao. O
        // testbench compara contra ele: se o bit order ou a contagem
        // estiverem errados, o teste reprova.
        .SIM_DNA_VALUE (57'h0123456789ABCDE)
    ) u_dna (
        .DOUT  (dna_dout),
        .CLK   (clk_i),
        .DIN   (1'b0),
        .READ  (dna_read),
        .SHIFT (dna_shift)
    );

    always @(posedge clk_i) begin
        if (!rstn_i) begin
            dna_st    <= D_START;
            dna_cnt   <= 6'd0;
            dna_read  <= 1'b0;
            dna_shift <= 1'b0;
            dna_valid <= 1'b0;
            dna_sr    <= 57'd0;
        end else begin
            case (dna_st)
                D_START: begin           // um ciclo de READ
                    dna_read  <= 1'b1;
                    dna_shift <= 1'b0;
                    dna_st    <= D_LOAD;
                end
                D_LOAD: begin            // o primitivo carregou; DOUT = bit 56
                    dna_read  <= 1'b0;
                    dna_shift <= 1'b1;
                    dna_cnt   <= 6'd0;
                    dna_st    <= D_SHIFT;
                end
                D_SHIFT: begin
                    // Captura 57 vezes. O primeiro bit capturado e o 56 e
                    // acaba na posicao 56 depois dos 56 deslocamentos
                    // seguintes -- o registrador termina com o DNA na
                    // ordem natural.
                    dna_sr <= {dna_sr[55:0], dna_dout};
                    if (dna_cnt == 6'd56) begin
                        dna_shift <= 1'b0;
                        dna_valid <= 1'b1;
                        dna_st    <= D_DONE;
                    end else begin
                        dna_cnt <= dna_cnt + 6'd1;
                    end
                end
                default: begin           // D_DONE: uma vez so, ate o reset
                    dna_read  <= 1'b0;
                    dna_shift <= 1'b0;
                end
            endcase
        end
    end

    // ------------------------------------------------------------------
    // TRNG -- fonte de ruido, health tests e retrato da amostra bruta
    //
    // Divisao entre hardware e firmware, e ela e o conteudo da fase:
    //
    //   aqui        os health tests CONTINUOS, sobre toda amostra bruta.
    //               Nao cabe em firmware: a fonte produz uma amostra por
    //               ciclo de 100 MHz e a SP 800-90B exige que o teste
    //               continuo veja todas. Ver rtl/crypto/hsm_health.v.
    //
    //   firmware    os testes de PARTIDA (secao 4.3), sobre o retrato de
    //               1024 amostras brutas CONSECUTIVAS congelado abaixo, e
    //               toda a POLITICA: falha -> TAMPERED, DRBG parado, LED
    //               vermelho. A decisao continua sendo do firmware.
    //
    // O retrato tambem e o caminho para um dia estimar H de verdade: e
    // dele que sai a coleta de amostras brutas que a ferramenta ea_non_iid
    // do NIST consome. Enquanto H for hipotese, os cutoffs sao hipotese.
    //
    // FRONTEIRA: o retrato bruto e legivel pelo firmware, que esta DENTRO.
    // Nao existe, e nao pode passar a existir, comando de host que devolva
    // amostra bruta -- o comando RANDOM devolve saida do DRBG. Expor a
    // fonte entregaria ao atacante exatamente o que ele precisa para
    // prever a semente.
    // ------------------------------------------------------------------
    reg trng_en;

    assign ent_en_o = trng_en;

    wire        hz_rct_fail, hz_apt_fail, hz_fail, hz_startup_ok;
    wire [15:0] hz_rct_cnt, hz_apt_cnt;

    hsm_health u_health (
        .clk_i        (clk_i),
        .rstn_i       (rstn_i),
        .en_i         (trng_en),
        .sample_i     (ent_raw_i),
        .valid_i      (ent_raw_valid_i),
        .rct_fail_o   (hz_rct_fail),
        .apt_fail_o   (hz_apt_fail),
        .fail_o       (hz_fail),
        .startup_ok_o (hz_startup_ok),
        .rct_count_o  (hz_rct_cnt),
        .apt_count_o  (hz_apt_cnt)
    );

    // Byte condicionado. Um registrador so: se o firmware nao ler a tempo,
    // o byte seguinte sobrescreve. Descartar entropia nao lida nao custa
    // seguranca nenhuma -- so vazao -- e evita uma FIFO que teria de ser
    // zeroizada junto com o resto.
    reg [7:0] trng_byte;
    reg       trng_byte_vld;

    // Retrato: 1024 amostras BRUTAS consecutivas.
    reg [1023:0] snap_sr;
    reg [10:0]   snap_cnt;
    reg          snap_busy;
    reg          snap_ready;

    wire snap_req = stb_i & rw_i & (waddr == A_TRNG_CTRL) & wdata_i[1] & ~snap_busy;

    always @(posedge clk_i) begin
        if (!rstn_i) begin
            trng_byte     <= 8'd0;
            trng_byte_vld <= 1'b0;
            snap_sr       <= 1024'd0;
            snap_cnt      <= 11'd0;
            snap_busy     <= 1'b0;
            snap_ready    <= 1'b0;
        end else if (!trng_en) begin
            // Fonte desligada: nao guardar byte nem retrato velhos. Um
            // retrato de antes do desligamento nao e feito de amostras
            // consecutivas com o de depois.
            trng_byte     <= 8'd0;
            trng_byte_vld <= 1'b0;
            snap_sr       <= 1024'd0;
            snap_busy     <= 1'b0;
            snap_ready    <= 1'b0;
            snap_cnt      <= 11'd0;
        end else begin
            if (ent_byte_valid_i) begin
                trng_byte     <= ent_byte_i;
                trng_byte_vld <= 1'b1;
            end else if (stb_i & ~rw_i & (waddr == A_TRNG_BYTE)) begin
                trng_byte_vld <= 1'b0;      // a leitura consome
            end

            if (snap_req) begin
                snap_busy  <= 1'b1;
                snap_ready <= 1'b0;
                snap_cnt   <= 11'd0;
            end else if (snap_busy && ent_raw_valid_i) begin
                snap_sr <= {snap_sr[1022:0], ent_raw_i};
                if (snap_cnt == 11'd1023) begin
                    snap_busy  <= 1'b0;
                    snap_ready <= 1'b1;
                end else begin
                    snap_cnt <= snap_cnt + 11'd1;
                end
            end
        end
    end

    wire [31:0] trng_status_w = {24'd0,
                                 hz_apt_fail, hz_rct_fail, hz_startup_ok,
                                 snap_ready, snap_busy, trng_byte_vld,
                                 ent_raw_valid_i, trng_en};

    // ------------------------------------------------------------------
    // WIPE -- zeroizacao
    //
    // Zerar os registradores visiveis nao basta: a chave expandida vive na
    // aes_key_mem, o resultado no aes_*_block e o digest no sha256_core.
    // Um "zeroize" que deixa a chave expandida intacta e teatro.
    //
    // Entao o wipe e uma sequencia:
    //   1. zera aes_key, aes_block e sha_block  (no bloco de escrita)
    //   2. AES_INIT  -> a expansao de chave e reescrita com a chave zero
    //   3. AES_NEXT  -> result e os estados internos do cipher sao reescritos
    //   4. SHA_INIT  -> digest e o w_mem sao reescritos
    //
    // Leva algumas centenas de ciclos. STATUS[5] indica ocupado, e escritas
    // em CTRL sao ignoradas enquanto durar -- para nao existir um caminho em
    // que o firmware acha que zeroizou e nao zeroizou.
    //
    // Isto e infraestrutura da fase 3 (comando ZEROIZE e estado TAMPERED)
    // entrando junto com o bloco que guarda a chave. Deixar para depois
    // significaria um periodo com material de chave sem caminho de apagar.
    // ------------------------------------------------------------------
    localparam [1:0] W_IDLE = 2'd0, W_AES_I = 2'd1, W_AES_N = 2'd2, W_SHA = 2'd3;

    reg [1:0] wipe_st;
    wire      wipe_busy = (wipe_st != W_IDLE);

    // Um pedido de wipe so e aceito quando nao ha outro em curso.
    wire wipe_req = stb_i & rw_i & (waddr == A_CTRL) & wdata_i[5] & ~wipe_busy;

    always @(posedge clk_i) begin
        aes_init_wipe <= 1'b0;
        aes_next_wipe <= 1'b0;
        sha_init_wipe <= 1'b0;

        if (!rstn_i) begin
            wipe_st <= W_IDLE;
        end else begin
            case (wipe_st)
                W_IDLE:
                    if (wipe_req) begin
                        aes_init_wipe <= 1'b1;
                        wipe_st       <= W_AES_I;
                    end
                W_AES_I:
                    if (!aes_active) begin
                        aes_next_wipe <= 1'b1;
                        wipe_st       <= W_AES_N;
                    end
                W_AES_N:
                    if (!aes_active) begin
                        sha_init_wipe <= 1'b1;
                        wipe_st       <= W_SHA;
                    end
                default:   // W_SHA
                    if (!sha_active) wipe_st <= W_IDLE;
            endcase
        end
    end

    // ------------------------------------------------------------------
    // Acesso do barramento
    // ------------------------------------------------------------------
    wire [31:0] status_w = {26'd0, wipe_busy, dna_valid,
                            sha_valid, sha_active, aes_valid, aes_active};

    always @(posedge clk_i) begin
        // Pulsos de comando duram exatamente um ciclo.
        aes_init_bus <= 1'b0;
        aes_next_bus <= 1'b0;
        sha_init_bus <= 1'b0;
        sha_next_bus <= 1'b0;

        if (!rstn_i) begin
            aes_key    <= 256'd0;
            aes_block  <= 128'd0;
            sha_block  <= 512'd0;
            aes_encdec <= 1'b0;
            trng_en    <= 1'b0;
            rdata_o    <= 32'd0;
            ack_o      <= 1'b0;
        end else begin
            ack_o   <= stb_i;
            rdata_o <= 32'd0;      // zero fora de um acesso de leitura real

            if (stb_i) begin
                if (rw_i) begin
                    // ---------------- escrita ----------------
                    if (waddr == A_CTRL) begin
                        if (wdata_i[5]) begin
                            // WIPE ignora os outros bits de propósito: nunca
                            // se combina "apaga" com "usa" na mesma escrita.
                            if (!wipe_busy) begin
                                aes_key   <= 256'd0;
                                aes_block <= 128'd0;
                                sha_block <= 512'd0;
                            end
                        end else if (!wipe_busy) begin
                            aes_encdec   <= wdata_i[2];
                            aes_init_bus <= wdata_i[0];
                            aes_next_bus <= wdata_i[1];
                            sha_init_bus <= wdata_i[3];
                            sha_next_bus <= wdata_i[4];
                        end
                    end
                    // AES_KEY: 0x020..0x03C
                    else if (waddr[6:3] == 4'b0001)
                        aes_key[255 - 32*waddr[2:0] -: 32] <= wdata_i;
                    // AES_BLOCK: 0x040..0x04C
                    else if (waddr[6:2] == 5'b00100)
                        aes_block[127 - 32*waddr[1:0] -: 32] <= wdata_i;
                    // SHA_BLOCK: 0x080..0x0BC
                    else if (waddr[6:4] == 3'b010)
                        sha_block[511 - 32*waddr[3:0] -: 32] <= wdata_i;
                    // TRNG_CTRL. O bit SNAP e tratado no bloco do TRNG.
                    else if (waddr == A_TRNG_CTRL)
                        trng_en <= wdata_i[0];
                    // resto: ignorado (mas com ACK)
                end else begin
                    // ---------------- leitura ----------------
                    // AES_KEY, AES_BLOCK, SHA_BLOCK e CTRL nao aparecem
                    // aqui: leitura devolve zero. Escrita-somente.
                    if (waddr == A_ID)
                        rdata_o <= ID_MAGIC;
                    else if (waddr == A_STATUS)
                        rdata_o <= status_w;
                    // AES_RESULT: 0x050..0x05C
                    else if (waddr[6:2] == 5'b00101)
                        rdata_o <= aes_result[127 - 32*waddr[1:0] -: 32];
                    // SHA_DIGEST: 0x0C0..0x0DC
                    else if (waddr[6:3] == 4'b00110)
                        rdata_o <= sha_digest[255 - 32*waddr[2:0] -: 32];
                    else if (waddr == A_DNA_LO)
                        rdata_o <= dna_sr[31:0];
                    else if (waddr == A_DNA_HI)
                        rdata_o <= {7'd0, dna_sr[56:32]};
                    else if (waddr == A_TRNG_STATUS)
                        rdata_o <= trng_status_w;
                    else if (waddr == A_TRNG_BYTE)
                        rdata_o <= {24'd0, trng_byte};
                    else if (waddr == A_TRNG_DIAG)
                        rdata_o <= {hz_apt_cnt, hz_rct_cnt};
                    // TRNG_SNAP: 0x140..0x1BC, 32 palavras.
                    //
                    // Palavra 0 traz as 32 amostras MAIS ANTIGAS, para a
                    // leitura sair na ordem temporal em que a fonte
                    // produziu. RCT e APT dependem da ORDEM: entregar
                    // invertido faria o firmware testar uma sequencia que
                    // nunca existiu, e ainda por cima concordar com o
                    // hardware por acaso na maioria das vezes.
                    else if (waddr[6:5] == 2'b11)
                        rdata_o <= snap_sr[1023 - 32*waddr[4:0] -: 32];
                end
            end
        end
    end

    assign irq_o = 1'b0;

endmodule
