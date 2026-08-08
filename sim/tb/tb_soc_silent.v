`timescale 1ns/1ps
//
// tb_soc_silent -- o dispositivo nao fala sem ser perguntado
//
// Regra do projeto: nada vai para a placa sem passar antes aqui.
//
// Substitui o antigo tb_soc_boot, que decodificava o banner do bootloader
// do NEORV32. Com BOOT_MODE_SELECT = 2 nao existe mais bootloader, e aquele
// teste passou a ser impossivel por construcao. O terreno que ele cobria
// (MMCM, reset, CPU, UART, CLOCK_FREQUENCY) e coberto melhor pelo
// tb_uart_frame, que conversa o protocolo de verdade a 115200.
//
// O que sobra e a propriedade DUAL, que vale por si num dispositivo
// criptografico: nada sai pela UART enquanto ninguem pediu.
//
//   - um banner de boot vaza versao e identidade para quem so escuta;
//   - um printf de depuracao esquecido no firmware e um canal lateral
//     permanente, e este teste falha no dia em que alguem adicionar um.
//
// Silencio sozinho nao prova nada: firmware travado tambem fica quieto.
// Por isso o teste exige silencio E vida -- main() precisa ter passado da
// inicializacao e aceso o LED de atividade.
//
module tb_soc_silent;

    // Precisa cobrir o POST INTEIRO, que roda antes de main() acender o
    // LED de atividade: KAT de AES, SHA, HMAC e CTR_DRBG, mais os testes
    // de partida da fonte de entropia sobre 1024 amostras. Sao alguns
    // milissegundos de tempo simulado -- irrelevante em hardware, caro
    // aqui. Encolher esta janela nao acelera nada: so faz o teste reprovar
    // um dispositivo que estava apenas ocupado.
    localparam real WATCH_NS = 12000000.0;  // 12 ms

    reg  sys_clk = 1'b0;
    reg  rst_n   = 1'b0;
    reg  uart_rx = 1'b1;
    reg  btn_a   = 1'b1;
    reg  btn_b   = 1'b1;

    wire       uart_tx;
    wire [4:0] led;
    wire [7:0] seg;
    wire [2:0] seg_an;

    integer errors    = 0;
    real    t_alive   = 0.0;   // quando o POST terminou

    // Marca o instante em que o LED de atividade acende. Serve de medida
    // do custo do POST: se ele crescer sem que ninguem perceba, este numero
    // cresce junto e aparece no log.
    always @(negedge led[1]) begin
        if (t_alive == 0.0) begin
            t_alive = $realtime;
        end
    end
    reg     tx_spoke  = 1'b0;
    real    t_spoke;

    always #10 sys_clk = ~sys_clk;   // 50 MHz

    hsm_top dut (
        .sys_clk_i  (sys_clk),
        .rst_n_i    (rst_n),
        .uart_rxd_i (uart_rx),
        .uart_txd_o (uart_tx),
        .btn_a_i    (btn_a),
        .btn_b_i    (btn_b),
        .led_o      (led),
        .seg_o      (seg),
        .seg_an_o   (seg_an)
    );

    // Qualquer descida da linha e um byte comecando a sair.
    always @(negedge uart_tx) begin
        if (rst_n && !tx_spoke) begin
            tx_spoke = 1'b1;
            t_spoke  = $realtime;
        end
    end

    initial begin
        $display("[tb_soc_silent] inicio -- observando a UART por %0.1f ms",
                 WATCH_NS / 1000000.0);

        #200;
        rst_n = 1'b1;

        #(WATCH_NS);

        // ---- silencio ---------------------------------------------------
        if (tx_spoke) begin
            $display("[tb_soc_silent] FAIL: UART transmitiu em t=%0.1f us sem ninguem pedir",
                     t_spoke / 1000.0);
            errors = errors + 1;
        end else begin
            $display("[tb_soc_silent] UART em repouso o tempo todo");
        end

        // ---- vida -------------------------------------------------------
        // main() acende o LED de atividade (GPIO 0 -> D2) depois de
        // inicializar UART, estado, parser e checar o CLINT. Aceso = nivel
        // baixo, que e a polaridade da placa.
        if (t_alive != 0.0) begin
            $display("[tb_soc_silent] POST concluido em %.2f ms de tempo simulado",
                     t_alive / 1000000.0);
        end

        if (led[1] !== 1'b0) begin
            $display("[tb_soc_silent] FAIL: led[1]=%b, esperado 0 -- main() nao chegou ao laco",
                     led[1]);
            errors = errors + 1;
        end else begin
            $display("[tb_soc_silent] firmware vivo: LED de atividade aceso");
        end

        // O heartbeat de hardware confirma que o dominio de 100 MHz corre
        // mesmo que a CPU estivesse parada -- separa as duas causas.
        if (dut.mmcm_locked !== 1'b1) begin
            $display("[tb_soc_silent] FAIL: MMCM sem lock");
            errors = errors + 1;
        end

        if (errors == 0)
            $display("[tb_soc_silent] PASS");
        else
            $display("[tb_soc_silent] FAIL: %0d erro(s)", errors);

        $finish;
    end

endmodule
