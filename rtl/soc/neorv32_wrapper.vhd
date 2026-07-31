-- =====================================================================
-- neorv32_wrapper.vhd -- configuracao do SoC NEORV32 para o HSM
--
-- Wrapper fino sobre neorv32_top. Existe por dois motivos:
--
--   1. neorv32_top tem ~130 generics, muitos deles do tipo boolean, e
--      portas de tipo customizado (trace_port_t). Instanciar isso direto
--      de Verilog e impraticavel. O proprio upstream resolve assim
--      (rtl/verilog/neorv32_verilog_wrapper.vhd).
--   2. Este arquivo passa a ser o LUGAR UNICO onde a configuracao do
--      processador esta escrita -- e num projeto de seguranca a lista do
--      que esta DESLIGADO importa tanto quanto a do que esta ligado.
--
-- O core externo fica intocado em third_party/neorv32 (submodulo fixado
-- na tag v1.13.3). Este wrapper e codigo proprio do projeto.
--
-- Portas em std_logic com conversao explicita: funciona tanto em VHDL-93
-- quanto em 2008, e evita depender do modo de compilacao da ferramenta.
-- =====================================================================

library ieee;
use ieee.std_logic_1164.all;

library neorv32;
use neorv32.neorv32_package.all;

entity neorv32_wrapper is
  port (
    clk_i       : in  std_logic;                     -- 100 MHz
    rstn_i      : in  std_logic;                     -- ativo baixo
    uart0_txd_o : out std_logic;
    uart0_rxd_i : in  std_logic;
    gpio_o      : out std_logic_vector(7 downto 0);
    gpio_i      : in  std_logic_vector(7 downto 0)
  );
end entity;

architecture rtl of neorv32_wrapper is

  signal gpio_out_v : std_ulogic_vector(31 downto 0);
  signal gpio_in_v  : std_ulogic_vector(31 downto 0);

begin

  gpio_in_v(7 downto 0)  <= std_ulogic_vector(gpio_i);
  gpio_in_v(31 downto 8) <= (others => '0');
  gpio_o <= std_logic_vector(gpio_out_v(7 downto 0));

  u_neorv32: neorv32_top
  generic map (
    -- ---------------------------------------------------------------
    -- Geral
    -- ---------------------------------------------------------------
    -- Precisa bater com o clock real: o firmware deriva o divisor de
    -- baud daqui. Errar isto quebra a UART de um jeito que parece bug
    -- de protocolo.
    CLOCK_FREQUENCY  => 100_000_000,

    -- ---------------------------------------------------------------
    -- Boot
    -- ---------------------------------------------------------------
    -- 0 = bootloader interno (aceita upload de firmware pela UART)
    -- 2 = imagem embutida na IMEM, gravada junto com o bitstream
    --
    -- ESTA EM 2, e e assim que fica.
    --
    -- Com o bootloader ligado, qualquer um com acesso a UART reprograma o
    -- dispositivo e contorna a maquina de estados e a fronteira
    -- criptografica inteira -- num HSM de verdade e o problema de
    -- autenticidade de firmware. Ficou em 0 durante o entregavel 3 apenas
    -- porque nao havia firmware; agora ha.
    --
    -- Consequencia pratica: trocar o firmware exige regerar o bitstream.
    -- A imagem vem de fw/ (make image) e e substituida na lista de
    -- arquivos pelo build, sem tocar no submodulo -- ver doc/submodulos.md.
    --
    -- Para iterar rapido durante bring-up de bancada da para voltar a 0
    -- temporariamente e usar 'make exe' + upload pela UART. Nao commitar
    -- assim.
    BOOT_MODE_SELECT => 2,

    -- ---------------------------------------------------------------
    -- Debugger on-chip -- DESLIGADO, e nao e negociavel
    -- ---------------------------------------------------------------
    -- O OCD da acesso irrestrito de leitura e escrita a memoria via
    -- JTAG. Num dispositivo que guarda a LMK em BRAM, isso e um caminho
    -- direto de extracao de chave. E o generic mais importante do
    -- arquivo.
    OCD_EN           => false,

    -- ---------------------------------------------------------------
    -- ISA -- RV32IMC (PLANO secao 2)
    -- ---------------------------------------------------------------
    RISCV_ISA_C      => true,   -- comprimida: economiza IMEM
    RISCV_ISA_M      => true,   -- mul/div
    RISCV_ISA_Zicntr => true,   -- contadores base (cycle/instret):
                                -- timeouts e medida dos health tests

    -- As extensoes de cripto do RISC-V (Zkne/Zknd/Zknh) ficam
    -- DESLIGADAS de proposito. AES e SHA vao para o fabric como
    -- coprocessadores no CFS -- e isso e o objetivo do projeto, nao um
    -- detalhe de implementacao. Usar a instrucao pronta pularia
    -- exatamente a parte que se quer aprender.

    -- ---------------------------------------------------------------
    -- Tuning
    -- ---------------------------------------------------------------
    -- Barrel shifter: codigo de cripto em firmware (CMAC, HMAC, DRBG)
    -- e pesado em deslocamento. O shifter serial custa um ciclo por bit.
    CPU_FAST_SHIFT_EN => true,
    -- Multiplicador em DSP: desligado. Os 90 DSP48E1 estao reservados
    -- para o RSA de Montgomery da fase 7, e multiplicacao nao e caminho
    -- quente aqui.
    CPU_FAST_MUL_EN   => false,

    -- ---------------------------------------------------------------
    -- Memoria interna -- as chaves vivem aqui, e SO aqui
    -- ---------------------------------------------------------------
    IMEM_EN          => true,
    IMEM_SIZE        => 16*1024,
    DMEM_EN          => true,
    DMEM_SIZE        => 8*1024,

    -- ---------------------------------------------------------------
    -- Caches -- DESLIGADAS
    -- ---------------------------------------------------------------
    -- Duas razoes independentes, ambas suficientes:
    --   1. Inuteis: IMEM e DMEM ja sao BRAM on-chip, latencia 1 ciclo.
    --   2. Nocivas: cache introduz tempo de execucao dependente do dado,
    --      que e a base de ataque de canal lateral por temporizacao.
    ICACHE_EN        => false,
    DCACHE_EN        => false,

    -- ---------------------------------------------------------------
    -- Barramento externo -- DESLIGADO
    -- ---------------------------------------------------------------
    -- Sem XBUS nao existe caminho fisico para material de chave sair do
    -- die. Reforca em hardware a regra "chaves so em BRAM" do PLANO.
    -- A DDR3 da placa fica deliberadamente inacessivel.
    XBUS_EN          => false,
    SMC_EN           => false,

    -- ---------------------------------------------------------------
    -- Perifericos
    -- ---------------------------------------------------------------
    IO_CLINT_EN      => true,   -- machine timer: timeouts do protocolo
    IO_UART0_EN      => true,   -- canal do hsmtool.py
    IO_UART0_RX_FIFO => 64,     -- folga para frames do protocolo
    IO_UART0_TX_FIFO => 64,
    IO_GPIO_NUM      => 8,      -- LEDs de estado + botoes de dual control

    -- ---------------------------------------------------------------
    -- Ligados em fases seguintes -- listados para nao ficarem esquecidos
    -- ---------------------------------------------------------------
    -- IO_CFS_EN  : fase 2. E aqui que AES-256 e SHA-256 entram.
    -- IO_TRNG_EN : fase 2. neoTRNG. Ao ligar, manter IO_TRNG_NUM_RO
    --              pequeno (meia duzia) -- ver PLANO secao 3, cuidado
    --              termico com o array de osciladores em anel.
    -- IO_SPI_EN  : fase 4. Log de auditoria na flash MT25QL128.
    -- PMP_*      : fase 3+. Separacao de privilegio para a fronteira
    --              criptografica.
    IO_CFS_EN        => false,
    IO_TRNG_EN       => false,
    IO_SPI_EN        => false,
    PMP_NUM_REGIONS  => 0,

    -- Tracer: buffer de execucao. Desligado -- e observabilidade que
    -- nao queremos num dispositivo que guarda chave.
    IO_TRACER_EN     => false
  )
  port map (
    clk_i       => clk_i,
    rstn_i      => rstn_i,
    uart0_txd_o => uart0_txd_o,
    uart0_rxd_i => uart0_rxd_i,
    gpio_o      => gpio_out_v,
    gpio_i      => gpio_in_v
  );

end architecture;
