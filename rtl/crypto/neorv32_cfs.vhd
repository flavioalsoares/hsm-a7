-- =====================================================================
-- neorv32_cfs.vhd -- Custom Functions Subsystem do HSM
--
-- SUBSTITUI o arquivo de mesmo nome do submodulo NEORV32. O upstream
-- entrega um neorv32_cfs.vhd de exemplo (quatro registradores que fazem
-- OR e reversao de bits) explicitamente feito para ser trocado: o CFS e o
-- ponto de extensao PROJETADO do core.
--
-- A troca e feita na lista de arquivos do build -- scripts/build.tcl e
-- scripts/sim.sh filtram o arquivo do upstream e compilam este no lugar,
-- na mesma biblioteca VHDL 'neorv32'. Nada em third_party/ e tocado: o
-- submodulo continua byte a byte identico a tag v1.13.3.
--
-- E o grau 2 da escada do doc/submodulos.md. Nao e patch (grau 3) e nao e
-- fork (grau 4). Se um dia a entidade abaixo mudar no upstream, o build
-- quebra na compilacao -- que e o modo certo de descobrir.
--
-- Este arquivo e so o SHIM: desempacota os records bus_req_t/bus_rsp_t,
-- que nao atravessam a fronteira VHDL->Verilog, e instancia hsm_cfs.v.
-- A logica (AES-256, SHA-256, DNA_PORT, wipe) esta la, em Verilog, que e
-- a convencao do projeto para codigo proprio.
--
-- Conversoes explicitas std_ulogic_vector <-> std_logic_vector pelo mesmo
-- motivo do neorv32_wrapper.vhd: funciona em VHDL-93 e em 2008, sem
-- depender do modo de compilacao da ferramenta.
-- =====================================================================

library ieee;
use ieee.std_logic_1164.all;

library neorv32;
use neorv32.neorv32_package.all;

entity neorv32_cfs is
  port (
    -- global control --
    clk_i     : in  std_ulogic;
    rstn_i    : in  std_ulogic;
    -- CPU access --
    bus_req_i : in  bus_req_t;
    bus_rsp_o : out bus_rsp_t;
    -- CPU interrupt --
    irq_o     : out std_ulogic;
    -- external IO --
    cfs_in_i  : in  std_ulogic_vector(255 downto 0);
    cfs_out_o : out std_ulogic_vector(255 downto 0)
  );
end entity;

architecture hsm of neorv32_cfs is

  component hsm_cfs is
    port (
      clk_i   : in  std_logic;
      rstn_i  : in  std_logic;
      addr_i  : in  std_logic_vector(15 downto 0);
      wdata_i : in  std_logic_vector(31 downto 0);
      stb_i   : in  std_logic;
      rw_i    : in  std_logic;
      rdata_o : out std_logic_vector(31 downto 0);
      ack_o   : out std_logic;

      ent_en_o         : out std_logic;
      ent_raw_i        : in  std_logic;
      ent_raw_valid_i  : in  std_logic;
      ent_byte_i       : in  std_logic_vector(7 downto 0);
      ent_byte_valid_i : in  std_logic;

      irq_o   : out std_logic
    );
  end component;

  -- Fonte de ruido. Fica em VHDL porque reaproveita neoTRNG_cell, que e
  -- uma entidade do upstream -- instanciada, nao copiada e nao remendada.
  component hsm_entropy is
    generic (
      NUM_CELLS     : natural;
      NUM_INV_START : natural;
      SIM_MODE      : boolean
    );
    port (
      clk_i        : in  std_logic;
      rstn_i       : in  std_logic;
      en_i         : in  std_logic;
      raw_o        : out std_logic;
      raw_valid_o  : out std_logic;
      byte_o       : out std_logic_vector(7 downto 0);
      byte_valid_o : out std_logic
    );
  end component;

  signal rdata : std_logic_vector(31 downto 0);
  signal ack   : std_logic;

  signal ent_en    : std_logic;
  signal ent_raw   : std_logic;
  signal ent_rawv  : std_logic;
  signal ent_byte  : std_logic_vector(7 downto 0);
  signal ent_bytev : std_logic;

begin

  u_core : hsm_cfs
  port map (
    clk_i   => clk_i,
    rstn_i  => rstn_i,
    addr_i  => std_logic_vector(bus_req_i.addr(15 downto 0)),
    wdata_i => std_logic_vector(bus_req_i.data),
    stb_i   => bus_req_i.stb,
    rw_i    => bus_req_i.rw,
    rdata_o => rdata,
    ack_o   => ack,

    ent_en_o         => ent_en,
    ent_raw_i        => ent_raw,
    ent_raw_valid_i  => ent_rawv,
    ent_byte_i       => ent_byte,
    ent_byte_valid_i => ent_bytev,

    irq_o   => open
  );

  -- SIM_MODE vem de is_simulation_c: false em sintese, true em simulacao.
  --
  -- E o mesmo mecanismo que o proprio neorv32_trng usa, e nao ha escolha
  -- razoavel: em simulacao um anel de inversores com latches NAO oscila.
  -- Sem SIM_MODE a fonte nao produziria nada, o teste de partida do POST
  -- giraria ate o limite de espera e reprovaria -- e um POST que nao roda
  -- em simulacao nao pode ser testado em regressao nenhuma.
  --
  -- O preco, e ele precisa estar escrito: em simulacao o TRNG e um gerador
  -- PSEUDOaleatorio. Nenhum testbench aqui mede qualidade de entropia, e
  -- nem poderia. Quem exercita os health tests e tb_trng_health, direto
  -- sobre hsm_health, com sequencias construidas -- fonte travada e fonte
  -- enviesada, que e onde esses casos podem ser REPRODUZIDOS. Nenhuma
  -- fonte fisica permite reproduzir a propria falha sob demanda.
  u_entropia : hsm_entropy
  generic map (
    NUM_CELLS     => 6,       -- meia duzia. Cuidado termico, PLANO.md 3.
    NUM_INV_START => 3,
    SIM_MODE      => is_simulation_c
  )
  port map (
    clk_i        => clk_i,
    rstn_i       => rstn_i,
    en_i         => ent_en,
    raw_o        => ent_raw,
    raw_valid_o  => ent_rawv,
    byte_o       => ent_byte,
    byte_valid_o => ent_bytev
  );

  bus_rsp_o.data <= std_ulogic_vector(rdata);
  bus_rsp_o.ack  <= ack;

  -- Sem erro de acesso: endereco nao mapeado dentro do CFS e ignorado, com
  -- ACK. Nao dar ACK causaria excecao de bus timeout na CPU, e sinalizar
  -- erro por endereco daria ao firmware um mapa do que existe -- que e
  -- exatamente o tipo de oraculo que a secao 15 do manual discute.
  bus_rsp_o.err  <= '0';

  -- Sem interrupcao. Ver o cabecalho de hsm_cfs.v.
  irq_o <= '0';

  -- ------------------------------------------------------------------
  -- Conduits externos -- AMARRADOS EM ZERO, e isto e uma decisao de
  -- seguranca, nao economia de codigo.
  --
  -- cfs_out_o e o unico fio do CFS que chega ao toplevel do SoC e, dali,
  -- a pinos. Regra 2 do CLAUDE.md: material de chave nunca vai para um
  -- registrador exposto no toplevel. Com este sinal em zero, nao existe
  -- caminho fisico do bloco que guarda a chave ate fora do die -- do mesmo
  -- jeito que XBUS_EN => false elimina o caminho pela DDR3.
  --
  -- cfs_in_i e deixado sem uso pelo motivo simetrico: uma entrada do
  -- toplevel para dentro da fronteira e uma superficie de ataque que este
  -- projeto nao precisa ter.
  -- ------------------------------------------------------------------
  cfs_out_o <= (others => '0');

end architecture;
