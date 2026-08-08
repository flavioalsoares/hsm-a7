-- =====================================================================
-- hsm_entropy.vhd -- fonte de ruido do HSM, com derivacao da amostra bruta
--
-- ---------------------------------------------------------------------
-- POR QUE NAO USAR O PERIFERICO neorv32_trng DIRETO
--
-- O NEORV32 traz o neoTRNG pronto e bastaria ligar IO_TRNG_EN => true.
-- Duas razoes para nao fazer isso:
--
-- 1. A SP 800-90B manda rodar os health tests sobre a saida da FONTE DE
--    RUIDO, antes de qualquer condicionamento. O neoTRNG so expoe bytes
--    ja condicionados: von Neumann para tirar vies, mais um registrador
--    de deslocamento com realimentacao CRC-8 para misturar. Testar essa
--    saida testa o CONDICIONADOR, nao a fonte. E um condicionador e bom
--    justamente em fazer entrada ruim parecer boa -- e exatamente o que
--    o health test precisa enxergar.
--
--    (Uma fonte totalmente travada nem produz saida: o von Neumann so
--    emite em transicao, entao o TRNG simplesmente para. Isso e
--    detectavel. Mas uma fonte apenas ENVIESADA passa pelo condicionador
--    parecendo otima, e essa e a falha que interessa pegar.)
--
-- 2. Como periferico de IO, a entropia vive fora do bloco que guarda
--    chave. Aqui ela entra no CFS, do lado de dentro da fronteira, junto
--    com AES e SHA.
--
-- O que se reaproveita do upstream e a parte dificil e a que nao se deve
-- reescrever: a CELULA osciladora (neoTRNG_cell), com os latches que
-- impedem a ferramenta de sintese de "otimizar" o anel de inversores e
-- sem precisar de primitiva ou atributo especifico de fabricante.
-- Instanciada como entidade, direto da biblioteca neorv32 -- sem patch,
-- sem fork, third_party/ intocado. Ver doc/submodulos.md.
--
-- O que se escreve aqui e so o amostrador, porque e nele que fica a
-- derivacao do sinal bruto que a norma exige.
--
-- ---------------------------------------------------------------------
-- A CADEIA, E ONDE CADA COISA ENTRA
--
--   celulas em anel  -->  XOR  -->  raw_o        amostra BRUTA, 1 por ciclo
--                                    |
--                                    +--> health tests (hsm_health.v)
--                                    |
--                                    +--> von Neumann  -->  8 bits  --> byte_o
--
-- Os health tests ficam ANTES do von Neumann, que e o unico lugar onde
-- eles significam alguma coisa.
--
-- NAO ha mistura CRC-8 aqui, de proposito: quem condiciona de verdade e
-- o CTR_DRBG em firmware, que e o condicionador aprovado pela SP 800-90A.
-- Duas camadas de mistura ad-hoc antes dele so dificultariam estimar
-- quanta entropia realmente entra na semente.
--
-- ---------------------------------------------------------------------
-- CUIDADO TERMICO
--
-- NUM_CELLS pequeno de proposito -- meia duzia. Centenas de aneis geram
-- calor e ruido de alimentacao localizados, acoplam entre si (o que
-- REDUZ a entropia independente em vez de aumentar) e nao melhoram nada.
-- Ver PLANO.md secao 3.
-- =====================================================================

library ieee;
use ieee.std_logic_1164.all;

entity hsm_entropy is
  generic (
    NUM_CELLS     : natural := 6;      -- aneis. Poucos, de proposito.
    NUM_INV_START : natural := 3;      -- inversores no primeiro anel, impar
    SIM_MODE      : boolean := false   -- true = SEM aleatoriedade fisica
  );
  port (
    clk_i        : in  std_logic;
    rstn_i       : in  std_logic;      -- reset sincrono, ativo baixo
    en_i         : in  std_logic;

    -- Saida da FONTE DE RUIDO, sem condicionamento nenhum. E o que os
    -- health tests observam, e o que uma coleta para estimar entropia
    -- (ea_non_iid do NIST) precisa capturar.
    raw_o        : out std_logic;
    raw_valid_o  : out std_logic;

    -- Saida apos von Neumann, agrupada em bytes. Vira semente do DRBG.
    byte_o       : out std_logic_vector(7 downto 0);
    byte_valid_o : out std_logic
  );
end entity;

architecture rtl of hsm_entropy is

  component neoTRNG_cell
    generic (
      NUM_INV  : natural;
      SIM_MODE : boolean
    );
    port (
      clk_i  : in  std_ulogic;
      rstn_i : in  std_ulogic;
      en_i   : in  std_ulogic;
      en_o   : out std_ulogic;
      rnd_o  : out std_ulogic
    );
  end component;

  signal cell_en_in  : std_ulogic_vector(NUM_CELLS-1 downto 0);
  signal cell_en_out : std_ulogic_vector(NUM_CELLS-1 downto 0);
  signal cell_rnd    : std_ulogic_vector(NUM_CELLS-1 downto 0);
  signal cell_sum    : std_ulogic;

  signal en_sync     : std_ulogic;
  signal fonte_pronta: std_ulogic;

  -- von Neumann
  signal vn_sreg  : std_ulogic_vector(1 downto 0);
  signal vn_fase  : std_ulogic;
  signal vn_valid : std_ulogic;
  signal vn_bit   : std_ulogic;

  -- agrupamento em byte
  signal pack_sreg : std_ulogic_vector(7 downto 0);
  signal pack_cnt  : integer range 0 to 8;
  signal pack_done : std_ulogic;

begin

  -- -------------------------------------------------------------------
  -- Celulas osciladoras, em cadeia de habilitacao.
  --
  -- Cada anel tem um numero IMPAR e CRESCENTE de inversores (3, 5, 7...).
  -- Comprimentos diferentes dao frequencias diferentes e nao harmonicas,
  -- o que reduz o travamento por injecao entre aneis vizinhos -- aneis
  -- iguais lado a lado tendem a sincronizar, e aneis sincronizados
  -- produzem MENOS entropia total, nao mais.
  --
  -- A cadeia de habilitacao liga um anel por vez. So depois que o ultimo
  -- entrou e que a saida vale: antes disso parte dos aneis esta parada e
  -- a amostra e previsivel.
  -- -------------------------------------------------------------------
  gen_celulas: for i in 0 to NUM_CELLS-1 generate
    u_cell: neoTRNG_cell
      generic map (
        NUM_INV  => NUM_INV_START + (2*i),
        SIM_MODE => SIM_MODE
      )
      port map (
        clk_i  => std_ulogic(clk_i),
        rstn_i => std_ulogic(rstn_i),
        en_i   => cell_en_in(i),
        en_o   => cell_en_out(i),
        rnd_o  => cell_rnd(i)
      );
  end generate;

  en_sync    <= std_ulogic(en_i);
  cell_en_in <= cell_en_out(NUM_CELLS-2 downto 0) & en_sync;

  -- XOR de todas as celulas: a amostra digitalizada.
  combina: process(cell_rnd)
    variable acc : std_ulogic;
  begin
    acc := '0';
    for i in 0 to NUM_CELLS-1 loop
      acc := acc xor cell_rnd(i);
    end loop;
    cell_sum <= acc;
  end process;

  fonte_pronta <= cell_en_out(cell_en_out'left);

  raw_o       <= std_logic(cell_sum);
  raw_valid_o <= std_logic(fonte_pronta);

  -- -------------------------------------------------------------------
  -- Extrator de von Neumann
  --
  -- Olha pares NAO sobrepostos de bits consecutivos:
  --   01 -> emite 0      10 -> emite 1      00 e 11 -> descarta
  --
  -- Tira vies de primeira ordem: mesmo com P(1) = 0,9, os pares 01 e 10
  -- sao equiprovaveis e o bit que sai e equilibrado. O preco e a vazao,
  -- que cai para menos de um quarto -- barato perto de semear um DRBG
  -- com bits enviesados.
  --
  -- Nao conserta CORRELACAO entre amostras, so vies. Por isso ele nao
  -- substitui os health tests nem o DRBG; e uma etapa, nao a solucao.
  -- -------------------------------------------------------------------
  von_neumann: process(clk_i)
  begin
    if rising_edge(clk_i) then
      if (rstn_i = '0') or (en_i = '0') then
        vn_sreg <= (others => '0');
        vn_fase <= '0';
      else
        vn_sreg <= vn_sreg(0) & cell_sum;
        vn_fase <= (not vn_fase) and fonte_pronta;
      end if;
    end if;
  end process;

  vn_valid <= vn_fase and (vn_sreg(1) xor vn_sreg(0));
  vn_bit   <= vn_sreg(0);

  -- -------------------------------------------------------------------
  -- Agrupamento em bytes
  -- -------------------------------------------------------------------
  empacota: process(clk_i)
  begin
    if rising_edge(clk_i) then
      if (rstn_i = '0') or (en_i = '0') then
        pack_sreg <= (others => '0');
        pack_cnt  <= 0;
        pack_done <= '0';
      else
        pack_done <= '0';
        if vn_valid = '1' then
          pack_sreg <= pack_sreg(6 downto 0) & vn_bit;
          if pack_cnt = 7 then
            pack_cnt  <= 0;
            pack_done <= '1';
          else
            pack_cnt <= pack_cnt + 1;
          end if;
        end if;
      end if;
    end if;
  end process;

  byte_o       <= std_logic_vector(pack_sreg);
  byte_valid_o <= std_logic(pack_done);

end architecture;
