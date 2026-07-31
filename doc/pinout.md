# Pinout e clocking — QMTECH XC7A35T-FTG256 + daughterboard

Registro dos pinos com fonte. **Regra do projeto: nenhum pino entra no XDC sem
fonte.** Um pino errado num banco de I/O pode danificar a placa.

## Procedência

Estes dados vêm do projeto irmão `~/Projetos/MSXInArt/msxinart`, que roda na
**mesma placa** (core board QMTECH XC7A35T-DDR3 + daughterboard). Boa parte foi
verificada em hardware lá, não apenas lida no esquemático.

- Esquemáticos e manuais: `doc/datasheets/` (cópia local)
- XDCs oficiais QMTECH (repo `ChinaQMTECH/QM_XC7A35T_DDR3`): `doc/qmtech_official_xdc/`

Legenda de confiança:

| Marca | Significado |
|---|---|
| **[HW]** | verificado em hardware no MSXInArt (2026-07-26) |
| **[SCH]** | lido no esquemático `DB-FPGA-XC7A35T-DDR3-V03` / `Artix7-DDR3-V5` |
| **[XDC]** | consta nos XDCs oficiais de exemplo |
| **[TBD]** | ainda sem fonte — não usar |

---

## Clock e reset

| Função | Pino | Fonte | Nota |
|---|---|---|---|
| `sys_clk_i` 50 MHz | **N11** | [HW][XDC] | oscilador do core board; presente em todos os exemplos |
| `rst_n_i` | **B7** (SW1) | [HW][SCH] | ativo baixo, pull-up 4,7k na placa |

A dúvida sobre `CLOCK_DEDICATED_ROUTE` em N11 está **resolvida**: o MSXInArt
sintetiza, roteia e roda em hardware com `create_clock` direto em N11, sem
waiver e sem erro de roteamento dedicado. Nenhum waiver é necessário.

O MMCM 50 → 100 MHz da Fase 1 é derivado daqui. Referência de dimensionamento
que já funcionou na placa: `PLLE2_BASE` com VCO = 50 × 20 = 1000 MHz e divisor
de saída (o MSXInArt usa ÷40 para 25 MHz; para 100 MHz é ÷10).

---

## UART — canal do `hsmtool.py`

| Função | Pino | Fonte |
|---|---|---|
| `uart_rxd_i` | **T15** | **[HW]** verificado 2026-07-31 |
| `uart_txd_o` | **T14** | **[HW]** verificado 2026-07-31 |

Ligado ao **CP2102 do core board** (`10c4:ea60`), que aparece no host como
`/dev/ttyUSB*`. Confirmado com 10.000 pings sem erro a 115200 8N1.

> ⚠ **Duas `/dev/ttyUSB*` quando o gravador está ligado.** O adaptador JTAG
> "DLC9LP" é um FT232H (`0403:6014`) e também cria uma porta serial — que
> costuma ficar em `ttyUSB0`, *antes* da placa. Escolher a porta por ordem
> alfabética acerta o cabo de gravação e o sintoma é um timeout sem
> explicação. O `hsmtool.py` escolhe por VID:PID por causa disto.

Isto atende diretamente o critério da Fase 3: por ser um par de pinos físicos
identificável, dá para pôr o analisador lógico em T14 e **provar** que nenhum
byte de chave em claro cruza a fronteira criptográfica.

---

## Botões — dual control da cerimônia de LMK

Daughterboard, SW1–SW5. **Todos ativos em nível baixo**, pull-up 4,7k para 3V3,
fecham para GND. [HW][SCH]

| Silk | Pino | Uso no HSM |
|---|---|---|
| SW1 | **B7** | `rst_n_i` (reset do sistema) |
| SW2 | **M6** | `btn_a_i` — dual control A |
| SW3 | N6 | livre |
| SW4 | R5 | livre |
| SW5 | **P6** | `btn_b_i` — dual control B |

**Por que SW2 e SW5 e não dois adjacentes:** são os extremos da fileira, o que
dificulta pressionar ambos com uma mão só. `LMK_LOAD_COMPONENT` exige os dois
simultaneamente (PLANO §4) — o ponto pedagógico é separar fisicamente "quem
digita" de "quem autoriza", e dois botões coláveis com um polegar só enfraquecem
a demonstração. **A confirmar visualmente** que a ordem no silk é mesmo uma
fileira SW1→SW5; se não for, escolher outro par pelo mesmo critério.

Como são ativos baixos, o firmware lê `!btn` para "pressionado". Debounce é
obrigatório: um botão mecânico gera dezenas de transições, e um glitch aqui
significa aceitar um componente de LMK sem autorização real.

---

## LEDs

Daughterboard D1–D5. **Ativos em nível baixo** — catodo no pino do FPGA, anodo
via 1k em 3V3, então `'0'` acende. [HW][SCH]

| Silk | Pino | Uso atual | Estado |
|---|---|---|---|
| D1 | **R6** | heartbeat 1 Hz (hardware) | **[HW]** verificado 2026-07-31 |
| D2 | **T5** | firmware vivo (GPIO 0) | **[HW]** verificado 2026-07-31 |
| D3 | **R7** | GPIO 1 | pino [SCH], não aceso ainda |
| D4 | **T7** | GPIO 2 | pino [SCH], não aceso ainda |
| D5 | **R8** | GPIO 3 → `TAMPERED` (Fase 3) | pino [SCH], não aceso ainda |

**Polaridade ativa-baixa confirmada em hardware** (2026-07-31): com o
bitstream da Fase 1 carregado, D1 pisca a 1 Hz e D2 fica aceso, que é
exatamente o que o firmware pede escrevendo `1` no GPIO. A inversão única no
toplevel está correta.

O heartbeat a 1 Hz cronometrado a olho também confirma a divisão do MMCM: o
contador é `CLK_HZ/2` e só bate 1 Hz se o clock for mesmo 100 MHz.

**[TBD] As cores dos LEDs continuam sem documentação.** O PLANO §3 pede "LED
vermelho" para `TAMPERED`, hoje mapeado em D5. Conferir visualmente e
remapear se D5 não for vermelho — D3/D4/D5 ainda não foram acesos por
firmware nenhum.

---

## Display 7 segmentos — estado do HSM

Daughterboard, **3 dígitos multiplexados**. Pinos dos XDCs oficiais (Test06).
[XDC]

| Sinal | Pino |
|---|---|
| `seg_o[0]` (a) | T10 |
| `seg_o[1]` (b) | K13 |
| `seg_o[2]` (c) | P11 |
| `seg_o[3]` (d) | R11 |
| `seg_o[4]` (e) | R10 |
| `seg_o[5]` (f) | N9 |
| `seg_o[6]` (g) | K12 |
| `seg_o[7]` (dp) | P9 |
| `seg_an_o[0]` | T9 |
| `seg_an_o[1]` | P10 |
| `seg_an_o[2]` | T8 |

**3 dígitos casam exatamente** com os mnemônicos de estado do PLANO §4:
`Uni` / `Aut` / `OPE` / `tPr`. Nenhuma adaptação necessária.

**[TBD] Polaridade:** o mapeamento bit→segmento (a..g,dp) e se o display é
anodo ou catodo comum **não foram verificados em hardware** — o MSXInArt não
chegou a usar o 7-seg. Confirmar no manual da daughterboard antes de escrever a
tabela de fontes, ou descobrir empiricamente acendendo um segmento por vez.

---

## SPI flash — log de auditoria e blobs (Fases 4/5)

| Item | Valor | Fonte |
|---|---|---|
| Peça | **MT25QL128**, SPI, 16 MB | manual §1.2 |
| Peça no Vivado | `mt25ql128-spi-x1_x2_x4` | — |
| Alerta | o `openFPGALoader` a reporta como **N25Q128** (sucessora); não é outra peça | [HW] |

Cuidado que o MSXInArt já pagou: o datasheet e alguns scripts falam em
`n25q64` (8 MB) — **peça errada**, gravação falha ou trunca.

**Consequência de arquitetura para o HSM:** esta é a *mesma* flash que guarda o
bitstream. O log de auditoria e os blobs wrapped precisam morar num offset
acima da imagem de configuração. O bitstream do XC7A35T é ~2,1 MB não
comprimido, então **começar a região de log em 0x400000 (4 MB)** dá margem
folgada, inclusive para um futuro bitstream encriptado.

Acesso a partir da lógica do usuário exige a primitiva **`STARTUPE2`** para
dirigir o CCLK — os pinos de configuração são dedicados e não recebem
`PACKAGE_PIN` no XDC. Isso precisa entrar no desenho antes da Fase 4.

---

## Gravação e JTAG

| Item | Valor |
|---|---|
| Adaptador | caixa "Xilinx DLC9LP", internamente **FT232H**, enumera como Digilent (`0403:6014`) |
| Comando | `openFPGALoader -c digilent_hs2` |
| Vivado usado no projeto irmão | 2026.1 |

Config por JTAG é **volátil** — some no power-off. Gravar na flash para testes
de bancada que sobrevivam ao ciclo de energia.

Isto conversa com a nota do PLANO §0 sobre a BBRAM: `VCCBATT` (F8) está ligado
ao rail 1V8, sem bateria, então a chave de bitstream em BBRAM também se perde no
power-off. Ambos são recarregáveis por JTAG — que é exatamente o motivo de o
JTAG **nunca** ser desabilitado neste projeto.

---

## Pinos conflitantes — leia antes de reaproveitar exemplo oficial

Os XDCs oficiais `LED.xdc` e `key.xdc` valem para o core board **sem** a
daughterboard. Com ela montada, os pinos que eles usam pertencem ao microSD:

| Pino | No exemplo oficial | Com daughterboard |
|---|---|---|
| **E6** | `sys_rst_n` / `led_1` | SD CLK |
| **K5** | `key_1` | SD MOSI (CMD) |
| **B7** | `sys_rst_n` (MicroSD/VGA) | SW1 — usável como reset |

Copiar `LED.xdc` ou `key.xdc` sem ler isto leva a acionar linhas do cartão SD
achando que se está piscando um LED.

---

## O que continua [TBD] neste projeto

- **Polaridade e mapeamento de segmentos do 7-seg** (acima).
- **Cores dos LEDs** (acima).
- **Ordem física dos botões no silk**, para validar a escolha SW2/SW5.
- **Pinos do microSD** — não usados pelo HSM, mas registrados aqui para evitar
  colisão: J5 (CS), K5 (MOSI), E6 (CLK), B5 (MISO), B6/J4/A7 (DAT1/DAT2/CD).
