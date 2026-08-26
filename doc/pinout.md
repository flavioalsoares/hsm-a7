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
| SW2 | **M6** | `btn_a_i` — dual control A — **[HW]** 2026-08-21 |
| SW3 | N6 | livre |
| SW4 | R5 | livre |
| SW5 | **P6** | `btn_b_i` — dual control B — **[HW]** 2026-08-21 |

**[HW] Ordem física no silk — verificada 2026-08-21.** Fecha o último TBD de
bancada, e ele importava: o dual control da cerimônia de LMK exige dois
operadores em botões distintos, e **trocar SW2 com SW5 não é detectável por
software** — o dispositivo aceitaria a cerimônia com uma pessoa só apertando
os dois, que é exatamente o que o dual control existe para impedir.

Medido com o `rtl/diag/`, que passou a reportar o estado dos dois botões na
mensagem periódica (campo `Bab`, 1 = pressionado).

**Como foi medido, e por que não do jeito óbvio.** Pedir "aperte o SW2" e
observar não funcionou: em duas tentativas nada registrou, e a conclusão
apressada seria "SW5 não está em P6". O que resolveu foi um **padrão
codificado** — uma pressão isolada no primeiro botão, pausa, três no
segundo:

```
 2,5 s   M6 pressionado   uma vez, no inicio    -> SW2
13,0 s   P6 pressionado
15,5 s   P6 pressionado   repetido, apos pausa  -> SW5
```

O padrão se identifica sozinho, sem depender de sincronizar a janela de
leitura com quem está apertando.

⚠ **Limitação do instrumento:** a mensagem sai a cada 500 ms, então um
toque curto cai entre duas amostras e some. Foi isso que fez as primeiras
tentativas parecerem negativas. Para leitura confiável, **segurar** o botão
por mais de um segundo — ou repetir, como no padrão acima.

**[HW] A fileira é mesmo SW1→SW5 — confirmada visualmente em 2026-08-26.**
Fecha o TBD que restava aqui. O mapeamento elétrico já estava medido desde
2026-08-21; o que faltava era a *posição*, e ela só se fecha com o olho.

**Por que SW2 e SW5 e não dois adjacentes:** são o par mais afastado
**disponível**, o que dificulta pressionar ambos com uma mão só.

⚠ Não são "os extremos da fileira" — os extremos são SW1 e SW5, e **SW1 é o
reset**. Sobram SW2, SW3, SW4 e SW5, e o par mais separado entre eles é
SW2↔SW5: três posições de distância numa fileira de cinco.

Esta nota existe porque a afirmação errada — "os extremos" — chegou a
circular no manual como se fosse fato. Ela era plausível, era quase
verdadeira, e ninguém a mediu. É o mesmo defeito que a §26 do manual ensina
a evitar, cometido no arquivo que existe justamente para registrar
procedência.

`LMK_LOAD_COMPONENT` exige os dois simultaneamente (PLANO §4) — o ponto
pedagógico é separar fisicamente "quem digita" de "quem autoriza", e dois
botões coláveis com um polegar só enfraquecem a demonstração.

**Para o operador:** contando do reset, `btn_a` é o **2º** botão e `btn_b` é
o **5º** — o último da fileira. É por posição, e não pelo rótulo impresso,
que o `hsmtool.py` descreve os dois.

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

**[HW] Cores dos LEDs — verificado 2026-08-09: os cinco são VERMELHOS.**

Isso fecha o TBD e, junto, invalida o requisito como estava escrito. O
`PLANO.md` §3 pedia "LED vermelho" para `TAMPERED`; D5 é vermelho, mas todos
são — logo **cor não carrega informação nenhuma nesta placa**.

Consequência de projeto, e ela não é cosmética: um indicador de estado tem
de se distinguir por **posição** e por **padrão**, não por cor. Em
particular:

- `TAMPERED` em D5 aceso **fixo** é fraco: D2 aceso fixo (firmware vivo) é
  visualmente do mesmo tipo, e quem olha de longe não distingue.
- O que distingue sem ambiguidade é **piscar** — nenhum outro LED do design
  pisca além de D1 (heartbeat, 1 Hz, hardware). Um D5 piscando em ritmo
  diferente do heartbeat é inconfundível.
- E o caminho de verdade é o **display de 7 segmentos**, que soletra o
  estado (`Uni`/`Aut`/`OPE`/`tPr`). A cor uniforme dos LEDs torna o display
  mais importante, não menos.

Verificado com o bitstream de diagnóstico (`rtl/diag/`), que acende D2–D5
separados no tempo em luz corrida — cada LED isolado, um de cada vez.

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

**[HW] Polaridade e mapeamento — verificados 2026-08-09.**

```
segmento acende com 0        ->  SEG_ACTIVE_LOW = 1
digito  habilita  com 1      ->  AN_ACTIVE_LOW  = 0

seg_o[0]=a  [1]=b  [2]=c  [3]=d  [4]=e  [5]=f  [6]=g  [7]=dp
```

**Como foi medido.** Não por varredura fixa em RTL — cada hipótese custaria
um bitstream. O `rtl/diag/` ganhou **controle direto pelo host**: a UART
aceita `0xAA <seg> <an>` e aplica os valores crus nos pinos, então o ciclo
de experimento caiu de vinte minutos para dois segundos.

As quatro combinações de polaridade, uma por vez:

| `seg_o` | `seg_an_o` | resultado |
|---|---|---|
| `0x00` | `000` | apagado |
| `0xFF` | `000` | apagado |
| `0xFF` | `111` | apagado |
| `0x00` | `111` | **tudo aceso** |

Depois, `0xA4` com `an=111` desenhou **`222`** nos três dígitos — o padrão
do algarismo 2 (a, b, g, e, d). Glifo assimétrico de propósito: qualquer
troca entre segmentos apareceria como outro caractere.

**[HW] Ordem dos dígitos — verificada 2026-08-26.** `seg_an_o[0]` é o
dígito da **esquerda**, `[1]` o do meio, `[2]` o da direita.

A medida de 2026-08-09 **não servia para isto**, e vale entender por quê: ela
desenhou `222` nos **três dígitos ao mesmo tempo**, o que confirma polaridade
e mapeamento de segmento — e não distingue ordem nenhuma. Três dígitos iguais
são iguais em qualquer ordem. O TBD ficou aberto sem que ninguém notasse,
porque o experimento *parecia* ter coberto o display inteiro.

**Como foi medido:** desenhando `123`. O `rtl/diag/` aplica o mesmo valor de
segmentos a todos os dígitos habilitados, então três glifos diferentes exigem
varredura — e ela veio **do host**, três comandos em laço, um dígito por vez:

```python
UM   = 0b00000110   # b c
DOIS = 0b01011011   # a b g e d
TRES = 0b01001111   # a b g c d

for glifo, an in [(UM, 0b001), (DOIS, 0b010), (TRES, 0b100)]:
    s.write(bytes([0xAA, (~glifo) & 0xFF, an]))
```

A 115200 baud, três bytes levam ~260 µs, então o quadro sai em ~780 µs —
cerca de 1,3 kHz, muito acima da cintilação. O olho lê `123` estático.

⚠ **Conferência que a tabela de glifos precisava:** `~0b01011011 == 0xA4`, e
`0xA4` é exatamente o byte que desenhou `222` na medida de 2026-08-09. Se o
mapa de segmentos daqui estivesse errado, esse valor não bateria com o
registro anterior. Duas medidas independentes concordando é o que fecha um
TBD; uma medida sozinha só o adia.

**O esquemático concorda.** O `7SEG_Test.xdc` oficial confere pino a pino
com o nosso, e `DB-FPGA-XC7A35T-DDR3-V03.pdf` lista `SEG_A … SEG_G, DP`
nessa ordem. Medida e documento em acordo — que é o padrão de procedência
mais forte que este projeto tem.

⚠ **O palpite anterior estava invertido.** `hsm_top.v` trazia
`AN_ACTIVE_LOW = 1'b1`. Não aparecia porque, com os segmentos todos
desligados, habilitar ou não os dígitos dá no mesmo — apareceria na fase 3,
no primeiro estado exibido. Corrigido.

A tabela de fontes para `Uni`/`Aut`/`OPE`/`tPr` **já pode ser escrita**, e
agora sobre medida em vez de palpite.

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

Nada de pinagem. Os três TBD que restavam — cores dos LEDs, polaridade do
7 segmentos e ordem física dos botões — foram fechados por medida em
hardware entre 2026-08-09 e 2026-08-21.

Registrado abaixo apenas por precaução, não é pendência:

- **Pinos do microSD** — não usados pelo HSM, mas registrados aqui para evitar
  colisão: J5 (CS), K5 (MOSI), E6 (CLK), B5 (MISO), B6/J4/A7 (DAT1/DAT2/CD).
