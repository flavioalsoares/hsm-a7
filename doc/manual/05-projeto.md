# Parte V — O equipamento hsm-a7

## 23. Objetivo, plataforma e restrições

### O objetivo

Construir, do zero, um módulo criptográfico com hierarquia de chaves,
cerimônia de carga, key blocks e API de host — reproduzindo a arquitetura de
um HSM real em escala reduzida, para **entendê-la de dentro para fora**.

A escolha de fazer em FPGA, e não em software, é deliberada: obriga a
enfrentar a fronteira física, a distinguir memória interna de externa, e a
lidar com clock e reset como questões de segurança e não de infraestrutura.

### A plataforma

| Item | Valor |
|---|---|
| FPGA | Xilinx Artix-7 **XC7A35T**, encapsulamento FTG256, speed grade -1 |
| Placa | QMTECH core board + daughterboard |
| Recursos | 20.800 LUTs, 41.600 flip-flops, 50 BRAMs, 90 DSP48E1 |
| Clock | 50 MHz no pino N11 → 100 MHz por MMCM |
| Processador | NEORV32 (RISC-V RV32IMC), submódulo fixado em v1.13.3 |
| Canal | UART 115200 8N1 pelo CP2102 do core board |
| Flash | MT25QL128, 16 MB, a mesma que guarda o bitstream |

O orçamento de fabric é apertado de propósito: AES, SHA, key store e
processador precisam caber em 20.800 LUTs, e isso força decisões explícitas
em vez de acumulação.

### As restrições invioláveis

Estas não são preferências. Estão no topo do plano e do arquivo de
instruções do projeto.

**1. Nada de eFUSE.** Não gerar, sugerir ou executar `program_efuse`,
`CFG_AES_ONLY`, `W_DIS`/`R_DIS` ou qualquer variante. São memórias de
programação única: o erro é um *brick* permanente. Chave de bitstream apenas
em BBRAM, que é recuperável.

**2. Chaves em claro só em BRAM e na região segura da flash.** Nunca DDR3,
nunca um registrador exposto no toplevel. A região da flash a partir de 4 MB
faz o papel da memória com bateria de um HSM comercial: a LMK fica nela em
claro, e as chaves de trabalho, embrulhadas sob a LMK. A seção 27 explica
por que, e o que isso não protege.

**3. Nada atravessa a fronteira em claro.** Saem apenas key blocks
embrulhados, KCVs, criptogramas, *handles* e log.

**4. Simulação antes de hardware.** Nenhum módulo vai para a placa sem
testbench passando. Depurar criptografia por UART, sem visibilidade interna,
é a forma mais lenta possível de descobrir que faltou um byte no
preenchimento.

**5. Não enfraquecer testes para fazer algo passar.** Se um KAT falha, o bug
está no código, não no vetor.

A regra do eFUSE merece um comentário, porque ela ilustra um princípio geral:
**preferir sempre o mecanismo recuperável ao irreversível, num projeto de
estudo**. O JTAG também nunca é desabilitado — é a única via de recuperação,
e um projeto de aprendizado precisa poder voltar atrás. Um produto real faria
o oposto em ambos os casos, e entender por que os dois caminhos são corretos
em contextos diferentes é parte do conteúdo.

## 24. A plataforma, peça por peça

Esta seção pega cada peça da plataforma e responde: **o que essa peça
corresponde num HSM real?**

Várias terminam com *o que um HSM real tem a mais*. A distância entre este
equipamento e um produto também é conteúdo.

### Mapa

| O que construímos | O que é num HSM real |
|---|---|
| `clk_rst_gen.v` | Monitor de integridade do clock (sensor antitamper) |
| `debounce.v` | Integridade da autorização física (dual control) |
| `neorv32_wrapper.vhd` | Endurecimento da plataforma: o que a máquina **não** faz |
| `hsm_top.v` | Definição física da fronteira criptográfica |
| `cmd.c` | A API — a superfície de ataque principal |
| CRC32 | Integridade de transporte (num HSM real, viraria MAC) |
| `state.c` | A chave de switch de três posições |
| `wipe.c` | Requisito de zeroização do FIPS 140-3 |
| LEDs D1–D5 | Indicadores de estado e de violação |
| `BOOT_MODE_SELECT=2` | Autenticidade de firmware / secure boot |
| IMEM como ROM | Integridade do código em execução |
| `tb_soc_silent` | Higiene de canal lateral |
| `hsmtool.py` | O cliente da API — futuro PKCS#11 |
| Teste de 10.000 pings | Requisito de confiabilidade operacional |


<figure class="fig">
<svg viewBox="0 0 680 300" xmlns="http://www.w3.org/2000/svg">
<rect class="fr" x="120" y="10" width="440" height="280"/>
<text x="550" y="26" text-anchor="end" class="ts td">hsm_top.v: a fronteira (24.4)</text>
<rect class="cx" x="10" y="30" width="90" height="34"/><text x="55" y="51" text-anchor="middle" class="ts">oscilador 50 MHz</text>
<rect class="cx" x="140" y="30" width="130" height="44"/><text x="205" y="48" text-anchor="middle" class="tb">clk_rst_gen</text><text x="205" y="64" text-anchor="middle" class="ts">MMCM, reset (24.1)</text>
<line class="ln" x1="100" y1="47" x2="138" y2="47" marker-end="url(#seta)"/>
<rect class="cxa" x="10" y="100" width="90" height="34"/><text x="55" y="121" text-anchor="middle" class="ts">host: UART</text>
<rect class="cxa" x="10" y="170" width="90" height="34"/><text x="55" y="186" text-anchor="middle" class="ts">botões</text><text x="55" y="198" text-anchor="middle" class="ts">SW2, SW5</text>
<rect class="cx" x="140" y="168" width="110" height="38"/><text x="195" y="185" text-anchor="middle" class="tb">debounce</text><text x="195" y="199" text-anchor="middle" class="ts">10 ms (24.2)</text>
<line class="ln" x1="100" y1="187" x2="138" y2="187" marker-end="url(#seta)"/>
<rect class="cx" x="290" y="90" width="150" height="130"/>
<text x="365" y="110" text-anchor="middle" class="tb">NEORV32</text>
<text x="365" y="126" text-anchor="middle" class="ts">wrapper: o que se desliga (24.3)</text>
<text x="365" y="146" text-anchor="middle" class="ts">cmd.c: API (24.5)</text>
<text x="365" y="160" text-anchor="middle" class="ts">state.c: estados (24.7)</text>
<text x="365" y="174" text-anchor="middle" class="ts">wipe.c (24.8)</text>
<text x="365" y="188" text-anchor="middle" class="ts">IMEM em ROM (24.10)</text>
<text x="365" y="206" text-anchor="middle" class="ts">UART · GPIO · SPI</text>
<line class="ln" x1="100" y1="117" x2="288" y2="117" marker-end="url(#seta)"/>
<line class="ln" x1="288" y1="127" x2="100" y2="127" marker-end="url(#seta)"/>
<line class="ln" x1="250" y1="187" x2="288" y2="187" marker-end="url(#seta)"/>
<line class="ln" x1="205" y1="74" x2="300" y2="88" marker-end="url(#seta)"/>
<rect class="cx" x="460" y="90" width="85" height="60"/><text x="502" y="112" text-anchor="middle" class="tb">CFS</text><text x="502" y="128" text-anchor="middle" class="ts">cripto</text><text x="502" y="140" text-anchor="middle" class="ts">em fabric</text>
<line class="ln" x1="440" y1="120" x2="458" y2="120" marker-end="url(#seta)"/>
<rect class="cx" x="140" y="240" width="110" height="38"/><text x="195" y="257" text-anchor="middle" class="tb">D1</text><text x="195" y="271" text-anchor="middle" class="ts">1 Hz em fabric (24.9)</text>
<rect class="cx" x="290" y="240" width="150" height="38"/><text x="365" y="257" text-anchor="middle" class="tb">D2–D5, display</text><text x="365" y="271" text-anchor="middle" class="ts">pelo GPIO</text>
<line class="ln" x1="365" y1="220" x2="365" y2="238" marker-end="url(#seta)"/>
<rect class="cx" x="580" y="190" width="95" height="44"/><text x="627" y="208" text-anchor="middle" class="tb">flash</text><text x="627" y="224" text-anchor="middle" class="ts">SPI</text>
<line class="ln" x1="440" y1="205" x2="578" y2="210" marker-end="url(#seta)"/>
</svg>
<figcaption>Figura 24.1 — A plataforma, peça por peça. O número entre parênteses é a subseção que explica cada peça.</figcaption>
</figure>

### 24.1 `clk_rst_gen.v` — o clock é um sensor

MMCM que transforma 50 MHz em 100 MHz (VCO em 1000 MHz, meio da faixa do
speed grade -1), mais geração de reset: afirma assíncrono, libera síncrono,
segura 64 ciclos após o lock.

**Num HSM real:** monitoramento de clock é sensor antitamper. Ver seção 17.3
— glitch de clock é o ataque de injeção de falha mais barato que existe, e
faz a CPU pular exatamente a instrução que verifica alguma coisa.

O ponto de projeto está numa linha:

```verilog
    wire rst_src_n = locked_w & rst_n_sync[1];
```

Perda de `LOCKED` **reafirma o reset**. Não sabemos por que o lock caiu, mas
sabemos que não dá para confiar no que vier depois.


<figure class="fig">
<svg viewBox="0 0 680 160" xmlns="http://www.w3.org/2000/svg">
<rect class="cx" x="10" y="40" width="90" height="40"/><text x="55" y="64" text-anchor="middle" class="ts">50 MHz</text>
<line class="ln" x1="100" y1="60" x2="138" y2="60" marker-end="url(#seta)"/>
<rect class="cx" x="140" y="30" width="140" height="60"/><text x="210" y="52" text-anchor="middle" class="tb">MMCM</text><text x="210" y="68" text-anchor="middle" class="ts">VCO 1000 MHz</text><text x="210" y="82" text-anchor="middle" class="ts">saída 100 MHz</text>
<line class="ln" x1="280" y1="45" x2="620" y2="45" marker-end="url(#seta)"/><text x="600" y="38" text-anchor="end" class="ts">clock do sistema</text>
<line class="ln" x1="280" y1="75" x2="358" y2="75" marker-end="url(#seta)"/><text x="319" y="70" text-anchor="middle" class="ts">LOCKED</text>
<rect class="cx" x="360" y="60" width="40" height="30"/><text x="380" y="80" text-anchor="middle" class="tb">&amp;</text>
<rect class="cxa" x="250" y="110" width="90" height="30"/><text x="295" y="129" text-anchor="middle" class="ts">SW1, sincron.</text>
<line class="ln" x1="340" y1="125" x2="380" y2="125"/><line class="ln" x1="380" y1="125" x2="380" y2="92" marker-end="url(#seta)"/>
<line class="ln" x1="400" y1="75" x2="458" y2="75" marker-end="url(#seta)"/>
<rect class="cx" x="460" y="60" width="130" height="30"/><text x="525" y="80" text-anchor="middle" class="ts">segura 64 ciclos</text>
<line class="ln" x1="590" y1="75" x2="640" y2="75" marker-end="url(#seta)"/><text x="645" y="79" class="ts">reset</text>
<rect class="cxd" x="460" y="110" width="200" height="34"/><text x="560" y="126" text-anchor="middle" class="ts">LOCKED caiu: flip-flop sem reset retém;</text><text x="560" y="139" text-anchor="middle" class="ts">o boot seguinte apaga e vai a TAMPERED</text>
</svg>
<figcaption>Figura 24.2 — O clock como sensor. Sem lock não há clock confiável, e o reset volta; a perda fica registrada para o boot seguinte.</figcaption>
</figure>

O gerador é também a única exceção à convenção de reset síncrono do projeto,
e por necessidade: com o MMCM em reset, o clock de saída não está correndo e
não existe borda para registrar nada. Usa o padrão clássico *afirma
assíncrono / libera síncrono*, justamente para que todo o resto do projeto
possa usar reset puramente síncrono.

A perda de lock também fica retida num flip-flop sem reset. O módulo pulsa o
`RST` do MMCM sozinho, porque o MMCM não volta a travar sem isso. O boot
seguinte encontra a perda, apaga as chaves, vai para `TAMPERED` e registra o
evento (seção 29).

**Um HSM real tem a mais:** monitoração ativa da frequência, em vez de só
reagir à perda de lock.

### 24.2 `debounce.v` — quando um ressalto vira autorização

Exige 10 ms de estabilidade contínua antes de aceitar mudança; qualquer
transição no meio zera a contagem.


<figure class="fig">
<svg viewBox="0 0 680 150" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="38" class="ts">contato</text>
<path d="M90,30 H150 V60 H156 V30 H162 V60 H170 V30 H176 V60 H190 V30 H196 V60 H420 V54 H424 V60 H426 V30 H432 V60 H440 V30 H448 V30 H660" fill="none" stroke="#7a1f1f" stroke-width="1.5"/>
<text x="10" y="98" class="ts">filtrado</text>
<path d="M90,90 H300 V120 H560 V90 H660" fill="none" stroke="#2f5f2f" stroke-width="2"/>
<line x1="196" y1="66" x2="300" y2="66" stroke="#555" marker-start="url(#seta)" marker-end="url(#seta)"/>
<text x="248" y="80" text-anchor="middle" class="ts">10 ms estável</text>
<line x1="448" y1="66" x2="560" y2="66" stroke="#555" marker-start="url(#seta)" marker-end="url(#seta)"/>
<text x="504" y="80" text-anchor="middle" class="ts">10 ms estável</text>
<text x="170" y="22" text-anchor="middle" class="ts td">apertou: ressalta</text>
<text x="430" y="22" text-anchor="middle" class="ts td">soltou: ressalta</text>
<text x="340" y="144" text-anchor="middle" class="ts">cada transição no meio zera a contagem; um ressalto nunca vira um segundo aperto</text>
</svg>
<figcaption>Figura 24.3 — O filtro de ressalto. A autorização segue a intenção humana, e não o estado elétrico do contato.</figcaption>
</figure>

**Num HSM real:** integridade da autorização física (seção 7). O mecanismo
precisa refletir intenção humana, não estado elétrico de contato.

Os dois botões escolhidos são o **2º e o 5º** de uma fileira de cinco, cujo
primeiro é o reset — o par mais afastado disponível, o que dificulta
pressionar ambos com uma mão só.

**A camada de política acima deste filtro** está na seção 26: os
dois botões autorizam a cerimônia de carga da chave mestra, e não basta que
estejam pressionados — cada autorização exige um aperto *novo*. O `debounce`
garante que o contato parou quieto; a política garante que o operador
soltou.

**Um HSM real tem a mais:** autenticação de custodiante (smartcard + PIN) e registro de *quem*
autorizou, não só de que houve autorização. Dois botões na mesma placa cabem
nas duas mãos de uma pessoa — isto prova presença física, não consentimento
de duas pessoas.

### 24.3 `neorv32_wrapper.vhd` — segurança é o que se desliga

Fixa os ~130 generics do processador. É o único lugar onde a configuração do
SoC está escrita — e num relatório de avaliação, é exatamente essa lista que
o laboratório examina.

| Desligado | Por quê |
|---|---|
| `OCD_EN` | Debugger dá leitura e escrita irrestritas de memória por JTAG. Com a LMK em BRAM, **é** extração de chave sem passar pela API. O generic mais importante do arquivo. |
| `ICACHE`/`DCACHE` | Inúteis (BRAM já responde em 1 ciclo) e nocivas: tempo dependente do dado é canal lateral (seção 16.2). |
| `XBUS`/`SMC` | Sem barramento externo, não há caminho físico até a DDR3. A regra vira estrutura. |
| `IO_TRACER` | Buffer de rastreamento de execução é observabilidade indesejada. |
| `Zkne`/`Zknd`/`Zknh` | AES e SHA vão para o fabric via CFS: construí-los é o objetivo do projeto. |

Sobre desligar o debugger, note a assimetria com a regra de nunca desabilitar
JTAG no FPGA: lá é o caminho de recuperação do **bitstream**, e precisa
existir num projeto de estudo. Aqui é o caminho de leitura da **memória do
processador**, e não precisa. Duas coisas diferentes com o mesmo nome.

Ligados: RV32IMC (`RISCV_ISA_C` + `_M`), contadores base, barrel shifter
(código criptográfico é pesado em deslocamento), IMEM de 128 KB, DMEM de 32 KB,
UART0 com FIFO de 64, temporizador, GPIO de 8 bits e o SPI da flash.

**Um HSM real tem a mais:** PMP (proteção de memória física) para separar
privilégio dentro do firmware, de modo que um bug no parser não alcance a
região da LMK. Este equipamento não usa PMP.

### 24.4 `hsm_top.v` — onde a fronteira fica física

Único arquivo do projeto que conhece nome de pino. Corresponde à **definição
da fronteira criptográfica** — o desenho que num documento FIPS marca dentro
e fora, com a lista de todas as portas.

Aqui a lista é curta e verificável:

| Porta | Direção | O que atravessa |
|---|---|---|
| `uart_rxd_i` / `uart_txd_o` | ambas | comandos e respostas |
| `btn_a_i` / `btn_b_i` | entra | autorização física |
| `led_o`, `seg_o`, `seg_an_o` | sai | estado |

E só. Não existe porta de dados além da UART, e o que passa por ela é
definido pela tabela de comandos.

O toplevel também absorve, num ponto só, as duas inversões da placa — LEDs e
botões são ativos em nível baixo. Parece cosmético e não é: **um LED de
`TAMPERED` invertido é defeito de segurança**, porque o dispositivo mostraria
"tudo bem" exatamente quando não está.

### 24.5 `cmd.c` — o parser é a superfície de ataque

Máquina de estados de recepção, verificação de CRC, tabela de comandos com
verificação de estado, montagem da resposta.


<figure class="fig">
<svg viewBox="0 0 680 150" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="40"  y="40" width="100" height="36"/><text x="90"  y="56" text-anchor="middle" class="tb">LEN</text><text x="90"  y="70" text-anchor="middle" class="ts">2 bytes</text>
<rect class="cx"  x="140" y="40" width="90"  height="36"/><text x="185" y="56" text-anchor="middle" class="tb">opcode</text><text x="185" y="70" text-anchor="middle" class="ts">1 byte</text>
<rect class="cx"  x="230" y="40" width="270" height="36"/><text x="365" y="56" text-anchor="middle" class="tb">payload</text><text x="365" y="70" text-anchor="middle" class="ts">LEN − 1 bytes, até 3072</text>
<rect class="cxv" x="500" y="40" width="130" height="36"/><text x="565" y="56" text-anchor="middle" class="tb">CRC32</text><text x="565" y="70" text-anchor="middle" class="ts">4 bytes, zlib</text>
<path class="ln" d="M40,90 V100 H500 V90"/>
<text x="270" y="116" text-anchor="middle" class="ts">o CRC cobre LEN e corpo: LEN é o campo que induziria leitura fora do buffer</text>
<path class="ln" d="M140,32 V24 H500 V32"/>
<text x="320" y="18" text-anchor="middle" class="ts">corpo (LEN bytes); na resposta, o primeiro byte é o status</text>
<text x="340" y="142" text-anchor="middle" class="ts">entre dois bytes, no máximo 250 ms: um host que morre no meio não trava o parser</text>
</svg>
<figcaption>Figura 24.4 — O quadro do console binário. O CRC detecta corrupção; não autentica nada.</figcaption>
</figure>

**Num HSM real:** esta é a API, e é onde mora a maior parte dos ataques reais
(seção 15).

Por isso o checklist obrigatório para todo opcode novo:

- Em quais estados é permitido?
- Exige dual control?
- **O que pode vazar se for chamado em laço com entradas escolhidas?**
- Respeita a exportabilidade do slot?
- Entra no log **antes** da execução?

O parser é deliberadamente burro: máquina de estados explícita, todos os
limites verificados, sem alocação dinâmica, sem recursão. É o único código
que processa entrada arbitrária antes de qualquer verificação — não é lugar
para esperteza.

**O timeout entre bytes** é o que satisfaz o critério "frame malformado nunca
trava a máquina de estados". Sem ele, um host que morre no meio de um frame
deixa o parser esperando para sempre e o dispositivo mudo: negação de serviço
com um único byte enviado. É rearmado a cada byte, e não por frame, porque um
key block TR-31 leva cerca de 45 ms a 115200 baud e um timeout de frame
teria de ser afrouxado até deixar de proteger.

Disponibilidade é requisito num HSM: um módulo que para de responder derruba
a autorização de transações.

O log de auditoria registra cada comando antes da execução (seção 27).

**Um HSM real tem a mais:** tempo de resposta constante. Aqui um comando
recusado responde mais rápido que um aceito, e isso é informação.

### 24.6 O CRC32, e por que num HSM real seria um MAC

Detecta corrupção de enquadramento. Polinômio IEEE 802.3 refletido, idêntico
ao `zlib.crc32`.

**Distinção que vale internalizar:** CRC é detecção de erro, **não**
autenticação. Quem altera o payload recalcula o CRC trivialmente.

Num HSM de pagamentos, o canal com o host costuma ser autenticado de verdade
— MAC sobre a mensagem com chave de sessão, ou TLS mútuo.

Aqui o CRC basta, e o motivo é conceitualmente importante: **a fronteira de
confiança está no dispositivo, não no canal**. Assumimos que o host pode ser
hostil, e um host hostil não precisa falsificar CRC — ele manda comandos
válidos. A defesa não é autenticar o canal; é a máquina de estados, o dual
control físico e os atributos de chave.

É por isso que dual control é feito com botões na própria placa e não com um
comando "eu autorizo" vindo pelo cabo.

Duas decisões de formato que o plano deixava em aberto e precisavam ser
fixadas antes de o host existir:

- **o CRC cobre `LEN` + corpo** — incluir o `LEN` importa, porque é o campo
  que um atacante usaria para induzir leitura fora do buffer;
- **polinômio idêntico ao `zlib.crc32`** — mantém o host trivial e elimina
  uma fonte clássica de divergência.

O CRC existe em três implementações independentes: C no firmware, Verilog no
testbench, Python no host. Divergência apareceria como erro de CRC
intermitente — dos sintomas mais enganosos que existem, porque parece problema
de cabo.

### 24.7 `state.c` — a chave de switch

Cada linha da tabela de comandos carrega a **máscara de estados**
permitidos para aquele comando. O despachante consulta a máscara antes de
chamar o handler. Nenhum handler verifica estado por conta própria.

```c
#define ST_NORMAL  (ST_UNINIT | ST_AUTH | ST_OPER)
```

`TAMPERED` fica fora de propósito: dispositivo comprometido responde o
mínimo possível. A única exceção é o `SELFTEST`, e ela é deliberada — sem
ela o operador teria um LED vermelho e nenhuma informação sobre o quê
reprovou.


<figure class="fig">
<svg viewBox="0 0 680 190" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="70" width="90" height="40"/><text x="55" y="94" text-anchor="middle" class="ts">pedido</text>
<line class="ln" x1="100" y1="90" x2="148" y2="90" marker-end="url(#seta)"/>
<rect class="cx" x="150" y="60" width="130" height="60"/><text x="215" y="84" text-anchor="middle" class="tb">despachante</text><text x="215" y="100" text-anchor="middle" class="ts">consulta a máscara</text>
<rect class="cx" x="310" y="20" width="350" height="110"/>
<g class="ts">
<text x="320" y="38" class="tb">comando</text><text x="450" y="38" text-anchor="middle">UNINIT</text><text x="510" y="38" text-anchor="middle">AUTH</text><text x="570" y="38" text-anchor="middle">OPER</text><text x="630" y="38" text-anchor="middle">TAMP</text>
<text x="320" y="60">PING</text><text x="450" y="60" text-anchor="middle">●</text><text x="510" y="60" text-anchor="middle">●</text><text x="570" y="60" text-anchor="middle">●</text><text x="630" y="60" text-anchor="middle">·</text>
<text x="320" y="78">LMK_LOAD</text><text x="450" y="78" text-anchor="middle">●</text><text x="510" y="78" text-anchor="middle">·</text><text x="570" y="78" text-anchor="middle">·</text><text x="630" y="78" text-anchor="middle">·</text>
<text x="320" y="96">GEN_KEY</text><text x="450" y="96" text-anchor="middle">·</text><text x="510" y="96" text-anchor="middle">·</text><text x="570" y="96" text-anchor="middle">●</text><text x="630" y="96" text-anchor="middle">·</text>
<text x="320" y="114">SELFTEST</text><text x="450" y="114" text-anchor="middle">●</text><text x="510" y="114" text-anchor="middle">●</text><text x="570" y="114" text-anchor="middle">●</text><text x="630" y="114" text-anchor="middle" class="td">●</text>
</g>
<line class="ln" x1="280" y1="90" x2="308" y2="90" marker-end="url(#seta)"/>
<line class="ln" x1="215" y1="120" x2="215" y2="150" marker-end="url(#seta)"/>
<rect class="cxv" x="110" y="152" width="210" height="30"/><text x="215" y="172" text-anchor="middle" class="ts">permitido: chama o handler</text>
<rect class="cxd" x="380" y="152" width="230" height="30"/><text x="495" y="172" text-anchor="middle" class="ts">fora da máscara: recusa, e o log registra</text>
<line class="lnd" x1="280" y1="110" x2="400" y2="150" marker-end="url(#seta-d)"/>
</svg>
<figcaption>Figura 24.5 — O despachante e a máscara de estados. A tabela decide; nenhum handler confere estado por conta própria.</figcaption>
</figure>

A cerimônia de carga da chave mestra (seção 26) move o dispositivo pela
escada `UNINITIALIZED` → `AUTHORIZED` → `OPERATIONAL`. Cada passo muda o
conjunto de comandos aceitos sem nenhum código que ligue ou desligue
comandos: a tabela decide.

É a diferença entre política declarada e política executada. Um `if` dentro
de cada handler seria a mesma regra escrita uma vez por comando — e cada
cópia é um lugar onde alguém a esquece.

### 24.8 `wipe.c` — zeroização antes de haver chave

Ponteiro `volatile` mais barreira de memória, pelo motivo explicado na
seção 12.

Os buffers de frame são limpos após cada comando, porque são eles que
carregam componente de LMK e key block.

O `ZEROIZE` usa `wipe_padrao()`, que escreve um padrão antes dos zeros. A
razão não é a que o folclore de disco magnético sugere: para memória
estática a passada de zeros é a que conta. A primeira existe porque uma
zeroização **interrompida** tem de deixar padrão, não meia chave.

A prova de que apagou vem de duas verificações independentes, e a segunda é
a interessante — o KCV. Seção 26.

### 24.9 Os LEDs, e por que D1 é em hardware

D1 pisca a 1 Hz por lógica no fabric; D2 a D5 são GPIO controlado pelo
firmware.

A decisão interessante: **D1 é independente da CPU**. Se o firmware travar,
D1 continua piscando. Isso distingue duas falhas que de fora parecem iguais:

| Sintoma | Diagnóstico |
|---|---|
| D1 parado | clock morto — MMCM sem lock, alimentação, bitstream |
| D1 piscando, D2 apagado | clock bom, firmware pendurado |
| D1 piscando, D2 aceso | plataforma viva; o problema é protocolo ou host |

Num dispositivo sem console, essa é a diferença entre depurar e adivinhar. É
o mesmo princípio do watchdog independente: o indicador de vida não pode
depender da coisa cuja vida ele indica.

Bônus de verificação: D1 a 1 Hz cronometrado a olho **confirma a divisão do
MMCM**, porque o contador é `CLK_HZ/2` e só bate 1 Hz se o clock for mesmo
100 MHz.

### 24.10 `BOOT_MODE_SELECT = 2` — autenticidade de firmware

O SoC sobe a partir de uma imagem embutida na IMEM, não do bootloader do
NEORV32.

**Num HSM real:** isto é *secure boot*, um dos requisitos mais duros de
certificação.

O bootloader do NEORV32 aceita upload de firmware pela UART. Com ele ligado,
qualquer um com acesso ao serial substitui o firmware — e firmware
substituído contorna a máquina de estados, o dual control, a exportabilidade
e a fronteira inteira. **Todas as defesas discutidas neste documento passam a
valer zero**, porque quem escreve o código escreve as regras.

Num HSM comercial isso se resolve com boot ROM imutável que verifica
assinatura da imagem antes de executá-la, com a chave pública em memória de
programação única.

A versão deste projeto é mais simples e mais rude: **não há caminho de
atualização**. O firmware está no bitstream; trocá-lo exige regerar o
bitstream e gravar por JTAG, o que é acesso físico.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<text x="165" y="18" text-anchor="middle" class="tb">com o bootloader pela UART</text>
<rect class="cxa" x="20" y="34" width="110" height="34"/><text x="75" y="55" text-anchor="middle" class="ts">qualquer host</text>
<line class="lnd" x1="130" y1="51" x2="188" y2="51" marker-end="url(#seta-d)"/>
<text x="159" y="44" text-anchor="middle" class="ts">upload</text>
<rect class="cxd" x="190" y="34" width="130" height="34"/><text x="255" y="55" text-anchor="middle" class="ts">firmware novo</text>
<line class="lnd" x1="255" y1="68" x2="255" y2="96" marker-end="url(#seta-d)"/>
<rect class="cxd" x="120" y="98" width="200" height="44"/><text x="220" y="116" text-anchor="middle" class="ts td">quem escreve o código</text><text x="220" y="130" text-anchor="middle" class="ts td">escreve as regras</text>
<line class="lnt" x1="340" y1="10" x2="340" y2="190"/>
<text x="510" y="18" text-anchor="middle" class="tb">BOOT_MODE_SELECT = 2 (este projeto)</text>
<rect class="cx" x="370" y="34" width="120" height="34"/><text x="430" y="55" text-anchor="middle" class="ts">bitstream</text>
<line class="ln" x1="490" y1="51" x2="528" y2="51" marker-end="url(#seta)"/>
<rect class="cxv" x="530" y="34" width="130" height="34"/><text x="595" y="49" text-anchor="middle" class="ts">IMEM em ROM</text><text x="595" y="62" text-anchor="middle" class="ts">sem circuito de escrita</text>
<rect class="cxa" x="370" y="98" width="120" height="34"/><text x="430" y="119" text-anchor="middle" class="ts">host pela UART</text>
<line class="lnt" x1="490" y1="115" x2="528" y2="115"/>
<text x="555" y="120" class="ts">só comandos; nenhum troca o código</text>
<text x="510" y="170" text-anchor="middle" class="ts">trocar o firmware: novo bitstream, gravado com acesso físico</text>
</svg>
<figcaption>Figura 24.6 — Os dois caminhos de boot. Sem caminho de atualização pela serial, o firmware é parte do hardware.</figcaption>
</figure>

**Efeito colateral que veio de graça:** com esse modo, o NEORV32 liga
`MEM_INIT` e a IMEM vira memória **somente de leitura**. A memória de código
não é gravável em tempo de execução — não há injeção de código nem código
automodificável, independentemente de qualquer bug no parser.

Isso é integridade de código em execução. Num sistema com MMU seria o
equivalente a marcar as páginas de texto como não-graváveis; aqui é mais
forte, porque não é uma permissão que alguém pode mudar — é a ausência de
circuito de escrita.

### 24.11 `tb_soc_silent` — não falar sem ser perguntado

Verifica que o dispositivo não transmite nada pela UART até receber um
comando — **e** que está vivo.

**Num HSM real:** higiene de canal lateral e de vazamento de identidade. Um
banner de boot entrega versão e identidade a quem só escuta o barramento, o
que é reconhecimento gratuito. E um `printf` de depuração esquecido no
firmware é um canal lateral permanente, historicamente uma das formas mais
comuns de vazamento em dispositivos embarcados.

**O detalhe que torna o teste honesto:** silêncio sozinho não prova nada,
porque firmware travado também fica quieto. Por isso o teste exige silêncio
**e** vida — `main()` precisa ter chegado ao laço e aceso o LED de atividade.
Um teste que passa quando o dispositivo está morto é pior que teste nenhum.

### 24.12 `hsmtool.py` — o cliente da API

Codec do protocolo binário, transporte serial, CLI. É o **console**:
cerimônia, estado, diagnóstico e log. O cliente das aplicações usa outra
porta lógica, o command set ASCII da seção 28.

O comentário no topo do arquivo é a regra que o mantém honesto:

```python
# FRONTEIRA: tudo aqui esta FORA. Este programa nunca ve chave em claro --
# so key blocks wrapped, KCVs, criptogramas, handles e log. Se algum comando
# futuro fizer material de chave aparecer neste arquivo, o comando esta
# errado, nao o script.
```

Aqui se entende por que a API de um HSM é do jeito que é: **é você que
precisa impedi-la de vazar.** Quando se escreve os dois lados, a tentação de
adicionar um "só para depurar, me devolva a chave" fica concreta — e recusá-la
ensina mais do que ler que não se deve.

### 24.13 O teste de 10.000 pings

**Num HSM real:** disponibilidade e determinismo são requisitos operacionais.
Um módulo autorizando transações tem acordo de nível de serviço; um que perde
uma mensagem em dez mil produz falhas intermitentes que ninguém reproduz.

E há um aspecto de segurança: **erro intermitente esconde ataque**. Se o
canal normalmente perde alguns frames, ninguém investiga o dia em que alguém
está injetando tráfego. Uma taxa de erro de exatamente zero é o que torna
qualquer erro digno de investigação.
