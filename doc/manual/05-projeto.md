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

### 24.14 Por onde passa cada pedido — o equipamento comercial e este

Um HSM não fica no caminho do cartão. Ele fica atrás de uma aplicação, e só
ela fala com ele. Esta seção mostra, para cada família de comando deste
equipamento, quem pede a operação num equipamento comercial, por onde a
mensagem passa, e como o mesmo pedido chega a esta placa.

Nas figuras, a faixa de cima é o equipamento comercial, e a de baixo é este.
O retângulo tracejado em vermelho é a fronteira criptográfica.

#### A ligação

<figure class="fig">
<svg viewBox="0 0 680 312" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<rect class="cxa" x="10" y="40" width="130" height="54"/>
<text x="75" y="58.5" text-anchor="middle" class="tb">aplicações</text>
<text x="75" y="71.5" text-anchor="middle" class="ts">autorizador,</text>
<text x="75" y="84.5" text-anchor="middle" class="ts">gestão de chaves</text>
<rect class="cxc" x="180" y="40" width="120" height="54"/>
<text x="240" y="58.5" text-anchor="middle" class="tb">rede interna</text>
<text x="240" y="71.5" text-anchor="middle" class="ts">TCP, várias</text>
<text x="240" y="84.5" text-anchor="middle" class="ts">conexões</text>
<rect class="fr" x="340" y="28" width="190" height="118"/>
<text x="435" y="46" text-anchor="middle" class="tb">HSM</text>
<rect class="cx" x="355" y="54" width="160" height="38"/>
<text x="435" y="71" text-anchor="middle" class="tb">porta host</text>
<text x="435" y="84" text-anchor="middle" class="ts">Ethernet, LEN(2) + ASCII</text>
<rect class="cx" x="355" y="100" width="160" height="38"/>
<text x="435" y="117" text-anchor="middle" class="tb">porta de console</text>
<text x="435" y="130" text-anchor="middle" class="ts">separada</text>
<rect class="cxa" x="560" y="100" width="110" height="38"/>
<text x="615" y="117" text-anchor="middle" class="tb">console</text>
<text x="615" y="130" text-anchor="middle" class="ts">cartão + senha</text>
<line class="ln" x1="140" y1="67" x2="178" y2="67" marker-end="url(#seta)"/>
<line class="ln" x1="300" y1="67" x2="353" y2="72" marker-end="url(#seta)"/>
<line class="ln" x1="560" y1="119" x2="517" y2="119" marker-end="url(#seta)"/>
<text x="548" y="46" text-anchor="start" class="ts">várias unidades</text>
<text x="548" y="60" text-anchor="start" class="ts">em grupo, para</text>
<text x="548" y="74" text-anchor="start" class="ts">volume e reserva</text>
<line class="grade" x1="10" y1="160" x2="670" y2="160"/>
<text x="10" y="180" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="cxa" x="10" y="200" width="130" height="54"/>
<text x="75" y="218.5" text-anchor="middle" class="tb">hsmhost.py</text>
<text x="75" y="231.5" text-anchor="middle" class="ts">faz o papel</text>
<text x="75" y="244.5" text-anchor="middle" class="ts">do autorizador</text>
<rect class="cxc" x="170" y="200" width="110" height="54"/>
<text x="225" y="218.5" text-anchor="middle" class="tb">hsm_ponte.py</text>
<text x="225" y="231.5" text-anchor="middle" class="ts">TCP 1500 → serial</text>
<text x="225" y="244.5" text-anchor="middle" class="ts">só repassa</text>
<rect class="cxa" x="170" y="262" width="110" height="40"/>
<text x="225" y="280" text-anchor="middle" class="tb">hsmtool.py</text>
<text x="225" y="293" text-anchor="middle" class="ts">console</text>
<rect class="fr" x="360" y="192" width="175" height="112"/>
<text x="447.5" y="210" text-anchor="middle" class="tb">placa</text>
<rect class="cx" x="372" y="218" width="151" height="42"/>
<text x="447.5" y="237" text-anchor="middle" class="tb">UART única</text>
<text x="447.5" y="250" text-anchor="middle" class="ts">1º byte: ASCII ou binário</text>
<rect class="cxd" x="372" y="266" width="151" height="30"/>
<text x="447.5" y="285.5" text-anchor="middle" class="tb">botões SW2 + SW5</text>
<line class="ln" x1="140" y1="227" x2="168" y2="227" marker-end="url(#seta)"/>
<line class="ln" x1="280" y1="233" x2="370" y2="236" marker-end="url(#seta)"/>
<text x="322" y="214" text-anchor="middle" class="ts">USB-serial</text>
<text x="322" y="226" text-anchor="middle" class="ts">115 200 baud</text>
<line class="ln" x1="280" y1="282" x2="370" y2="248" marker-end="url(#seta)"/>
<text x="548" y="220" text-anchor="start" class="ts">uma conexão</text>
<text x="548" y="234" text-anchor="start" class="ts">e um pedido</text>
<text x="548" y="248" text-anchor="start" class="ts">por vez</text>
</svg>
<figcaption>Figura 24.7 — A ligação. A aplicação fala TCP nos dois casos; o que muda é o que fica atrás da porta.</figcaption>
</figure>

**No equipamento comercial**, as aplicações conectam por TCP, na rede
interna do centro de dados. A porta host recebe cada mensagem com 2 bytes de
comprimento e o comando em ASCII. Várias aplicações conectam ao mesmo tempo,
e várias unidades trabalham em grupo, para dar volume e para uma substituir a
outra. A porta de console é separada: por ela os custodiantes fazem a
cerimônia, com cartão e senha.

**Neste equipamento**, a placa tem uma UART só, ligada ao PC pelo conversor
USB-serial. O enquadramento na UART é o mesmo da rede: 2 bytes de comprimento
e o comando. No PC, `host/hsm_ponte.py` abre a porta TCP 1500 e repassa os
bytes, sem os entender. Quem interpreta o comando é o firmware, dentro da
fronteira (seção 28). Para a aplicação, a diferença é só o que fica atrás da
porta TCP.

| | Equipamento comercial | Este equipamento |
|---|---|---|
| Porta host | Ethernet, várias conexões | ponte TCP → UART; uma conexão e um pedido por vez |
| Console | porta própria | a mesma UART; o primeiro byte separa o ASCII do binário |
| Quem interpreta o comando | o HSM | o firmware; a ponte só repassa |
| Vazão | milhares de operações por segundo | 115 200 baud, cerca de 11 KB/s: um key block de 144 caracteres leva cerca de 13 ms só na linha |

A ponte recusa mensagem que não comece por um caractere entre `'0'` e `'~'`.
Assim, nenhum comando de console chega pela rede.

A placa filha tem uma porta Ethernet, sem uso. O projeto escolheu a UART
primeiro: é um canal simples, que um analisador lógico observa inteiro. Com
ele se prova que nenhuma chave em claro sai pela fronteira.

#### Quem fala com o HSM

<figure class="fig">
<svg viewBox="0 0 680 196" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="50" width="120" height="56"/>
<text x="70" y="69.5" text-anchor="middle" class="tb">terminal</text>
<text x="70" y="82.5" text-anchor="middle" class="ts">ou outra</text>
<text x="70" y="95.5" text-anchor="middle" class="ts">instituição</text>
<rect class="cxa" x="270" y="50" width="140" height="56"/>
<text x="340" y="76" text-anchor="middle" class="tb">autorizador</text>
<text x="340" y="89" text-anchor="middle" class="ts">separa os campos</text>
<rect class="fr" x="560" y="40" width="110" height="76"/>
<text x="615" y="58" text-anchor="middle" class="tb">HSM</text>
<text x="615" y="73" text-anchor="middle" class="ts">faz só a conta</text>
<line class="ln" x1="130" y1="66" x2="268" y2="66" marker-end="url(#seta)"/>
<text x="199" y="60" text-anchor="middle" class="ts">pedido (ISO 8583)</text>
<line class="ln" x1="268" y1="92" x2="130" y2="92" marker-end="url(#seta)"/>
<text x="199" y="106" text-anchor="middle" class="ts">resposta (ISO 8583)</text>
<line class="ln" x1="410" y1="66" x2="558" y2="66" marker-end="url(#seta)"/>
<text x="484" y="60" text-anchor="middle" class="ts">comando do HSM</text>
<line class="ln" x1="558" y1="92" x2="410" y2="92" marker-end="url(#seta)"/>
<text x="484" y="106" text-anchor="middle" class="ts">resposta do HSM</text>
<rect class="cxc" x="10" y="130" width="320" height="54"/>
<text x="170" y="147.5" text-anchor="middle" class="ts tb">na mensagem ISO 8583:</text>
<text x="170" y="160.5" text-anchor="middle" class="ts">PAN, valor, data, terminal, PIN block, MAC…</text>
<text x="170" y="173.5" text-anchor="middle" class="ts">dezenas de campos</text>
<rect class="cxc" x="350" y="130" width="320" height="54"/>
<text x="510" y="147.5" text-anchor="middle" class="ts tb">no comando do HSM:</text>
<text x="510" y="160.5" text-anchor="middle" class="ts">key blocks, PAN, PIN block: só o que a</text>
<text x="510" y="173.5" text-anchor="middle" class="ts">conta precisa. O HSM não lê ISO 8583</text>
</svg>
<figcaption>Figura 24.8 — Quem fala com o HSM. A mensagem da transação termina na aplicação; ao HSM chega só o comando, com o que a conta precisa.</figcaption>
</figure>

O terminal e as outras instituições falam com a aplicação, em mensagens
**ISO 8583**: pedido de autorização, resposta, estorno. Uma mensagem dessas
tem dezenas de campos. **O HSM não lê ISO 8583.** A aplicação tira da
mensagem os campos de que a conta precisa e monta o comando do HSM. A
resposta do HSM volta para a aplicação, que monta a resposta ISO 8583.

Disso vem um limite de segurança: o HSM não sabe qual transação está
atendendo. Ele confere o que está no comando: o uso e o modo da chave no key
block, a forma dos campos, o estado do equipamento. O resto do controle é da
aplicação e do log. É por isso que as seções 15 e 34 tratam cada comando
como um oráculo: quem tem acesso à porta host escolhe as entradas.

Neste equipamento não há mensagem ISO 8583. Os programas de teste montam os
comandos do HSM diretamente.

#### Cerimônia e administração: o console

<figure class="fig">
<svg viewBox="0 0 680 310" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<rect class="lnt" x="10" y="26" width="525" height="124"/>
<text x="20" y="42" text-anchor="start" class="ts">sala segura</text>
<rect class="cxa" x="25" y="50" width="110" height="42"/>
<text x="80" y="69" text-anchor="middle" class="tb">custodiante A</text>
<text x="80" y="82" text-anchor="middle" class="ts">cartão + senha</text>
<rect class="cxa" x="25" y="100" width="110" height="42"/>
<text x="80" y="119" text-anchor="middle" class="tb">custodiante B</text>
<text x="80" y="132" text-anchor="middle" class="ts">cartão + senha</text>
<rect class="cxa" x="185" y="72" width="120" height="46"/>
<text x="245" y="92" text-anchor="middle" class="tb">terminal de</text>
<text x="245" y="107" text-anchor="middle" class="tb">console</text>
<rect class="fr" x="355" y="40" width="165" height="100"/>
<text x="437.5" y="58" text-anchor="middle" class="tb">HSM</text>
<text x="437.5" y="73" text-anchor="middle" class="ts">porta de console</text>
<text x="437.5" y="87" text-anchor="middle" class="ts">componente → KCV</text>
<text x="437.5" y="101" text-anchor="middle" class="ts">estado, log, zeroize</text>
<line class="ln" x1="135" y1="71" x2="183" y2="88" marker-end="url(#seta)"/>
<line class="ln" x1="135" y1="121" x2="183" y2="104" marker-end="url(#seta)"/>
<line class="ln" x1="305" y1="95" x2="353" y2="95" marker-end="url(#seta)"/>
<text x="548" y="62" text-anchor="start" class="ts">cada componente</text>
<text x="548" y="76" text-anchor="start" class="ts">entra sozinho, e o</text>
<text x="548" y="90" text-anchor="start" class="ts">HSM devolve só o</text>
<text x="548" y="104" text-anchor="start" class="ts">KCV dele</text>
<line class="grade" x1="10" y1="162" x2="670" y2="162"/>
<text x="10" y="182" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="cxa" x="25" y="202" width="110" height="42"/>
<text x="80" y="221" text-anchor="middle" class="tb">custodiante A</text>
<text x="80" y="234" text-anchor="middle" class="ts">componente</text>
<rect class="cxa" x="25" y="252" width="110" height="42"/>
<text x="80" y="271" text-anchor="middle" class="tb">custodiante B</text>
<text x="80" y="284" text-anchor="middle" class="ts">componente</text>
<rect class="cxa" x="185" y="224" width="120" height="46"/>
<text x="245" y="245" text-anchor="middle" class="tb">hsmtool.py</text>
<text x="245" y="258" text-anchor="middle" class="ts">no PC do host</text>
<rect class="fr" x="355" y="194" width="165" height="108"/>
<text x="437.5" y="212" text-anchor="middle" class="tb">placa</text>
<rect class="cx" x="370" y="220" width="135" height="28"/>
<text x="437.5" y="238.5" text-anchor="middle" class="tb">UART</text>
<rect class="cxd" x="370" y="256" width="135" height="38"/>
<text x="437.5" y="273" text-anchor="middle" class="tb">SW2 + SW5</text>
<text x="437.5" y="286" text-anchor="middle" class="ts">os dois botões</text>
<line class="ln" x1="135" y1="223" x2="183" y2="240" marker-end="url(#seta)"/>
<line class="ln" x1="135" y1="273" x2="183" y2="256" marker-end="url(#seta)"/>
<line class="ln" x1="305" y1="247" x2="368" y2="236" marker-end="url(#seta)"/>
<text x="535" y="214" text-anchor="start" class="ts">os componentes passam</text>
<text x="535" y="228" text-anchor="start" class="ts">pelo PC do host: é o</text>
<text x="535" y="242" text-anchor="start" class="ts">desvio registrado</text>
<text x="535" y="270" text-anchor="start" class="ts">o display mostra</text>
<text x="535" y="284" text-anchor="start" class="ts">Uni, Aut, OPE</text>
</svg>
<figcaption>Figura 24.9 — A cerimônia, pelo console. Os botões fazem o papel dos cartões: duas pessoas, ao mesmo tempo.</figcaption>
</figure>

**No equipamento comercial**, a cerimônia acontece numa sala segura. Cada
custodiante se identifica no console, com cartão e senha, e digita o seu
componente. O HSM devolve o KCV de cada componente, e nunca a chave montada.
Pelo console também se muda o estado, se autorizam funções sensíveis e se lê
o log.

**Neste equipamento**, o console é o `hsmtool.py`, no mesmo PC e na mesma
UART do host. Os dois botões (SW2 e SW5) fazem o papel dos cartões: o
comando com dual control só executa com os dois apertados. O display mostra
o estado. O desvio está no caminho dos componentes: eles passam pelo PC do
host (seção 26).

| Função | Comando aqui | `hsmtool.py` |
|---|---|---|
| Carregar um componente da LMK | `0x20` | `lmk-load` |
| Mudar o estado | `0x26` | `activate` |
| Formar uma chave de trabalho por componentes (uma KEK, por exemplo) | `0x2C` | `comp-load` |
| Autorizar uma tabela de decimalização | `0x80` | `tabela-autoriza` |
| Ler o log | `0x2D` | `audit` |
| Apagar todas as chaves | `0x2F` | `zeroize` |

#### Gerar e guardar uma chave: `K0`, `K2`

<figure class="fig">
<svg viewBox="0 0 680 304" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<rect class="cxa" x="10" y="40" width="130" height="54"/>
<text x="75" y="65" text-anchor="middle" class="tb">gestão</text>
<text x="75" y="78" text-anchor="middle" class="ts">de chaves</text>
<rect class="fr" x="240" y="30" width="150" height="74"/>
<text x="315" y="48" text-anchor="middle" class="tb">HSM</text>
<text x="315" y="63" text-anchor="middle" class="ts">K0: gera, sob a LMK</text>
<text x="315" y="77" text-anchor="middle" class="ts">e não guarda</text>
<rect class="cxc" x="450" y="40" width="110" height="54"/>
<text x="505" y="64" text-anchor="middle" class="tb">banco de</text>
<text x="505" y="79" text-anchor="middle" class="tb">dados</text>
<rect class="cxa" x="578" y="40" width="92" height="54"/>
<text x="624" y="71.5" text-anchor="middle" class="tb">autorizador</text>
<line class="ln" x1="140" y1="56" x2="238" y2="56" marker-end="url(#seta)"/>
<text x="189" y="50" text-anchor="middle" class="ts">uso, modo</text>
<line class="ln" x1="238" y1="80" x2="140" y2="80" marker-end="url(#seta)"/>
<text x="189" y="94" text-anchor="middle" class="ts">key block + KCV</text>
<path class="ln" d="M75,94 L75,124 L505,124 L505,96" marker-end="url(#seta)"/>
<text x="290" y="138" text-anchor="middle" class="ts">guarda o key block</text>
<line class="ln" x1="560" y1="67" x2="576" y2="67" marker-end="url(#seta)"/>
<text x="630" y="110" text-anchor="middle" class="ts">lê o bloco e o</text>
<text x="630" y="122" text-anchor="middle" class="ts">manda com cada</text>
<text x="630" y="134" text-anchor="middle" class="ts">comando</text>
<line class="grade" x1="10" y1="152" x2="670" y2="152"/>
<text x="10" y="172" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="cxa" x="10" y="190" width="130" height="54"/>
<text x="75" y="215" text-anchor="middle" class="tb">hsmhost.py</text>
<text x="75" y="228" text-anchor="middle" class="ts">gen, check</text>
<rect class="fr" x="240" y="180" width="150" height="74"/>
<text x="315" y="198" text-anchor="middle" class="tb">placa</text>
<text x="315" y="213" text-anchor="middle" class="ts">K0 gera, K2 confere</text>
<text x="315" y="227" text-anchor="middle" class="ts">slot efêmero apagado</text>
<rect class="cxc" x="450" y="190" width="110" height="54"/>
<text x="505" y="215" text-anchor="middle" class="tb">arquivo</text>
<text x="505" y="228" text-anchor="middle" class="ts">ou variável Python</text>
<line class="ln" x1="140" y1="206" x2="238" y2="206" marker-end="url(#seta)"/>
<text x="189" y="200" text-anchor="middle" class="ts">pela ponte</text>
<line class="ln" x1="238" y1="230" x2="140" y2="230" marker-end="url(#seta)"/>
<text x="189" y="244" text-anchor="middle" class="ts">key block + KCV</text>
<path class="ln" d="M75,244 L75,274 L505,274 L505,246" marker-end="url(#seta)"/>
<text x="290" y="288" text-anchor="middle" class="ts">o teste guarda o bloco e o manda de volta a cada comando</text>
</svg>
<figcaption>Figura 24.10 — Gerar e guardar uma chave. O HSM gera e devolve em key block; quem guarda é o banco de dados, e não o HSM.</figcaption>
</figure>

**No equipamento comercial**, um sistema de gestão de chaves pede uma chave
nova, com uso, algoritmo e modo. O HSM a gera dentro da fronteira e a
devolve em key block, sob a LMK, com o KCV. **O HSM não guarda essa chave.**
O sistema grava o key block no banco de dados, e o autorizador o lê e o
manda com cada comando que usa a chave. Para conferir um bloco guardado sem
usar a chave, há um comando que devolve o cabeçalho e o KCV.

**Neste equipamento** é igual: `K0` gera, `K2` confere. O teste guarda o key
block numa variável, ou num arquivo. Dentro da placa, a chave do comando
fica no slot efêmero, que o despachante apaga no fim de todo comando
(seção 28).

#### Trocar uma chave com outra instituição: `K4`, `K6`

<figure class="fig">
<svg viewBox="0 0 680 334" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<text x="130" y="40" text-anchor="middle" class="tb">instituição A</text>
<text x="550" y="40" text-anchor="middle" class="tb">instituição B</text>
<rect class="fr" x="60" y="50" width="140" height="60"/>
<text x="130" y="68" text-anchor="middle" class="tb">HSM A</text>
<text x="130" y="83" text-anchor="middle" class="ts">K4: sai sob a KEK</text>
<rect class="fr" x="480" y="50" width="140" height="60"/>
<text x="550" y="68" text-anchor="middle" class="tb">HSM B</text>
<text x="550" y="83" text-anchor="middle" class="ts">K6: entra sob a KEK</text>
<rect class="cxa" x="60" y="136" width="140" height="34"/>
<text x="130" y="157.5" text-anchor="middle" class="tb">custodiantes de A</text>
<rect class="cxa" x="480" y="136" width="140" height="34"/>
<text x="550" y="157.5" text-anchor="middle" class="tb">custodiantes de B</text>
<rect class="cxc" x="270" y="136" width="140" height="34"/>
<text x="340" y="157.5" text-anchor="middle" class="tb">componentes</text>
<line class="lnt" x1="270" y1="153" x2="200" y2="153"/>
<line class="lnt" x1="410" y1="153" x2="480" y2="153"/>
<line class="ln" x1="130" y1="136" x2="130" y2="112" marker-end="url(#seta)"/>
<line class="ln" x1="550" y1="136" x2="550" y2="112" marker-end="url(#seta)"/>
<text x="340" y="190" text-anchor="middle" class="ts">1. a mesma KEK nasce por componentes nas duas pontas, por canais separados</text>
<line class="ln" x1="200" y1="78" x2="478" y2="78" marker-end="url(#seta)"/>
<text x="339" y="70" text-anchor="middle" class="ts">2. key block sob a KEK</text>
<text x="339" y="96" text-anchor="middle" class="ts">em arquivo, ou numa mensagem de gestão de rede</text>
<line class="grade" x1="10" y1="204" x2="670" y2="204"/>
<text x="10" y="224" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="fr" x="60" y="240" width="140" height="60"/>
<text x="130" y="258" text-anchor="middle" class="tb">placa</text>
<text x="130" y="273" text-anchor="middle" class="ts">K4 exporta, K6 importa</text>
<rect class="cxa" x="480" y="240" width="140" height="60"/>
<text x="550" y="268" text-anchor="middle" class="tb">host/tr31.py</text>
<text x="550" y="281" text-anchor="middle" class="ts">faz a instituição B</text>
<line class="ln" x1="200" y1="262" x2="478" y2="262" marker-end="url(#seta)"/>
<text x="339" y="254" text-anchor="middle" class="ts">key block versão D (KEK AES) ou B (3DES)</text>
<line class="ln" x1="478" y1="284" x2="200" y2="284" marker-end="url(#seta)"/>
<text x="339" y="298" text-anchor="middle" class="ts">e o caminho de volta</text>
<text x="130" y="320" text-anchor="middle" class="ts">a KEK: comp-load, no console</text>
</svg>
<figcaption>Figura 24.11 — Trocar uma chave com outra instituição. Primeiro a KEK, por componentes nas duas pontas; depois a chave, em key block sob ela.</figcaption>
</figure>

**No equipamento comercial**, duas instituições precisam da mesma chave: por
exemplo, o adquirente e a bandeira, para o PIN. Primeiro, as duas formam a
mesma **KEK**, por componentes. Os custodiantes de cada lado recebem os
componentes por canais separados, e cada um os carrega no seu HSM. Depois,
uma instituição gera a chave e a exporta sob a KEK. O key block vai em
arquivo, ou numa mensagem de gestão de rede. A outra instituição importa o
bloco: o HSM dela confere o MAC e devolve a chave em key block sob a sua
própria LMK.

**Neste equipamento**, a KEK nasce por componentes no console
(`comp-load --uso K0`). `K4` exporta e `K6` importa. Sob KEK AES, o bloco é
da versão D; sob KEK 3DES, da versão B (seção 39.9). A outra instituição é o
Python: `host/tr31.py` abre o bloco que a placa exportou e monta o bloco que
ela importa.

#### O caminho de um PIN: `P0`, `P2`, `V2`, `V6`

<figure class="fig">
<svg viewBox="0 0 680 348" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<rect class="cxa" x="10" y="34" width="100" height="46"/>
<text x="60" y="55" text-anchor="middle" class="tb">terminal</text>
<text x="60" y="68" text-anchor="middle" class="ts">cifra o PIN</text>
<rect class="cxa" x="175" y="34" width="120" height="46"/>
<text x="235" y="55" text-anchor="middle" class="tb">adquirente</text>
<text x="235" y="68" text-anchor="middle" class="ts">autorizador</text>
<rect class="cxa" x="360" y="34" width="120" height="46"/>
<text x="420" y="55" text-anchor="middle" class="tb">bandeira</text>
<text x="420" y="68" text-anchor="middle" class="ts">autorizador</text>
<rect class="cxa" x="545" y="34" width="125" height="46"/>
<text x="607.5" y="55" text-anchor="middle" class="tb">emissor</text>
<text x="607.5" y="68" text-anchor="middle" class="ts">autorizador</text>
<line class="ln" x1="110" y1="57" x2="173" y2="57" marker-end="url(#seta)"/>
<line class="ln" x1="295" y1="57" x2="358" y2="57" marker-end="url(#seta)"/>
<line class="ln" x1="480" y1="57" x2="543" y2="57" marker-end="url(#seta)"/>
<text x="142" y="96" text-anchor="middle" class="ts">chave do</text>
<text x="142" y="108" text-anchor="middle" class="ts">terminal</text>
<text x="327" y="96" text-anchor="middle" class="ts">chave de</text>
<text x="327" y="108" text-anchor="middle" class="ts">zona 1</text>
<text x="512" y="96" text-anchor="middle" class="ts">chave de</text>
<text x="512" y="108" text-anchor="middle" class="ts">zona 2</text>
<rect class="fr" x="185" y="124" width="100" height="52"/>
<text x="235" y="142" text-anchor="middle" class="tb">HSM</text>
<text x="235" y="157" text-anchor="middle" class="ts tm">P2 ou P0</text>
<line class="ln" x1="220" y1="80" x2="220" y2="122" marker-end="url(#seta)"/>
<line class="ln" x1="250" y1="122" x2="250" y2="80" marker-end="url(#seta)"/>
<rect class="fr" x="370" y="124" width="100" height="52"/>
<text x="420" y="142" text-anchor="middle" class="tb">HSM</text>
<text x="420" y="157" text-anchor="middle" class="ts tm">P0</text>
<line class="ln" x1="405" y1="80" x2="405" y2="122" marker-end="url(#seta)"/>
<line class="ln" x1="435" y1="122" x2="435" y2="80" marker-end="url(#seta)"/>
<rect class="fr" x="557" y="124" width="100" height="52"/>
<text x="607" y="142" text-anchor="middle" class="tb">HSM</text>
<text x="607" y="157" text-anchor="middle" class="ts tm">V2 ou V6</text>
<line class="ln" x1="592" y1="80" x2="592" y2="122" marker-end="url(#seta)"/>
<line class="ln" x1="622" y1="122" x2="622" y2="80" marker-end="url(#seta)"/>
<text x="340" y="196" text-anchor="middle" class="ts">ISO 8583 entre as instituições; a cada trecho, o PIN block muda de chave</text>
<line class="grade" x1="10" y1="210" x2="670" y2="210"/>
<text x="10" y="230" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="cxa" x="10" y="248" width="172" height="72"/>
<text x="96" y="269" text-anchor="middle" class="tb">hsmhost.py</text>
<text x="96" y="282" text-anchor="middle" class="ts">monta o PIN block como o</text>
<text x="96" y="295" text-anchor="middle" class="ts">terminal e chama os comandos</text>
<text x="96" y="308" text-anchor="middle" class="ts">como cada autorizador</text>
<rect class="cxc" x="216" y="264" width="90" height="40"/>
<text x="261" y="288.5" text-anchor="middle" class="tb">ponte</text>
<rect class="fr" x="345" y="242" width="325" height="84"/>
<text x="507.5" y="260" text-anchor="middle" class="tb">placa: uma só, no papel dos três HSMs</text>
<rect class="cx" x="358" y="270" width="92" height="44"/>
<text x="404" y="289" text-anchor="middle" class="tm">P2 / P0</text>
<text x="404" y="302" text-anchor="middle" class="ts">adquirente</text>
<rect class="cx" x="462" y="270" width="92" height="44"/>
<text x="508" y="289" text-anchor="middle" class="tm">P0</text>
<text x="508" y="302" text-anchor="middle" class="ts">bandeira</text>
<rect class="cx" x="566" y="270" width="92" height="44"/>
<text x="612" y="289" text-anchor="middle" class="tm">V2 / V6</text>
<text x="612" y="302" text-anchor="middle" class="ts">emissor</text>
<line class="ln" x1="182" y1="284" x2="214" y2="284" marker-end="url(#seta)"/>
<line class="ln" x1="306" y1="284" x2="343" y2="284" marker-end="url(#seta)"/>
<text x="508" y="342" text-anchor="middle" class="ts">cada zona é um key block diferente, sob a mesma LMK</text>
</svg>
<figcaption>Figura 24.12 — O caminho de um PIN. Em cima, uma transação real, com um HSM em cada instituição; embaixo, a placa fazendo os três.</figcaption>
</figure>

O cliente digita o PIN no terminal. Quem pode dizer se o PIN está certo é o
emissor do cartão. No caminho, o PIN passa por três ou mais instituições, e
cada trecho tem a sua chave.

1. **Terminal.** Cifra o PIN block sob a chave dele (DUKPT, seção 37) e o
   manda na mensagem ISO 8583.
2. **Adquirente.** O autorizador tira o PIN block e o KSN da mensagem e pede
   ao HSM: traduza da chave do terminal para a chave de zona com a bandeira
   (`P2`). Com chave fixa no terminal, o comando é o `P0`.
3. **Bandeira.** Traduz da chave de zona do adquirente para a do emissor
   (`P0`).
4. **Emissor.** Pede ao HSM: este PIN confere com o offset, ou com o PVV,
   deste cartão? (`V2` ou `V6`, seção 35). Sai um bit.

O PIN em claro só existe dentro de cada HSM, durante a tradução ou a
verificação. Nunca na aplicação, e nunca na rede.

**Neste equipamento**, a placa faz os três HSMs. Cada zona é um key block
diferente, todos sob a mesma LMK. O `hsmhost.py` monta o PIN block como o
terminal e chama os comandos na ordem de cada autorizador: `pin-confere`
cobre a tradução, `pinv-confere` a verificação, e `dukpt-confere` o trecho do
terminal DUKPT.

#### O terminal DUKPT: `I0`, `P2`, `M4`, `M6`, `C4`, `C6`

<figure class="fig">
<svg viewBox="0 0 680 338" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<text x="125" y="40" text-anchor="middle" class="ts tb">na fabricação</text>
<rect class="fr" x="15" y="50" width="105" height="52"/>
<text x="67.5" y="68" text-anchor="middle" class="tb">HSM</text>
<text x="67.5" y="83" text-anchor="middle" class="ts tm">I0</text>
<rect class="cxa" x="140" y="50" width="100" height="52"/>
<text x="190" y="74" text-anchor="middle" class="tb">injetor</text>
<text x="190" y="87" text-anchor="middle" class="ts">de chaves</text>
<rect class="cxa" x="140" y="124" width="100" height="38"/>
<text x="190" y="147.5" text-anchor="middle" class="tb">terminal</text>
<line class="ln" x1="120" y1="76" x2="138" y2="76" marker-end="url(#seta)"/>
<text x="67" y="118" text-anchor="middle" class="ts">IPEK ou IK,</text>
<text x="67" y="130" text-anchor="middle" class="ts">sob a KEK</text>
<line class="ln" x1="190" y1="102" x2="190" y2="122" marker-end="url(#seta)"/>
<line class="lnt" x1="255" y1="30" x2="255" y2="170"/>
<text x="470" y="40" text-anchor="middle" class="ts tb">em cada transação</text>
<rect class="cxa" x="270" y="56" width="105" height="66"/>
<text x="322.5" y="80.5" text-anchor="middle" class="tb">terminal</text>
<text x="322.5" y="93.5" text-anchor="middle" class="ts">KSN, PIN block,</text>
<text x="322.5" y="106.5" text-anchor="middle" class="ts">dados e MAC</text>
<rect class="cxa" x="420" y="56" width="110" height="66"/>
<text x="475" y="87" text-anchor="middle" class="tb">adquirente</text>
<text x="475" y="100" text-anchor="middle" class="ts">autorizador</text>
<rect class="fr" x="565" y="48" width="105" height="90"/>
<text x="617.5" y="66" text-anchor="middle" class="tb">HSM</text>
<text x="617.5" y="81" text-anchor="middle" class="ts tm">P2 M4 C4</text>
<text x="617.5" y="95" text-anchor="middle" class="ts tm">M6 C6</text>
<text x="617.5" y="109" text-anchor="middle" class="ts">deriva da BDK</text>
<line class="ln" x1="375" y1="76" x2="418" y2="76" marker-end="url(#seta)"/>
<text x="396.5" y="70" text-anchor="middle" class="ts">pedido</text>
<line class="ln" x1="418" y1="102" x2="375" y2="102" marker-end="url(#seta)"/>
<text x="396.5" y="116" text-anchor="middle" class="ts">resposta</text>
<line class="ln" x1="530" y1="76" x2="563" y2="76" marker-end="url(#seta)"/>
<line class="ln" x1="563" y1="102" x2="530" y2="102" marker-end="url(#seta)"/>
<line class="grade" x1="10" y1="182" x2="670" y2="182"/>
<text x="10" y="202" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="cxa" x="10" y="220" width="200" height="70"/>
<text x="110" y="246.5" text-anchor="middle" class="tb">hsmhost.py + dukpt.py</text>
<text x="110" y="259.5" text-anchor="middle" class="ts">faz o terminal: deriva a chave</text>
<text x="110" y="272.5" text-anchor="middle" class="ts">da transação a partir da IPEK</text>
<rect class="cxc" x="246" y="235" width="90" height="40"/>
<text x="291" y="259.5" text-anchor="middle" class="tb">ponte</text>
<rect class="fr" x="375" y="214" width="295" height="84"/>
<text x="522.5" y="232" text-anchor="middle" class="tb">placa</text>
<text x="522.5" y="247" text-anchor="middle" class="ts">P2 M4 C4 M6 C6: o adquirente</text>
<text x="522.5" y="261" text-anchor="middle" class="ts">I0: a IPEK ou a IK, sob a KEK</text>
<text x="522.5" y="275" text-anchor="middle" class="ts">a BDK só deriva (modo X)</text>
<line class="ln" x1="210" y1="255" x2="244" y2="255" marker-end="url(#seta)"/>
<line class="ln" x1="336" y1="255" x2="373" y2="255" marker-end="url(#seta)"/>
<text x="340" y="324" text-anchor="middle" class="ts">o teste faz o lado do terminal e confere com os valores publicados</text>
</svg>
<figcaption>Figura 24.13 — O terminal DUKPT. O HSM faz o lado do adquirente; o lado do terminal, aqui, é o teste.</figcaption>
</figure>

**No equipamento comercial**, na fabricação do terminal, ou num centro de
injeção de chaves, o HSM deriva da BDK a chave inicial do terminal (a IPEK;
no DUKPT AES, a IK). Ela sai sob uma KEK para o injetor, que a grava no
terminal. Em operação, cada transação leva o KSN e o PIN block, e pode levar
MAC e dados cifrados. No adquirente, o HSM confere o MAC do pedido, decifra
os dados, traduz o PIN, e faz o MAC e a cifra da resposta.

O HSM faz **só o lado do adquirente**. Fazer o MAC ou a cifra de um pedido,
ou conferir uma resposta, é papel do terminal. Um comando para isso
permitiria forjar mensagens de terminal.

**Neste equipamento**, a placa faz o lado do adquirente, com os mesmos
comandos. O terminal não existe: `host/dukpt.py` faz o papel dele, deriva a
chave da transação a partir da IPEK, e o teste confere tudo com os valores
publicados (seção 37.4).

#### Emitir e verificar: `V0`, `V4`, `W0`; `V2`, `V6`, `W2`

<figure class="fig">
<svg viewBox="0 0 680 356" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<text x="170" y="40" text-anchor="middle" class="ts tb">na emissão do cartão</text>
<text x="510" y="40" text-anchor="middle" class="ts tb">na autorização</text>
<line class="lnt" x1="340" y1="30" x2="340" y2="215"/>
<rect class="cxa" x="10" y="52" width="120" height="56"/>
<text x="70" y="78" text-anchor="middle" class="tb">emissão</text>
<text x="70" y="91" text-anchor="middle" class="ts">sistema do emissor</text>
<rect class="fr" x="168" y="50" width="160" height="64"/>
<text x="248" y="68" text-anchor="middle" class="tb">HSM</text>
<text x="248" y="83" text-anchor="middle" class="ts">V0 V4: offset, PVV</text>
<text x="248" y="97" text-anchor="middle" class="ts">W0: CVV, CVV2, iCVV</text>
<line class="ln" x1="130" y1="68" x2="166" y2="68" marker-end="url(#seta)"/>
<line class="ln" x1="166" y1="94" x2="130" y2="94" marker-end="url(#seta)"/>
<rect class="cxc" x="10" y="140" width="120" height="46"/>
<text x="70" y="161" text-anchor="middle" class="tb">personalização</text>
<text x="70" y="174" text-anchor="middle" class="ts">tarja e chip</text>
<rect class="cxc" x="168" y="140" width="160" height="46"/>
<text x="248" y="161" text-anchor="middle" class="tb">cadastro</text>
<text x="248" y="174" text-anchor="middle" class="ts">offset ou PVV</text>
<line class="ln" x1="60" y1="108" x2="60" y2="138" marker-end="url(#seta)"/>
<path class="ln" d="M110,108 L110,124 L248,124 L248,138" marker-end="url(#seta)"/>
<text x="170" y="202" text-anchor="middle" class="ts">o código vai para o cartão;</text>
<text x="170" y="214" text-anchor="middle" class="ts">o offset ou o PVV, para o cadastro</text>
<rect class="cxa" x="355" y="52" width="120" height="56"/>
<text x="415" y="78" text-anchor="middle" class="tb">autorizador</text>
<text x="415" y="91" text-anchor="middle" class="ts">do emissor</text>
<rect class="fr" x="512" y="50" width="158" height="64"/>
<text x="591" y="68" text-anchor="middle" class="tb">HSM</text>
<text x="591" y="83" text-anchor="middle" class="ts">V2 V6: o PIN confere?</text>
<text x="591" y="97" text-anchor="middle" class="ts">W2: o código confere?</text>
<line class="ln" x1="475" y1="68" x2="510" y2="68" marker-end="url(#seta)"/>
<line class="ln" x1="510" y1="94" x2="475" y2="94" marker-end="url(#seta)"/>
<rect class="cxc" x="355" y="140" width="120" height="46"/>
<text x="415" y="161" text-anchor="middle" class="tb">cadastro</text>
<text x="415" y="174" text-anchor="middle" class="ts">offset ou PVV</text>
<line class="ln" x1="415" y1="140" x2="415" y2="110" marker-end="url(#seta)"/>
<text x="591" y="136" text-anchor="middle" class="ts">sai um bit:</text>
<text x="591" y="148" text-anchor="middle" class="ts">confere ou não</text>
<line class="grade" x1="10" y1="226" x2="670" y2="226"/>
<text x="10" y="246" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="cxa" x="10" y="262" width="200" height="60"/>
<text x="110" y="283.5" text-anchor="middle" class="tb">hsmhost.py</text>
<text x="110" y="296.5" text-anchor="middle" class="ts">pinv-confere, cvv-confere:</text>
<text x="110" y="309.5" text-anchor="middle" class="ts">emite e depois verifica</text>
<rect class="cxc" x="246" y="272" width="90" height="40"/>
<text x="291" y="296.5" text-anchor="middle" class="tb">ponte</text>
<rect class="fr" x="375" y="258" width="295" height="70"/>
<text x="522.5" y="276" text-anchor="middle" class="tb">placa</text>
<text x="522.5" y="291" text-anchor="middle" class="ts">V0 V4 W0: emissão</text>
<text x="522.5" y="305" text-anchor="middle" class="ts">V2 V6 W2: autorização</text>
<line class="ln" x1="210" y1="292" x2="244" y2="292" marker-end="url(#seta)"/>
<line class="ln" x1="336" y1="292" x2="373" y2="292" marker-end="url(#seta)"/>
<text x="340" y="348" text-anchor="middle" class="ts">a tabela de decimalização do V0 e do V2 só entra com o MAC do console (tabela-autoriza)</text>
</svg>
<figcaption>Figura 24.14 — Emitir e verificar. O HSM do emissor calcula o código e o offset na emissão, e confere os dois na autorização.</figcaption>
</figure>

**No equipamento comercial**, na emissão do cartão, o sistema do emissor
pede ao HSM o offset ou o PVV do PIN (seção 35), e o código de verificação
(seção 36): o CVV, para a tarja; o CVV2, para o verso; o iCVV, para o chip.
O código vai para a personalização do cartão, e o offset ou o PVV vai para o
cadastro. Os equipamentos comerciais também imprimem o envelope do PIN, por
uma porta de impressora. Esta função não existe aqui.

Na autorização, o autorizador do emissor lê o offset ou o PVV do cadastro e
pede ao HSM: o PIN confere? O código confere? Sai um bit.

**Neste equipamento**, `pinv-confere` e `cvv-confere` fazem as duas pontas:
emitem, e depois verificam. A tabela de decimalização do `V0` e do `V2` só
entra com o MAC que o console calcula (`tabela-autoriza`, seção 35).

#### Dados e MAC: `C0`, `C2`, `M0`, `M2`

<figure class="fig">
<svg viewBox="0 0 680 312" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<rect class="cxa" x="30" y="34" width="120" height="44"/>
<text x="90" y="60.5" text-anchor="middle" class="tb">aplicação A</text>
<rect class="fr" x="30" y="110" width="120" height="54"/>
<text x="90" y="128" text-anchor="middle" class="tb">HSM A</text>
<text x="90" y="143" text-anchor="middle" class="ts">M0: gera o MAC</text>
<rect class="cxa" x="530" y="34" width="120" height="44"/>
<text x="590" y="60.5" text-anchor="middle" class="tb">aplicação B</text>
<rect class="fr" x="530" y="110" width="120" height="54"/>
<text x="590" y="128" text-anchor="middle" class="tb">HSM B</text>
<text x="590" y="143" text-anchor="middle" class="ts">M2: confere</text>
<line class="ln" x1="80" y1="78" x2="80" y2="108" marker-end="url(#seta)"/>
<line class="ln" x1="100" y1="108" x2="100" y2="78" marker-end="url(#seta)"/>
<line class="ln" x1="580" y1="78" x2="580" y2="108" marker-end="url(#seta)"/>
<line class="ln" x1="600" y1="108" x2="600" y2="78" marker-end="url(#seta)"/>
<line class="ln" x1="150" y1="56" x2="528" y2="56" marker-end="url(#seta)"/>
<text x="339" y="48" text-anchor="middle" class="ts">mensagem ou arquivo + MAC</text>
<text x="339" y="74" text-anchor="middle" class="ts">a chave de MAC foi trocada antes, sob a KEK</text>
<text x="339" y="128" text-anchor="middle" class="ts">C0 C2: a aplicação cifra um campo ou um arquivo,</text>
<text x="339" y="142" text-anchor="middle" class="ts">e o HSM decifra para quem tem a chave</text>
<line class="grade" x1="10" y1="184" x2="670" y2="184"/>
<text x="10" y="204" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="cxa" x="10" y="222" width="200" height="60"/>
<text x="110" y="243.5" text-anchor="middle" class="tb">hsmhost.py</text>
<text x="110" y="256.5" text-anchor="middle" class="ts">confere, tdes-confere: compara</text>
<text x="110" y="269.5" text-anchor="middle" class="ts">com AES, CMAC e 3DES de fora</text>
<rect class="cxc" x="246" y="232" width="90" height="40"/>
<text x="291" y="256.5" text-anchor="middle" class="tb">ponte</text>
<rect class="fr" x="375" y="218" width="295" height="70"/>
<text x="522.5" y="236" text-anchor="middle" class="tb">placa</text>
<text x="522.5" y="251" text-anchor="middle" class="ts">C0 C2: AES-CBC ou 3DES-CBC</text>
<text x="522.5" y="265" text-anchor="middle" class="ts">M0 M2: CMAC ou retail MAC</text>
<line class="ln" x1="210" y1="252" x2="244" y2="252" marker-end="url(#seta)"/>
<line class="ln" x1="336" y1="252" x2="373" y2="252" marker-end="url(#seta)"/>
</svg>
<figcaption>Figura 24.15 — Dados e MAC entre instituições. Cada ponta tem a mesma chave, trocada antes sob a KEK; cada uma usa o seu HSM.</figcaption>
</figure>

**No equipamento comercial**, duas instituições protegem as mensagens e os
arquivos que trocam com um MAC. A chave de MAC é a mesma nas duas pontas,
trocada antes, sob a KEK. Quem envia pede o MAC ao seu HSM; quem recebe pede
ao seu que o confira. Com a cifra de dados, a aplicação protege um campo ou
um arquivo, e o HSM decifra para quem tem a chave.

**Neste equipamento**, os mesmos comandos atendem chave AES (CBC e CMAC) e
chave 3DES (CBC e retail MAC, seção 39.10). `confere` e `tdes-confere`
comparam cada resultado com uma implementação de fora da placa.

#### Assinatura: `R0`, `R2`, `R4`, `E0`, `E2`, `E4`

<figure class="fig">
<svg viewBox="0 0 680 300" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<rect class="cxa" x="10" y="40" width="120" height="56"/>
<text x="70" y="66" text-anchor="middle" class="tb">aplicação</text>
<text x="70" y="79" text-anchor="middle" class="ts">calcula o hash</text>
<rect class="fr" x="190" y="30" width="140" height="76"/>
<text x="260" y="48" text-anchor="middle" class="tb">HSM</text>
<text x="260" y="63" text-anchor="middle" class="ts tm">R2 E2: assina</text>
<text x="260" y="77" text-anchor="middle" class="ts">a chave privada</text>
<text x="260" y="91" text-anchor="middle" class="ts">não sai</text>
<line class="ln" x1="130" y1="56" x2="188" y2="56" marker-end="url(#seta)"/>
<text x="159" y="50" text-anchor="middle" class="ts">digest</text>
<line class="ln" x1="188" y1="82" x2="130" y2="82" marker-end="url(#seta)"/>
<text x="159" y="96" text-anchor="middle" class="ts">assinatura</text>
<rect class="cxc" x="390" y="40" width="110" height="56"/>
<text x="445" y="66" text-anchor="middle" class="tb">documento</text>
<text x="445" y="79" text-anchor="middle" class="ts">+ assinatura</text>
<rect class="cxa" x="550" y="40" width="120" height="56"/>
<text x="610" y="59.5" text-anchor="middle" class="tb">quem recebe</text>
<text x="610" y="72.5" text-anchor="middle" class="ts">confere com a</text>
<text x="610" y="85.5" text-anchor="middle" class="ts">chave pública</text>
<path class="ln" d="M70,96 L70,126 L445,126 L445,98" marker-end="url(#seta)"/>
<text x="260" y="140" text-anchor="middle" class="ts">segue com o documento</text>
<line class="ln" x1="500" y1="68" x2="548" y2="68" marker-end="url(#seta)"/>
<text x="610" y="120" text-anchor="middle" class="ts">outro HSM (R4 E4)</text>
<text x="610" y="134" text-anchor="middle" class="ts">ou software</text>
<line class="grade" x1="10" y1="160" x2="670" y2="160"/>
<text x="10" y="180" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="cxa" x="10" y="200" width="200" height="60"/>
<text x="110" y="221.5" text-anchor="middle" class="tb">hsmhost.py</text>
<text x="110" y="234.5" text-anchor="middle" class="ts">rsa-confere, ecdsa-confere:</text>
<text x="110" y="247.5" text-anchor="middle" class="ts">confere com a cryptography</text>
<rect class="cxc" x="246" y="210" width="90" height="40"/>
<text x="291" y="234.5" text-anchor="middle" class="tb">ponte</text>
<rect class="fr" x="375" y="196" width="295" height="84"/>
<text x="522.5" y="214" text-anchor="middle" class="tb">placa</text>
<text x="522.5" y="229" text-anchor="middle" class="ts">R0 E0: gera o par (key block PKCS#8)</text>
<text x="522.5" y="243" text-anchor="middle" class="ts">R2 E2: assina o digest</text>
<text x="522.5" y="257" text-anchor="middle" class="ts">R4 E4: confere</text>
<line class="ln" x1="210" y1="230" x2="244" y2="230" marker-end="url(#seta)"/>
<line class="ln" x1="336" y1="230" x2="373" y2="230" marker-end="url(#seta)"/>
</svg>
<figcaption>Figura 24.16 — Assinatura. A aplicação calcula o hash; o HSM assina com a chave privada, que não sai; qualquer um confere com a pública.</figcaption>
</figure>

**No equipamento comercial**, a assinatura aparece, por exemplo, na carga
remota de chaves em terminais (ANSI X9.24-2): o terminal só aceita uma chave
nova se a assinatura do host confere. Aparece também em certificados e em
arquivos assinados. A aplicação calcula o hash; o HSM assina com a chave
privada, que não sai dele; qualquer um confere com a chave pública.

**Neste equipamento**, `R0` e `E0` geram o par e devolvem a chave privada em
key block (PKCS#8, seção 30), `R2` e `E2` assinam o digest, e `R4` e `E4`
conferem. `rsa-confere` e `ecdsa-confere` conferem as assinaturas com a
biblioteca `cryptography`.

#### Diagnóstico: `D0`

<figure class="fig">
<svg viewBox="0 0 680 240" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="14" text-anchor="start" class="ts tb">NO EQUIPAMENTO COMERCIAL</text>
<rect class="cxa" x="10" y="36" width="150" height="54"/>
<text x="85" y="61" text-anchor="middle" class="tb">monitoramento</text>
<text x="85" y="74" text-anchor="middle" class="ts">de tempos em tempos</text>
<rect class="fr" x="250" y="30" width="150" height="66"/>
<text x="325" y="48" text-anchor="middle" class="tb">HSM</text>
<text x="325" y="63" text-anchor="middle" class="ts">estado, KCV da LMK,</text>
<text x="325" y="77" text-anchor="middle" class="ts">versão</text>
<rect class="cxc" x="490" y="36" width="180" height="54"/>
<text x="580" y="61" text-anchor="middle" class="tb">alarme</text>
<text x="580" y="74" text-anchor="middle" class="ts">o estado ou o KCV mudou</text>
<line class="ln" x1="160" y1="52" x2="248" y2="52" marker-end="url(#seta)"/>
<text x="204" y="46" text-anchor="middle" class="ts">D0</text>
<line class="ln" x1="248" y1="76" x2="160" y2="76" marker-end="url(#seta)"/>
<text x="204" y="90" text-anchor="middle" class="ts">resposta</text>
<path class="ln" d="M85,90 L85,114 L580,114 L580,92" marker-end="url(#seta)"/>
<text x="330" y="128" text-anchor="middle" class="ts">se algo muda</text>
<line class="grade" x1="10" y1="144" x2="670" y2="144"/>
<text x="10" y="164" text-anchor="start" class="ts tb">NESTE EQUIPAMENTO</text>
<rect class="cxa" x="10" y="180" width="150" height="46"/>
<text x="85" y="201" text-anchor="middle" class="tb">hsmhost.py</text>
<text x="85" y="214" text-anchor="middle" class="ts tm">diag</text>
<rect class="cxc" x="196" y="183" width="90" height="40"/>
<text x="241" y="207.5" text-anchor="middle" class="tb">ponte</text>
<rect class="fr" x="325" y="176" width="345" height="54"/>
<text x="497.5" y="194" text-anchor="middle" class="tb">placa</text>
<text x="497.5" y="209" text-anchor="middle" class="ts">D0: estado, KCV da LMK e versão; não em TAMPERED</text>
<line class="ln" x1="160" y1="203" x2="194" y2="203" marker-end="url(#seta)"/>
<line class="ln" x1="286" y1="203" x2="323" y2="203" marker-end="url(#seta)"/>
</svg>
<figcaption>Figura 24.17 — Diagnóstico. O monitoramento pergunta de tempos em tempos; um KCV de LMK que muda sem cerimônia marcada é alarme.</figcaption>
</figure>

**No equipamento comercial**, um sistema de monitoramento consulta o HSM de
tempos em tempos: estado, KCV da LMK, versão. Um KCV de LMK que muda sem
cerimônia marcada é alarme.

**Neste equipamento**, `D0` devolve o estado, o KCV da LMK e a versão
(`hsmhost.py diag`). Pelo console há mais: `ping`, `version`, `build` (o hash
do firmware gravado), `post` e `env` (os sensores).

#### Resumo

| Família | Quem pede, no equipamento comercial | Quando | Comandos aqui | Quem faz o papel, aqui |
|---|---|---|---|---|
| Cerimônia e administração | custodiantes, no console | instalação, troca de LMK | `0x20` `0x26` `0x2C` `0x80` `0x2D` `0x2F` | `hsmtool.py` e os botões |
| Gerar e guardar | gestão de chaves | quando uma chave nasce | `K0` `K2` | `hsmhost.py gen`, `check` |
| Troca com outra instituição | gestão de chaves, nas duas pontas | quando uma chave é trocada | `K4` `K6` | `host/tr31.py` |
| PIN | autorizadores do adquirente, da bandeira e do emissor | em cada transação | `P0` `P2` `V2` `V6` | `pin-confere`, `pinv-confere` |
| Terminal DUKPT | fabricação; autorizador do adquirente | uma vez; em cada transação | `I0`; `P2` `M4` `M6` `C4` `C6` | `dukpt-confere` |
| Emissão | sistema do emissor | quando o cartão é emitido | `V0` `V4` `W0` | `pinv-confere`, `cvv-confere` |
| Dados e MAC | aplicações das instituições | em cada mensagem ou arquivo | `C0` `C2` `M0` `M2` | `confere`, `tdes-confere` |
| Assinatura | aplicações | carga remota, arquivos | `R0` `R2` `R4` `E0` `E2` `E4` | `rsa-confere`, `ecdsa-confere` |
| Diagnóstico | monitoramento | de tempos em tempos | `D0` | `hsmhost.py diag` |
