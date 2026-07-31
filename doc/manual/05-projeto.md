# Parte V — O projeto hsm-a7

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

**2. Chaves em claro só em BRAM.** Nunca DDR3, nunca flash sem embrulho,
nunca um registrador exposto no toplevel.

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

## 24. Fase 1, peça por peça

Esta seção pega cada arquivo escrito e responde: **o que essa peça
corresponde num HSM real?**

Cada uma termina com *o que ainda falta*, porque a distância entre o
brinquedo e o produto é o conteúdo das fases seguintes.

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

O gerador é também a única exceção à convenção de reset síncrono do projeto,
e por necessidade: com o MMCM em reset, o clock de saída não está correndo e
não existe borda para registrar nada. Usa o padrão clássico *afirma
assíncrono / libera síncrono*, justamente para que todo o resto do projeto
possa usar reset puramente síncrono.

**Falta:** zeroizar e ir para `TAMPERED`, registrar o evento, e monitorar a
frequência ativamente em vez de só reagir à perda de lock. Fase 6.

### 24.2 `debounce.v` — quando um ressalto vira autorização

Exige 10 ms de estabilidade contínua antes de aceitar mudança; qualquer
transição no meio zera a contagem.

**Num HSM real:** integridade da autorização física (seção 7). O mecanismo
precisa refletir intenção humana, não estado elétrico de contato.

Os dois botões escolhidos são SW2 e SW5 — os extremos da fileira — para
dificultar pressionar ambos com uma mão só.

**Falta:** autenticação de custodiante (smartcard + PIN) e registro de *quem*
autorizou, não só de que houve autorização.

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
(código criptográfico é pesado em deslocamento), IMEM 16 KB, DMEM 8 KB,
UART0 com FIFO de 64, temporizador, GPIO de 8 bits.

**Falta:** PMP (proteção de memória física) para separar privilégio dentro do
firmware, de modo que um bug no parser não alcance a região da LMK. Fase 3.

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

**Falta:** o log antes da execução (o ponto está marcado no código), e tempo
de resposta constante — hoje um comando recusado responde mais rápido que um
aceito, e isso é informação.

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

Hoje só o enum e a consulta: o dispositivo nasce e permanece em
`UNINITIALIZED`.

Existe agora, com um estado só, porque **a tabela de comandos já carrega a
máscara de estados permitidos**. Retroajustar verificação de estado em cada
handler depois é como se esquece um.

```c
#define ST_NORMAL  (ST_UNINIT | ST_AUTH | ST_OPER)
```

`TAMPERED` fica fora de propósito: dispositivo comprometido responde o
mínimo possível.

### 24.8 `wipe.c` — zeroização antes de haver chave

Ponteiro `volatile` mais barreira de memória, pelo motivo explicado na
seção 12.

Está no lugar mesmo a Fase 1 não movimentando chave nenhuma, e os buffers de
frame são limpos após cada comando. Motivo: são **esses mesmos buffers** que
vão carregar componente de LMK e key block na Fase 3.

**Falta:** o `ZEROIZE` de verdade, com sobrescrita por padrão e depois zeros,
e o teste que faz dump da região e **prova** que apagou.

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

**Efeito colateral que veio de graça:** com esse modo, o NEORV32 liga
`MEM_INIT` e a IMEM vira memória **somente de leitura**. A memória de código
não é gravável em tempo de execução — não há injeção de código nem código
automodificável, independentemente de qualquer bug no parser.

Isso é integridade de código em execução. Num sistema com MMU seria o
equivalente a marcar as páginas de texto como não-graváveis; aqui é mais
forte, porque não é uma permissão que alguém pode mudar — é a ausência de
circuito de escrita.

Também sumiu a boot ROM: a BRAM caiu de 8 tiles para 3,5.

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

Codec do protocolo, transporte serial, CLI. Em produção isso seria PKCS#11 ou
um command set ASCII estilo payShield — é o que a Fase 5 constrói.

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

## 25. Resultados medidos

### Recursos e temporização

| Recurso | Só clock/reset | Com o SoC | Com firmware | Disponível |
|---|---|---|---|---|
| Slice LUTs | 24 | 2247 | **2240** (10,8%) | 20800 |
| Flip-flops | 42 | 1633 | **1633** (3,9%) | 41600 |
| Block RAM | 0 | 8 | **3,5** (7%) | 50 |
| DSP48E1 | 0 | 0 | **0** | 90 |
| MMCM | 1 | 1 | 1 | 5 |

Temporização final: **WNS +0,637 ns** em período de 10 ns, sem endpoints
falhando em 4529. Fmax ≈ 107 MHz para os 100 MHz exigidos.

A margem já caiu duas vezes — de +5,95 ns com só o gerador de clock, para
+0,898 com o SoC, para +0,637 com o firmware. O caminho crítico está dentro
da CPU: banco de registradores em BRAM, onze níveis de lógica com sete
cadeias de carry, de volta ao banco. Os cores de criptografia da Fase 2 são
datapath separado e não alongam *esse* caminho, mas adicionam
congestionamento — e roteamento já é 45% do atraso.

Firmware: **1652 bytes de código, 1572 de dados não inicializados** — 10% da
IMEM e 19% da DMEM. A maior parte da bss são os três buffers de frame.

### Critério de aceitação, medido na placa

```
iteracoes  : 10000 em 44,3 s (226/s)
erros      : 0
latencia   : min 3,97   mediana 4,36   p99 4,85   max 6,50 ms
```

Zero erros de CRC em dez mil iterações, e o pior caso 7,7 vezes abaixo do
limite de 50 ms. A distribuição é apertada, sem cauda longa — cauda longa
indicaria contenção ou retentativa escondida.

A latência é dominada pelo USB, não pelo dispositivo: dezesseis bytes a
115200 baud são 1,4 ms de tempo de linha, e o resto é o temporizador de
latência do CP2102. Vale lembrar disso antes de "otimizar" o firmware por
engano.

## 26. Três lições que a Fase 1 ensinou fazendo

Não estavam no plano. Vieram de erros reais.

### Verificação encontra o que revisão não encontra

O testbench do toplevel reprovou a primeira versão com `led=1111x`.
Registradores sem valor inicial mais reset síncrono deixam uma janela
indefinida entre a configuração do FPGA e o primeiro clock.

Em hardware a ferramenta teria inicializado implicitamente e nada
apareceria. Mas a saída em questão é um **indicador visível de estado** — e
na Fase 3 uma delas é o LED de `TAMPERED`. Depender de comportamento
implícito da ferramenta para o estado de um indicador de segurança é
exatamente o tipo de coisa que um avaliador pergunta.

### Cuidado ao "corrigir" um teste que falha

O testbench de boot reprovou esperando `\n` e recebendo `\r\n`. A tentação é
ajustar a expectativa e seguir.

A conduta correta foi ir verificar na fonte do NEORV32 que o driver realmente
expande LF em CRLF **antes** de mexer no teste. A diferença entre "corrigi
uma expectativa errada" e "ajustei o teste ao resultado observado" é
invisível no diff e enorme na prática — é a mesma disciplina da regra
inviolável número 5.

### Hardware expõe o que simulação estruturalmente não pode

A ferramenta de host escolhia a primeira porta serial encontrada. Na bancada
isso é o **adaptador JTAG**, porque o gravador usado é um FT232H que também
cria porta serial e enumera antes da placa.

O sintoma seria timeout sem explicação, apontando para o firmware quando o
problema é o cabo. Nenhum teste sem hardware pegaria: o pseudo-terminal usado
no teste de transporte não tem identificador USB, e o selftest do codec nem
abre porta.

A lição não é "simulação é insuficiente" — a Fase 1 pegou dois defeitos reais
em simulação e só um escapou. É saber **qual classe** de defeito cada método
alcança, e não confundir "os testes passam" com "está correto".
