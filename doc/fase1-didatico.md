# Fase 1, peça por peça: o que cada uma é num HSM real

Este documento pega cada arquivo escrito na Fase 1 e responde: **o que essa
peça corresponde num módulo criptográfico de verdade, e por que ela existe.**

`doc/arquitetura.md` explica os conceitos de HSM de cima para baixo. Este
aqui vai de baixo para cima: parte do código que existe e sobe até a função
de segurança.

Ao final de cada peça há uma nota **"o que ainda falta"**, porque a diferença
entre o que fizemos e o que um HSM comercial faz é, em si, o conteúdo do
curso.

---

## Mapa rápido

| O que construímos | O que é num HSM real |
|---|---|
| `clk_rst_gen.v` | Monitor de integridade do clock (sensor antitamper) |
| `debounce.v` | Integridade da autorização física (dual control) |
| `neorv32_wrapper.vhd` | Endurecimento da plataforma: o que a placa **não** faz |
| `hsm_top.v` | Definição física da fronteira criptográfica |
| `cmd.c` (parser) | A API do HSM — a superfície de ataque principal |
| CRC32 | Integridade de transporte (num HSM real, vira MAC) |
| `state.c` | A chave de switch de três posições |
| `wipe.c` | Requisito de zeroização do FIPS 140-3 |
| LEDs D1..D5 | Indicadores de estado e de tamper |
| `BOOT_MODE_SELECT=2` | Autenticidade de firmware / secure boot |
| IMEM como ROM | Integridade do código em execução |
| `tb_soc_silent` | Higiene de canal lateral (não falar sem ser perguntado) |
| `hsmtool.py` | O cliente da API — futuro PKCS#11 |
| Teste de 10.000 pings | Requisito de confiabilidade operacional |

---

## 1. `rtl/soc/clk_rst_gen.v` — o clock é um sensor de segurança

**O que faz:** MMCM que transforma os 50 MHz do oscilador em 100 MHz, mais
geração de reset. Reset afirma assíncrono, libera síncrono, e segura 64
ciclos depois do lock.

**Num HSM real:** monitoramento de clock é um **sensor antitamper**. Um dos
ataques mais baratos contra um dispositivo criptográfico é o *clock glitch*:
injetar um pulso fora de especificação num instante escolhido, fazendo a CPU
pular uma instrução. Se essa instrução for o `if` que compara a senha, ou o
que verifica a exportabilidade da chave, você acabou de contornar a
verificação sem quebrar nenhuma matemática.

HSMs comerciais têm detectores de frequência fora de faixa que disparam
zeroize. É a mesma família de ataque que *voltage glitching* e *laser fault
injection*.

**Como isso aparece no nosso código:**

```verilog
wire rst_src_n = locked_w & rst_n_sync[1];
```

Perda de `LOCKED` reafirma o reset — não é ignorada. Um SoC que guarda LMK em
BRAM não pode continuar executando com o clock fora de especificação. É a
versão mínima e honesta do detector: não sabemos *por que* o lock caiu, mas
sabemos que não dá para confiar no que vier depois.

**O que ainda falta:** um HSM real não só reseta, ele **zeroiza** e vai para
`TAMPERED`, registrando o evento. E monitora ativamente a frequência, em vez
de só reagir à perda de lock. A Fase 6 do plano faz exatamente esse ataque
(glitch via DRP do MMCM) e implementa contramedidas.

---

## 2. `rtl/soc/debounce.v` — quando um ressalto vira uma autorização

**O que faz:** exige 10 ms de estabilidade antes de aceitar mudança de estado
do botão. Qualquer transição no meio zera a contagem.

**Num HSM real:** este é o mecanismo de **integridade da autorização
física**. Os dois botões implementam *dual control*: `LMK_LOAD_COMPONENT` só é
aceito com ambos pressionados simultaneamente.

Por que dual control existe: em PCI PIN Security, carregar componente de chave
mestra exige que nenhuma pessoa sozinha consiga fazê-lo. Não é desconfiança do
operador — é remoção da possibilidade. Um operador que *não pode* agir sozinho
não pode ser coagido, subornado ou chantageado com sucesso individual, e não
pode cometer o erro sozinho.

**Por que o debounce é código de segurança, não de usabilidade:**

Um contato mecânico produz dezenas de transições em milissegundos. Sem filtro,
um único toque parece vários pressionamentos. Se o firmware lê "pressionado"
num ressalto que ocorreu *depois* de o custodiante soltar o botão, ele
registrou uma autorização que ninguém deu.

Traduzindo para a linguagem do padrão: o mecanismo de autorização precisa
refletir **intenção do humano**, não estado elétrico do contato.

Escolhi SW2 e SW5 — os extremos da fileira — para dificultar pressionar os
dois com uma mão só. Um HSM comercial resolve isso com duas chaves físicas
distintas, ou dois smartcards em leitores separados.

**O que ainda falta:** num HSM real, cada custodiante se autentica
(smartcard + PIN), não apenas pressiona. E o dispositivo registra *quem*
autorizou, não só *que* houve autorização.

---

## 3. `rtl/soc/neorv32_wrapper.vhd` — segurança é o que você desliga

**O que faz:** fixa os ~130 generics do processador. É o único lugar onde a
configuração do SoC está escrita.

**Num HSM real:** corresponde ao **endurecimento da plataforma**. A lista do
que está desligado é mais informativa que a do que está ligado — e num
relatório de certificação, é exatamente essa lista que o avaliador examina.

### `OCD_EN => false` — o generic mais importante do arquivo

O debugger on-chip dá leitura e escrita irrestritas de memória via JTAG. Num
dispositivo com a LMK em BRAM, isso **é** um comando de extração de chave, só
que sem passar pela API.

Num HSM comercial isso corresponde a desabilitar JTAG/debug em produção — e é
um requisito explícito de certificação. Muitos ataques públicos a dispositivos
embarcados consistem inteiramente em achar um header de debug esquecido.

> Note a assimetria com a regra do projeto de nunca desabilitar JTAG no FPGA:
> ali é o caminho de recuperação do *bitstream* e precisa existir num projeto
> de estudo. Aqui é o caminho de leitura da *memória do processador*, e não
> precisa. São duas coisas diferentes com o mesmo nome.

### `ICACHE_EN`/`DCACHE_EN => false` — cache é canal lateral

Duas razões independentes, e a segunda é a interessante: cache introduz tempo
de execução **dependente do dado**. Se uma comparação de MAC sai mais rápido
quando o primeiro byte difere, um atacante mede o tempo e recupera o MAC byte
a byte — sem quebrar a criptografia.

É a família dos ataques de temporização, e é por isso que código
criptográfico sério usa comparação em tempo constante. Não ter cache remove a
fonte mais comum de variação.

### `XBUS_EN => false` — a regra virou estrutura

Sem barramento externo, não existe caminho físico do processador até a DDR3.
A regra "chaves só em BRAM" deixa de depender de disciplina do programador e
passa a ser uma propriedade do hardware.

Essa é a diferença entre uma política e um controle. Num HSM real, é a
diferença entre "o firmware não escreve chave na flash" e "não há trilha
ligando o motor de cripto à flash".

### `Zkne`/`Zknd`/`Zknh => false` — recusar o atalho

O RISC-V tem extensões de instrução para AES e SHA. Estão desligadas de
propósito: AES e SHA vão para o fabric como coprocessadores no CFS, porque
construí-los é o objetivo do projeto.

Num HSM real a escolha é outra e vale entender: motores dedicados em hardware
existem por desempenho **e** por isolamento — a chave pode ficar num registro
que o barramento do processador não consegue ler.

**O que ainda falta:** PMP (Physical Memory Protection) para separar
privilégio dentro do próprio firmware, de modo que um bug no parser não
alcance a região da LMK. Está previsto para a Fase 3.

---

## 4. `rtl/top/hsm_top.v` — onde a fronteira fica física

**O que faz:** é o único arquivo do projeto que conhece nome de pino.
Instancia o gerador de clock, os sincronizadores, o debounce e o SoC.

**Num HSM real:** corresponde à **definição da fronteira criptográfica**. Num
documento de certificação FIPS, existe literalmente um desenho marcando o que
está dentro e o que está fora, e uma lista de todas as portas que atravessam.

Aqui essa lista é curta e verificável:

| Porta | Direção | O que atravessa |
|---|---|---|
| `uart_rxd_i`/`uart_txd_o` | ambas | comandos e respostas |
| `btn_a_i`/`btn_b_i` | entra | autorização física |
| `led_o` | sai | estado |
| `seg_o`/`seg_an_o` | sai | estado |

**E só.** Não há porta por onde chave em claro possa sair, porque não existe
porta de dados além da UART — e o que passa pela UART é definido pela tabela
de comandos.

O toplevel também absorve as duas inversões da placa (LEDs e botões são
ativos em nível baixo) num ponto só. Isso parece cosmético e não é: um LED de
`TAMPERED` invertido é um defeito de segurança — o dispositivo mostraria
"tudo bem" exatamente quando não está.

---

## 5. `fw/src/cmd.c` — o parser é a superfície de ataque

**O que faz:** máquina de estados de recepção, verificação de CRC, tabela de
comandos com verificação de estado, montagem da resposta.

**Num HSM real:** este é **a API do HSM**, e é onde mora a maior parte dos
ataques reais.

A observação central de Anderson em *Security Engineering*: contra um HSM
bem construído, você não ataca a criptografia. Você ataca a **API** —
encontra uma sequência de comandos legítimos que, combinados, revelam algo que
nenhum comando isolado revelaria. Os ataques clássicos aos HSMs bancários dos
anos 2000 (Bond, Clulow) são todos desse tipo.

Por isso o checklist do `CLAUDE.md` para todo opcode novo:

- Em quais estados é permitido?
- Exige dual control?
- **O que pode vazar se for chamado em laço com entradas escolhidas?**
- Respeita `exportability` do slot?
- Entra no log **antes** da execução?

A terceira pergunta é a que pega ataque de API. Não é "este comando vaza a
chave?" — é "dez mil chamadas deste comando vazam a chave?".

### Por que o parser é deliberadamente burro

É o único código que processa entrada arbitrária **antes** de qualquer
verificação. Máquina de estados explícita, todos os limites checados, sem
alocação, sem recursão. Nada de esperto.

### O timeout que impede negação de serviço com um byte

```c
g_rx_deadline = ms_from_now(CMD_INTERBYTE_TIMEOUT_MS);
```

Sem ele, um host que morre no meio de um frame deixa o parser esperando bytes
que nunca chegam. O dispositivo fica mudo para sempre — negação de serviço
com um único byte enviado.

Num HSM real, disponibilidade é requisito: um dispositivo que para de
responder derruba a autorização de transações. O critério do `PLANO.md` —
"frame malformado nunca trava a máquina de estados" — é a versão mínima
disso.

É timeout **entre bytes**, rearmado a cada byte, e não do frame inteiro. A
diferença importa: um key block TR-31 leva ~45 ms a 115200 baud, e um timeout
de frame teria de ser afrouxado até deixar de proteger.

### O status que não conta demais

```c
/* Um status nunca pode revelar mais do que o host tem direito de saber.
   "Chave errada" e "slot vazio" devem ser o mesmo codigo sempre que a
   distincao ajudar um atacante a enumerar o key store. */
```

Isso é engenharia de **canal lateral por mensagem de erro**. O exemplo
clássico fora de HSM é o *padding oracle*: um servidor que distingue "padding
inválido" de "MAC inválido" entrega decifração completa a quem souber
perguntar o suficiente.

**O que ainda falta:** o log de auditoria antes da execução (o ponto está
marcado no código), e o tempo de resposta constante — hoje um comando
recusado responde mais rápido que um aceito, o que é informação.

---

## 6. O CRC32 — e por que num HSM real ele seria um MAC

**O que faz:** detecta corrupção no enquadramento. Polinômio IEEE 802.3
refletido, idêntico ao `zlib.crc32`.

**Distinção importante, e é didática:** CRC é **detecção de erro**, não
autenticação. Ele protege contra ruído na linha, não contra adversário — quem
altera o payload recalcula o CRC trivialmente.

Num HSM comercial de pagamentos, o canal com o host costuma ser autenticado
de verdade: MAC sobre a mensagem com uma chave de sessão, ou TLS mútuo. O
payShield, por exemplo, tem modos de comando autenticado.

Aqui o CRC é adequado porque a fronteira de confiança está no dispositivo, não
no canal: **assumimos que o host pode ser hostil**. Um host hostil não precisa
falsificar CRC — ele simplesmente manda comandos válidos. A defesa não é
autenticar o canal, é a máquina de estados, o dual control físico e os
atributos de chave.

Essa é uma inversão que vale internalizar: num HSM, o canal ser confiável não
é premissa. É por isso que dual control é feito com **botões na própria
placa**, e não com um comando "eu autorizo" vindo do host.

### Por que três implementações independentes

O CRC existe em C (firmware), Verilog (testbench) e Python (host). Divergência
apareceria como `STATUS_BAD_CRC` intermitente — dos sintomas mais enganosos
que existem, porque parece problema de cabo.

Os vetores do `selftest` do host são **fixos**, não gerados pelo próprio
módulo. Se fossem gerados, o teste só provaria que o código concorda consigo
mesmo. É o mesmo princípio dos KAT: vetor vem de fora.

---

## 7. `fw/src/state.c` — a chave de switch

**O que faz:** hoje, só o enum e a consulta. O dispositivo nasce e fica em
`UNINITIALIZED`.

**Num HSM real:** é a **chave física de três posições** que fica no painel.
Comandos sensíveis existem apenas em `AUTHORIZED`, um estado no qual o
dispositivo não atende produção e no qual só se entra por ação física
deliberada.

O raciocínio: em operação normal, a superfície de ataque deve ser mínima. Em
`OPERATIONAL` o dispositivo faz o trabalho e nada mais — não carrega chave,
não exporta LMK, não muda política. Um invasor que comprometa **totalmente** o
host de produção ainda não carrega componente de LMK, porque o dispositivo não
aceita aquele opcode naquele estado, e mudar de estado exige mão humana no
equipamento.

Já existe agora, com o dispositivo tendo um estado só, porque a tabela de
comandos carrega a máscara de estados permitidos. Retroajustar verificação de
estado em cada handler depois é como se lembrar tarde demais — e é exatamente
assim que se esquece um.

```c
#define ST_NORMAL  (ST_UNINIT | ST_AUTH | ST_OPER)
```

`TAMPERED` fica **fora** de propósito: dispositivo comprometido responde o
mínimo possível.

---

## 8. `fw/src/wipe.c` — apagar é mais difícil do que parece

**O que faz:** zeroização com ponteiro `volatile` e barreira de memória.

**Num HSM real:** zeroização é **requisito explícito** do FIPS 140-3. E o
detalhe técnico aqui é uma armadilha real de C, não teoria:

```c
memset(chave, 0, 32);   /* ...e a funcao termina */
```

Para o compilador, isso é *dead store*: escrita num buffer que ninguém lê
depois. O padrão permite eliminar, e com `-O2`/`-Os` o compilador elimina. A
chave permanece na memória, e o código **parece** correto na revisão.

Já está no lugar mesmo a Fase 1 não movimentando chave nenhuma, e os buffers
de frame são limpos após cada comando. Motivo: são esses mesmos buffers que
vão carregar componente de LMK e key block na Fase 3.

**O que ainda falta:** o `ZEROIZE` de verdade, que sobrescreve a BRAM com
padrão e depois zeros — e o teste que **prova** que apagou, fazendo dump da
região. "Chamei a função de apagar" não é evidência; num HSM certificado,
a evidência é exigida.

---

## 9. Os LEDs — indicadores de estado, e por que D1 é em hardware

**O que faz:** D1 pisca a 1 Hz por lógica no fabric; D2..D5 são GPIO do
firmware.

**Num HSM real:** o painel indica estado e condição de tamper. Existe porque
o operador precisa saber, sem console e sem confiar no host, em que condição o
equipamento está.

**A decisão interessante:** D1 é gerado em **hardware, independente da CPU**.

Se o firmware travar, D1 continua piscando. Isso distingue duas falhas que de
fora parecem idênticas:

| Sintoma | Diagnóstico |
|---|---|
| D1 parado | clock morto — MMCM sem lock, alimentação, bitstream |
| D1 piscando, D2 apagado | clock bom, firmware pendurado |
| D1 piscando, D2 aceso | plataforma viva, problema é de protocolo/host |

Num dispositivo sem console, essa é a diferença entre depurar e adivinhar. E é
o mesmo princípio do *watchdog* independente num HSM real: o indicador de vida
não pode depender da coisa cuja vida ele indica.

Na bancada isso funcionou exatamente assim: você viu D1 a 1 Hz e D2 aceso, e
com esses dois sinais já sabíamos que MMCM, clock, reset, CPU e `main()`
estavam bons — antes de qualquer byte de UART.

**Bônus de verificação:** D1 a 1 Hz cronometrado a olho confirma a divisão do
MMCM. O contador é `CLK_HZ/2`; ele só bate 1 Hz se o clock for mesmo 100 MHz.

**O que ainda falta:** D5 está reservado para `TAMPERED` e nunca foi aceso.
E as cores dos LEDs continuam sem documentação — a Fase 3 precisa saber se D5
é vermelho.

---

## 10. `BOOT_MODE_SELECT = 2` — autenticidade de firmware

**O que faz:** o SoC sobe a partir de uma imagem embutida na IMEM, não do
bootloader do NEORV32.

**Num HSM real:** isto é **secure boot**, e é um dos requisitos mais duros de
certificação.

O bootloader do NEORV32 aceita upload de firmware pela UART. Com ele ligado,
qualquer um com acesso ao serial substitui o firmware — e um firmware
substituído contorna a máquina de estados, o dual control, a exportabilidade
e a fronteira inteira. Todas as defesas discutidas neste documento passam a
valer zero, porque quem escreve o código escreve as regras.

Este é o problema de autenticidade de firmware. Num HSM comercial, ele é
resolvido com boot ROM imutável que verifica assinatura da imagem antes de
executá-la, e a chave pública fica em OTP.

**Nossa versão é mais simples e mais rude:** não há caminho de atualização.
O firmware está no bitstream. Trocá-lo exige regerar o bitstream e gravar por
JTAG — que é acesso físico.

**Efeito colateral que veio de graça:** com `BOOT_MODE_SELECT = 2`, o NEORV32
liga `MEM_INIT` e a IMEM vira **memória somente de leitura**. A memória de
código não é gravável em tempo de execução — não há injeção de código nem
código automodificável, independentemente de qualquer bug no parser.

Isso é integridade de código em execução, e num sistema com MMU seria o
equivalente a marcar as páginas de texto como não-graváveis (W^X). Aqui é mais
forte, porque não é uma permissão que alguém pode mudar: é a ausência de
circuito de escrita.

Também sumiu a boot ROM: a BRAM caiu de 8 tiles para 3,5.

---

## 11. `tb_soc_silent` — não falar sem ser perguntado

**O que faz:** verifica que o dispositivo não transmite nada pela UART até
receber um comando — **e** que está vivo (LED de atividade aceso).

**Num HSM real:** é higiene de **canal lateral e de vazamento de
identidade**.

Um banner de boot entrega, para quem só escuta o barramento, a versão do
firmware e a identidade do equipamento. Isso é reconhecimento gratuito: quem
sabe a versão sabe quais vulnerabilidades públicas tentar.

E um `printf` de depuração esquecido no firmware é um canal lateral
permanente — historicamente uma das formas mais comuns de vazamento em
dispositivos embarcados. Este testbench falha no dia em que alguém adicionar
um.

**O detalhe que torna o teste honesto:** silêncio sozinho não prova nada, já
que firmware travado também fica quieto. Por isso o teste exige silêncio
**e** vida. Um teste que passa quando o dispositivo está morto é pior que
teste nenhum.

---

## 12. `host/hsmtool.py` — o cliente da API

**O que faz:** codec do protocolo, transporte serial, CLI.

**Num HSM real:** é o **cliente da API** — em produção, isso seria PKCS#11
(`C_Initialize`, `C_GenerateKey`, `C_WrapKey`, `C_Sign`), ou o command set
ASCII estilo payShield. A Fase 5 do plano constrói exatamente isso.

O comentário no topo do arquivo é a regra que o mantém honesto:

```python
# FRONTEIRA: tudo aqui esta FORA. Este programa nunca ve chave em claro --
# so key blocks wrapped, KCVs, criptogramas, handles e log. Se algum comando
# futuro fizer material de chave aparecer neste arquivo, o comando esta
# errado, nao o script.
```

Aqui se entende por que a API de um HSM é do jeito que é: **é você que
precisa impedi-la de vazar material de chave.** Quando você escreve os dois
lados, a tentação de adicionar um "só para depurar, me devolva a chave" fica
concreta — e recusá-la ensina mais que ler que não se deve.

O codec (`build_request`/`parse_response`) são funções puras, sem porta
serial. Isso permite testar o protocolo sem hardware e, na Fase 3, deixa
`tr31.py` e `audit.py` reaproveitarem o enquadramento em vez de escreverem a
terceira cópia dele.

---

## 13. O teste de 10.000 pings — confiabilidade é requisito

**O que faz:** 10.000 transações, contando erro de protocolo e latência.

```
iteracoes  : 10000 em 44.3 s (226/s)
erros      : 0
latencia   : min 3.97  mediana 4.36  p99 4.85  max 6.50 ms
```

**Num HSM real:** disponibilidade e determinismo são requisitos operacionais,
não conforto. Um HSM autorizando transações de cartão tem SLA; um que perde
1 em 10.000 mensagens produz falhas intermitentes que ninguém consegue
reproduzir.

E há um aspecto de segurança: **erro intermitente esconde ataque**. Se o
canal normalmente perde alguns frames, ninguém investiga o dia em que alguém
está injetando tráfego. Uma taxa de erro de exatamente zero é o que torna
qualquer erro digno de investigação.

O p99 em 4,85 ms contra máximo de 6,50 ms também diz algo: a distribuição é
apertada, sem cauda longa. Cauda longa indicaria contenção, retry escondido
ou coleta de lixo em algum lugar — todos comportamentos que atrapalham
diagnóstico.

**Nota didática sobre a latência:** ela é dominada pelo USB, não pelo
dispositivo. Dezesseis bytes a 115200 baud são 1,4 ms de tempo de linha; o
resto é o timer de latência do CP2102. Ou seja: o HSM responde muito mais
rápido do que a medida sugere. Vale lembrar disso antes de "otimizar" o
firmware por engano.

---

## 14. O que a Fase 1 **não** é

Honestidade sobre o alcance, porque a diferença é o conteúdo das próximas
fases:

| Ainda não existe | Fase |
|---|---|
| Qualquer criptografia | 2 |
| Fonte de entropia e health tests | 2 |
| POST com KAT | 2 |
| Key store e LMK | 3 |
| Dual control funcionando de fato | 3 |
| Key blocks TR-31 | 3 |
| Zeroize com prova | 3 |
| Log de auditoria | 3 |
| Armazenamento não-volátil | 4 |
| API PKCS#11 | 5 |
| Detecção de tamper | 6 |

O que existe é a **plataforma**: clock confiável, reset que falha de forma
segura, processador configurado com o mínimo de superfície, memória de código
não-gravável, canal de comando enquadrado e testado, e um dispositivo que não
fala sem ser perguntado.

Nenhuma dessas coisas é criptografia. Todas elas são a razão pela qual a
criptografia que vier depois vai poder ser confiável — e num HSM real são
justamente elas que consomem a maior parte do esforço de certificação.

---

## 15. Três lições que a Fase 1 ensinou fazendo

Estas não estavam no plano. Vieram de erros reais, e são o tipo de coisa que
só se aprende construindo.

### Verificação encontra o que revisão não encontra

O `tb_hsm_top` reprovou a primeira versão do toplevel com `led=1111x`.
Registradores sem valor inicial mais reset síncrono deixam uma janela
indefinida entre a configuração do FPGA e o primeiro clock.

Em hardware o Vivado teria inicializado implicitamente e nada apareceria.
Mas a saída em questão é um **indicador visível de estado** — e na Fase 3 uma
delas é o LED de `TAMPERED`. Depender de comportamento implícito da ferramenta
para o estado de um indicador de segurança é exatamente o tipo de coisa que um
avaliador pergunta.

### Cuidado ao "corrigir" um teste que falha

O testbench do boot reprovou esperando `\n` e recebendo `\r\n`. A tentação é
ajustar a expectativa e seguir.

Fui verificar na fonte do NEORV32 (`neorv32_uart.c:308`) que o driver
realmente expande LF em CRLF **antes** de mexer no teste. A diferença entre
"corrigi uma expectativa errada" e "ajustei o teste ao resultado observado" é
invisível no diff e enorme na prática — é a mesma disciplina da regra
inviolável nº 5: se um KAT falha, o bug está no código, não no vetor.

### Hardware expõe o que simulação estruturalmente não pode

O `hsmtool` escolhia a primeira `/dev/ttyUSB*`. Na bancada isso é o
**adaptador JTAG**, porque o "DLC9LP" é um FT232H que também cria porta
serial e enumera antes da placa.

O sintoma seria timeout sem explicação, apontando para o firmware quando o
problema é o cabo. Nenhum teste sem hardware pegaria: o pty do teste de
transporte não tem VID:PID, e o selftest do codec nem abre porta.

A lição não é "simulação é insuficiente" — a Fase 1 pegou dois defeitos reais
em simulação e só um escapou. É saber **qual classe** de defeito cada método
alcança, e não confundir "os testes passam" com "está correto".

---

## Onde continuar

- `doc/arquitetura.md` — os conceitos de HSM de cima para baixo
- `doc/fase1-notas.md` — o registro técnico detalhado, com números
- `doc/pinout.md` — pinagem com procedência e o que foi verificado em hardware
- `doc/submodulos.md` — política de código de terceiros
- `PLANO.md` §3 — a Fase 2, que traz a primeira criptografia
