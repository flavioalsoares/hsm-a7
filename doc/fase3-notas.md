# Fase 3 — notas de implementação

Objetivo da fase (`PLANO.md` §4): **hierarquia de chaves**. É o coração do
projeto — a partir daqui o dispositivo deixa de ser uma caixa de primitivas
e passa a guardar chave.

Estado: **em andamento.** CMAC, key store, a cerimônia de LMK, o key block
X9.143, o zeroize e os comandos de chave `0x22`–`0x25` prontos. Faltam um
`DELETE_KEY` que não estava previsto, as versões por handle dos comandos da
fase 2, e o log de auditoria.

---

## Retomando o trabalho

A placa **guarda o bitstream na flash** e sobe sozinha na energização. Não
precisa gravar nada para voltar ao ponto:

```bash
python3 host/hsmtool.py version     # deve responder v0.1.0, UNINITIALIZED
python3 host/hsmtool.py post        # os OITO testes devem passar
                                   # ⚠ DESTRUTIVO: apaga a LMK se houver
python3 host/hsmtool.py lmk-status  # 0 de 3 componentes
```

⚠ **A LMK não sobrevive a um desligamento.** Ela vive em BRAM, e BRAM é
volátil — é exatamente o que a regra nº 2 pede. Então toda sessão de bancada
que precise de LMK começa refazendo a cerimônia. Não é defeito: é a fase 4
(armazenamento não-volátil) que ainda não existe, e é bom que a ordem seja
essa. Guardar chave antes de saber embrulhá-la seria guardar chave em claro.

Se não responder, o problema é físico — `doc/bancada.md` tem a tabela de
discriminadores. **Não regravar por reflexo**: a gravação por JTAG *não
aplica a inicialização das Block RAMs* nesta bancada, e é dela que a IMEM
tira o código. Se for preciso gravar, é `./scripts/program.sh flash`.

Para simular e construir:

```bash
source /opt/AMD/2026.1/Vivado/settings64.sh
./scripts/sim.sh                        # suite completa (~10 min)
vivado -mode batch -source scripts/build.tcl
```

⚠ Depois de mexer em `vectors/`, regerar os vetores embutidos:
`python3 scripts/mkkat.py`.

---

## Pronto

### CMAC-AES-256 (`fw/src/cmac.c`)

NIST SP 800-38B, sobre o AES do coprocessador. Está no POST, verificado em
hardware. É a peça de que o resto da fase depende: deriva KBEK/KBAK da LMK
*por propósito* e autentica o key block sobre header **mais** corpo.

Detalhes e a limitação dos vetores truncados: `doc/fase2-notas.md`, seção
final.

### Key store em BRAM (`fw/src/keystore.c`)

16 slots mais a LMK em região separada, com os campos do header X9.143
modelados desde já — é essa estrutura que o key block vai serializar.

**Onde as chaves ficam.** Os slots são estáticos, então vivem na DMEM do
NEORV32, que é inferida em Block RAM. A regra 2 (`chaves só em BRAM`) fica
satisfeita **por construção**, não por promessa — e o que ela proíbe também
está ausente por construção: não há DDR3 no design (XBUS desligado) e não há
caminho do firmware para a SPI flash.

**A API é assimétrica de propósito**, e essa é a decisão que carrega a fase:

```
keystore_usa_aes()   carrega a chave no coprocessador e NAO a devolve.
                     E por onde toda operacao criptografica passa.

keystore_exporta()   devolve os bytes. E a UNICA funcao que faz isso,
                     checa exportabilidade, e existe so para a camada de
                     key block.
```

Duas portas, uma trancada. Se houvesse um `keystore_get_key()` genérico, a
checagem de `exportabilidade` viraria convenção — e convenção é o que se
esquece no caminho raro. Do mesmo modo, `keystore_info()` devolve metadados
e **nunca** chave: não existe forma de pedir "o slot inteiro".

**Separação de uso** no `keystore_usa_aes()`: uma chave marcada `'E'`
recusa operação de decifrar. É a mesma disciplina que o CMAC aplica ao
derivar KBEK e KBAK por propósito, e a falta dela é a origem da família de
ataques de confusão de tipo (manual, §15.1).

**A LMK fica fora do vetor de slots.** Não tem handle, não é exportável por
caminho nenhum, e zeroizá-la apaga todos os slots junto — chave derivada não
sobrevive à chave que a protege. Um `keystore_apaga()` que pudesse alcançá-la
por índice seria um bug de uma linha com consequência total.

**KCV de três bytes**, e a escolha é uma troca: mais bytes verificam melhor
e vazam mais. O KCV é um oráculo de verificação de chave; três bytes dão 1
em 16 milhões de colisão, o que basta para pegar erro de digitação e não
basta para atacar.

### Teste de função crítica no POST

O key store entrou no POST, e vale distinguir: o FIPS 140-3 separa
*self-tests criptográficos* de **testes de funções críticas**. Não há
"resposta conhecida" para instalar uma chave, mas há propriedades que, se
falharem, tornam o dispositivo perigoso **sem parecer quebrado**:

- `exportabilidade='N'` deixando a chave sair
- slot apagado ainda respondendo
- chave de cifrar aceita para decifrar
- header inválido (3DES, que este hardware não faz) sendo aceito

Os quatro são verificados a cada boot. E o KCV tem resposta conhecida sem
custar vetor novo: KCV é AES-ECB sobre um bloco de **zeros**, e o vetor
`ECBKeySbox256` do CAVP tem exatamente `PLAINTEXT = 0` — então o KCV daquela
chave é, por definição, os três primeiros bytes do criptograma que já está
em `kat_vectors.h`.

---

### Cerimônia de LMK (`fw/src/dualctl.c`, comandos `0x20`/`0x21`/`0x26`)

Três componentes por XOR, KCV a cada passo, dual control pelos dois botões
físicos — **`SW2` → `M6` → `btn_a`** e **`SW5` → `P6` → `btn_b`**
(`doc/pinout.md`, verificados em hardware em 2026-08-21). Já vêm debounced
pelo `rtl/top/hsm_top.v`, nos bits 0 e 1 do GPIO de entrada. O toplevel
inverte, então **no firmware 1 = pressionado**.

**A regra do aperto novo** é a parte que não estava no plano e que só
aparece quando se tenta derrotar o próprio mecanismo. Não basta que os dois
botões estejam pressionados: entre duas autorizações, os dois têm de ser
vistos **soltos**. Sem isso, fita adesiva sobre os dois carregaria a LMK
inteira sozinha — e um botão travado em "pressionado" passaria a autorizar
tudo em vez de nada.

Consequência de projeto: o rearme mora no **laço principal**
(`fw/src/main.c`), não no handler. Um handler só enxerga o instante em que
foi chamado, e nesse instante os botões já estão pressionados de novo; o
evento que interessa acontece *entre* comandos.

**A escada é de uma via só**, e isso está nas máscaras da tabela, não em
código de política:

```
UNINITIALIZED --0x20 x3--> AUTHORIZED --0x26--> OPERATIONAL
   ST_UNINIT                 ST_AUTH
```

O `0x20` tem máscara `ST_UNINIT`: completar a LMK leva a `AUTHORIZED` e o
comando desaparece sozinho. Não há caminho para trocar a chave mestra por
cima da existente, que seria substituir a raiz sem apagar o que ela protege.
O `0x26` tem máscara `ST_AUTH` e some do mesmo jeito. Descer exige o
`ZEROIZE`, que apaga.

⚠ **Dual control NÃO está na tabela de comandos, de propósito.** A máscara
responde "em que estado", não "quem autoriza". Misturar as duas coisas numa
coluna só faria a leitura da tabela depender de decorar qual bit significa o
quê. O `dualctl_autoriza()` fica dentro do handler, onde pode recusar **sem
gastar o rearme** — e essa distinção importa: se a recusa consumisse, um host
hostil negaria a cerimônia chamando o comando em laço.

**O KCV que sai a cada passo é o do COMPONENTE, nunca o do acumulado.** É o
que permite ao custodiante conferir que digitou o dele; sem isso, um
componente trocado só apareceria no KCV final, quando já não dá para saber
qual dos três estava errado. O `tb_uart_frame` verifica que nenhum dos três
KCVs de componente é igual ao da LMK — se fosse, o comando estaria vazando um
oráculo sobre a chave mestra em construção.

**De onde vem o valor esperado do teste.** KCV é AES-ECB da chave sobre um
bloco de **zeros**, e o vetor `ECBKeySbox256` do CAVP tem `PLAINTEXT = 0`.
Os três componentes do testbench são escolhidos para que o XOR dê exatamente
aquela chave, e então o KCV esperado — `46F2FB` — é vetor oficial do NIST,
não "o que o firmware devolveu da outra vez". Mesmo truque do teste de key
store no POST.

⚠ **O componente atravessa o link do host em claro.** É a maior distância
entre este projeto e um HSM de verdade, onde ele entraria por teclado local
ou cartão do custodiante. Aqui a porta é uma só. Está documentado no
`cmd.c`, no `hsmtool.py` e no manual — e não escondido.

⚠ **`tb_uart_frame` roda com `CLK_HZ = 100_000`** para encolher o divisor do
debounce (`CLK_HZ/100`); com os 100 MHz reais, cada transição de botão
custaria 10 ms de simulação e a cerimônia sozinha passaria de 100 ms. O
filtro de ressalto continua verificado no valor de produção pelo
`tb_debounce`.

### Display de estado (`rtl/top/seg_display.v`)

Soletra `Uni`/`Aut`/`OPE`/`tPr` em três dígitos multiplexados a 600 Hz por
dígito (quadro completo a 200 Hz), e o **ponto decimal acende enquanto o
dual control está satisfeito**.

Nasceu de uma pergunta de bancada — *"que botões?"* — e não de um item de
plano. A ferramenta mandava segurar SW2 e SW5, e o operador não tinha como
identificá-los. Descrever por posição resolveu metade; a outra metade é o
dispositivo responder por si.

**Interface com o firmware, e por que é tão estreita:**

```
gpio_out[5:4]   estado (hsm_state_t)
gpio_out[6]     dual control satisfeito AGORA
```

O display **não lê a máquina de estados**. Um caminho de hardware até a
estrutura de estado seria caminho de hardware até o que está ao lado dela na
DMEM — e ótico é o único canal do dispositivo que não aparece numa captura
de UART, então é onde um vazamento passaria despercebido por mais tempo.

⚠ **`dualctl_pronto()` não autoriza.** É consulta pura, existe só para o
ponto decimal. Decidir com ela se um comando pode rodar abriria uma janela
entre a pergunta e a ação — TOCTOU. Quem autoriza é `dualctl_autoriza()`,
que consome o rearme.

⚠ **O `default` do decodificador de glifos é `tPr`.** Estado corrompido tem
de aparecer como comprometido, não como `Uni` nem apagado. Falhar para o
lado seguro vale também para o painel.

**A medida que faltava, e que ninguém notou que faltava.** A verificação de
2026-08-09 desenhou `222` nos três dígitos ao mesmo tempo: confirma
polaridade e mapeamento de segmento, e **não distingue ordem** — três dígitos
iguais são iguais em qualquer ordem. O experimento parecia ter coberto o
display inteiro e deixou um TBD aberto em silêncio. Fechou em 2026-08-26
desenhando `123`, com a varredura vindo **do host** (`0xAA <seg> <an>` em
laço), porque o `rtl/diag/` aplica o mesmo glifo a todos os dígitos
habilitados. `seg_an_o[0]` é o da esquerda.

⚠ **Cintilação e ghosting daquela medida eram do instrumento**, não do
projeto: a varredura pela USB tem jitter de milissegundos e não apaga entre
dígitos. O `seg_display.v` tem contador determinístico e janela de
apagamento de ~104 µs por troca.

✅ **Validado em hardware, 2026-08-26.** Mostra `Uni` legível e na ordem
certa, e o ponto decimal acende ao apertar os dois botões.

Vale registrar **o que** essa confirmação fecha, porque não é o display: é a
única corrente do projeto que nenhum testbench pode percorrer inteira.

```
dualctl_pronto()  ->  gpio_out[6]  ->  dual_ok_i  ->  segmento dp
       ^                                                    |
       |                                                    v
   os dois botoes fisicos  <----  o dedo do operador  <---- o olho
```

A simulação verifica cada elo, e não fecha o círculo: o botão que o firmware
lê é o mesmo que a mão apertou, e o dígito que acendeu é o que o olho
esperava. Software nenhum detecta uma troca aí. É o mesmo argumento pelo qual
a ordem física dos botões teve de ser medida, um nível acima.

⚠ **Custo em timing: −0,133 ns.** A folga foi de +0,380 para **+0,247 ns**.
Ainda fecha, com 0 endpoints falhando — mas a série é +0,637 → +0,487 →
+0,380 → +0,247, e ela só desce.

### Key blocks ANSI X9.143 / TR-31 versão D (`fw/src/tr31.c`, `host/tr31.py`)

O formato inteiro, **escrito duas vezes**: em C dentro da fronteira, em
Python no host sobre uma biblioteca de terceiros. As duas foram escritas
para discordar — se compartilhassem o AES, concordariam sobre um erro no
AES sem nunca discordar.

```
cabeçalho(16 ASCII) || hex(corpo cifrado) || hex(MAC de 16 bytes)

D 0144 D0 A B 00 E 00 00
| |    |  | | |  | |  +-- reservado
| |    |  | | |  | +----- blocos opcionais
| |    |  | | |  +------- exportabilidade
| |    |  | | +---------- versão da chave
| |    |  | +------------ modo de uso
| |    |  +-------------- algoritmo
| |    +----------------- uso
| +---------------------- comprimento total, 4 dígitos ASCII
+------------------------ versão do formato
```

Corpo em claro: `comprimento em BITS (2 bytes) || chave || enchimento`.

**As três decisões que o formato toma**, e que valem mais que o código:

1. **Duas subchaves, não uma.** KBEK cifra, KBAK autentica, as duas saem
   da KBPK por CMAC com um campo de **propósito** diferente na entrada
   (`0x0000` e `0x0001`). Se fossem a mesma, um oráculo de MAC seria um
   oráculo de cifragem de graça.
2. **O cabeçalho entra no MAC.** São 16 bytes de ASCII legível — e
   autenticados. Sem isso, quem nem consegue decifrar o corpo edita
   `exportabilidade` de `N` para `E` e devolve o bloco: o criptograma não
   muda, a **política** muda. Chave protegida sob metadado desprotegido
   não está protegida.
3. **O MAC é o IV do CBC.** Não há IV para transmitir, e é
   MAC-then-encrypt sobre o texto claro — que é o que permite recusar um
   bloco adulterado *antes* de acreditar no que decifrou.

⚠ **As funções em C recebem KBEK e KBAK, nunca a KBPK.** A KBPK deste
dispositivo é a LMK, e a LMK não sai do keystore. `tr31_deriva()` existe
para o caso em que a KBPK está legitimamente em mãos — hoje, só o KAT.
Quem for embrulhar sob a LMK vai derivar as subchaves *por dentro* do
keystore, na fase dos comandos.

⚠ **O enchimento não é gerado dentro de `tr31_embrulha()`.** É parâmetro.
Uma função de formato que puxa entropia por conta própria é uma função
impossível de testar de forma determinística — e o POST precisa dar o
mesmo resultado a cada boot.

**As duas implementações são mais estritas que a norma em dois pontos, de
propósito e nas duas ao mesmo tempo:**

- hexadecimal **maiúsculo** e só. `bytes.fromhex` aceitaria minúscula de
  graça e o firmware não — e aí a mesma chave teria duas grafias de bloco,
  com MACs diferentes, porque o cabeçalho entra no MAC como *bytes*.
- **blocos opcionais são recusados**, não ignorados. Um bloco opcional
  ignorado ainda estaria no MAC: o MAC fecharia e o dispositivo teria
  aceitado um campo que não entendeu. É assim que uma restrição de uso
  desaparece sem ninguém notar.

#### A procedência do vetor, que não é como a dos outros

⚠ **Não existe KAT do CAVP para este formato, e não há como existir:** o
CAVP valida **algoritmo**, e X9.143 é **formato**. A norma que traz o
exemplo é paga.

O vetor em `vectors/tr31/` é **valor conhecido de terceiros** — do arquivo
de testes de uma biblioteca MIT, da função que o próprio autor chama de
*"known values from 3rd parties"*. Está fixado por **commit** e por hash
em `vectors/MANIFEST.txt` (fixar em `master` seria fixar num alvo móvel, e
um vetor cujo hash muda sozinho não é vetor, é expectativa).

O que ele vale: um número que este projeto não escolheu, produzido por uma
implementação independente, e que exercita derivação + CBC + CMAC de uma
vez. O que ele não é: autoridade.

⚠ **E ele só cobre DESEMBRULHAR.** Embrulhar não tem KAT possível — o
enchimento é aleatório por norma, então a operação não é determinística.
Essa direção é coberta por ida-e-volta.

#### Como está verificado

| Onde | O quê |
|---|---|
| `host/test_tr31.py` | vetor externo, ida e volta (16/24/32 bytes), derivação, **bit trocado em todas as 112 posições do bloco**, 12 formas de bloco malformado, e o ataque literal de reescrever a exportabilidade |
| POST (`tr31_selftest()`) | vetor externo, cabeçalho adulterado recusado, ida e volta — a cada boot, no silício |
| `tb_tr31_block` | o C rodando no NEORV32 real, cobrado pela UART |

✅ **Validado em hardware, 2026-08-29.** Gravado na flash, o POST responde
com os **oito** testes verdes, `key block X9.143` entre eles — o vetor de
terceiros desembrulhado pelo C, no AES do coprocessador, no silício. É a
parte que a simulação não cobre: aqui o CBC e o CMAC rodam sobre o
coprocessador de verdade, e o vetor externo não teria como fechar se algum
elo do caminho estivesse trocado.

```
python3 host/hsmtool.py post
  AES-256 · SHA-256 · HMAC-SHA-256 · CTR_DRBG · TRNG
  CMAC-AES-256 · key store · key block X9.143      todos ok
```

**O teste que vale mais que os outros** é o do bit trocado em todas as
posições: uma implementação que "esqueceu" de incluir o cabeçalho no MAC
passa no vetor e na ida-e-volta, e falha só ali.

**Disciplina de sabotagem** — o suite foi verificado quebrando o código de
propósito, porque um teste que nunca reprovou não se sabe se testa:

| Sabotagem | Quem pegou |
|---|---|
| cabeçalho fora do MAC | 4 verificações, incluindo o vetor externo |
| comparação de MAC sempre verdadeira | a varredura de bits (posição 5 em diante) |
| `KBEK = KBAK` (mesmo propósito) | o vetor externo **e** a checagem de separação |

⚠ **O que ainda NÃO está provado é o critério de aceitação da fase:**
*"parser Python e firmware C concordam em 100 blocos aleatórios"*. Isso
exige entregar um key block ao dispositivo e receber outro de volta, e os
comandos `IMPORT_KEY` (0x24) e `EXPORT_KEY` (0x23) ainda não existem. Hoje
o acordo entre as duas implementações está provado **só no ponto onde as
duas tocam o mesmo número externo**. Está dito assim no cabeçalho do
`tb_tr31_block` também: um testbench que se descrevesse como "C e Python
concordam" rodando só o lado C mentiria sobre a própria cobertura.

#### Custo

**Fabric: zero.** É firmware, e a IMEM é ROM de tamanho fixo no bitstream —
os relatórios saíram byte a byte idênticos aos da cerimônia de LMK: 7 427
LUTs, 7 495 FF, BRAM 7, DSP 0, **WNS +0,247 ns**, 0 endpoints falhando. A
série de folga (+0,637 → +0,487 → +0,380 → +0,247) não se moveu.

**Boot: 5,94 → 8,31 ms.** O teste de key block custa 2,37 ms a cada
energização. Medido na simulação, que é onde o número é comparável.

**IMEM: 10 444 → 12 700 bytes** dos 16 384 (77,5%). São +2 256 bytes, e
essa é a conta que aperta agora — a folga que resta tem de cobrir o
zeroize e os cinco comandos que faltam. BSS não mudou (2 436): o módulo
usa só pilha.

⚠ **Os oito bits da máscara do POST acabaram.** `KAT_FALHA_TR31 = 0x80` é
o último, e o `SELFTEST` devolve a máscara em **um byte**. Um nono teste
sumiria na conversão e o dispositivo reportaria `KAT_OK` sobre um teste
que reprovou — a pior falha possível num POST. Há um `typedef` em
`fw/include/kat.h` que quebra o build em vez disso.

### Zeroize (`0x2F`, `fw/src/keystore.c`, `sim/tb/tb_zeroize.v`)

Apaga os 16 slots e a LMK, **e prova que apagou**. Foi o item que mais
rendeu por linha escrita, e não pelo apagar — pelo provar.

#### O defeito que apareceu no caminho

⚠ **O autoteste sob demanda sempre foi destrutivo, e o estado não
acompanhava.** `SELFTEST` → `kat_post()` → `kat_keystore()` →
`keystore_init()` → `lmk_zeroiza()`: o teste de função crítica do key store
instala e apaga chaves de verdade e termina com o store vazio, LMK
inclusive. O dispositivo continuava dizendo `OPERATIONAL`.

O operador rodava um diagnóstico e o dispositivo passava a **mentir sobre
ter chave** — estado e realidade divergindo, que é a pior coisa que uma
máquina de estados pode fazer.

Não dá para consertar tornando o autoteste inofensivo: um teste que
poupasse a LMK exercitaria um caminho diferente do que roda no boot, e
deixaria de valer. O conserto é tornar a destruição **visível** —
`h_selftest` zeroiza explicitamente e desce para `UNINITIALIZED`. O
`hsmtool` avisa, e `tb_zeroize` prende o comportamento.

#### Provar que apagou, sem acreditar em quem apagou

"Chamei a função de apagar" não é o mesmo que "apagou", e a diferença é
invisível de fora: um `wipe()` que o compilador eliminou, um campo novo
fora do laço, um slot fora do intervalo — os três falham em **silêncio**.

São duas camadas, e elas são independentes de propósito:

| Camada | O que faz | Limite |
|---|---|---|
| `keystore_prova_zeroizacao()` | varre a região byte a byte — slots, **padding das structs**, LMK e KCV. Roda no POST | auto-atestação: o mesmo código dizendo que funcionou |
| `tb_zeroize`, via **KCV** | cerimônia → KCV `46F2FB` → `ZEROIZE` → mesma cerimônia → `46F2FB` de novo | só alcança a LMK, não os 16 slots |

⚠ **A prova por KCV é criptografia provando memória.** A LMK acumula por
XOR; se a zeroização deixasse um único bit em `g_lmk`, a cerimônia seguinte
acumularia sobre o resíduo e o KCV seria outro — porque o KCV é AES da
chave inteira. E o valor esperado é **vetor oficial do NIST**
(`ECBKeySbox256`, cujo `PLAINTEXT` é um bloco de zeros, o que faz o
criptograma *ser* o KCV daquela chave), não "o que o firmware devolveu da
outra vez".

⚠ **`volatile` na varredura não é enfeite.** Sem ele, o compilador pode
**provar** que acabou de zerar aquela memória e dobrar o laço inteiro em
`return 1` — a prova viraria uma constante que passa sempre, inclusive
quando a zeroização falhou.

⚠ **A varredura só vale porque `keystore_init()` apaga a área como BYTES
CRUS**, e não campo a campo. Com o padding das structs intocado, a
varredura leria lixo indeterminado e não provaria nada. Efeito colateral
bem-vindo: um campo novo em `slot_t` entra já zerado sem ninguém lembrar.

⚠ **Não dá para ler a Block RAM do testbench.** O array é um
`signal spram : ram_t` **VHDL** dentro de `neorv32_prim_spram`, e o
testbench é Verilog — a mesma fronteira que o xsim recusou em
`tb_post_tamper` (`XSIM 43-4289`). Está dito no cabeçalho do teste: um
testbench que se descrevesse como "varri a BRAM" quando na verdade
perguntou ao dispositivo mentiria sobre a própria cobertura.

#### As três decisões do comando

**Permitido em TODOS os estados, `TAMPERED` inclusive** — é o único com
essa máscara. Um dispositivo que não se deixa apagar não garante nada além
de que a chave continua lá, e em `TAMPERED` é exatamente quando se quer
apagar. De lá não se **sai**: apaga e continua comprometido, e isso sai de
graça porque `state_set()` já é absorvente.

**Dual control sim — e a assimetria com o gatilho automático é o ponto.**
O autoteste reprovado apaga sem pedir autorização a ninguém. Pessoas
precisam de duas pessoas; um dispositivo que se descobre comprometido não
precisa de ninguém. Se o gatilho automático exigisse dual control, bastaria
não haver operador na sala para a chave sobreviver ao comprometimento.

**`exportabilidade='N'` não protege contra apagar** — protege contra a
chave *sair*. Uma chave que o dispositivo não pudesse apagar seria uma
chave que ele não controla.

E a recusa por falta de dual control **não gasta o rearme**: se gastasse,
um host hostil impediria a zeroização chamando o comando em laço, e o dual
control viraria uma forma de *proteger* a chave de quem tem direito de
apagá-la.

#### `wipe_padrao()` — duas passadas, e a honesta razão

0xAA, depois zeros. **Para SRAM a segunda passada é a que conta**, e dizer
o contrário seria repetir folclore de disco magnético. A primeira existe
por um motivo diferente e concreto: se a zeroização for **interrompida**
(reset, queda de alimentação), o que sobra é padrão, não meia chave.

#### A sabotagem, e o que ela encontrou antes de encontrar o que procurava

Duas sabotagens deliberadas, porque um teste que nunca reprovou não se sabe
se testa:

| Sabotagem | Quem pegou |
|---|---|
| a LMK não é apagada | a varredura do firmware: `ZEROIZE` → `INTERNAL_ERROR`, dispositivo vai a `TAMPERED` |
| a LMK não é apagada **e** a varredura do firmware sempre diz "limpo" | **só o KCV**: `dc95c0` em vez de `46F2FB`, um erro, no lugar exato |

A segunda linha é a que justifica a prova por KCV existir. Sem ela, uma
varredura mentirosa passaria despercebida.

⚠ **E o valor `dc95c0` diz mais do que pareceu na hora.** Ele é o KCV de uma
chave de **256 bits em zero** — os três primeiros bytes de
`AES-256(chave=0, bloco=0)`, o mesmo `dc95c078a24089…` que o comando `aes`
devolve num dispositivo recém-apagado.

Por quê: com a zeroização sabotada, o acumulador guardava a LMK anterior, e a
cerimônia seguinte usava **os mesmos três componentes** — XOR do mesmo valor
sobre ele mesmo dá zero. A chave mestra não ficava "com resíduo". Ficava
**inteiramente zerada**, que é o pior desfecho possível: perfeitamente
previsível, e com um KCV de aparência tão inocente quanto qualquer outro.

O teste do KCV não pegou um detalhe de implementação. Pegou a diferença
entre uma chave mestra e nenhuma.

⚠ **Mas a primeira tentativa das duas sabotagens PASSOU**, e a causa não
era o teste: **`scripts/sim.sh` nunca recompilou o firmware.** Ele conferia
que `fw/neorv32_imem_image.vhd` existia e seguia — então editar C e rodar a
simulação validava o binário anterior. O comentário no próprio arquivo
alertava contra "verde e mentiroso" ao explicar o cache; o buraco estava ao
lado dele.

Um teste que nunca vê o código em teste é pior que teste nenhum. Corrigido
em 2026-08-29: `sim.sh` compara a data de `fw/src/*.c`, `fw/include/*.h` e
`fw/Makefile` com a da imagem e recompila sozinho.

⚠ **Consequência retroativa, e vale ser explícito:** todas as simulações
anteriores rodaram contra imagens compiladas à mão logo antes, então
estavam corretas — mas por disciplina de quem digitou, não por garantia da
ferramenta.

E um defeito de relatório que só a sabotagem expôs: o testbench imprimia
"nenhum bit da LMK anterior sobreviveu" na linha seguinte ao `FAIL` do KCV.
Anunciar sucesso ao lado de uma falha é como um teste engana quem lê o log
em diagonal. As mensagens de sucesso agora dependem de o bloco ter passado.

#### Validado em hardware, 2026-08-30

Gravado na flash. O POST responde com os oito testes verdes — a varredura
de prova roda a cada energização, no silício — e `zeroize` sem os botões é
recusado com `NOT_AUTHORIZED`.

```
post      8 de 8 ok
zeroize   STATUS_NOT_AUTHORIZED (0x21) sem dual control
```

⚠ O caminho que **falta** confirmar na bancada é o `ZEROIZE` bem-sucedido:
ele exige alguém com dois dedos na placa. A simulação cobre o comando
inteiro; o que só a mão fecha é o mesmo elo do display — o botão que o
firmware lê é o mesmo que a mão apertou.

#### Custo

**POST: 8,31 → 9,09 ms.** A varredura de prova custa 0,78 ms por boot.
(Hoje o POST está em **9,25 ms** — a diferença veio da zeroização por duas
passadas alcançar a área inteira dos slots, e não só os campos de chave.)
**IMEM: 12 700 → 12 860 bytes** dos 16 384 (78,5%).

⚠ **`ZEROIZE` é o comando que mais precisa de log de auditoria, e o log
ainda não existe** — `fw/src/audit_log.c` continua um placeholder de uma
linha. Anotado no handler.

### Comandos de chave — `0x22`–`0x25`

`GEN_KEY` · `EXPORT_KEY` · `IMPORT_KEY` · `KEY_INFO`. Os quatro têm a
**mesma máscara** (`ST_OPER`) e **nenhum exige dual control**.

#### Por que nenhum exige dual control

A intuição puxa para o lado errado, então vale escrever: **dual control é
para cerimônia, não para operação.** Carregar a chave mestra e ativar o
dispositivo são eventos raros, com gente na frente da placa. Gerar,
exportar e importar chave é o que um HSM faz o dia inteiro — exigir dois
dedos ali não aumentaria segurança nenhuma, só garantiria que ninguém usa
o equipamento. E um controle que impede o uso legítimo é desligado no
primeiro dia ruim.

O que protege estes comandos é estrutural: a chave nunca sai em claro, o
key block é autenticado sobre cabeçalho **mais** corpo, e
`exportabilidade` decide quem pode sair.

#### O contraste com a fase 2, que é o que a fase inteira ensina

`AES_ENC` recebia a chave **no payload**, vinda do host. `GEN_KEY` deixa o
host escolher os **metadados** e nunca ver o material. Os dois não podem
coexistir com chave de verdade no dispositivo — e não coexistem, sem uma
linha de código desligando nada: a máscara de `AES_ENC` é `ST_UNINIT`.

#### As decisões que carregam peso

**A LMK não aparece em nenhum handler.** `lmk_deriva_kb()` devolve KBEK e
KBAK derivadas por CMAC; a chave mestra não sai de `keystore.c`. Se
`h_export_key` precisasse dela, existiria um `lmk_exporta()` — e a partir
daí "a LMK não sai daqui" vira convenção. A derivação não é inversível:
quem tiver as subchaves não volta à LMK.

**`IMPORT_KEY` devolve UM código para toda recusa.** Bloco malformado,
hexadecimal inválido, MAC errado e comprimento impossível são todos
`BAD_PARAM`. É o comando mais exposto dos quatro — um atacante manda
blocos forjados em laço e cada resposta é informação. Distinguir em qual
etapa parou é o oráculo de padding clássico: o atacante não precisa da
chave, precisa que a vítima diga onde a validação falhou.

**Os metadados do bloco importado vêm DO BLOCO**, autenticados. É a razão
de o cabeçalho X9.143 entrar no MAC: sem isso, trocar um `N` por um `E`
promoveria a chave na importação.

**`KEY_INFO` com handle inválido e com slot vazio devolvem o mesmo
código.** Separar permitiria mapear o key store sem instalar nada.

**Duas exportações do mesmo slot dão blocos diferentes.** O enchimento é
aleatório, e isso não é desperdício: dois blocos idênticos denunciariam
que a mesma chave saiu duas vezes.

#### Um erro meu, e como ele foi pego

A primeira versão distinguia "store cheio" de "cabeçalho inválido"
testando **se o último slot estava ocupado**. Está errado: os slots são
alocados no primeiro livre, então apagar um do meio deixa buraco — o
último pode estar ocupado com o store longe de cheio. Trocado por
`keystore_livres()`.

⚠ **E o limite que o ciclo de teste expôs: não existe comando para apagar
um slot.** `keystore_apaga()` existe no firmware e não tem opcode. O key
store é gravável 16 vezes, e depois só o `ZEROIZE` — que exige os dois
botões — libera espaço.

Consequência direta no critério de aceitação: **a direção Python → C não
chega a 100 blocos**, para em 16. O `hsmtool keycycle` contorna metade
disso — na direção C → Python usa **um slot só**, exportando N vezes, e
cada exportação dá um bloco diferente por causa do enchimento aleatório.

Fechar o critério exige um `DELETE_KEY`, que é um quinto opcode e está
fora do que foi pedido. Fica registrado aqui.

#### `hsmtool keycycle` — a validação mútua sobre blocos de verdade

Até aqui as duas implementações do X9.143 concordavam sobre **um vetor**.
O `keycycle` as faz concordar sobre blocos que o dispositivo acabou de
produzir, nas duas direções:

```
C -> Python   o dispositivo exporta N blocos; o Python desembrulha
              todos e confere a chave contra o KCV
Python -> C   o Python embrulha chaves que ele escolheu; o dispositivo
              importa e o KCV que volta é o que o Python calculou
```

Sem a segunda direção o acordo seria de mão única — o C poderia estar
errado do mesmo jeito nas duas pontas e ninguém notaria.

⚠ **`keycycle` precisa da LMK no host**, e isso é o brinquedo aparecendo.
Um HSM de verdade nunca entrega a chave mestra à ferramenta; aqui os
componentes foram digitados no host mesmo, então ele pode reconstruí-la
por XOR. É a mesma distância já registrada na cerimônia, e por isso o
`--lmk` é obrigatório e explícito em vez de escondido.

#### Validado em hardware, 2026-08-30

Sessão de bancada completa, com os botões apertados por gente.

```
cerimônia          3 componentes, KCVs EABFCA · 7FA68A · 9C9DA5
                   KCV da LMK 7B1D2F  -- PREVISTO no host antes de perguntar
activate           OPERATIONAL; display passa de Aut para OPE
aes (fase 2)       WRONG_STATE -- sumiu sozinho, pela máscara
gen-key            handle 1, KCV 8650D9
export-key 1       D0144D0AB00E0000... (144 caracteres)
export-key 1       de novo: difere em 118 dos 144 caracteres
import-key         handle 2, KCV 8650D9  -- a mesma chave voltou
import 1 char      BAD_PARAM
gen-key --exp N    handle 3; export-key 3 -> NOT_EXPORTABLE
keycycle -n 100    C -> Python: 100 blocos, 100 distintos, todos abertos
                   Python -> C: 12 (parou por falta de slot)
```

⚠ **O KCV da LMK foi PREVISTO, não conferido depois.** Com os três
componentes anotados, o host calculou `XOR` e o AES de um bloco de zeros e
chegou a `7B1D2F` **antes** de perguntar ao dispositivo — que respondeu o
mesmo. O XOR aconteceu dentro do firmware, byte a byte, e o AES no
coprocessador do fabric; qualquer erro de ordem, de endianness ou de um byte
no acumulador daria um KCV completamente diferente.

✅ **Os três estados operacionais estão validados em hardware**: `Uni`
(2026-08-26), `Aut` e `OPE` (2026-08-30), lidos no display de 7 segmentos.
Falta só o `tPr`, que por natureza só aparece quando algo reprova.

⚠ **E o `12 de 100` é a lacuna do `DELETE_KEY` medida**, não estimada: cada
importação gasta um slot, e não há como devolvê-lo.

E o `zeroize` fechou a sessão, com os dois botões:

```
zeroize       apagado, estado UNINITIALIZED; display volta a Uni
lmk-status    0 de 3
key-info 1    WRONG_STATE  -- o slot nao existe mais
gen-key       WRONG_STATE  -- os comandos de chave sumiram
aes ...       dc95c078...  -- e os da fase 2 VOLTARAM a responder
```

A escada desceu inteira e a tabela de comandos girou junto, **sem uma linha
de código ligando ou desligando nada**. É a máscara de estados fazendo o
trabalho, e é a demonstração mais limpa que o projeto tem de por que ela
existe.

#### Custo

**IMEM: 12 860 → 13 768 bytes** dos 16 384 (**84,0%**). São +908 bytes para
quatro comandos, e a folga que resta — 2 616 bytes — tem de cobrir o
`DELETE_KEY`, as versões por handle dos comandos da fase 2 e o log de
auditoria. **É o recurso que aperta agora**, não o fabric.

Série da fase: 10 444 (cerimônia) → 12 700 (key block) → 12 860 (zeroize)
→ 13 768 (comandos de chave).

---

## O que falta, na ordem

### 1. `DELETE_KEY` — o opcode que falta, e que só apareceu ao testar

Todos os comandos previstos para a fase estão prontos:
`0x20 LMK_LOAD_COMPONENT` · `0x21 LMK_STATUS` · `0x22 GEN_KEY`
· `0x23 EXPORT_KEY` · `0x24 IMPORT_KEY` · `0x25 KEY_INFO`
· `0x26 SET_STATE` · `0x2F ZEROIZE`.

Mas **falta um que não estava previsto**: apagar um slot. `keystore_apaga()`
existe no firmware, é exercitado pelo POST, e não tem opcode. O key store é
gravável 16 vezes e depois só o `ZEROIZE` libera espaço — e ele exige os
dois botões, o que num uso normal é absurdo.

Isso bloqueia o critério "100 blocos aleatórios" na direção Python → C.
Checklist, para quando for escrito:

- estados: `ST_OPER`
- dual control: **não** — é operação, não cerimônia. Apagar UM slot é
  reversível pela reimportação do key block; apagar TUDO não é, e é por
  isso que o `ZEROIZE` pede dois dedos e este não pediria
- vazamento: apagar um handle que não existe e um que existe têm de
  devolver o mesmo código, senão é um mapa do key store
- log de auditoria: obrigatório, quando o log existir

### 2. Questão em aberto — a LMK montada não é verificada

*Levantada em 2026-08-31, a partir de uma pergunta sobre o valor `dc95c0`.
**Não decidida.***

`lmk_componente()` acumula por XOR e conta; `lmk_completa()` só verifica se
chegaram três. **Não há checagem nenhuma do valor montado.**

Consequência: um terceiro custodiante que conheça os outros dois componentes
pode escolher o dele para forçar a LMK a qualquer valor, inclusive **zero**.
Ele não ganha conhecimento novo — se sabe os outros dois, já sabia a LMK —
mas ganha uma chave mestra **previsível e reproduzível em qualquer
dispositivo**, sem que nada reclame.

A única defesa hoje é o operador reconhecer que `DC95C0` é o KCV de uma
chave zerada, o que ninguém faz de cabeça.

**A favor de implementar:** são poucas linhas, no ponto em que o terceiro
componente entra; um HSM de verdade recusa chave mestra fraca; e a mesma
checagem pega o caso banal de um componente esquecido em zeros.

**Contra, ou pelo menos a favor de pensar antes:** "chave fraca" não tem
definição óbvia além do caso todo-zero. Recusar só o zero é pouco e dá falsa
sensação de cobertura; recusar mais exige decidir o quê, e critérios de
chave fraca mal escolhidos já reprovaram chaves boas em sistemas reais.

### 3. Questão em aberto — os comandos com chave em claro

*Levantada em 2026-08-31 pelo Flavio, revisando o resultado do `zeroize`.
**Não decidida** — uma implementação foi feita e revertida a pedido.*

`AES_ENC` (`0x10`), `AES_DEC` (`0x11`) e `HMAC` (`0x13`) recebem a **chave no
payload** e respondem só em `UNINITIALIZED`.

**O argumento que estava no código** era que chave em claro não pode
coexistir com chave de verdade — correto, e é o argumento fraco.

**O argumento forte, que só apareceu na discussão:** um comando que recebe
chave em claro faz material de chave **atravessar a fronteira na direção de
entrada**, e isso é errado em `UNINITIALIZED` exatamente tanto quanto em
`OPERATIONAL`. O defeito não é de estado, então **nenhuma máscara conserta —
só a remoção**.

E há a parte mensurável: o critério de aceitação da fase é *"a captura da
UART não contém nenhum byte de chave em claro"*. Enquanto eles existirem,
esse critério **não pode passar** — ou passa com uma exceção que o esvazia.

⚠ **Nota sobre a formulação, porque a distinção importa:** esses comandos
não dependem de chave *armazenada*. Eles usam a chave que o chamador
mandou, e não consultam nada interno. Então o raciocínio "está vazio, logo
não deveria conseguir" não se aplica a eles — aplica-se a
`GEN_KEY`/`EXPORT_KEY`/`IMPORT_KEY`/`KEY_INFO`, que **já** recusam em
`UNINITIALIZED` pela máscara.

**Contra a remoção pura:** o dispositivo fica sem caminho nenhum para AES
até as versões por handle existirem. Um meio-termo é escrever as
substitutas primeiro e apagar as antigas depois, sem intervalo.

**Onde a primitiva crua deveria morar, se for útil:** no bitstream de
diagnóstico (`rtl/diag/`), que não é build de produção.

Medido durante a tentativa revertida: remover os três libera **260 bytes**
de IMEM.

### 4. Usar chave por handle

A outra metade do item 3, e ela vale por si mesmo: **não existe forma de
usar uma chave guardada**. O key store instala, exporta e importa; não há
comando que diga "cifre isto com o slot 2".

É o que fecha o critério "gerar → exportar → reimportar → **usar em AES**:
resultado idêntico". Hoje o ida-e-volta é provado pelo KCV, que é forte
(AES da chave inteira sobre um bloco de zeros) mas não é *usar*.

`keystore_usa_aes()` já existe e já faz a parte difícil: carrega a chave no
coprocessador, **não devolve os bytes**, e recusa se o `modo` do slot não
permitir a operação pedida. Falta só o comando por cima.

### 5. Log de auditoria

`fw/src/audit_log.c` e `host/audit.py` continuam placeholders de uma linha.
O `ZEROIZE` é o comando que mais o pede, e o comentário do handler diz isso.

---

## Decisão de rumo que afeta esta fase

O formato de key block está **fixado em ANSI X9.143**, não num TR-31
genérico (`PLANO.md`, "Alvo declarado"). O modelo de referência é a
categoria HSM de pagamento; a documentação não nomeia fabricante nem
produto, e nada vem de manual proprietário. Ver `THIRD-PARTY.md`.

---

## Critérios de aceitação (`PLANO.md` §4)

- [x] Cerimônia de 3 componentes com KCV conferido a cada passo
- [x] `LMK_LOAD_COMPONENT` rejeitado sem os dois botões — e também com os
      botões **segurados** desde a autorização anterior, que é o caso que a
      fita adesiva cobriria
- [~] Gerar chave → exportar → reimportar: **provado pelo KCV**
      (`tb_keystore`). O "usar em AES" depende dos comandos por handle,
      que ainda não existem
- [~] Parser Python e firmware C concordam em 100 blocos aleatórios —
      `hsmtool keycycle`. Fecha na direção **C → Python** (um slot,
      N exportações, enchimento aleatório dá N blocos distintos); na
      direção **Python → C** para em 16, por falta de `DELETE_KEY`
- [x] Alterar 1 bit do header ou do corpo → MAC inválido — provado nas
      112 posições do bloco (`host/test_tr31.py`) e no POST do firmware.
      Falta o "import recusado", que depende do comando
- [x] Chave marcada `exportabilidade='N'` não sai, por nenhum caminho —
      `tb_keystore` gera uma `'N'` e o `EXPORT_KEY` devolve
      `NOT_EXPORTABLE`. Há um único caminho para os bytes
      (`keystore_exporta()`), e é ele que consulta o campo
- [x] `ZEROIZE` apaga, e a prova é independente do firmware — o KCV da
      cerimônia seguinte tem de voltar a bater com o vetor do CAVP
- [ ] Captura da UART durante a suíte inteira **não contém nenhum byte de
      chave em claro**

O último é o que fecha a fase, e é o único que não se prova lendo código.
