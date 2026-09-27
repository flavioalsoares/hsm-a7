# Fase 3 — notas de implementação

Objetivo da fase (`PLANO.md` §4): **hierarquia de chaves**. É o coração do
projeto — a partir daqui o dispositivo deixa de ser uma caixa de primitivas
e passa a guardar chave.

Estado: **em andamento.** CMAC, key store, a cerimônia de LMK, o key block
X9.143, o zeroize, os comandos de chave `0x22`–`0x25`, o uso por handle
(`0x27`/`0x28`) e o MAC por handle (`0x29`/`0x2A`) prontos.

⚠ **Nenhum comando deste dispositivo aceita mais chave em claro** — os três
da fase 2 que aceitavam foram removidos, cada um depois de o substituto
existir.

Prontos também o `DELETE_KEY` (`0x2B`) e a formação de chave de trabalho
por componentes (`0x2C`) — nenhum dos dois estava no plano; os dois
apareceram **usando** o dispositivo.

⚠ **Falta o log de auditoria, e ele não cabe mais na IMEM** (1 548 bytes
livres). Passa a ser item de Fase 4, junto com a persistência — que é onde
ele sempre pertenceu: um log que não sobrevive ao desligamento não é log de
auditoria.

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

### Usar a chave guardada (`0x27` · `0x28`, `fw/src/aes_modos.c`)

Até aqui o dispositivo sabia **guardar, exportar e importar** chave, e não
sabia **usá-la**. Um cofre que não deixa trabalhar com o que guarda é um
depósito.

```
0x27 ENCRYPT   handle(1) || iv(16) || dados  ->  dados cifrados
0x28 DECRYPT   handle(1) || iv(16) || dados  ->  dados em claro
```

#### A função de modo não tem parâmetro de chave

Essa é a decisão que carrega o resto. `aes_cbc()` opera sobre a chave que
**já está** carregada no coprocessador — não há parâmetro de chave, então
não há como a função de modo ver material de chave nem deixá-lo num buffer
esquecido.

Quem carrega é quem tem direito:

| | |
|---|---|
| `keystore_usa_aes()` | carrega a chave de um **slot**, e checa o `modo` antes. É o caminho dos comandos de operação |
| `hsm_cfs_aes_key()` | carrega bytes crus. Só quem já tem os bytes legitimamente — hoje só o `tr31.c`, com as subchaves derivadas da LMK |

Consequência prática: acrescentar um comando que cifra dados **não abriu
caminho novo para chave**. O comando pede ao key store que carregue, e o key
store decide. A separação de uso vive num lugar só.

O CBC foi extraído do `tr31.c` para `fw/src/aes_modos.c` no mesmo movimento —
antes ele recebia a chave e a carregava por conta própria.

#### CBC com IV explícito, não ECB

ECB para dados é o erro que a Parte III do manual usa como exemplo: blocos
iguais viram criptogramas iguais, e a estrutura do texto claro atravessa a
cifra intacta. O IV vem de quem chama, pelo mesmo motivo do enchimento do
key block — uma função que puxa entropia por conta própria é impossível de
testar de forma determinística.

#### O que o comando é, dito no próprio handler

⚠ **É um oráculo de cifragem.** Quem tem o handle cifra e decifra o que
quiser sob aquela chave, em laço. **Não há como não ser** — é exatamente o
serviço que um HSM presta. O que ele não entrega é a chave, e é para isso
que o handle existe.

O controle real não está no comando: está no `modo` do slot, que separa
cifrar de decifrar, e no log de auditoria, que ainda não existe.

⚠ **`exportabilidade='N'` não impede usar.** Impede **sair**. Uma chave que
nunca sai e trabalha o dia inteiro é o caso mais comum de uma chave bem
configurada — e confundir os dois campos é confundir "não posso levar" com
"não posso mexer".

#### O critério de aceitação, fechado

```
[tb_keystore] CRITERIO: gerar -> exportar -> reimportar -> USAR
[tb_keystore]   os dois handles cifram identico -- e a mesma chave
[tb_keystore] decifrar devolve o texto claro
[tb_keystore] chave marcada 'E' recusa decifrar: BAD_KEY_USE
```

Os dois handles — a chave original e a que voltou do key block — cifram o
**mesmo bloco com o mesmo IV**, e os criptogramas batem. É mais forte que o
KCV: **128 bits de evidência contra 24**. O KCV prova que provavelmente é a
mesma chave; isto prova que é, bit a bit.

#### ✅ Validado em hardware, 2026-09-25

A simulação provava o critério; faltava o silício. Sessão completa de
bancada, com os botões apertados por gente.

```
KCVs previstos    componentes 749629 · 85053C · 6285D1, LMK 1DED8C
                  todos calculados no host ANTES de perguntar à placa

gen-key           handle 1, KCV C031D1
export/import     handle 2, KCV C031D1

encrypt 1         D9F91B5399080DEC363CED65B628C6F9
encrypt 2         D9F91B5399080DEC363CED65B628C6F9   <- mesmo IV, mesmo bloco
decrypt 2         00112233445566778899AABBCCDDEEFF

modo 'E'          cifra ok            decifra -> BAD_KEY_USE
exp  'N'          exporta -> NOT_EXPORTABLE   cifra ok

keycycle -n 100   C -> Python: 100 blocos, 100 distintos
                  Python -> C: 11 (parou por falta de slot)
```

⚠ **A linha do `'N'` é a distinção registrada em §5, agora medida.** Uma
chave marcada `'N'` **recusa sair e cifra normalmente**. Não poder sair é
diferente de não poder trabalhar — e é o caso mais comum de uma chave bem
configurada.

⚠ **E o `11 de 100` é o `DELETE_KEY` cobrando de novo**, um a menos que na
sessão de agosto porque os testes acima gastaram um slot. Cada importação
come um slot e não há como devolvê-lo. O número muda conforme o que se fez
antes — é lacuna, não medida estável.

#### Custo

**IMEM: 13 768 → 13 816 bytes** (84,3%). Sobram **2 568** para o
`DELETE_KEY`, o MAC por handle, a formação por componentes e o log de
auditoria — quatro candidatos para um espaço que provavelmente comporta
dois.

A série completa: 13 768 (comandos de chave) → 13 984 (usar por handle) →
13 724 (remoção do AES em claro) → 13 816 (o `HMAC` de volta).

### MAC por handle (`0x29` · `0x2A`), e o fim da chave em claro

O último comando que aceitava **chave no payload** era o `HMAC` (`0x13`).
Ele só pôde sair depois que o substituto existiu — a regra de sempre,
"escrever o substituto primeiro e apagar depois".

```
0x29 MAC_GENERATE   handle(1) || mensagem       -> tag(16)
0x2A MAC_VERIFY     handle(1) || tag(16) || msg -> vazio; o veredito é o STATUS
```

⚠ **Hoje nenhum comando deste dispositivo aceita chave em claro.** É a
frase que o `cmd.h` passou a poder dizer.

#### CMAC, não HMAC

Os slots guardam chaves **AES** (`algoritmo='A'`); usá-las para HMAC seria
a confusão de tipo que o resto do projeto passa o tempo todo evitando. CMAC
é o que a categoria usa para MAC de dados com chave AES, e já estava
validado contra o CAVP desde a fase 2.

#### Os modos de uso estavam incompletos, e isso era a lacuna de verdade

O keystore aceitava `'E'`/`'D'`/`'B'`/`'N'` — **todos do grupo de cifra**. A
X9.143 define também `'G'` (gerar MAC), `'V'` (verificar) e `'C'` (ambos).
Acrescentar os três não foi variação: era aderência que faltava.

E é o que fecha a confusão de tipo **de verdade**:

| grupo | valores | quem aceita |
|---|---|---|
| cifra | `E` `D` `B` | `ENCRYPT`/`DECRYPT` |
| MAC | `G` `V` `C` | `MAC_GENERATE`/`MAC_VERIFY` |

**Os dois grupos não se cruzam.** Uma chave `'B'` não autentica; uma `'C'`
não cifra. E dentro do grupo de MAC, `'G'` gera e **não** verifica — porque
gerar e verificar são permissões distintas, e uma chave que só gera não
deve servir de oráculo de verificação.

⚠ **Os dois parsers de X9.143 mudaram JUNTOS** — `fw/src/tr31.c` e
`host/tr31.py`. Se só um aceitasse `'C'`, um key block legítimo seria
recusado de um lado e aceito do outro: exatamente a divergência que o par
de implementações existe para pegar.

#### A chave não sai do keystore, de novo

`cmac_aes256()` precisa dos bytes, então o cálculo mora em
`keystore_cmac()` — mesmo padrão de `lmk_deriva_kb()`. Um handler que
calculasse por conta própria precisaria de `keystore_exporta()`, e aí uma
chave marcada `'N'` não poderia mais autenticar — ou `exportabilidade`
viraria um controle sobre **uso**, que não é o que ela é.

#### `MAC_VERIFY` devolve um bit, e é isso que o torna melhor que gerar

O dispositivo compara em **tempo constante, dentro da fronteira**, e
devolve o veredito no status. Ele não devolve a tag calculada para o host
comparar — isso entregaria 128 bits em vez de 1, e reintroduziria o canal
lateral que `cmac_aes256_verifica()` existe para fechar.

⚠ Vazar um bit por chamada é **inerente** ao serviço de verificação, e está
certo. O valor está em o atacante não conseguir mais que esse bit.

#### Provado em

```
[tb_keystore] MAC gerado, verificado, e tag trocada recusada
[tb_keystore] os dois grupos de modo nao se cruzam:
[tb_keystore]   'C' recusa cifrar, 'B' recusa autenticar
[tb_keystore] modo 'G': gera, e recusa verificar
[tb_uart_frame] 0x10/0x11/0x13 -> UNKNOWN_CMD: nenhum comando
[tb_uart_frame]   deste dispositivo aceita chave em claro
```

⚠ **Não validado em hardware ainda** — exige a cerimônia, que exige os dois
botões.

#### As duas dívidas que os próprios testes cobraram

O `tb_uart_frame` guardava duas armadilhas deliberadas, e as duas
dispararam quando o `HMAC` saiu:

1. um teste que cobrava que o `0x13` **ainda respondesse** — a dívida
   guardada por teste, para ser impossível esquecê-la;
2. o teste da propriedade "um comando com chave em claro para de responder
   sozinho quando existe LMK", cujo sujeito era o `HMAC`.

O primeiro foi apagado junto com a dívida. O segundo também — e não
consertado, porque era o que a própria nota dele mandava: **não há mais
nenhum comando que demonstre a propriedade, já que não há mais nenhum
comando com chave em claro.** Que era o objetivo.

Vale como método: uma reprovação futura que **significa sucesso**, com a
instrução do que fazer escrita ao lado. Sem isso, alguém veria um `FAIL` e
o "consertaria" baixando a expectativa.

#### Custo

**IMEM: 13 816 → 14 292 (MAC) → 14 192 (HMAC removido)**, 86,6%. Sobram
**2 192 bytes** para o `DELETE_KEY`, a formação por componentes e o log de
auditoria.

Fabric: zero. 7 427 LUTs, 7 495 FF, BRAM 7, WNS +0,247 ns — iguais desde a
cerimônia de LMK.

### `DELETE_KEY` (`0x2B`) e chave por componentes (`0x2C`)

Os dois últimos comandos da fase, e os dois apareceram **usando** o
dispositivo, não planejando-o.

#### `DELETE_KEY` — e uma discordância com o meu próprio checklist

`keystore_apaga()` existia desde a fase 3 e era exercitado pelo POST;
faltava só o opcode. Sem ele o key store era gravável dezesseis vezes e
depois só o `ZEROIZE` liberava espaço — e ele pede os dois botões, o que
num uso normal é absurdo.

⚠ **Sem dual control, ao contrário do `ZEROIZE`, e a assimetria é o
ponto:** apagar **um** slot é reversível — o key block daquela chave
continua existindo fora, e reimportar devolve tudo. Apagar **tudo** não é.

⚠ **Desvio do checklist que eu mesmo tinha registrado.** Ele dizia que
apagar um handle inexistente e um existente deviam devolver o **mesmo**
código, *"senão é um mapa do key store"*.

Esse mapa **já existe**: o `KEY_INFO` responde para todo handle de 1 a 16,
e quem está em `OPERATIONAL` enumera o store inteiro em dezesseis
comandos. Esconder a distinção no `DELETE` não fecha nada — e custa ao
operador saber se apagou algo ou digitou o handle errado, num comando
**destrutivo**. Slot vazio devolve `BAD_PARAM`.

A regra que continua valendo é a outra: não inventar código novo para cada
causa. "Handle fora da faixa" e "slot vazio" são o mesmo `BAD_PARAM`,
porque a diferença entre os dois não ajuda ninguém.

**E é ele que destrava o critério dos 100 blocos**: o `keycycle` passou a
devolver o slot a cada iteração, então a direção Python → C deixa de parar
em ~12.

#### Chave de trabalho por componentes — a cerimônia um nível abaixo

```
0x2C  n(1) || total(1) || uso(2) || alg(1) || modo(1) || exp(1) || comp(32)
      -> kcv_do_componente(3) || carregados(1) || total(1) || handle(1)
```

O mesmo split knowledge da LMK, aplicado a uma chave de trabalho: cada
custodiante entra com a sua parte, ninguém vê a chave inteira, e o
dispositivo monta por XOR **dentro da fronteira**.

**É o único comando de `ST_OPER` com dual control.** Os outros são
operação; este é cerimônia, e a regra vale: aperto novo a cada componente,
e a recusa **não gasta o rearme** — um host hostil não consegue consumir as
autorizações de quem está na frente da placa.

⚠ **O KCV que sai é o do COMPONENTE, nunca o do acumulado.** É o que
permite ao custodiante conferir que digitou o dele; o do acumulado seria um
oráculo sobre a chave em construção.

⚠ **A resposta tem comprimento fixo**, com `handle = 0` enquanto a
montagem não termina. Resposta curta e resposta longa distinguíveis de fora
são um canal, ainda que estreito.

⚠ **`n == 0` reinicia a montagem.** É como se abandona uma cerimônia
começada errado, sem precisar de um opcode de cancelar. E um `total`
inconsistente num `n > 0` é recusado **sem tocar no acumulado**.

#### Dois erros de ORDEM, no mesmo handler

Nenhum dos dois era de lógica — a montagem funcionava e a chave era
instalada certo nos dois casos. Ficam registrados porque a armadilha é a
mesma e ela é convidativa.

**O primeiro, pego pelo testbench.** `comp_instala()` limpa o acumulador —
de propósito, para não deixar chave montada pendurada —, e eu lia
`comp_carregados()`/`comp_total()` **depois** dela. O componente que
completava a montagem respondia *"0 de 0"* em vez de *"2 de 2"*. O handle
vinha certo, então um teste que só perguntasse "instalou?" teria passado; o
que pegou foi conferir **todos** os campos da resposta, inclusive os que
parecem decorativos.

**O segundo, pego relendo contra o comando irmão.** O `dualctl_autoriza()`
vinha **antes** da validação de sequência. Um `n` fora de ordem gastava o
**aperto do custodiante** numa requisição que ia ser recusada de qualquer
jeito. O `LMK_LOAD_COMPONENT` sempre fez na ordem certa — forma, sequência,
**depois** autorização — e eu tinha deixado a checagem de sequência dentro
do `comp_componente()`, que roda tarde demais.

> Autorização se consome no que vai **acontecer**, não no que vai ser
> rejeitado.

O teste que prende isso é mais fino que o normal: um aperto novo, um
componente com `total` inconsistente que tem de ser recusado, e **sem
soltar os botões** o componente legítimo em seguida. Se a recusa tivesse
consumido o rearme, o segundo reprovaria com `NOT_AUTHORIZED`.

⚠ **Desvio de forma em relação ao modelo comercial, e está declarado:** lá
o comando devolve a chave **embrulhada sob a LMK**. Aqui ele instala num
slot e devolve **handle + KCV**, como o `GEN_KEY` e o `IMPORT_KEY` — quem
quiser o key block chama `EXPORT_KEY`. A propriedade que importa é
idêntica; o que muda é o formato de saída, e ele segue o modelo deste
dispositivo, que é baseado em slots.

#### O acumulador é material de chave, e o resto do firmware sabe disso

`g_comp` entra no `keystore_init()` (zeroização) **e** na
`keystore_prova_zeroizacao()` (varredura byte a byte). Uma montagem
interrompida deixaria partes de uma chave de trabalho vivas na BRAM depois
de um zeroize, e a prova não veria.

E `comp_instala()` limpa o acumulador **em qualquer desfecho, inclusive na
falha**: uma chave montada pendurada seria material de chave esperando por
um comando que talvez não venha.

#### Provado em

```
[tb_keystore] DELETE_KEY: apaga, o handle morre, e o slot volta
[tb_keystore] chave montada por componentes: handle N,
[tb_keystore]   KCV 46F2FB -- vetor do CAVP, nao auto-referencia
```

⚠ **O KCV esperado da chave montada é vetor oficial do NIST.** As duas
partes do teste são escolhidas para que o XOR dê exatamente a chave do
`ECBKeySbox256` — então se o XOR dentro do firmware errar um byte, o KCV
não bate. Mesmo truque da cerimônia de LMK: o valor esperado não é "o que o
firmware devolveu da outra vez".

#### Gravados na placa, 2026-09-27

15/15 testbenches, bitstream com 0 erros e 0 critical warnings, e a flash
gravada. O que dá para provar **sozinho**, sem ninguém na bancada:

```
post                     OK, oito testes
0x2B DELETE_KEY          WRONG_STATE
0x2C KEY_FROM_COMPONENTS WRONG_STATE
0x29 MAC_GENERATE        WRONG_STATE
0x10 AES_ENC (removido)  UNKNOWN_CMD
```

⚠ **Os três primeiros são recusas, e é só isso que dá para verificar sem
os botões.** Os comandos vivem em `ST_OPER`, chegar lá exige a cerimônia,
e a cerimônia exige dois dedos na placa. A distinção entre `WRONG_STATE` e
`UNKNOWN_CMD` na última linha é o que separa "existe mas não agora" de
"não existe mais" — as duas propriedades que esta noite produziu.

**Falta validar em hardware**, com a cerimônia: `comp-load` montando uma
chave a várias mãos, `delete-key` devolvendo o slot, e o `keycycle`
chegando aos 100 nas duas direções. Roteiro em `doc/bancada.md`.

#### Custo, e a resposta para a fila da IMEM

**IMEM: 14 192 → 14 276 (`DELETE_KEY`) → 14 856 (componentes)**, ou
**90,7%**. Sobram **1 528 bytes**.

⚠ **Isso praticamente decide o log de auditoria.** Ele é transversal, toca
a flash SPI (que exige o driver que ainda não existe) e precisa de
contador anti-rollback. Em 1 548 bytes não cabe — e essa era a conta que
eu vinha dizendo que teria de ser feita antes, não descoberta no fim.

O log passa a ser item de **Fase 4**, junto com a persistência, que é onde
ele sempre pertenceu tecnicamente: um log que não sobrevive ao
desligamento não é log de auditoria.

---

## O que falta, na ordem

### 1. Questão em aberto — a LMK montada não é verificada

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

### 2. Lacunas do controle de exportabilidade

*Levantadas em 2026-08-31, respondendo "isso existe aqui?". **Ambas
padrão da categoria; ambas faltam.***

O que **existe e funciona**: os três valores da norma (`'E'`, `'N'`, `'S'`)
no cabeçalho X9.143, um **único** ponto de saída para os bytes
(`keystore_exporta()`) que consulta o campo, e o campo viajando **dentro do
MAC** — trocar o caractere da posição 11 mata o bloco. Validado no POST, no
`tb_keystore` e em hardware (`gen-key --exp N` → `export-key` →
`NOT_EXPORTABLE`).

#### 6a. `'S'` é aceito e não significa nada

`KS_EXP_SENSIVEL` aparece **só** nas listas de validação de cabeçalho
(`header_valido()` em keystore.c, `cab_valido()` em tr31.c). Nenhum código
trata "sensível" diferente de "exportável": `keystore_exporta()` recusa
apenas `KS_EXP_NAO`.

Ou seja, o comentário no header — *"sai só sob regra mais estrita"* —
descreve uma regra que **não existe**. É pior que uma lacuna: é uma
promessa no código.

Duas saídas honestas, e nenhuma é deixar como está:

1. **Implementar a semântica**, e aí decidir qual é. O que a categoria faz
   é qualificar a exportação — ver 6b —, então essa decisão não é
   independente da outra.
2. **Recusar `'S'` na instalação** enquanto não houver semântica, e dizer
   por quê. Um campo que o dispositivo não sabe honrar não deve ser
   aceito: aceitar e ignorar é como uma restrição de uso desaparece.

⚠ A opção 2 tem um custo de interoperabilidade que precisa ser pesado: um
key block legítimo de outro sistema, com `'S'`, passaria a ser recusado na
importação.

#### 6b. A exportação não é qualificada

Aqui o campo é praticamente booleano e a KEK é **sempre a LMK**. No modelo
comercial a exportação é qualificada: sob **qual** KEK, para qual zona, e se
apenas em key block. É a diferença entre "esta chave pode sair" e "esta
chave pode sair **para lá**".

Coerente com só existirem 16 slots e uma chave mestra — mas é menos do que o
padrão oferece, e a diferença aparece no momento em que existir uma segunda
KEK (uma ZMK, por exemplo, para trocar chave com outra instituição). Nesse
dia isto deixa de ser lacuna e passa a ser bloqueio.

⚠ **Não confundir com o campo `modo`.** `exportabilidade` impede **sair**;
`modo` restringe o que a chave pode **fazer**. Uma chave `'N'` pode e deve
ser usada pelos comandos `ENCRYPT`/`DECRYPT` — não poder sair é diferente de
não poder trabalhar, e é o caso mais comum de uma chave bem configurada.

### 3. Log de auditoria — **movido para a Fase 4**, e por dois motivos

`fw/src/audit_log.c` e `host/audit.py` continuam placeholders de uma linha.

**Motivo 1, o que força:** não cabe. A IMEM está em 14 836 de 16 384
(90,6%), com **1 548 bytes livres**. O log precisa de estrutura de registro,
serialização, contador monotônico e o driver de flash SPI que ainda não
existe. Não entra nesse espaço.

**Motivo 2, o que torna isso certo em vez de apenas inevitável:** um log
que não sobrevive ao desligamento **não é log de auditoria**. Ele registra
exatamente os eventos que alguém teria interesse em apagar — zeroize,
carga de chave mestra, mudança de estado — e um registro volátil some junto
com a energia, que é a primeira coisa que se corta.

Então o lugar dele sempre foi ao lado da persistência, e a persistência é
a Fase 4. Os dois compartilham tudo: o driver de flash, o MAC de
integridade sobre o blob, e o contador anti-rollback.

⚠ **Enquanto ele não existe, os handlers carregam `TODO` no checklist, e
isso é deliberado.** `ZEROIZE`, `DELETE_KEY`, `KEY_FROM_COMPONENTS` e os
dois de MAC são os que mais o pedem — apagar chave e montar chave sem
deixar registro de quem pediu e quando é exatamente o evento que um log
existe para cobrir.

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
- [x] Gerar chave → exportar → reimportar → **usar em AES**: resultado
      idêntico. Os dois handles cifram o mesmo bloco com o mesmo IV e os
      criptogramas batem — 128 bits de evidência, contra os 24 do KCV.
      Provado em `tb_keystore` e **confirmado em hardware em 2026-09-25**
- [x] Parser Python e firmware C concordam em 100 blocos aleatórios —
      `hsmtool keycycle`. A direção **C → Python** já fechava; a
      **Python → C** parava quando os slots acabavam, e o `DELETE_KEY`
      (`0x2B`) destravou: o ciclo devolve o slot a cada iteração.
      **Falta reconfirmar em hardware**, o que exige a cerimônia
- [x] Alterar 1 bit do header ou do corpo → MAC inválido — provado nas
      112 posições do bloco (`host/test_tr31.py`) e no POST do firmware.
      Falta o "import recusado", que depende do comando
- [x] Chave marcada `exportabilidade='N'` não sai, por nenhum caminho —
      `tb_keystore` gera uma `'N'` e o `EXPORT_KEY` devolve
      `NOT_EXPORTABLE`. Há um único caminho para os bytes
      (`keystore_exporta()`), e é ele que consulta o campo
- [x] `ZEROIZE` apaga, e a prova é independente do firmware — o KCV da
      cerimônia seguinte tem de voltar a bater com o vetor do CAVP
- [x] **Nada que o dispositivo gere ou guarde sai em claro.** Nenhum
      comando devolve material de chave: `GEN_KEY` devolve handle e KCV,
      `EXPORT_KEY` devolve key block embrulhado, `KEY_INFO` devolve
      metadados, `MAC_VERIFY` devolve um bit. E desde 2026-09-25 nenhum
      comando **aceita** chave em claro, então não há como induzir o
      dispositivo a isso
- [x] **Captura durante a OPERAÇÃO não contém byte de chave em claro.**
      Nenhum comando aceita nem devolve material de chave; a única coisa
      que atravessa é handle, KCV, key block embrulhado e criptograma
- [ ] **Console e host em portas separadas.** Hoje os componentes de LMK
      passam pela mesma porta — e pela mesma máquina — que o host usa. O
      dual control impede *carregar*; não impede *observar*. É desvio
      estrutural, não defeito de comando

#### ⚠ Sobre o critério original, desdobrado em 2026-09-26

O critério dizia: *"captura da UART durante toda a suíte não contém nenhum
byte de chave em claro"*. Ele **não pode passar como escrito** — e a
primeira explicação que eu registrei para isso estava **incompleta**.

##### A leitura errada, e por que ela era errada

Eu escrevi que o problema era os componentes da LMK atravessarem a UART
**em claro**. Isso trata "material de chave num fio" como defeito em si, e
não é.

**Num HSM de pagamento comercial a porta de console é uma serial comum**, e
os componentes digitados ali atravessam o cabo em claro exatamente do mesmo
jeito. O controle nunca foi criptográfico: é **ambiental e procedimental** —
sala controlada, acesso registrado, dois custodiantes presentes, dual
control. Chave em claro num fio só é violação **em relação a um modelo de
ameaça**, e o modelo daquela porta pressupõe o ambiente.

⚠ **A premissa precisa estar escrita, e é esta:** este projeto assume, como
o modelo comercial assume, que a cerimônia acontece em ambiente controlado.
O dispositivo **não sabe** se está numa sala cofre — quem garante isso é o
procedimento. Um documento que não escreve a premissa deixa o leitor achar
que o equipamento se defende sozinho.

##### O que de fato falta, e não é o fio

Num equipamento comercial as duas portas são **fisicamente distintas**. O
host — a máquina na rede, a que pode ser comprometida — fica na *outra*
porta e **nunca** carrega componente de LMK. O console costuma ser um
terminal dedicado, não o host de transações.

Aqui é **a mesma porta e a mesma máquina**. E a consequência concreta não é
o cabo: é que **os componentes passam pelo host**.

Um host comprometido não consegue *carregar* LMK — não aperta os botões, e
o dual control segura isso. Mas ele **vê** os componentes quando o
custodiante os digita.

> O dual control protege contra **carregar**. Não protege contra
> **observar**. Quem protege contra observar é a separação de portas, e é
> ela que falta.

##### Como o critério fica

Dividido por **fase de operação**, e aí a metade que importa vira testável:

| captura | conteúdo | veredito |
|---|---|---|
| durante a **cerimônia** | contém componentes | **esperado** — é tráfego de console, aceitável sob a premissa de ambiente controlado |
| durante a **operação** | não pode conter byte de chave | **verificável hoje**, e é o que a remoção dos comandos com chave em claro garantiu |

E a lacuna real deixa de ser "chave em claro na UART" e passa a ser
**"console e host compartilham a porta e a máquina"** — que já está
registrada como desvio estrutural no `PLANO.md`, agora com a razão certa.

Desdobrar não é abrandar: é parar de tratar como um item o que são duas
propriedades com causas e prazos diferentes.
