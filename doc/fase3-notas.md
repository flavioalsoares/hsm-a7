# Fase 3 — notas de implementação

Objetivo da fase (`PLANO.md` §4): **hierarquia de chaves**. É o coração do
projeto — a partir daqui o dispositivo deixa de ser uma caixa de primitivas
e passa a guardar chave.

Estado: **em andamento.** CMAC, key store, a cerimônia de LMK e o key
block X9.143 prontos; faltam o zeroize e o resto dos comandos.

---

## Retomando o trabalho

A placa **guarda o bitstream na flash** e sobe sozinha na energização. Não
precisa gravar nada para voltar ao ponto:

```bash
python3 host/hsmtool.py version     # deve responder v0.1.0, UNINITIALIZED
python3 host/hsmtool.py post        # os SETE testes devem passar
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

---

## O que falta, na ordem

### 2. Zeroize

Comando, mais gatilho por falha de health test. O gatilho já existe em
parte: o POST leva a `TAMPERED` (`fw/src/main.c`), e `tb_post_tamper` prova
a corrente. Falta o comando e a sobrescrita da BRAM com teste que **prove**
que apagou.

### 3. Comandos da fase

Prontos: `0x20 LMK_LOAD_COMPONENT` · `0x21 LMK_STATUS` · `0x26 SET_STATE`.

Faltam: `0x22 GEN_KEY` · `0x23 EXPORT_KEY` · `0x24 IMPORT_KEY`
· `0x25 KEY_INFO` · `0x2F ZEROIZE`

Cada um passa pelo checklist do `CLAUDE.md` **antes** de ser escrito.

⚠ **E cada um deles apaga um comando da fase 2.** `AES_ENC`, `AES_DEC` e
`HMAC` recebem chave no payload e só respondem em `UNINITIALIZED`; quando
houver LMK, param sozinhos, pela máscara de estados. Na fase 3 eles são
**substituídos** por versões que falam por handle de slot — não estendidos.

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
- [ ] Gerar chave → exportar → reimportar → usar em AES: resultado idêntico
- [ ] Parser Python e firmware C concordam em 100 blocos aleatórios
      — depende de `IMPORT_KEY`/`EXPORT_KEY`; hoje os dois concordam no
      vetor externo, e só
- [x] Alterar 1 bit do header ou do corpo → MAC inválido — provado nas
      112 posições do bloco (`host/test_tr31.py`) e no POST do firmware.
      Falta o "import recusado", que depende do comando
- [ ] Chave marcada `exportabilidade='N'` não sai, por nenhum caminho
- [ ] Captura da UART durante a suíte inteira **não contém nenhum byte de
      chave em claro**

O último é o que fecha a fase, e é o único que não se prova lendo código.
