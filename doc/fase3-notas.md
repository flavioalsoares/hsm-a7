# Fase 3 — notas de implementação

Objetivo da fase (`PLANO.md` §4): **hierarquia de chaves**. É o coração do
projeto — a partir daqui o dispositivo deixa de ser uma caixa de primitivas
e passa a guardar chave.

Estado: **em andamento.** CMAC, key store e a cerimônia de LMK prontos;
faltam os key blocks, o zeroize e o resto dos comandos.

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

---

## O que falta, na ordem

### 1. Key blocks ANSI X9.143 (TR-31 versão D) — **é o próximo passo**

- KBEK e KBAK derivados da LMK por CMAC
- corpo em AES-CBC, autenticação por CMAC sobre header + corpo
- header em ASCII, **contado no MAC** — um byte errado invalida tudo

**Escrever o parser duas vezes**, em C no firmware e em Python no host, e
fazer os dois se validarem mutuamente. É de longe a forma mais rápida de
aprender o formato, porque a menor divergência aparece como MAC inválido.

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
- [ ] Alterar 1 bit do header ou do corpo → MAC inválido, import recusado
- [ ] Chave marcada `exportabilidade='N'` não sai, por nenhum caminho
- [ ] Captura da UART durante a suíte inteira **não contém nenhum byte de
      chave em claro**

O último é o que fecha a fase, e é o único que não se prova lendo código.
