# Fase 3 — notas de implementação

Objetivo da fase (`PLANO.md` §4): **hierarquia de chaves**. É o coração do
projeto — a partir daqui o dispositivo deixa de ser uma caixa de primitivas
e passa a guardar chave.

Estado: **em andamento.** CMAC e key store prontos; falta a cerimônia
de LMK, os key blocks e os comandos.

---

## Retomando o trabalho

A placa **guarda o bitstream na flash** e sobe sozinha na energização. Não
precisa gravar nada para voltar ao ponto:

```bash
python3 host/hsmtool.py version     # deve responder v0.1.0, UNINITIALIZED
python3 host/hsmtool.py post        # os seis testes devem passar
```

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

## O que falta, na ordem

### 1. Cerimônia de LMK

Três componentes por XOR, cada custodiante carregando só o seu. Dual control
pelos **dois botões físicos** (SW2 e SW5, já debounced e ligados ao GPIO —
`rtl/top/hsm_top.v`).

O `LMK_LOAD_COMPONENT` tem de ser **recusado** sem os dois botões, e isso
precisa de teste.

### 2. Key blocks ANSI X9.143 (TR-31 versão D)

- KBEK e KBAK derivados da LMK por CMAC
- corpo em AES-CBC, autenticação por CMAC sobre header + corpo
- header em ASCII, **contado no MAC** — um byte errado invalida tudo

**Escrever o parser duas vezes**, em C no firmware e em Python no host, e
fazer os dois se validarem mutuamente. É de longe a forma mais rápida de
aprender o formato, porque a menor divergência aparece como MAC inválido.

### 3. Zeroize

Comando, mais gatilho por falha de health test. O gatilho já existe em
parte: o POST leva a `TAMPERED` (`fw/src/main.c`), e `tb_post_tamper` prova
a corrente. Falta o comando e a sobrescrita da BRAM com teste que **prove**
que apagou.

### 4. Comandos da fase

`0x20 LMK_LOAD_COMPONENT` · `0x21 LMK_STATUS` (só KCV) · `0x22 GEN_KEY`
· `0x23 EXPORT_KEY` · `0x24 IMPORT_KEY` · `0x25 KEY_INFO` · `0x26 SET_STATE`
· `0x2F ZEROIZE`

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

- [ ] Cerimônia de 3 componentes com KCV conferido a cada passo
- [ ] `LMK_LOAD_COMPONENT` rejeitado sem os dois botões
- [ ] Gerar chave → exportar → reimportar → usar em AES: resultado idêntico
- [ ] Parser Python e firmware C concordam em 100 blocos aleatórios
- [ ] Alterar 1 bit do header ou do corpo → MAC inválido, import recusado
- [ ] Chave marcada `exportabilidade='N'` não sai, por nenhum caminho
- [ ] Captura da UART durante a suíte inteira **não contém nenhum byte de
      chave em claro**

O último é o que fecha a fase, e é o único que não se prova lendo código.
