# Fase 3 — notas de implementação

Objetivo da fase (`PLANO.md` §4): **hierarquia de chaves**. É o coração do
projeto — a partir daqui o dispositivo deixa de ser uma caixa de primitivas
e passa a guardar chave.

Estado: **começou.** O CMAC está pronto; o resto não.

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

---

## O que falta, na ordem

### 1. Key store em BRAM

É o próximo passo, e é ele que dá sentido a tudo que vem depois. A estrutura
do slot precisa nascer certa, porque é ela que o key block X9.143 serializa:

```c
typedef struct {
    uint8_t  usage[2];        /* 'B0' BDK, 'K0' KEK, 'D0' dados, ... */
    uint8_t  algoritmo;       /* 'A' AES */
    uint8_t  modo_uso;        /* 'E' cifrar, 'D' decifrar, 'B' ambos, ... */
    uint8_t  exportabilidade; /* 'E' sob KEK, 'N' nunca, 'S' sensivel */
    uint8_t  chave[32];
    uint8_t  kcv[3];
    ...
} slot_t;
```

**Modelar os campos do header desde já** (`PLANO.md` §4). Refatorar isso
depois é caro, e o motivo não é preguiça: `exportabilidade` só significa
alguma coisa se **nenhum caminho** de código puder ignorá-la, e caminhos se
multiplicam com o tempo.

Regras invioláveis que valem aqui: chave em claro só em BRAM, nunca em DDR3,
nunca em flash sem wrap, nunca num registrador exposto no toplevel.

### 2. Cerimônia de LMK

Três componentes por XOR, cada custodiante carregando só o seu. Dual control
pelos **dois botões físicos** (SW2 e SW5, já debounced e ligados ao GPIO —
`rtl/top/hsm_top.v`).

O `LMK_LOAD_COMPONENT` tem de ser **recusado** sem os dois botões, e isso
precisa de teste.

### 3. Key blocks ANSI X9.143 (TR-31 versão D)

- KBEK e KBAK derivados da LMK por CMAC
- corpo em AES-CBC, autenticação por CMAC sobre header + corpo
- header em ASCII, **contado no MAC** — um byte errado invalida tudo

**Escrever o parser duas vezes**, em C no firmware e em Python no host, e
fazer os dois se validarem mutuamente. É de longe a forma mais rápida de
aprender o formato, porque a menor divergência aparece como MAC inválido.

### 4. Zeroize

Comando, mais gatilho por falha de health test. O gatilho já existe em
parte: o POST leva a `TAMPERED` (`fw/src/main.c`), e `tb_post_tamper` prova
a corrente. Falta o comando e a sobrescrita da BRAM com teste que **prove**
que apagou.

### 5. Comandos da fase

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
