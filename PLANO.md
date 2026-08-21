# HSM educacional em FPGA — Artix-7 XC7A35T (QMTECH)

Projeto de estudo: construir, do zero, um módulo criptográfico com hierarquia de
chaves, cerimônia de carga, key blocks e API de host — reproduzindo a arquitetura
de um HSM real em escala reduzida.

**Este dispositivo não é um HSM.** Não há PUF, malha antitamper, sensores físicos,
RNG certificado nem qualquer validação FIPS/PCI. O objetivo é entender a
arquitetura de dentro para fora, não proteger material de chave real. Nenhuma
chave de produção deve jamais ser carregada nele.

---

## Alvo declarado — para onde este projeto aponta

*Decidido em 2026-08-08.*

O modelo de referência é um **HSM de pagamento comercial**, e não
um token PKCS#11 genérico. Isso não muda as fases 1 a 4; muda **duas escolhas**
que já estavam em aberto:

| Onde | Escolha |
|---|---|
| Fase 3, key blocks | **ANSI X9.143** (TR-31 versão D), que é o formato que os HSM de pagamento comerciais consomem e produzem |
| Fase 5, API de host | **Command set ASCII** de dois caracteres sobre socket, não `.so` PKCS#11 |

**O que este projeto passa a ensinar bem:** a fronteira criptográfica, a
hierarquia sob uma LMK, key blocks com *usage*, *mode of use* e
*exportability*, KCV, cerimônia com split knowledge e dual control, estado
autorizado, POST, e por que a API é a superfície de ataque de um HSM. Quem
terminar isto lê o manual de um HSM de pagamento comercial reconhecendo
decisões em vez de
decorando comandos.

**O que ele continua NÃO ensinando, e é bom deixar escrito:** o command set
real de cada fabricante e seus códigos, os esquemas de LMK proprietários,
e o negócio de pagamento propriamente dito — PIN blocks ISO 9564, PVV,
offsets IBM 3624, CVV, ARQC/EMV, DUKPT. Nada disso está em nenhuma das sete
fases. **Este projeto não substitui o equipamento nem o manual dele.**

Se algum dia o alvo mudar, esta seção muda primeiro, e as duas escolhas
acima mudam com ela.

---

## 0. Restrições invioláveis do projeto

Esta seção vem primeiro por um motivo: é checklist, não introdução. Ler antes de
qualquer comando na Vivado que toque em segurança do dispositivo.

### PROIBIDO — nenhuma destas operações será executada neste projeto

| Operação | Motivo |
|---|---|
| Queimar **qualquer** eFUSE | OTP, irreversível. Inclui `FUSE_USER`. |
| `CFG_AES_ONLY` | Brick permanente se a chave for perdida ou errada. |
| Desabilitar JTAG (`W_DIS`/`R_DIS`) | Elimina a única via de recuperação. |
| `program_efuse` na Vivado / `-efuse` no bitstream | Idem. |

Regra prática: se a operação contém a palavra **eFUSE**, ela não acontece.
Qualquer tutorial que mande queimar fusível é lido, documentado e não executado.

### Permitido — risco zero, recuperável por JTAG

- Chave AES em **BBRAM** (`BITSTREAM.ENCRYPTION.ENCRYPTKEYSELECT bbram`)
- `DNA_PORT` — identificador único, read-only de fábrica
- SPI flash — sempre reprogramável por JTAG indireto
- XADC (temperatura/tensão), MMCM/DRP, ICAP
- Qualquer coisa que seja apenas bitstream

### Nota de hardware verificada no esquemático

No core board QMTECH (`Artix7-DDR3-V5.pdf`, `XC7A35T-FTG256`), o pino **F8
(`VCCBATT`) está ligado ao rail `1V8`**, o mesmo do `VCCAUX` (pino L10). Não há
bateria nem suporte para uma.

**Consequência:** a chave em BBRAM é perdida a cada power-off e precisa ser
recarregada por JTAG. Isso é desejável aqui — nada persiste no hardware — e é
exatamente o comportamento do HSM comercial cuja bateria descarregou.

---

## 1. Arquitetura alvo

```
                    ┌───────────────── FPGA ─────────────────┐
   host (PC)        │                                        │
   ┌────────┐  UART │  ┌──────────┐      ┌────────────────┐  │
   │hsmtool │◄─────►│  │ NEORV32  │◄────►│ AES-256 (CFS)  │  │
   │  .py   │ 115k2 │  │  RV32IMC │      │ SHA-256        │  │
   └────────┘       │  │          │      │ TRNG           │  │
   ┌────────┐       │  └────┬─────┘      └────────────────┘  │
   │libhsm  │       │       │                                │
   │  .so   │       │  ┌────▼──────────────────────────────┐ │
   └────────┘       │  │ Key store  (BRAM — NUNCA DDR3)    │ │
                    │  │ LMK + 16 slots + estado           │ │
                    │  └───────────────────────────────────┘ │
                    │       │                                │
                    │  ┌────▼─────┐  ┌─────────┐  ┌────────┐ │
                    │  │SPI flash │  │ 2 botões│  │ 7-seg  │ │
                    │  │blobs+log │  │dual ctrl│  │ estado │ │
                    └──┴──────────┴──┴─────────┴──┴────────┴─┘
```

**Decisões e o porquê:**

- **NEORV32** em vez de LiteX/MicroBlaze: VHDL autocontido, sem geradores no
  caminho, e o **CFS** (Custom Functions Subsystem) é um slot de periférico feito
  para encaixar coprocessadores. Em projeto de segurança, "nada de mágica
  escondida" vale mais que conveniência.
- **Chaves só em BRAM.** A DDR3 é externa e sondável; o barramento fica exposto
  nos conectores. A LMK nunca sai da BRAM, em nenhuma circunstância. Esta é a
  fronteira criptográfica do projeto e tudo mais é derivado dela.
- **UART antes de Ethernet.** Canal simples, observável com analisador lógico —
  o que permite *provar* que material de chave em claro nunca cruza a fronteira.

### Fronteira criptográfica

Dentro: LMK, chaves de trabalho em claro, estado do DRBG.
Fora: key blocks wrapped, KCVs, criptogramas, handles, log de auditoria.
Nada da primeira lista atravessa para a segunda. Todo comando novo é avaliado
contra essa regra antes de ser implementado.

---

## 2. Fase 1 — SoC base

**Objetivo:** infraestrutura confiável antes de qualquer cripto.

### Entregáveis

1. `hsm_top.v` — toplevel, MMCM 50 MHz → 100 MHz, reset síncrono
2. XDC com clock, UART, botões, LEDs, 7-seg
3. NEORV32 instanciado: RV32IMC, IMEM/DMEM em BRAM, UART0, GPIO
4. Firmware C: `main.c` + parser de comandos
5. `host/hsmtool.py` — CLI do host

### Protocolo (definir agora, não depois)

```
  ┌────────┬─────┬──────────┬────────┐
  │ LEN(2) │CMD(1)│ PAYLOAD  │CRC32(4)│
  └────────┴─────┴──────────┴────────┘
   big-endian, LEN cobre CMD+PAYLOAD
```

Resposta: `LEN | STATUS(1) | PAYLOAD | CRC32`. Timeout de 2 s no host.
Metade dos bugs de HSM caseiro nasce de framing frouxo — este é fechado desde o
primeiro commit.

### Comandos da fase

`0x01 PING` → `PONG` · `0x02 GET_VERSION` · `0x03 GET_DNA` (lê `DNA_PORT`)

Os tres validados em hardware. O `GET_DNA` so fechou na Fase 2, com o CFS:
o `DNA_PORT` e primitiva Xilinx e precisava de um caminho ate a CPU.

### Critérios de aceitação

- [x] `hsmtool.py ping` responde em < 50 ms, 10.000 iterações sem erro de CRC —
      em hardware 2026-07-31: 0 erros, mediana 4,36 ms, p99 4,85 ms, máx 6,50 ms
- [x] Frame malformado → `STATUS_BAD_CRC`, nunca trava a máquina de estados —
      `tb_uart_frame` em simulação, e opcode desconhecido confirmado na placa
- [x] Relatório de utilização arquivado em `doc/utilization_fase1.txt` (linha base)
- [x] Timing clean com 100 MHz — WNS +5,950 ns, todas as restrições atendidas

---

## 3. Fase 2 — engines e self-test

**Objetivo:** primitivas corretas e verificáveis. Correção antes de desempenho.

### Cores

| Bloco | Fonte | Notas |
|---|---|---|
| AES-256 | secworks/aes | ECB e CBC; encrypt + decrypt |
| SHA-256 | secworks/sha256 | HMAC em firmware sobre o core |
| TRNG | neoTRNG (NEORV32) | fonte de entropia bruta |
| CTR_DRBG | firmware | AES-256, reseed por política |

**Cuidado térmico:** manter o array de osciladores em anel pequeno (meia dúzia
de anéis). Centenas geram calor e ruído de alimentação localizado sem ganho.

### Health tests — onde está o aprendizado real

Implementar em firmware, sobre a fonte bruta, conforme SP 800-90B:

- **RCT** (Repetition Count Test) — corta na repetição de amostra idêntica
- **APT** (Adaptive Proportion Test) — janela de 512/1024 amostras
- Falha em qualquer um → estado `TAMPERED`, DRBG parado, LED vermelho

Escrever esses testes ensina mais sobre certificação de HSM que qualquer
whitepaper: eles são o motivo de um HSM real levar meses de validação.

### POST — power-on self-test

No boot, antes de aceitar qualquer comando, o firmware roda os KAT:

- AES-256 ECB/CBC — vetores CAVP (`vectors/aes256.txt`)
- SHA-256 — vetores FIPS 180-4
- HMAC-SHA-256 — RFC 4231
- DRBG — vetores SP 800-90A

**Falhou um vetor → o HSM não entra em operação.** Não é capricho: é literalmente
o requisito de self-test do FIPS 140-3. Você implementa a exigência e entende de
onde ela veio.

Os mesmos vetores rodam em simulação nos testbenches. Se um KAT passa no
testbench e falha no POST, o problema está no barramento, não no core.

Por isso o barramento tem testbench próprio: `tb_cfs` replica os vetores do
NIST **através do mapa de registradores** do coprocessador, e não direto nos
cores. É a mesma família de defeito que o parágrafo acima antecipa — ordem de
palavra trocada, handshake mal esperado — pega em simulação, onde custa
segundos.

### Comandos da fase

`0x10 AES_ENC` · `0x11 AES_DEC` · `0x12 SHA256` · `0x13 HMAC` · `0x14 RANDOM`
· `0x15 SELFTEST`

### Critérios de aceitação

- [x] Todos os KAT passam em simulação **e** no POST — AES-256 (1620 vetores
      CAVP) e SHA-256 (65 mensagens SHAVS) em simulação, nos cores e através
      do barramento do CFS; e AES, SHA, HMAC-SHA-256 e CTR_DRBG no POST,
      **verificados em hardware** em 2026-08-08.
- [~] `RANDOM` de 1 MB passa em `ent` — **1 MB colhido da placa passa nas
      cinco medidas** (`scripts/entstat.py`, reimplementação do `ent`, com
      as faixas verificadas contra fontes sabidamente ruins). Falta
      `dieharder -a`, que não está instalado nesta máquina.
- [x] Forçar falha artificial no RCT leva o dispositivo a `TAMPERED` —
      `tb_post_tamper`: POST reprova, LED de tamper acende, `PING` é
      recusado com `WRONG_STATE` e o `SELFTEST` acusa o TRNG.
- [x] Utilização e timing arquivados — `doc/utilization_fase2.txt` e
      `doc/timing_fase2.txt`, atualizados em 2026-08-09 com o TRNG dentro:
      **7392 LUT** (35,5%), **7475 FF** (18,0%), 5 BRAM, 0 DSP,
      **WNS +0,359 ns**, WHS +0,026.

---

## 4. Fase 3 — hierarquia de chaves (o coração)

**Objetivo:** entender por que a API de um HSM é do jeito que é — descobrindo, na
prática, o que ela precisa impedir.

### Key store

Modelar os campos no header TR-31 **desde o início**. Refatorar isso depois é
doloroso porque o MAC cobre o header inteiro.

```c
typedef struct {
    uint8_t  in_use;
    uint8_t  usage[2];      // TR-31: 'B0'=BDK, 'K0'=KEK, 'D0'=data, ...
    uint8_t  algorithm;     // 'A'=AES, 'T'=3DES
    uint8_t  mode_of_use;   // 'E'=encrypt, 'D'=decrypt, 'B'=both, 'N'=none
    uint8_t  exportability; // 'E'=exportável, 'N'=não, 'S'=sensível
    uint8_t  key_len;
    uint8_t  key[32];       // BRAM. Nunca sai daqui em claro.
    uint8_t  kcv[3];
    uint32_t use_count;
} key_slot_t;
```

16 slots + a LMK em região separada.

### Máquina de estados

```
UNINITIALIZED ──LMK completa──► AUTHORIZED ──ativar──► OPERATIONAL
      ▲                              │                      │
      └──────────── zeroize ─────────┴──── tamper/zeroize ───┘
                                     ▼
                                 TAMPERED
```

Comandos sensíveis (carga de componente, export de LMK-derived) existem **apenas**
em `AUTHORIZED`. É o modelo da chave de switch dos HSMs comerciais.
7-seg mostra o estado: `Uni` / `Aut` / `OPE` / `tPr`.

### Cerimônia da LMK

Três componentes de 32 bytes, combinados por XOR. Para cada um: KCV
(AES-ECB de um bloco de zeros, 3 bytes mais significativos). KCV final da LMK
conferido contra o valor calculado no host.

**Dual control em hardware:** `LMK_LOAD_COMPONENT` só é aceito com os **dois
botões pressionados simultaneamente**. É simplório e é surpreendentemente
instrutivo — separa "quem digita" de "quem autoriza" fisicamente.

Cada custodiante carrega apenas o seu componente e não vê os demais (split
knowledge). Nenhum componente isolado revela nada sobre a LMK.

### Key blocks ANSI X9.143 (TR-31 versão D)

*Formato fixado em 2026-08-08 pela decisão de rumo da seção 0: X9.143, que é
o formato que os HSM de pagamento comerciais consomem e produzem. TR-31
"genérico" não existe como alvo —
o que existe é a versão D do padrão, e é ela.*

- KBEK e KBAK derivados da LMK por CMAC (derivação por propósito)
- Corpo em AES-CBC, autenticação por CMAC sobre header + corpo
- Header em ASCII, contado no MAC — **um byte errado explode tudo**

**Escrever o parser/gerador duas vezes:** em C no firmware e em Python no host.
Fazer os dois se validarem mutuamente é de longe a forma mais rápida de aprender
o padrão de verdade, porque a menor divergência aparece como MAC inválido.

### Zeroize

Comando + trigger por falha de health test. Sobrescrita da BRAM (padrão, depois
zeros), com um teste que **prova** que apagou: dump da região e verificação.

### Comandos da fase

`0x20 LMK_LOAD_COMPONENT` · `0x21 LMK_STATUS` (só KCV) · `0x22 GEN_KEY`
· `0x23 EXPORT_KEY` (TR-31) · `0x24 IMPORT_KEY` · `0x25 KEY_INFO`
· `0x26 SET_STATE` · `0x2F ZEROIZE`

### Critérios de aceitação

- [ ] Cerimônia de 3 componentes com KCV conferido a cada passo
- [ ] `LMK_LOAD_COMPONENT` rejeitado sem os dois botões
- [ ] Gerar chave → exportar TR-31 → reimportar → usar em AES: resultado idêntico
- [ ] Parser Python e firmware C concordam em 100 blocos aleatórios
- [ ] Alterar 1 bit do header ou do corpo → MAC inválido, import recusado
- [ ] Chave marcada `exportability='N'` não pode ser exportada, em nenhum caminho
- [ ] **Captura da UART durante toda a suíte não contém nenhum byte de chave em
      claro** (grep automatizado contra as chaves conhecidas do teste)

O último item é o critério que realmente importa. Automatizar em `host/audit.py`.

---

## 5. Transversal — log de auditoria

Desde a fase 3, não como extra: registro em SPI flash com contador monotônico,
gravado **antes** de executar o comando, não depois. Entradas: contador, estado,
comando, slot afetado, resultado. Sem material de chave, obviamente.

Motivo de ser "antes": o log precisa capturar tentativas que falharam ou que
travaram o dispositivo. Log escrito depois só registra sucesso — inútil como
trilha forense.

---

## 6. Fases seguintes (esboço)

**Fase 4 — NV storage.** Blobs wrapped na SPI flash, MAC de integridade,
contador anti-rollback, recuperação de estado no boot. Modelo real de HSM.

**Fase 5 — API de host: command set ASCII de HSM de pagamento.** *Decisão de rumo
tomada em 2026-08-08 — ver "Alvo declarado" na seção 0.* Em vez de um subconjunto
PKCS#11 como `.so`, um command set ASCII sobre socket, no formato de um HSM de
pagamento: código de comando de dois caracteres, código de resposta = comando + 1,
códigos de erro numéricos, campos posicionais.

Não é só troca de sintaxe. PKCS#11 é uma API de *biblioteca* — objetos, sessões,
atributos. Um command set de HSM de pagamento é um protocolo de *serviço*, sem
sessão e sem estado do lado do cliente, e essa diferença muda como o dispositivo
tem de se defender: cada comando chega sozinho e precisa se bastar.

Aqui se entende por que a API é o que é: é você que precisa impedi-la de vazar
material de chave.

**Fase 6 — tamper e ataques.** XADC monitorando temperatura/tensão dispara
zeroize. Depois, ataque o próprio HSM: glitch de clock via DRP do MMCM, observe a
assinatura sair errada, implemente contramedidas (dupla execução, verificação de
resultado). Bitstream encriptado com chave em BBRAM como confidencialidade de
firmware.

**Fase 8 — criptografia de pagamento (esboço, decidido em 2026-08-08).**
Depois que a hierarquia de chaves e a API existirem, é o que falta para o
projeto encostar de verdade no assunto. Nem tudo é
ensinável aqui; o que separa é o **hardware** e a **procedência dos
vetores**, não a dificuldade.

| Assunto | Dá? | O que decide |
|---|---|---|
| **PIN block ISO 9564 formato 4** | **sim** | é AES, que já temos. Formatação, XOR com o PAN, cifra |
| **PIN block formato 0** | **sim** | 3DES no uso real, mas a *estrutura* é a mesma e o ataque não depende da cifra |
| **PIN translate** | **sim** | o comando de tradução é o alvo clássico de ataque de API |
| **Ataque de tabela de decimalização** | **sim, e é o melhor item da lista** | Bond/Clulow. Não precisa de 3DES nem de vetor da Visa: o ataque é sobre a *API*, e reproduz num esquema nosso com AES |
| **DUKPT AES (X9.24-3)** | **sim** | cabe no hardware AES-only. Ensina gerenciamento de chave em escala |
| **CVV / CVC** | **não sem 3DES** | inerentemente 3DES nos esquemas de cartão. Não existe variante AES em uso |
| **PVV** | **não sem 3DES** | idem. O *ataque* sobre ele é ensinável sem ele |
| **DUKPT TDES (X9.24-1)** | **não sem 3DES** | idem |

**O 3DES é uma decisão de arquitetura, não uma tarefa.** O CFS tem `keylen`
fixo em AES-256 **sem caminho de downgrade**, de propósito (§3). Um core DES
contradiz isso. É defensável como engine separado e rotulado como legado —
que é honestamente o que um HSM de pagamento real tem — mas é escolha
consciente, e a decisão fica para quando a fase chegar.

**O obstáculo maior são os vetores.** A regra inviolável nº 5 exige
procedência verificável, e para cripto de pagamento os vetores oficiais
estão atrás de paywall (ANSI X9.24-3) ou dentro de manual de fabricante.
Sem vetor autoritativo não há KAT, e "implementei e parece certo" é
exatamente o que a regra proíbe. Onde não houver vetor público, o item
**não entra** — ou entra explicitamente marcado como não verificado.

⚠ **Nenhum PAN real, nunca**, pela mesma razão que nenhuma chave de
produção. Gerar CVV ou PIN para um número de cartão que existe deixa de ser
exercício.

⚠ **Não nomear fabricante nem produto, e não copiar documentação deles.**
O modelo de referência é a *categoria* — HSM de pagamento — e a documentação
deste projeto fala dela sem citar marca. Não há vínculo, endosso nem
alegação de compatibilidade com equipamento comercial algum.

O conteúdo técnico sai de **normas públicas** (ISO 9564, ANSI X9.24 e
X9.143, NIST) e de **literatura acadêmica publicada**. Tabela de comandos,
código de erro e esquema de chave de manual de fabricante são material
licenciado e **não entram aqui em nenhuma hipótese**.

Quando a fase 5 definir o command set ASCII, ele será **nosso**: o formato
geral (código de dois caracteres, resposta = comando + 1) é público e
observável, e é só dele que a inspiração vem.

**Fase 7 — assimétrico.** RSA-2048 por Montgomery nos 90 DSP48E1; P-256 depois.
Deixar por último: o aprendizado de HSM está nas fases 3 a 5.

---

## 7. Estrutura do repositório

```
hsm-a7/
├── PLANO.md                  este arquivo
├── constraints/
│   └── qmtech_a35t.xdc       pinos (core board verificado; daughterboard TODO)
├── rtl/
│   ├── top/hsm_top.v         toplevel
│   ├── soc/                  NEORV32 + wrappers de periférico
│   └── crypto/               aes, sha256, trng (cores externos + CFS)
├── sim/tb/                   testbenches (KAT em simulação)
├── fw/
│   ├── src/                  main, cmd, keystore, tr31, kat, drbg
│   └── include/
├── host/
│   ├── hsmtool.py            CLI
│   ├── tr31.py               implementação independente (cross-check)
│   └── audit.py              verificação de vazamento na UART
├── scripts/build.tcl         build não-interativo da Vivado
├── vectors/                  KAT: CAVP, FIPS 180-4, RFC 4231
└── doc/                      relatórios de utilização e notas
```

## 8. Ordem de trabalho

Uma regra só, e ela vale para as três fases: **nada vai para a placa sem passar
antes no testbench.** Depurar cripto por UART, no hardware, sem visibilidade
interna, é a forma mais lenta possível de descobrir que faltou um byte no
padding. Simulação primeiro, sempre.
