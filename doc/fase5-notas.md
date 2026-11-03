# Fase 5 — API de host: command set ASCII

*Iniciada em 2026-11-02.*

Até a Fase 4, o dispositivo tinha um protocolo só: frames binários com CRC,
um opcode por comando e chaves referidas por **handle** de slot. É um bom
protocolo de bancada e um mau modelo de HSM de pagamento. Esta fase
acrescenta a interface que o host de um HSM comercial usa de verdade: um
**command set ASCII**, sem sessão, em que a chave de trabalho viaja **dentro
do comando**, embrulhada sob a LMK.

---

## As três decisões, tomadas pelo usuário em 2026-11-02

| Pergunta | Decisão | Por quê |
|---|---|---|
| Quem interpreta o ASCII? | **O firmware.** No PC fica só uma ponte TCP↔UART que repassa bytes | A API é a superfície de ataque. Um gateway no PC que traduzisse o ASCII deixaria a defesa da API fora da fronteira |
| Console × host | **Separados por protocolo**, na mesma UART | O binário vira o **console** (cerimônia, estado, diagnóstico, log); o ASCII é o **host** e não tem nenhum comando de cerimônia. Sem hardware novo |
| Como o host indica a chave | **Key block no comando** | É o modelo da categoria: o equipamento não guarda as chaves de trabalho do host; o host as mantém no banco de dados dele, embrulhadas sob a LMK, e manda o bloco a cada comando |

### O que muda no modelo mental

```
                    antes (fase 3/4)                 agora (fase 5, porta host)
onde vive a chave   num slot do dispositivo          no banco de dados do HOST,
                                                     como key block sob a LMK
como o host a cita  handle (1 byte)                  o key block inteiro
quantas cabem       16                               quantas o host quiser
estado no HSM       o key store                      nenhum: cada comando se basta
```

O dispositivo abre o bloco por dentro, usa a chave, e a apaga **antes de
responder**. Entre dois comandos ASCII, não sobra chave de trabalho nenhuma
na BRAM. É isso que "sem estado" quer dizer, e é por isso que um HSM de
pagamento atende milhões de chaves com memória de poucas.

Os slots continuam existindo, mas só pelo console. A LMK é a única chave que
o dispositivo **precisa** guardar — e é exatamente o que um HSM comercial
guarda.

⚠ **A porta continua compartilhada.** Separar por protocolo dá a separação
de **papéis** — nenhum comando ASCII carrega componente, muda estado ou
zeroiza —, mas quem tem a UART fala os dois protocolos. A separação física
continua registrada como o maior desvio em relação ao modelo (`PLANO.md`,
"Aderência antes de variação").

---

## Enquadramento: dois protocolos na mesma UART

Os dois começam com o mesmo campo, `LEN` em 2 bytes big-endian. O que os
separa é o **primeiro byte depois do LEN**:

```
binário (console)   LEN(2) | CMD(1) 0x00..0x2F | PAYLOAD | CRC32(4)
ASCII   (host)      LEN(2) | cabeçalho(4) '0'..'z' | comando(2) | campos
```

O cabeçalho ASCII começa com um caractere imprimível de `0x30` (`'0'`) a
`0x7E` (`'~'`); qualquer outro primeiro byte é opcode binário. Os opcodes em
uso vão até `0x2F`, e os desconhecidos acima de `0x7E` continuam recebendo
`UNKNOWN_CMD` do console. O firmware lê o corpo inteiro e decide pelo
primeiro byte.

- **O ASCII não tem CRC.** Num HSM comercial a mensagem ASCII viaja por TCP,
  que já tem a sua verificação; o formato da mensagem não traz CRC. Aqui ela
  atravessa a UART entre a ponte e a placa, e um bit trocado na linha não é
  detectado pelo protocolo. O dano é limitado: um key block com um bit
  trocado é recusado pelo MAC dele, e um dado trocado sai trocado — como num
  enlace sem verificação.
- **O LEN é o mesmo do TCP.** O enquadramento por comprimento de 2 bytes é a
  forma usual de mensagem ASCII de HSM sobre TCP. Por isso a ponte não
  precisa entender nada: ela lê 2 bytes, lê o resto, repassa.
- ⚠ **Opcode binário de `0x30` a `0x7E` deixa de existir.** Um frame
  binário com esse primeiro byte seria lido como ASCII. Os opcodes em uso
  vão até `0x2F`, e nenhum novo deve entrar nessa faixa.

### Formato da mensagem

```
pedido     cabeçalho(4) | comando(2) | campos...
resposta   cabeçalho(4) | resposta(2) | erro(2) | campos...
```

- **Cabeçalho:** 4 caracteres escolhidos pelo host e **devolvidos iguais**.
  Servem para casar a resposta com o pedido. O dispositivo não os interpreta.
- **Resposta = comando com o segundo caractere + 1** (`K0` → `K1`). É a
  convenção pública e observável da categoria, e é só dela que vem a
  inspiração: **os códigos e os campos abaixo são deste projeto.**
- **Erro:** 2 dígitos. `00` é sucesso. Os campos de dados só vêm com `00`
  (e com `01` em nenhum caso: `01` não tem campos).

### Campos

| Campo | Formato |
|---|---|
| key block | o bloco X9.143 como está. O comprimento sai do **próprio cabeçalho** do bloco (posições 1–4), então o campo se delimita sozinho |
| dados | comprimento em **4 dígitos decimais**, contando bytes, seguido dos bytes em **hex maiúsculo** |
| IV | 32 dígitos hex (16 bytes) |
| MAC | 32 dígitos hex (16 bytes, CMAC inteiro) |
| KCV | 6 dígitos hex |

Hex minúsculo é aceito na entrada; a saída é sempre maiúscula.

---

## Os comandos

Todos os de chave exigem `OPERATIONAL`. Nenhum exige dual control: dual
control é para cerimônia, e a cerimônia não passa por aqui.

| Pedido | Resposta | Campos do pedido | Campos da resposta | Log |
|---|---|---|---|---|
| `D0` diagnóstico | `D1` | — | estado(1) · KCV da LMK(6) · versão(6) | não |
| `K0` gerar chave | `K1` | uso(2) · modo(1) · exportabilidade(1) | key block · KCV(6) | **sim** |
| `K2` conferir key block | `K3` | key block | uso(2) · algoritmo(1) · modo(1) · exportabilidade(1) · KCV(6) | não |
| `C0` cifrar | `C1` | key block · IV(32) · dados | dados | **sim** |
| `C2` decifrar | `C3` | key block · IV(32) · dados | dados | **sim** |
| `M0` gerar MAC | `M1` | key block · dados | MAC(32) | **sim** |
| `M2` verificar MAC | `M3` | key block · MAC(32) · dados | — | **sim** |

- **`D0`** responde em `UNINITIALIZED`, `AUTHORIZED` e `OPERATIONAL`. O
  estado é um dígito (`0`, `1`, `2`); o KCV é `000000` enquanto a LMK não
  estiver completa. O host confere o KCV da LMK antes de confiar que os
  blocos dele foram feitos sob ela — é o uso típico do diagnóstico.
- **`K0`** gera a chave no DRBG do dispositivo e a devolve **só embrulhada**.
  Nada fica no dispositivo. `exportabilidade = 'N'` também volta como bloco:
  guardar a chave no banco do host sob a LMK **não é exportar** — ela só
  abre dentro deste dispositivo.
- **`K2`** abre o bloco, confere o MAC e devolve o cabeçalho e o KCV. É como
  o host descobre se um bloco é íntegro e o que ele contém, sem usá-lo.
- **`C0`/`C2`** são AES-256-CBC com IV explícito e dados múltiplos de 16, até
  **160 bytes** (o limite vem do tamanho do frame: 513 bytes, com um key
  block de 144 caracteres e os dados em hex). O `modo` do bloco decide:
  `'E'` só cifra, `'D'` só decifra, `'B'` os dois.
- **`M0`/`M2`** são CMAC-AES-256, até **160 bytes** de mensagem. `'G'` só
  gera, `'V'` só verifica, `'C'` os dois. Os grupos de cifra e de MAC não se
  cruzam, como no console.
- **`M2` devolve um bit**, no código de erro: `00` confere, `01` não confere.
  A comparação é em tempo constante, dentro da fronteira.

### Códigos de erro

| Código | Significado |
|---|---|
| `00` | sem erro |
| `01` | verificação falhou (só `M2`) |
| `10` | key block inválido: malformado, MAC errado, ou feito sob outra LMK — **um código só**, pela mesma razão do `IMPORT_KEY` |
| `11` | o `modo` do bloco não permite esta operação |
| `15` | dados inválidos: hex, comprimento, múltiplo de 16, limite |
| `16` | parâmetro inválido em `K0` (uso, modo ou exportabilidade) |
| `20` | o estado do dispositivo não permite o comando |
| `21` | comando desconhecido |
| `22` | mensagem malformada: campo faltando ou sobrando |
| `27` | falha ao registrar no log de auditoria — o comando não executou |
| `90` | erro interno |

Mensagem com menos de 6 caracteres não tem comando para responder: volta com
o cabeçalho que veio (completado com `0`), resposta `ZZ` e erro `22`.

### Log de auditoria

Os comandos marcados entram no log **antes** de executar, como os do
console. O registro guarda o primeiro caractere do comando no campo
`comando` e o segundo no `argumento` — `K0` aparece como comando `0x4B` com
argumento `0x30`. Os opcodes binários vão até `0x2F`, então não há colisão.
`hsmtool audit` mostra os dois.

---

## No firmware

- `fw/src/cmd.c` lê o corpo e, pelo primeiro byte, entrega a mensagem a
  `ascii_despacha()` sem procurar CRC.
- `fw/src/cmd_ascii.c` é o parser e a tabela dos comandos ASCII. Mesma
  disciplina do binário: máquina explícita, todos os limites checados, sem
  alocação.
- **A chave do comando vai para um slot efêmero** do key store — um 17º
  slot, fora do vetor que se persiste, se lista ou se conta. O handler abre o
  bloco, instala a chave ali, usa pelas funções de sempre
  (`keystore_usa_aes()`, `keystore_cmac()`), e o despachante **apaga o slot
  efêmero depois de cada comando ASCII, em qualquer desfecho**. A checagem de
  `modo` continua morando num lugar só.
- O slot efêmero está dentro de `g_slots`, então o `ZEROIZE` e a prova de
  zeroização o cobrem sem código novo.

## No host

- `host/hsm_ponte.py` — a ponte. Escuta em TCP (padrão `127.0.0.1:1500`),
  lê `LEN` + mensagem, repassa à UART, devolve a resposta. Não interpreta
  nada.
- `host/hsmhost.py` — o cliente do host, que fala ASCII. Pela ponte (TCP) ou
  direto na serial.

⚠ **Só um processo abre a serial.** Com a ponte rodando, o `hsmtool` (console)
não consegue abrir a porta. É a consequência prática de console e host
dividirem a UART.

---

## Estado da verificação (2026-11-03)

- **Simulação:** `tb_ascii` passa — C0→C2 de ida e volta, o console
  (`IMPORT_KEY` + `ENCRYPT`) cifra idêntico ao `C0` com o mesmo bloco, M0→M2
  confere e um bit trocado na tag dá `01`, modo de uso respeitado nos dois
  grupos, blocos adulterados e mensagens malformadas recusados, e o slot
  efêmero vazio entre comandos. Suíte completa: 18 testbenches passam.
- **Bitstream:** 0 critical warnings, WNS +0,258 ns (RTL inalterado desde a
  fase 4). Firmware: 21 524 bytes de IMEM (32 KB).
- **Placa, sem botões:** gravada; `ping`, `version` e `post` (oito testes
  verdes) pelo console; `D0` responde pela serial direta **e** pela ponte;
  `K0` recusado com `20` em `UNINITIALIZED`.

✅ **Validado em hardware 2026-11-03, com os botões.** Cerimônia com três
componentes gerados por `--random` (KCVs `6F34C1`, `8AD3EA`, `3057EF`), KCV
da LMK `6935C4` igual nos dois lados — o console e o `D0` da porta host
mostram o mesmo valor que o Python calcula do XOR. `hsmhost.py confere`:
**10 de 10** voltas pela serial direta e **100 de 100** pela ponte TCP. Cada
volta: `K0` gera, o Python abre o bloco com a LMK, `K2` confere, `C0`/`C2`
e `M0`/`M2` batem com AES e CMAC independentes, e uma tag com bit trocado
dá `01`. O `hsmtool audit` mostra os comandos como `HOST xy`, a recusa do
`M2` incluída.

---

## Fora desta etapa

- **Exportar e importar sob outra chave** (uma KEK de troca com outra
  instituição): é o que qualifica a exportação (`doc/fase3-notas.md` §6b) e o
  passo seguinte natural. Exige abrir um bloco de KEK e usá-la como chave de
  proteção de um segundo bloco.
- **Checagem do `uso` da chave** (`D0`, `M?`, `K0`): hoje, como no console,
  quem decide o que a chave pode fazer é o `modo`. A norma também amarra o
  uso, e um HSM comercial confere os dois.
