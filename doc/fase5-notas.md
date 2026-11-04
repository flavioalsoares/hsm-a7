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
| `K4` exportar sob KEK | `K5` | bloco da KEK · bloco da chave (os dois sob a LMK) | bloco da chave sob a KEK · KCV(6) | **sim** |
| `K6` importar sob KEK | `K7` | bloco da KEK (sob a LMK) · bloco da chave (sob a KEK) | bloco da chave sob a LMK · KCV(6) | **sim** |
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
- **`K4`/`K6`** trocam chave com outra instituição — ver "Troca de chaves
  sob KEK", abaixo.
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
| `12` | a chave não é exportável (`'N'`) — só `K4` |
| `13` | o bloco de proteção não é uma KEK (uso ≠ `K0`) — `K4`/`K6` |
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

## Troca de chaves sob KEK (`K4`/`K6`)

*Acrescentada em 2026-11-03, fechando a lacuna 6b de `doc/fase3-notas.md`:
a exportação deixa de ser "sempre sob a LMK" e passa a ser **para quem**.*

Duas instituições que precisam trocar chaves combinam antes uma **KEK** —
uma chave de uso `K0` que as duas têm e cujo único serviço é proteger
outras chaves em trânsito. Cada lado a guarda sob a sua própria LMK. Daí em
diante:

```
instituicao A                                     instituicao B
bloco da chave sob LMK_A                          bloco da KEK sob LMK_B
bloco da KEK sob LMK_A                                     |
   |  K4                                                   |
   +--> bloco da chave sob a KEK  ----- rede ----->  K6 ---+
                                                     bloco da chave sob LMK_B
```

Em nenhum ponto a chave existe fora de um dispositivo em claro, e nenhuma
LMK sai de casa.

### De onde vem a KEK

O modelo da categoria é a KEK formada **por componentes**, em cerimônia,
com um custodiante de cada lado levando a sua parte. Aqui isso já existe
no console, sem comando novo:

```bash
python3 host/hsmtool.py comp-load 0 2 --random --uso K0 --modo B   # botões
python3 host/hsmtool.py comp-load 1 2 --random --uso K0 --modo B   # botões
python3 host/hsmtool.py export-key <handle>      # bloco da KEK sob a LMK
python3 host/hsmtool.py delete-key <handle>      # o host fica com o bloco
```

Para teste, `K0` com uso `K0` também gera uma KEK — mas uma KEK que só um
lado conhece não serve para trocar nada; o `confere` faz assim porque o
Python, tendo a LMK, abre o bloco e faz o papel da outra instituição.

### Passo a passo de uso

**1. Formar a KEK, nos dois dispositivos, com os MESMOS componentes.** Cada
instituição indica um custodiante, e cada custodiante leva o seu
componente aos dois lados. O `--random` serve só no primeiro dispositivo,
onde o componente é gerado e anotado; no segundo, o mesmo valor é digitado:

```bash
# instituicao A (custodiante de A gera o seu; o de B tambem)
python3 host/hsmtool.py comp-load 0 2 --random --uso K0 --modo B   # botões
python3 host/hsmtool.py comp-load 1 2 --random --uso K0 --modo B   # botões

# instituicao B: os mesmos dois componentes, digitados
python3 host/hsmtool.py comp-load 0 2 <componente 0> --uso K0 --modo B
python3 host/hsmtool.py comp-load 1 2 <componente 1> --uso K0 --modo B
```

**2. Conferir pelo KCV, sem trocar a chave.** Cada `comp-load` devolve o
KCV do componente, e o último devolve o handle; o `key-info` desse handle
dá o KCV da KEK montada. Os dois lados comparam KCVs por telefone ou
papel. Cada um pode prever o resultado antes, sem placa:

```bash
python3 host/hsmtool.py kcv <componente 0> <componente 1>
```

Mesmo KCV dos dois lados é a prova de que as duas KEKs são iguais. Nenhum
custodiante viu a KEK inteira.

**3. Tirar a KEK do key store.** Na porta host o dispositivo não guarda a
chave de ninguém: o host fica com a KEK como key block sob a LMK, igual a
qualquer outra chave, e o slot é apagado.

```bash
python3 host/hsmtool.py export-key <handle> -o kek.blk   # bloco sob a LMK
python3 host/hsmtool.py delete-key <handle>
```

**4. Mandar uma chave (lado A, `K4`).** Recebe o bloco da KEK e o da chave,
os dois sob a LMK_A, e devolve a chave sob a KEK. É o que vai pela rede,
junto com o KCV para o outro lado conferir:

```bash
python3 host/hsmhost.py export $(cat kek.blk) $(cat chave.blk) > p_B.blk
```

**5. Receber a chave (lado B, `K6`).** Recebe o bloco da KEK, sob a LMK_B,
e o que chegou, sob a KEK. Devolve a chave sob a LMK_B, que o host guarda
e passa a mandar nos `C0`/`M0`. O KCV que sai tem de bater com o que A
informou:

```bash
python3 host/hsmhost.py import $(cat kek.blk) $(cat p_B.blk) > chave_B.blk
```

O cabeçalho atravessa intacto: uso, modo e exportabilidade são os que a
chave tinha em A. Uma chave `'N'` chega e é usada em B, mas não segue
para uma terceira instituição.

**Para mão única**, forme a KEK com `--modo E` no lado que só manda e
`--modo D` no lado que só recebe. O componente é o mesmo, e o modo é do
cabeçalho de cada dispositivo, não da chave. O `K6` em A e o `K4` em B
passam a ser recusados com `11`.

### Regras

- **A KEK precisa de uso `K0`** (senão `13`). Sem isso, qualquer chave de
  dados com modo `'B'` viraria chave de proteção. E AES-256, porque a
  derivação X9.143 deste dispositivo é a da KBPK de 32 bytes.
- **O `modo` da KEK manda**: `'E'` só embrulha (só `K4`), `'D'` só
  desembrulha (só `K6`), `'B'` os dois (senão `11`). É a leitura que a
  norma dá ao modo de uma KEK, e é o que permite uma KEK de mão única.
- **`K4` é exportar, e `exportabilidade` decide** — `'N'` é recusado com
  `12`, dentro do key store, pela mesma função que o `EXPORT_KEY` do
  console usa (`exportavel()`, estática em `keystore.c`). O bloco sai com
  o cabeçalho de entrada.
- **`K6` não é exportar**: o resultado fica sob a LMK, e só abre aqui. Uma
  chave `'N'` recebida é aceita — `'N'` diz que ela não segue adiante, e
  não segue: o `K4` a recusa.
- **Bloco recebido inválido é `10`, um código só** — MAC errado, outra KEK,
  malformado. O `K6` é o comando mais exposto da porta, como o
  `IMPORT_KEY` do console.
- **A KEK e a chave nunca estão juntas no slot efêmero.** O firmware abre a
  KEK, deriva KBEK/KBAK dela (`keystore_kek_deriva()`, a mesma porta de
  `lmk_deriva_kb()` um degrau abaixo), apaga o slot, e só então abre a
  chave. O que sai do key store são subchaves derivadas, nunca a KEK.

✅ **Validado em hardware 2026-11-03.** Suíte com 18 testbenches passando
(`tb_ascii` com o passo de KEK: `K4` → `K6` volta com o mesmo KCV e cifra
idêntico; recusas `12`, `13`, `11`, `10`, `10`). Na placa, com a LMK
`6935C4` restaurada da flash, `hsmhost.py confere`: **10 de 10** pela
serial e **100 de 100** pela ponte. Em cada volta o Python, no papel da
outra instituição, abre o que o `K4` exportou com a KEK, embrulha uma chave
`'N'` sob a KEK para o `K6` importar, confere que ela volta sob a LMK com o
cabeçalho intacto e cifra certo, e cobra as seis recusas. O log mostra
`HOST K4`/`HOST K6` com os códigos. Firmware: 22 584 bytes de IMEM;
bitstream com 0 critical warnings, WNS +0,258 ns.

⚠ **`keystore_kek_deriva()` é o segundo chamador de `tr31_deriva()`.** O
CLAUDE.md avisa que um segundo chamador é sinal de alguém com a chave
mestra. Este está **dentro de `keystore.c`**, ao lado do primeiro, e deriva
de uma KEK — que é exatamente o que uma KBPK é. Fora de `keystore.c` o
aviso continua valendo.

⚠ **Uma KEK `'B'` ainda cifra dados pelo `C0`.** O `K4`/`K6` exigem uso
`K0`, mas os comandos de dados não recusam uso `K0` — é o item "checagem
do `uso`" abaixo, que continua aberto.

---

## Fora desta etapa

- **Checagem do `uso` da chave** (`D0`, `M?`, `K0`): hoje, como no console,
  quem decide o que a chave pode fazer é o `modo`. A norma também amarra o
  uso, e um HSM comercial confere os dois.
