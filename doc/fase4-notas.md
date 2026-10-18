# Fase 4 — armazenamento persistente e log de auditoria

*Iniciada em 2026-10-15.*

A fase em que o dispositivo passa a lembrar das coisas quando é desligado. Até
aqui, desligar a placa apagava a LMK e todas as chaves, e cada sessão de
bancada começava refazendo a cerimônia. Agora a LMK, o estado e as chaves de
trabalho voltam sozinhos no boot, e cada comando que mexe em chave deixa um
registro que sobrevive ao desligamento.

---

## ⚠ Por que a LMK é guardada em claro na flash

**Esta é a decisão mais importante da fase, e ela é deliberadamente fraca. O
leitor precisa saber por quê antes de olhar o código.**

### O que um HSM comercial faz

Num HSM de pagamento comercial, a LMK sobrevive ao desligamento porque fica
numa **memória mantida por bateria, dentro de um invólucro com detecção de
violação**. Abrir a caixa, furar a malha que a envolve, resfriar, variar a
tensão: qualquer um desses eventos corta a alimentação dessa memória, e a
chave desaparece em microssegundos. A memória é "segura" porque o
equipamento inteiro foi construído em volta dela.

As chaves de trabalho, por sua vez, só existem fora dessa memória
**embrulhadas sob a LMK**. É o modelo que esta fase reproduz.

### O que esta placa tem, e o que não tem

Para guardar a LMK de forma realmente protegida, seria preciso um segredo que
sobrevivesse ao desligamento **e** não pudesse ser lido de fora. Esta placa
não oferece nenhum:

| Opção | Por que não serve aqui |
|---|---|
| **eFUSE** do FPGA | Proibida pela regra nº 1 do projeto: é gravação única, e um erro inutiliza a placa para sempre. |
| **BBRAM** do FPGA | Existe, mas o pino de bateria (`VCCBATT`) desta placa está ligado ao 1,8 V, sem bateria. Perde o conteúdo no desligamento como a BRAM. |
| **DNA do chip** | É público: qualquer um o lê pelo JTAG. Uma chave derivada dele é previsível. |
| **PUF** | Previsto só como experimento (`doc/puf-experimento.md`), que já se declara "não é raiz de confiança": um RO-PUF de FPGA é instável e exigiria um fuzzy extractor, que é um projeto à parte. |
| **Invólucro com detecção de violação** | Não existe. A placa está aberta sobre a mesa. |

Sem um desses, qualquer esquema de "embrulhar a LMK antes de gravar" só muda
o problema de lugar: a chave que embrulha a LMK teria de estar guardada em
algum lugar, e esse lugar seria a mesma flash. Isso seria **segurança de
fachada**: código mais complexo, que pareceria proteger e não protegeria.

### A decisão

*Tomada pelo usuário em 2026-10-15.*

Este projeto é **educacional**. O objetivo é aprender **como um HSM funciona
e como se opera um**: cerimônia, hierarquia de chaves, key blocks, estados,
log. Não é proteger segredo real; nenhuma chave de produção entra aqui. Diante
disso, e da limitação de hardware acima, a escolha foi:

> **A região da SPI flash a partir de 4 MB é tratada como memória segura do
> dispositivo.** Ela faz o papel da memória com bateria do HSM comercial. A
> LMK é guardada nela em claro, e as chaves de trabalho, embrulhadas sob a
> LMK como key blocks X9.143.

O comportamento operacional fica igual ao de um equipamento comercial:
desliga, religa, e o HSM volta com a LMK e as chaves, sem nova cerimônia. O
que **não** é igual é a proteção física, e essa diferença está escrita aqui,
em vez de disfarçada.

### O que isso significa na prática

- **Quem tiver um gravador de flash e acesso à placa lê a LMK.** Num
  equipamento comercial, o equivalente exigiria vencer o invólucro de
  violação. Aqui basta um gravador SPI de poucos reais.
- Por consequência, **todas as chaves embrulhadas sob ela também ficam
  expostas** a quem ler a flash.
- O mesmo vale para o log de auditoria: quem tiver o gravador pode alterá-lo
  ou apagá-lo.

Está aceito. **Nenhuma mitigação além do normal foi construída**, por decisão
explícita: complicar o código para proteger o que a placa não consegue
proteger desviaria o projeto do que ele ensina.

A regra nº 2 do `CLAUDE.md` foi reescrita para refletir isso, com data e
autoria da decisão.

---

## O que entrou

### Hardware

- **SPI do NEORV32 ligado** (`IO_SPI_EN`), falando com a MT25QL128, a
  **mesma flash que guarda o bitstream**.
- **O clock da flash sai pela primitiva `STARTUPE2`.** Depois da
  configuração, o pino CCLK (E8) é dedicado e não aceita `PACKAGE_PIN`; a
  `STARTUPE2` é a única forma de a lógica do usuário alcançá-lo. A UG470
  avisa que os três primeiros ciclos são engolidos na troca de fonte, e o
  driver consome esses ciclos com um byte descartável antes do primeiro
  comando.
- `W#` e `HOLD#` (D02/D03) presos em alto.
- **IMEM de 16 para 32 KB, DMEM de 8 para 16 KB.** A IMEM estava em 90,7% no
  fim da fase 3, e persistência e log não cabiam.

Pinos (consultados com `get_package_pins` no Vivado): CS `L12`, MOSI `J13`,
MISO `J14`, `W#` `K15`, `HOLD#` `K16`.

### Mapa da flash

```
0x000000  bitstream                intocável (o driver recusa)
0x400000  registro persistente, A  4 KB
0x401000  registro persistente, B  4 KB
0x410000  log de auditoria         64 KB, 4096 registros em anel
```

⚠ **A guarda do bitstream mora no driver** (`fw/src/flash.c`), no único lugar
por onde toda escrita passa. Qualquer `ERASE` ou `PROGRAM` abaixo de
`0x400000` é recusado ali. O modelo de simulação conta qualquer tentativa
nessa região, e os testbenches exigem zero.

### Registro persistente (`fw/src/persist.c`)

Um registro com a LMK, o estado (`AUTHORIZED` ou `OPERATIONAL`) e os slots
ocupados, cada um como key block X9.143 sob a LMK, junto com o número do slot.
Os handles continuam os mesmos depois de religar.

**Duas cópias, e o contador escolhe.** Gravar exige apagar 4 KB antes, e uma
queda de energia no meio deixaria o dispositivo sem registro. Cada gravação
vai para a cópia mais velha; a outra fica intacta até a nova ser conferida
lendo de volta. No boot vale a cópia de maior contador cujo CRC confere. Se a
mais nova estiver corrompida, o boot usa a anterior, e a gravação seguinte vai
para a corrompida, nunca para a que acabou de salvar o dia.

**Quando grava:**

| Evento | O que acontece se a flash falhar |
|---|---|
| 3º componente da LMK | a LMK é descartada e o comando devolve `STORE_FAIL` |
| `SET_STATE` → `OPERATIONAL` | continua em `AUTHORIZED`, `STORE_FAIL` |
| `GEN_KEY`, `IMPORT_KEY`, chave por componentes | o slot é desfeito, `STORE_FAIL` |
| `DELETE_KEY` | não dá para desfazer; `STORE_FAIL` avisa que a chave **volta** no próximo boot |
| `ZEROIZE` | a BRAM é apagada de qualquer jeito; `STORE_FAIL` avisa que a flash não |

O princípio é um só: **uma chave que o dispositivo diz ter guardado tem de
estar guardada.**

**No boot**, depois do POST, o registro é restaurado e o dispositivo volta ao
estado em que estava. A LMK só é aceita se o KCV recalculado bater com o
gravado. Isso não defende contra ataque (a flash é tratada como segura); é
conferência de integridade, porque um bit trocado na LMK mudaria todas as
chaves que ela protege.

**O `SELFTEST` deixou de ser destrutivo para o operador.** Ele continua
zerando a BRAM, porque o teste de função crítica do key store precisa
exercitar o caminho real, mas restaura da flash em seguida, pelo mesmo
caminho do boot.

**O `ZEROIZE` apaga as duas cópias**, e o dispositivo religa em
`UNINITIALIZED`. O log fica.

### Log de auditoria (`fw/src/audit_log.c`)

`PLANO.md` §5, finalmente. Cada comando que não é puramente informativo deixa
um registro de 16 bytes:

```
seq(4) | comando(1) | estado(1) | argumento(1) | resultado(1) | reservado(4) | crc32(4)
```

⚠ **Gravado ANTES de executar, e o resultado vem depois.** O registro vai
para a flash com o resultado em `0xFF`; depois do handler, só aquele byte é
programado por cima. Não precisa apagar nada: flash só desce bits, e `0xFF` é
o valor apagado. **Um registro que ficou em `0xFF` é um comando que começou e
não terminou**, exatamente o que uma trilha forense quer ver.

⚠ **Sem registro, sem execução.** Se o log não puder ser gravado, o comando
devolve `STATUS_LOG_FAIL` e não roda. A exceção é o `ZEROIZE`: um dispositivo
que não apaga a chave porque o log quebrou é pior que um que apaga sem
registrar.

**O que entra:** cerimônia, ativação, todos os comandos de chave, uso de
chave (`ENCRYPT`, `DECRYPT`, MAC), autoteste e zeroize, **inclusive quando
recusados**: uma tentativa fora de hora entra com o resultado
`WRONG_STATE`. **O que não entra:** `PING`, `GET_VERSION`, `GET_DNA`,
`SHA256`, `RANDOM`, `LMK_STATUS`, `KEY_INFO` e o próprio `AUDIT_READ`; ler o
log não entra nele, ou cada leitura empurraria o que se quer ler para fora do
anel.

**Cada boot também entra**, com o comando `0x00`, e o argumento diz se o POST
passou, se a flash respondeu e se o registro persistente foi restaurado.

**Anel de 4096 registros.** O registro `seq` mora na posição `seq % 4096`,
então achar um registro antigo é conta, não busca. Ao entrar num subsetor
novo, os 256 registros mais velhos são apagados. O `ZEROIZE` **não** apaga
o log: ele é o registro de quem zeroizou.

### Comando novo: `AUDIT_READ` (`0x2D`)

```
pedido    seq_inicial(4)
resposta  proximo(4) || continuar(4) || até 16 registros de 16 bytes
```

Permitido em `ST_NORMAL`. Em `TAMPERED`, não, pela política de o dispositivo
comprometido responder o mínimo; o log continua na flash para quem religar.

Status novos: `STATUS_STORE_FAIL` (`0x26`) e `STATUS_LOG_FAIL` (`0x27`).

---

## Limitações, conhecidas e aceitas

Por decisão do usuário, todas estão **documentadas, não mitigadas**. O projeto
é didático; construir defesa além do normal desviaria do que ele ensina.

1. **A LMK está em claro na flash**, legível por quem tiver um gravador SPI.
   Ver a seção de abertura.
2. **Não há anti-rollback.** O contador escolhe a cópia mais nova, mas quem
   regravar a flash inteira com uma imagem antiga volta no tempo (uma chave
   apagada reaparece) e o dispositivo não percebe. Seria preciso um contador
   monotônico fora da flash, e a placa não tem.
3. **O log não é à prova de adulteração.** O CRC detecta corrupção acidental,
   não edição deliberada. Um log com encadeamento por MAC exigiria uma chave
   disponível em `UNINITIALIZED`, que este dispositivo não tem.
4. **O log perde os registros mais velhos** quando o anel dá a volta.
5. **O `contador_uso` dos slots não persiste**: volta a zero no boot.
6. **A flash é a mesma do bitstream.** O driver recusa escrever abaixo de
   4 MB, mas um defeito na guarda apagaria a configuração e a placa não
   subiria até ser regravada por JTAG.
7. **Sem flash, o dispositivo sobe mas não serve.** Todo comando que entra no
   log é recusado com `LOG_FAIL`, a cerimônia inclusive.

---

## Verificação

```
tb_persist   flash vazia; recusa registrada; cerimônia, chaves geradas e por
             componentes, apagar; a LMK na flash e a chave de trabalho SÓ
             embrulhada; 0 escritas abaixo de 4 MB; religar em OPERATIONAL
             sem cerimônia, cada chave no mesmo handle e com o mesmo KCV;
             log contínuo atravessando o boot, nenhum pendente; cópia nova
             corrompida -> o boot usa a anterior; ZEROIZE -> religa em
             UNINITIALIZED e o log fica
```

Suíte completa em 2026-10-16: **17 testbenches passam** (o `tb_hmac_kat`
segue pulado, sem implementação). Duas correções de testbench vieram junto,
e nenhuma relaxou um teste:

- **`tb_zeroize`** começava a cerimônia no instante em que o LED do POST
  acendia. Desde a fase 4 o boot continua depois disso (restaurar, gravar o
  registro de boot), e o primeiro aperto chegava antes de o laço principal
  ver os botões soltos. O dual control recusou, **corretamente**. O teste
  agora espera um `GET_VERSION` responder, que prova que o laço roda. O
  passo 5 mudou de sentido: o `SELFTEST` agora restaura da flash, e o teste
  exige isso.
- **`tb_persist`** reaproveitava a variável de um KCV para guardar outra
  consulta, e reprovou o próprio fallback que estava funcionando.

### ✅ Validado em hardware, 2026-10-16 (sem botões)

```
boot 1     estado UNINITIALIZED, PONG 4,90 ms, DNA 06CA58966E4285C
audit      0  BOOT      Uni  sem registro persistente  OK
post       os oito testes ok
audit      1  SELFTEST  Uni                            OK
gen-key    recusado com WRONG_STATE
reset por JTAG -> o FPGA se reconfigura DA FLASH
boot 2     2  GEN_KEY   Uni  arg=0x44                  WRONG_STATE
           3  BOOT      Uni  sem registro persistente  OK
```

O que isso prova na placa:

- **A `STARTUPE2` e o driver funcionam.** Sem o JEDEC ID certo, o log
  recusaria tudo com `LOG_FAIL`.
- **Apagar, gravar e ler funcionam**, e o log sobrevive a uma reconfiguração
  completa do FPGA.
- **A guarda do bitstream segurou.** Depois de o firmware apagar e gravar na
  região de 4 MB, o FPGA se reconfigurou da mesma flash e subiu. Um apagamento
  no lugar errado deixaria a placa sem subir.
- **A recusa entra no log** com o resultado (`0x44` é o `'D'` do primeiro
  byte do payload, `"D0"`).

### ✅ Validado em hardware, 2026-10-18 (com os botões)

A persistência da LMK e das chaves, de ponta a ponta. Roteiro seguido:

```bash
python3 host/hsmtool.py lmk-load 0 --random     # x3, com os dois botões
python3 host/hsmtool.py lmk-load 1 --random
python3 host/hsmtool.py lmk-load 2 --random
python3 host/hsmtool.py lmk-status              # anote o KCV
python3 host/hsmtool.py activate                # botões
python3 host/hsmtool.py gen-key                 # anote handle e KCV
python3 host/hsmtool.py gen-key --modo C        # outra
# DESLIGUE a placa da USB, espere, ligue de novo
python3 host/hsmtool.py version                 # OPERATIONAL, sem cerimônia
python3 host/hsmtool.py lmk-status              # o MESMO KCV
python3 host/hsmtool.py key-info 1              # mesmo handle, mesmo KCV
python3 host/hsmtool.py audit                   # a sessão inteira, com 2 boots
python3 host/hsmtool.py zeroize                 # botões; depois religar:
python3 host/hsmtool.py version                 # UNINITIALIZED
```

O resultado:

```
                       antes de desligar        depois de religar
estado                 OPERATIONAL              OPERATIONAL, sem cerimônia
KCV da LMK             374575                   374575
handle 1 (modo B)      KCV 801B9D               801B9D
handle 2 (modo C)      KCV 6FC550               6FC550
ENCRYPT h1, bloco fixo 7430714700C554F2...      7430714700C554F2...
MAC h2, mesmo bloco    8A89EEA3CA41F63F...      8A89EEA3CA41F63F...
```

- **O KCV da LMK foi previsto pelo host** antes de ser perguntado: XOR dos
  três componentes e AES da biblioteca `cryptography`, independente do
  firmware. Deu `374575`, o mesmo do dispositivo.
- **A cifragem e o MAC iguais** provam mais que o KCV: os 32 bytes de cada
  chave voltaram intactos da flash, desembrulhados sob a LMK restaurada.
- **`post` com o dispositivo carregado** zerou a BRAM e continuou em
  `OPERATIONAL`, com o mesmo KCV — restaurou da flash.
- **`zeroize` e religar:** `UNINITIALIZED`, 0 de 3 componentes, e o boot
  seguinte registra `sem registro persistente` — as duas cópias foram
  apagadas. O log continuou lá.
- **O log tem a sessão inteira**, recusas incluídas: duas tentativas de
  componente sem os botões (`NOT_AUTHORIZED`), os três componentes, o
  `SET_STATE`, as chaves, o uso delas, `BOOT … restaurado` depois do
  desligamento, o `SELFTEST` e o `ZEROIZE`.

Duas notas de bancada:

- O `hsmtool` pede o Enter **com os botões já apertados**. Rodado pelo `!`
  do Claude Code (sem terminal interativo) ele envia na hora, antes de dar
  tempo de apertar, e o dispositivo recusa. Rode num terminal de verdade.
- O ponto decimal acende **só no último dígito**. Fácil de não ver.

### ⚠ Observação em aberto: um registro de boot que não foi gravado

Depois do `zeroize`, um religamento completo (fonte, USB da placa e USB do
adaptador JTAG desligados) **não deixou registro de boot**. O `audit` na
mesma sessão leu a flash normalmente — a flash respondia à leitura, mas a
gravação do registro de boot não aconteceu. Um reset por JTAG em seguida
registrou o boot (seq 20); repetir o mesmo religamento, na mesma ordem
(fonte, USB da placa, JTAG), também registrou (seq 21), e uma gravação
feita depois nessa sessão entrou no log (seq 22).

Contagem: **três religamentos completos, um sem registro.** Não reproduzido,
causa desconhecida. A suspeita é energia instável na subida, com a fonte e
o USB entrando em instantes diferentes — suspeita, não diagnóstico.

O que limita o dano:

- todo comando que grava a flash confere lendo de volta, e falha vira
  `STORE_FAIL` com a operação desfeita — **uma chave não se perde em
  silêncio**;
- um comando que não consegue entrar no log não executa (`LOG_FAIL`).

O que não está coberto: o registro de **boot** é o único que falha **sem
aviso** — `main.c` ignora o retorno de `log_registra()` ali. O efeito é um
buraco na trilha, sem marca. Fica registrado, **sem conserto**, por decisão
do usuário (2026-10-18). Se voltar a acontecer, anotar a sequência exata
de energia.

Também sem explicação, e talvez nada: entre a validação de 2026-10-16 e
esta sessão apareceu um boot (seq 4) que ninguém anotou. Pode ter sido um
religamento esquecido — boot a mais é bem menos grave que boot a menos.

⚠ **O modelo da flash é próprio, não do fabricante** (`sim/models/`). Se o
datasheet tiver sido lido errado, o modelo e o driver concordam no erro. A
simulação é o filtro; a placa é a prova.
