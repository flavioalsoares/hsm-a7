# Fase 2 — notas de implementação

Objetivo da fase (`PLANO.md` §3): primitivas corretas e verificáveis.
**Correção antes de desempenho.**

Estado: **em andamento.** Vetores, cores e o coprocessador (CFS) estão
prontos e verificados. Falta o TRNG, o DRBG e o POST.

---

## Concluído

### Vetores KAT (`vectors/`)

Baixados das fontes oficiais em 2026-07-31, com hash registrado em
`vectors/MANIFEST.txt`. Nada foi escrito de memória.

| Diretório | Origem | Conteúdo |
|---|---|---|
| `aes/` | NIST CAVP (AESAVS) | AES-256 ECB e CBC, os 4 tipos de vetor |
| `sha/` | NIST CAVP (SHAVS) | SHA-256, mensagens curtas e longas |
| `hmac/` | IETF RFC 4231 | HMAC-SHA-256 |
| `drbg/` | NIST CAVP (SP 800-90A) | CTR_DRBG AES-256 |

```bash
./scripts/fetch-vectors.sh --check   # confere o repositório
./scripts/fetch-vectors.sh           # rebaixa e reextrai
```

Rodar o segundo sobre um repositório limpo termina **sem nenhuma
diferença** — verificado. Isso é o que sustenta a regra inviolável nº 5: "se
um KAT falha, o bug está no código, não no vetor" só vale se a procedência
do vetor for verificável por terceiros.

Os vetores são versionados, ao contrário dos outros derivados do projeto.
Dois motivos: um POST que depende de rede não é um POST, e o NIST reorganiza
URLs.

### Cores criptográficos

| Submódulo | Origem | Commit |
|---|---|---|
| `third_party/aes` | secworks/aes | `80dc471` |
| `third_party/sha256` | secworks/sha256 | `837c5cc` |

Fixados por **SHA de commit**, não por tag: o `aes` não tem tag nenhuma e a
única do `sha256` é de 2023, dois anos e meio atrás. SHA de commit é
igualmente imutável, que era o motivo de evitar branch (`doc/submodulos.md`).

### Testbenches

```
tb_aes_kat     405 × 4 (ECB/CBC, cifra/decifra) = 1620 vetores   PASS
tb_sha256_kat  65 mensagens, 74 blocos                            PASS
```

**Por que os quatro tipos do AESAVS, e não só um:**

- `GFSbox` — textos escolhidos, chave zero
- `KeySbox` — chaves escolhidas, texto zero
- `VarKey` — cada bit da chave ligado isoladamente, 256 vetores. Pega
  indexação errada na expansão de chave.
- `VarTxt` — cada bit do bloco ligado isoladamente, 128 vetores. Pega ordem
  de byte, rotação e permutação trocadas.

Um core que passa só no `GFSbox` pode estar inteiro errado.

### Divisão de responsabilidade, registrada nos testbenches

Importa porque o firmware vai precisar fazer a mesma coisa:

- **`aes_core` faz ECB.** O encadeamento de CBC é do chamador — o testbench
  faz o XOR com o IV do lado de fora.
- **`sha256_core` recebe blocos de 512 bits já preenchidos.** O padding
  (FIPS 180-4) é do chamador — aqui, `scripts/mkvectors.py`; no dispositivo,
  o firmware.

Testar o core com o padding embutido misturaria duas coisas que falham por
motivos diferentes.

### Ferramentas novas

| Script | O que faz |
|---|---|
| `scripts/fetch-vectors.sh` | baixa das fontes oficiais, confere hash, extrai |
| `scripts/mkvectors.py` | converte `.rsp` → hex para `$readmemh`, e emite `counts.vh` |

`mkvectors.py` **não calcula nada**: chave, entrada e saída esperada são
copiadas literalmente do arquivo do NIST. A única coisa derivada é o padding
do SHA, e é deliberado.

O `counts.vh` existe para o testbench não hardcodar o número de vetores —
um número desatualizado lá faria o teste rodar sobre lixo em silêncio.

`scripts/sim.sh` agora regenera os vetores antes de cada rodada e compila os
cores de cripto junto.

### Bug que o próprio teste encontrou

`tb_sha256_kat` reprovou com sintoma característico: digests **corretos, mas
deslocados de um** — a mensagem 1 devolvia o digest da 0.

Causa: esperar apenas `ready` alto depois do comando termina de imediato,
porque o core ainda não baixou `ready`. Lê-se o resultado da operação
anterior.

Correção: esperar a operação **começar** (`ready` cair) e só então
**terminar** (`ready` subir).

O `tb_aes_kat` passava com o handshake fraco, por sorte de temporização.
Recebeu a mesma correção e os 1620 vetores foram reconfirmados. Teste que
passa por sorte é dívida, não aprovação.

### CFS — AES e SHA como coprocessadores

O `neorv32_cfs.vhd` do upstream é um template feito para ser substituído.
A troca **não exigiu patch nem tocar no submódulo**: o build filtra o
arquivo do upstream da lista e compila o nosso na mesma biblioteca. É o
grau 2 da escada do `doc/submodulos.md`, e é o caso de uso para o qual
aquela escada foi escrita.

Dois arquivos, por motivos diferentes:

| Arquivo | Papel |
|---|---|
| `rtl/crypto/neorv32_cfs.vhd` | shim VHDL. Existe só porque `bus_req_t`/`bus_rsp_t` são *records* e não atravessam a fronteira VHDL→Verilog |
| `rtl/crypto/hsm_cfs.v` | a lógica: mapa de registradores, AES-256, SHA-256, `DNA_PORT`, wipe |

`IO_CFS_EN => true` no wrapper.

#### Mapa de registradores (base `0xFFEB0000`)

```
0x000  ID       r   "HSM1"
0x004  STATUS   r   [0]AES_BUSY [1]AES_VALID [2]SHA_BUSY
                    [3]SHA_VALID [4]DNA_VALID [5]WIPE_BUSY
0x008  CTRL     w   [0]AES_INIT [1]AES_NEXT [2]AES_ENCDEC
                    [3]SHA_INIT [4]SHA_NEXT [5]WIPE
0x020  AES_KEY[8]     w      0x040  AES_BLOCK[4]  w
0x050  AES_RESULT[4]  r      0x080  SHA_BLOCK[16] w
0x0C0  SHA_DIGEST[8]  r      0x100  DNA_LO/HI     r
```

Palavra mais significativa primeiro, como nos vetores do NIST. A CPU é
little-endian, então o firmware **tem** de montar cada palavra byte a byte
(`fw/src/hsm_cfs.c`). Um `memcpy` compilaria e reprovaria em todos os KAT —
que é o melhor desfecho possível para esse tipo de erro.

#### Decisões que valem registro

**`cfs_out_o` amarrado em zero.** É o único fio do CFS que chega ao toplevel.
Com ele em zero não existe caminho físico do bloco que guarda a chave até
fora do die — mesma lógica de `XBUS_EN => false`. Regra 2 do `CLAUDE.md`
deixa de ser promessa de firmware e vira topologia.

**Chave e blocos são escrita-somente.** Ler devolve zero. Não protege contra
a CPU, que acabou de escrever a chave; evita criar um caminho de leitura que
um bug de firmware use por acidente ao varrer o espaço de IO.

**`keylen` fixo em AES-256.** Não há caminho para AES-128. A hierarquia da
fase 3 é toda de 256 bits e um modo mais fraco alcançável por escrita em
registrador é um *downgrade* de graça.

**Sem interrupção.** `irq_o` em zero: o caminho de comando é síncrono e de
passo único, e um handler de IRQ mexendo nos mesmos buffers de chave é mais
difícil de auditar do que uma espera ocupada.

**O bit de BUSY não é o `ready` do core.** Esperar por `ready` logo depois do
comando não funciona — o core ainda não o baixou, a espera termina de
imediato e lê-se o resultado anterior. Foi assim que o `tb_sha256_kat`
reprovou. Lá o conserto foi no testbench; aqui é em hardware, e some para
todos os clientes futuros: `BUSY` sobe junto com o comando e só cai depois
que o core começou **e** terminou.

#### WIPE, e por que ele mexe nos cores

Zerar o registrador de chave não zeroiza nada: a chave **expandida** vive no
`aes_key_mem`, o resultado no bloco do cifrador, o digest no `sha256_core`.
Então `CTRL.WIPE` dispara uma sequência — zera os registradores, roda um
`AES_INIT` com chave zero (reescreve a expansão), um `AES_NEXT` (reescreve o
resultado) e um `SHA_INIT` (reescreve o digest).

O teste correspondente em `tb_cfs` é o que separa zeroização de teatro de
zeroização: **depois do wipe, cifrar sem carregar chave nenhuma tem de
produzir o resultado sob a chave zero.** Se a expansão anterior tivesse
sobrevivido, sairia outra coisa. O vetor de referência é do próprio AESAVS —
o `GFSbox` usa chave zero.

Isso é infraestrutura da fase 3 entrando junto com o bloco que guarda a
chave. Deixar para depois significaria um período com material de chave sem
caminho de apagar.

#### `GET_DNA` — a sobra da Fase 1, fechada

Respondia `STATUS_NOT_IMPLEMENTED` porque o `DNA_PORT` é primitiva Xilinx e
precisava de um caminho até a CPU, e o XBUS está desligado por decisão de
segurança. O registrador do CFS é esse caminho.

São 57 bits, entregues em 8 bytes big-endian. `tb_uart_frame` cobre a cadeia
inteira contra o `SIM_DNA_VALUE`: UART → parser → tabela de comandos →
driver → registrador → primitivo.

> **O DNA não é segredo.** É legível por JTAG em qualquer placa e não muda
> nunca. Serve para identificar a placa em log e inventário. Derivar chave
> dele é um erro clássico: público e constante são exatamente as duas
> propriedades que uma chave não pode ter.

⚠ **Não conferido:** o limite de frequência do `CLK` do `DNA_PORT` na UG470.
O bloco roda a 100 MHz, no mesmo domínio do resto. Se a leitura vier
inconsistente em hardware, o conserto é local — dividir o clock deste bloco.

#### `tb_cfs` — por que existe, se os cores já passavam

`tb_aes_kat` e `tb_sha256_kat` provam que os **cores** estão certos.
`tb_cfs` prova outra coisa: que o **caminho** entre a CPU e os cores está
certo. Um core correto atrás de um mapa de registradores com a ordem das
palavras invertida produz resultados perfeitamente errados, e nenhum KAT de
core pega isso.

Por isso os mesmos vetores do NIST são replicados **através do barramento**:

```
tb_cfs   ID, DNA_PORT, 405 AES-ECB cifra, 405 decifra,
         65 mensagens SHA (74 blocos), escrita-somente, WIPE   PASS
```

#### Timing: o CFS não fechou, e o que foi preciso fazer

Este foi o trabalho de verdade da integração. Relatórios completos em
`doc/utilization_fase2.txt` e `doc/timing_fase2.txt`.

| Ponto | WNS | Endpoints falhando |
|---|---|---|
| Fase 1, sem criptografia | +0,637 ns | 0 |
| CFS integrado, fluxo normal | **−2,388 ns** | 58 |
| CFS, esforço máximo de implementação | −1,215 ns | 53 |
| \+ patch 0001 (W registrado) e `phys_opt_design` | +0,014 ns | 0 |
| \+ patch 0002 (K registrado) | **+0,487 ns** | 0 |

O diagnóstico separou culpa antes de qualquer conserto: dos 58 endpoints,
**49 estavam no `sha256_core` e 9 no `aes_core`**. Pior slack do AES:
−0,087 ns — praticamente nada, coberto pelo `phys_opt_design`. Pior slack do
SHA: −2,388 ns. Um único bloco respondia por tudo.

E dentro dele, um único caminho:

```
w_mem[1] → σ0 → w_new (3 somas) → w (combinacional)
         → t1 (4 somas) → a_new (1 soma) → a_reg
```

**Oito somas de 32 bits encadeadas num ciclo só** — 19 níveis de lógica, 10
`CARRY4`. A causa é a expansão da mensagem e a rodada de compressão
dividirem o mesmo ciclo.

Os dois patches em `patches/sha256/` cortam isso registrando as duas
entradas combinacionais da rodada — `W` e `K`. A rodada passa a começar em
registradores. **Sem estágio de pipeline novo e sem ciclo a mais:** ainda
são 64 rodadas por bloco. O truque do 0001 é deslizar a janela uma rodada
mais cedo, o que faz os quatro *taps* andarem junto e a mesma expressão de
`w_new` passar a produzir `W[t+1]`.

Onde a folga está agora, e ela está distribuída:

```
+0,487  SHA  w_reg → a_reg        (a rodada, agora saindo de registrador)
+0,554  AES  FSM → key_mem
+0,592  barramento de IO → aes_key_reg
```

Nada mais domina. O `phys_opt_design` entrou no `build.tcl` junto: até a
Fase 1 o fluxo simples bastava, e agora vale quase 1 ns.

> **Por que patch e não fork nem core próprio.** Grau 3 da escada
> (`doc/submodulos.md`): não há generic que resolva, não há ponto de
> extensão, e um fork criaria obrigação de rebase sobre um core parado
> desde 2023.
>
> E não se reescreve implementação de criptografia por conta própria
> quando existe uma conhecida e testada. **O que torna este patch
> aceitável é a rede de vetores oficiais** — dá para provar que a
> modificação não mudou o resultado. As 65 mensagens do SHAVS passam nos
> cores e através do barramento, sem um vetor tocado e sem um assert
> relaxado. Sem essa rede, mexer aqui seria irresponsável, e é essa a
> lição — não a retimagem.

`scripts/apply-patches.sh` aplica os patches sobre uma **cópia** em
`build/patched/`. Aplicar dentro de `third_party/` deixaria o submódulo
sujo, e isso quebraria três coisas de uma vez: `git submodule update`
descartaria a mudança em silêncio, `mirror-deps.sh` se recusaria a rodar, e
o pin continuaria dizendo `837c5cc3` enquanto o bitstream conteria outra
coisa. O script confere que os submódulos seguem limpos e falha se não
estiverem.

#### Recursos

| Recurso | Fase 1 | Com o CFS | Disponível |
|---|---|---|---|
| Slice LUTs | 2240 | **7035** (33,8%) | 20800 |
| Flip-flops | 1633 | **6235** (15,0%) | 41600 |
| Block RAM | 3,5 | **3,5** (7%) | 50 |
| DSP48E1 | 0 | **0** | 90 |

Os cores custaram ~4800 LUTs e ~4600 FFs. A BRAM não mexeu: as S-boxes do
AES são lógica distribuída, não memória. Os 90 DSP seguem intactos,
reservados para o RSA de Montgomery da Fase 7.

#### Dois erros encontrados aqui

**1. Corrida de borda no testbench.** A primeira versão de `tb_cfs` dirigia
o barramento na borda de subida — a mesma em que o DUT amostra. O xsim
resolveu a favor do testbench, o DUT viu `stb` um ciclo cedo e **todas** as
leituras chegaram sem ACK. Estímulo na descida, amostragem na subida, e a
corrida some.

**2. Caixa preta silenciosa.** O `xelab` não conseguiu ligar o componente
VHDL `hsm_cfs` (biblioteca `neorv32`, obrigatória) ao módulo Verilog de
mesmo nome (biblioteca padrão). Deixou-o como **caixa preta** e seguiu em
frente com um `WARNING`. Resultado: o firmware não encontrou o
coprocessador, recusou-se a subir, e o sintoma apareceu a três camadas de
distância da causa.

Correção em duas partes, e a segunda importa mais que a primeira:

- `-L work` no `xelab`;
- `scripts/sim.sh` agora **falha** se aparecer `remains a black box`. Um
  aviso que ninguém lê é um aviso que não existe.

---

## O que falta, na ordem

### 1. neoTRNG e os health tests

`IO_TRNG_EN => true` no wrapper. **Manter `IO_TRNG_NUM_RO` pequeno** — meia
dúzia de anéis. Centenas geram calor e ruído de alimentação localizados sem
ganho de entropia (`PLANO.md` §3).

RCT e APT em firmware, sobre a fonte bruta, conforme SP 800-90B. Falha em
qualquer um → `TAMPERED`, DRBG parado, LED vermelho.

É o conteúdo real da fase: esses testes são boa parte do motivo de uma
avaliação de módulo criptográfico levar meses.

### 2. CTR_DRBG em firmware

AES-256, resemeadura por política. Os vetores já estão em
`vectors/drbg/CTR_DRBG_AES256.rsp` — falta o conversor em `mkvectors.py` e o
KAT correspondente.

### 3. POST e comandos

KAT de AES, SHA, HMAC e DRBG no boot, **antes** de aceitar qualquer comando.
Falhou um vetor → o dispositivo não entra em operação.

Comandos `0x10 AES_ENC` · `0x11 AES_DEC` · `0x12 SHA256` · `0x13 HMAC` ·
`0x14 RANDOM` · `0x15 SELFTEST`.

Cada um passa pelo checklist do `CLAUDE.md` antes de ser escrito — em
especial: *o que vaza se for chamado em laço com entradas escolhidas?*

### Critérios de aceitação da fase (`PLANO.md` §3)

- [x] KAT de AES e SHA passam em simulação — nos cores e através do CFS
- [ ] KAT passam também no POST
- [ ] `RANDOM` de 1 MB passa em `ent` e `dieharder -a` (sanidade, não validação)
- [ ] Forçar falha artificial no RCT leva o dispositivo a `TAMPERED`
- [x] Utilização e timing arquivados — `doc/utilization_fase2.txt`,
      `doc/timing_fase2.txt`

---

## Retomando o trabalho

```bash
git submodule update --init --recursive   # agora são três submódulos
source /opt/AMD/2026.1/Vivado/settings64.sh

./scripts/fetch-vectors.sh --check        # vetores íntegros?
./scripts/apply-patches.sh                # cores de terceiros -> build/patched/
make -C fw image
./scripts/sim.sh                          # 8 testbenches devem passar
```

`sim.sh` e `build.tcl` já chamam o `apply-patches.sh` sozinhos; a linha
acima serve para conferir à mão que os patches ainda aplicam. Se o
submódulo do SHA for atualizado algum dia, é ali que o build vai falhar —
e falhar é o comportamento certo.

**A placa não guarda nada.** A gravação da Fase 1 foi em RAM de configuração
(volátil) e se perdeu no desligamento. Para voltar ao ponto:

```bash
make -C fw image
vivado -mode batch -source scripts/build.tcl
./scripts/program.sh
python3 host/hsmtool.py ping
```

Se `--detect` do JTAG ficar intermitente, olhar o número do Device em
`lsusb` antes de suspeitar do bitstream: número mudando é conexão física
re-enumerando.

### Validação em hardware — e a caçada que ela custou

**Resolvido em 2026-08-07. Causa: oxidação nos contatos do cabo flat do
JTAG.** Depois de limpar e lixar os conectores, tudo passou de primeira:

```
ping     PONG  (4,13 ms)
version  v0.1.0, estado UNINITIALIZED
dna      06CA58966E4285C   (57 bits)
```

O `GET_DNA` fechou a última sobra da Fase 1, **em hardware**, com um valor
real e não trivial — nem zeros, nem `F`s. E o limite de frequência do
`DNA_PORT` que ficara registrado como não conferido não deu problema a
100 MHz. Segue valendo a ressalva: não foi verificado contra a UG470, só
observado funcionando.

Vale o registro de quanto o link degradado enganou, porque o padrão se
repete em qualquer bancada:

| Frequência do JTAG | Antes de limpar | Depois |
|---|---|---|
| 6 MHz, leitura de IDCODE | intermitente | 10/10 |
| 6 MHz, gravar 1,25 MB | `CRC Error`, FPGA em branco | `Done 0x1`, sem erro |
| 1 MHz, gravar 1,25 MB | passava | passava |

#### A parte que enganou de verdade

Numa das tentativas o bitstream gravou com **`Done 0x1` e `No CRC error`**
— e o dispositivo ficou mudo, com só o `D1` piscando. Ou seja: **o registro
de status disse que a configuração estava boa e ela não estava.**

Isso mandou o diagnóstico para o lugar errado. Foram construídas e
descartadas, nesta ordem:

1. **A leitura do registrador de ID do CFS trava o barramento.** Refutada
   por um firmware de diagnóstico com marcos por LED: nem `D2` nem `D3`
   acendiam, e os dois vêm *antes* de qualquer acesso ao CFS.
2. **Margem de hold** (`WHS +0,030 ns` contra `WNS +0,487`). Era o suspeito
   seguinte, e é uma hipótese razoável — violação de hold é a causa
   clássica de "funciona em simulação, morre em hardware". **Também
   refutada:** o mesmo bitstream, sem uma linha alterada, funciona
   perfeitamente com os contatos limpos.

**A lição prática:** `Done = 1` prova que a sequência de configuração
terminou, não que o dispositivo está funcionando. Antes de suspeitar do
RTL, da síntese ou do timing, vale gastar cinco minutos garantindo que o
elo físico é bom — porque contato ruim produz sintomas que imitam
perfeitamente defeitos de projeto, e caros de investigar.

Um segundo enganador, e este era código nosso: **duas verificações do
`program.sh` estavam quebradas** e produziam falsos negativos que reforçavam
o diagnóstico errado. O `grep` sobre saída com bytes NUL (o `grep` desta
máquina é o `ugrep`, que trata entrada binária diferente do GNU grep) e um
padrão de CRC que casava com o rótulo `CRC Error` e disparava mesmo em
`No CRC error`. Ambos corrigidos.

#### Sinais que valem para a próxima vez

- **Cadeia JTAG vazia que não melhora baixando a frequência** não é
  integridade de sinal — é conexão ausente. Sinal ruim melhora com clock
  menor; fio solto, não.
- **Precisar baixar para 1 MHz é sintoma, não configuração.** 6 MHz é
  modesto; o projeto irmão `msxinart` grava assim na mesma placa. Se só
  funciona devagar, o elo físico está ruim.
- **Mexer no cabo com a mão mudar o LED do adaptador** é diagnóstico
  fechado.

#### O que ficou de ferramenta

`scripts/program.sh` agora, antes de gravar, exige 5 leituras de IDCODE
consecutivas; e depois de gravar, confere `DONE` e `CRC Error` no registro
`STAT`. Começar e falhar no meio apaga a configuração e deixa o FPGA em
branco — falhar antes de começar é melhor.

```bash
CABLE_FREQ=6000000 ./scripts/program.sh   # cabo bom
./scripts/program.sh                       # padrao 1 MHz, conservador
openFPGALoader -c digilent_hs2 --read-register STAT   # diagnostico
```

---

<details>
<summary>Registro histórico: o quadro enquanto a falha estava aberta</summary>

O que estava provado na época:

| Fato | Prova |
|---|---|
| Bitstream íntegro na placa | `Done 0x1`, `No CRC error`, `EOS 0x1` |
| Clock de 100 MHz vivo, MMCM travado | `MMCM lock 0x1`, e `D1` piscando a 1 Hz |
| SoC fora de reset | `D1` é zerado pelo reset; piscando ⟹ reset liberado |
| Porta serial correta | `hsmtool` escolheu o CP2102 por VID:PID, conferido |
| Firmware não chega ao laço de comandos | `D2` apagado |
| Nem chega às paradas controladas | `D5` apagado — as duas paradas do `main()` acendem `D5` antes de travar |

O firmware congela nas primeiras linhas do `main()`, **antes** de acender
LED nenhum.

#### O diagnóstico já foi feito, e refutou a primeira hipótese

A hipótese era: a leitura do registrador de ID do CFS não retorna, a CPU
trava esperando ACK, e como o firmware nunca chamou `neorv32_rte_setup()`
uma eventual exceção salta para vetor indefinido.

Foi construído e gravado um firmware de diagnóstico que acende LEDs como
marcos e **não trava** na verificação:

```c
/* depois de cmd_init(), ANTES de qualquer coisa tocar no CFS */
neorv32_gpio_pin_set(LED_ALIVE, 1);      /* D2 */
neorv32_gpio_pin_set(LED_CMD, 1);        /* D3 */
{
    volatile uint32_t *cfs = (volatile uint32_t *)0xFFEB0000u;
    uint32_t id = *cfs;                  /* o suspeito */
    neorv32_gpio_pin_set(LED_STATE, 1);  /* D4: a leitura RETORNOU */
    if (id != HSM_CFS_ID_MAGIC) neorv32_gpio_pin_set(LED_TAMPER, 1);
}
/* segue para o laço de comandos, sem travar */
```

**Resultado medido: só o `D1` piscando.** `D2` e `D3` apagados.

Esses dois são acesos **antes** de qualquer acesso ao CFS. Apagados
significa que a CPU **não está executando o programa** — e portanto o CFS
não é o culpado. A hipótese está morta.

#### Onde procurar ao retomar

O quadro é: FPGA configurado, clock e MMCM bons, SoC fora de reset, e o
processador não roda o firmware. A Fase 1 rodava, na mesma placa, com o
mesmo fluxo. A diferença é o CFS ocupando o fabric.

**Suspeito principal: margem de hold.** O timing fecha em setup com
`+0,487 ns`, mas o **hold está em `+0,030 ns`** — trinta picossegundos.
Formalmente atendido, na prática nenhuma margem. Violação de hold é a causa
clássica de "funciona em simulação, morre em hardware": corrompe
registradores em silêncio, e simulação funcional não tem como enxergar,
porque não modela picossegundos. Na Fase 1 esse número não era vigiado.

**Experimento decisivo, e é uma bisseção:** regerar o bitstream com
`IO_CFS_EN => false` e o firmware sem a verificação do CFS.

- Se **bootar**, o problema é a presença do CFS no fabric — congestionamento
  e margem, não lógica. Aí a resposta é atacar o hold e/ou reduzir o clock.
- Se **não bootar**, algo mais básico quebrou entre a Fase 1 e agora
  (`phys_opt_design` no fluxo, os cores no build, a lista de arquivos) e a
  bisseção continua por aí.

**Independente do resultado, fazer:** `neorv32_rte_setup()` no boot. Com
tratador de exceção instalado, falha de barramento vira mensagem pela UART
em vez de congelamento mudo. Um HSM que congela em vez de reportar é pior
que um que reporta — e teria encurtado esta sessão inteira.

Hipóteses já eliminadas, para não repetir trabalho:

- **O CFS** — refutado pelo diagnóstico acima.

- **Caixa preta na síntese** — o log diz `Synth 8-3491 ... 'hsm_cfs' bound
  to instance 'u_core'`. Ligou. (Na *simulação* isso chegou a acontecer e
  foi corrigido com `-L work`.)
- **Roteamento de IO** — `DEV_11_EN bound to: 1`, base `0xFFEB0000`.
- **Imagem da IMEM desatualizada** — MD5 confere após rebuild.
- **Porta serial errada** — conferido por VID:PID.
- **Timing** — fecha com `+0,487 ns`, 0 endpoints falhando.

Nenhuma delas era a causa. Era contato oxidado.

</details>

### Bancada: hub USB, e uma atribuição de causa que estava errada

Registrado em 2026-08-06, depois de custar uma sessão inteira.

Com o adaptador JTAG e a USB da placa **no mesmo hub** (e ainda com outro
hub encadeado), a gravação falhou de um jeito que não parece falha de
gravação:

```
CRC Error       CRC error      bitstream corrompido em transito
Done            0x0            configuracao nao completou
```

O `openFPGALoader` **terminou com status 0** e o script disse "Pronto". Mas
a sequência JTAG apaga a memória de configuração antes de carregar, então
a falha no meio deixou o FPGA **em branco** — menos do que havia antes.

O sintoma na bancada engana: todos os LEDs apagados (são ativos em nível
baixo, e pino sem projeto fica em pull-up) e o dispositivo mudo na serial.
Parece firmware travado. Não é — não há firmware.

Por que hub atrapalha aqui: o FT232H em modo MPSSE faz milhares de
transferências pequenas para empurrar 1,25 MB. Hub encadeado acrescenta
latência, e dividir o upstream com o consumo da placa dá queda de corrente.
No log do kernel aparece como `error -71` (`EPROTO`) e re-enumeração.

**Correção posterior, e ela importa mais que o parágrafo acima.** Tirar o
JTAG do hub **não resolveu** — continuou dando cadeia vazia. O que resolveu
foi limpar a oxidação dos contatos do cabo flat. A explicação pelo hub era
hipótese promovida a fato cedo demais.

E ela é tecnicamente fraca: **o USB tem CRC e retransmissão próprios**. Um
hub não entrega bytes errados em silêncio — ele erra a transferência ou
fica lento. O `CRC Error` observado é do **FPGA**, calculado sobre o
bitstream recebido: os bytes saíram corretos do adaptador e chegaram
corrompidos ao chip. A corrupção aconteceu **depois** do USB, no cabo flat
— sinais single-ended a 6 MHz numa fita sem blindagem e com retorno de
terra pobre, que é o único trecho sem proteção do caminho.

O que continua valendo sobre hubs, mais modesto: dividem corrente (importa
se a placa também se alimenta dali), acrescentam latência ao vaivém do
MPSSE (deixa a gravação lenta, não errada), e hub marginal derruba
dispositivos. Porta direta é boa prática — não é lei, e **não é o primeiro
lugar para olhar** quando um bitstream chega corrompido.

`scripts/program.sh` agora lê o registro `STAT` depois de gravar e recusa
terminar com "Pronto" se o `DONE` não subir ou se houver `CRC Error`.
Diagnóstico útil quando isso acontecer:

```bash
openFPGALoader -c digilent_hs2 --read-register STAT
```

Sintoma correlato, e vale saber distinguir: se `--detect` devolve **cadeia
vazia** e baixar a frequência (`--freq 500000`) não muda nada, não é
integridade de sinal — é o cabo flat de 6 pinos ou o driver `ftdi_sio`
preso na interface. Integridade de sinal melhora com clock menor;
ausência de conexão, não.

E lembrar que existem **duas** `/dev/ttyUSB*` com o gravador ligado — o
`hsmtool` escolhe por VID:PID, mas `--port` na mão pode acertar o cabo
errado.
