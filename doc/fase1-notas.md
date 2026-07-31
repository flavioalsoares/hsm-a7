# Fase 1 — notas de implementação

## Entregável 1: clock e reset (concluído)

`rtl/soc/clk_rst_gen.v` + `rtl/top/hsm_top.v`. MMCM 50 → 100 MHz, reset síncrono
ativo baixo, bring-up de LEDs e botões.

### MMCM

| Parâmetro | Valor |
|---|---|
| `CLKIN1_PERIOD` | 20,000 ns (50 MHz, pino N11) |
| `DIVCLK_DIVIDE` | 1 |
| `CLKFBOUT_MULT_F` | 20,000 → **VCO = 1000 MHz** |
| `CLKOUT0_DIVIDE_F` | 10,000 → **100 MHz** |

VCO em 1000 MHz fica no meio da faixa 600–1200 MHz do Artix-7 -1. É a mesma
razão que o projeto irmão MSXInArt já validou em hardware nesta placa (lá com
÷40 para 25 MHz).

Realimentação por `BUFG` (`CLKFBOUT` → `CLKFBIN`) para compensar o atraso da
rede global e manter `clk_o` alinhado em fase com o clock de entrada.

### Reset — por que o gerador é a exceção da convenção

A convenção do projeto é reset **síncrono**, ativo baixo. O `clk_rst_gen` é o
único módulo que foge disso, e por necessidade: com o MMCM em reset, `clk_o`
não está correndo, então não existe borda para registrar coisa alguma. O
gerador usa o padrão clássico **afirma assíncrono / libera síncrono**,
justamente para que todo o resto do projeto possa usar reset puramente
síncrono.

Duas decisões que valem para um dispositivo que guarda chave:

- **Perda de `LOCKED` reafirma o reset.** Não é ignorada. Um SoC com LMK em
  BRAM não pode continuar executando com o clock fora de lock — é exatamente
  o tipo de condição que a Fase 6 vai explorar como ataque de glitch.
- **Hold de 64 ciclos após o lock** antes de liberar, dando margem para a rede
  global estabilizar.

### Valores iniciais explícitos nos registradores

Sincronizadores, contador do heartbeat e o próprio `heartbeat` são declarados
com valor inicial. Em hardware isso vira o `INIT` do flip-flop; em simulação
evita `X` nas saídas antes da primeira borda.

Não é cosmético: o reset é síncrono, então existe uma janela entre a
configuração do FPGA e o primeiro clock em que a saída não estaria definida. As
saídas em questão são **indicadores visíveis de estado**, e na Fase 3 uma delas
é o LED de `TAMPERED`. O testbench `tb_hsm_top` reprovou a primeira versão
justamente por isso (`led=1111x`).

## Entregável 3: SoC NEORV32 (concluído)

### Como o core entra no projeto

Submódulo git em `third_party/neorv32`, **fixado na tag v1.13.3**
(`b217ead59077d259d30c6168e19705ba087c5964`). Não em `main`: `main` muda
embaixo do projeto e dois builds da mesma árvore poderiam gerar bitstreams
diferentes, o que não é aceitável num dispositivo criptográfico.

A escolha entre submódulo e vendorização foi por submódulo porque torna
estrutural a regra do `CLAUDE.md` de que "cores externos ficam como estão":
não dá para editar o NEORV32 sem que apareça como um repositório sujo
separado. O custo é que um clone raso vem com a pasta vazia — `build.tcl` e
`sim.sh` detectam e imprimem o comando de correção.

**Pendência de cadeia de suprimentos, registrada de propósito:**
`rtl/core/neorv32_bootrom_image.vhd` é o bootloader **pré-compilado**,
distribuído como blob dentro de um arquivo VHDL. Estamos sintetizando um
binário que não compilamos. Aceitável na Fase 1; some quando
`BOOT_MODE_SELECT` virar 2 e a IMEM levar o nosso firmware.

### Por que existe um wrapper VHDL

`neorv32_top` tem ~130 generics, muitos `boolean`, e portas de tipo
customizado (`trace_port_t`). Instanciar isso direto de Verilog é
impraticável — o próprio upstream resolve com um wrapper
(`rtl/verilog/neorv32_verilog_wrapper.vhd`).

`rtl/soc/neorv32_wrapper.vhd` é código próprio e passa a ser **o lugar único
onde a configuração do processador está escrita**. Num projeto de segurança
a lista do que está desligado importa tanto quanto a do que está ligado.

### Configuração — o que está DESLIGADO e por quê

| Generic | Valor | Razão |
|---|---|---|
| `OCD_EN` | `false` | O debugger on-chip dá leitura e escrita irrestritas de memória via JTAG. Num dispositivo com a LMK em BRAM isso é um caminho direto de extração de chave. **É o generic mais importante do arquivo.** |
| `ICACHE_EN` / `DCACHE_EN` | `false` | Duas razões independentes: inúteis (IMEM/DMEM já são BRAM on-chip, latência 1 ciclo) e nocivas (cache introduz tempo de execução dependente do dado — base de ataque por canal lateral de temporização). |
| `XBUS_EN` / `SMC_EN` | `false` | Sem barramento externo não existe caminho físico para material de chave sair do die. Reforça em hardware a regra "chaves só em BRAM". A DDR3 da placa fica deliberadamente inacessível. |
| `IO_TRACER_EN` | `false` | Buffer de trace de execução — observabilidade que não se quer num dispositivo que guarda chave. |
| `RISCV_ISA_Zkne/Zknd/Zknh` | `false` | AES e SHA vão para o fabric como coprocessadores no CFS. Usar a instrução pronta pularia exatamente a parte que o projeto existe para aprender. |

### Configuração — o que está ligado

| Generic | Valor | Razão |
|---|---|---|
| `CLOCK_FREQUENCY` | `100_000_000` | Tem de bater com o clock real: o firmware deriva o divisor de baud daqui. |
| `RISCV_ISA_C` / `_M` | `true` | RV32IMC, conforme PLANO §2. |
| `RISCV_ISA_Zicntr` | `true` | Contadores base (`cycle`/`instret`) — timeouts e medida dos health tests da Fase 2. |
| `CPU_FAST_SHIFT_EN` | `true` | Barrel shifter. Cripto em firmware (CMAC, HMAC, DRBG) é pesada em deslocamento; o shifter serial custa um ciclo por bit. |
| `CPU_FAST_MUL_EN` | `false` | Os 90 DSP48E1 ficam reservados para o RSA de Montgomery da Fase 7. |
| `IMEM_SIZE` / `DMEM_SIZE` | 16 KB / 8 KB | Ponto de partida. Deve crescer na Fase 2/3. |
| `IO_UART0_EN` + FIFOs 64/64 | `true` | Canal do `hsmtool.py`; FIFO dá folga para os frames do protocolo. |
| `IO_CLINT_EN` | `true` | Machine timer, para os timeouts do protocolo. |
| `IO_GPIO_NUM` | `8` | LEDs de estado + botões de dual control. |

Desligados agora mas já nomeados no wrapper para não serem esquecidos:
`IO_CFS_EN` (Fase 2 — é onde AES-256 e SHA-256 entram), `IO_TRNG_EN`
(Fase 2 — neoTRNG, com `IO_TRNG_NUM_RO` pequeno pelo cuidado térmico do
PLANO §3), `IO_SPI_EN` (Fase 4 — log na flash) e `PMP_*` (Fase 3+).

### ⚠ `BOOT_MODE_SELECT = 0` é temporário

Hoje o SoC sobe pelo **bootloader interno**, que aceita upload de firmware
pela UART. Isso foi escolhido porque ainda não existe firmware, e o banner do
bootloader é a prova ponta-a-ponta de que a CPU roda.

**Precisa virar 2 (imagem na IMEM) antes da Fase 3.** Com o bootloader ligado,
qualquer um com acesso à UART reprograma o dispositivo, contornando a máquina
de estados e a fronteira criptográfica inteira. É literalmente o problema de
autenticidade de firmware de um HSM real.

### LEDs: por que D1 continua em hardware

D1 é heartbeat gerado em hardware, **independente da CPU**. É deliberado: se o
firmware travar, D1 continua piscando e distingue "clock morto" de "firmware
pendurado". Num dispositivo sem console, essa é a diferença entre depurar e
adivinhar.

D2..D5 passaram para o GPIO do firmware (apagados até o entregável 4; a Fase 3
usa D5 para `TAMPERED`). O MMCM não precisa mais de LED próprio: sem lock o
reset fica afirmado, o heartbeat não corre e D1 apaga.

### Debounce dos botões

`rtl/soc/debounce.v`, 10 ms de estabilidade exigida (escala com `CLK_HZ`, para
o testbench não precisar simular 10 ms reais). A saída só acompanha a entrada
depois que ela ficou diferente por 10 ms **consecutivos**; qualquer transição
no meio zera a contagem.

Não é detalhe de usabilidade: os dois botões autorizam `LMK_LOAD_COMPONENT`.
Um ressalto de contato lido como pressionamento vale por uma autorização que
ninguém deu — o custodiante que soltou o botão não consentiu com o segundo
pulso.

## Entregável 4: firmware C (concluído)

```bash
make -C fw image                 # -> fw/neorv32_imem_image.vhd
./scripts/sim.sh tb_uart_frame
```

Tamanho: **1652 bytes de text, 0 de data, 1572 de bss** — 10% da IMEM de
16 KB e 19% da DMEM de 8 KB. A bss é quase toda os três buffers de frame
(rx, tx e payload de saída).

### Toolchain no Debian/Ubuntu

Dois pacotes, e o compilador sozinho não basta:

```bash
sudo apt install -y gcc-riscv64-unknown-elf picolibc-riscv64-unknown-elf
```

O GCC fornece apenas os headers freestanding (`stdint`, `stdbool`, `stddef`,
`stdarg`), e `neorv32.h` precisa de `inttypes.h`, `stdlib.h`, `stdio.h`,
`string.h`, `fcntl.h` e `unistd.h`. Não há `libnewlib` para RISC-V nos
repositórios; picolibc é o equivalente.

Três atritos resolvidos, todos registrados no `fw/Makefile`:

1. **Prefixo.** O NEORV32 assume o toolchain xPack (`riscv-none-elf-`); o
   pacote Debian instala como `riscv64-unknown-elf-`.
2. **A picolibc não entra sozinha.** Vive fora do sysroot do compilador e só
   é encontrada via `--specs=picolibc.specs`.
3. **`neorv32_newlib.c` não compila contra a picolibc** — declara
   `extern int errno` enquanto a picolibc usa `errno` thread-local. São 359
   linhas de syscall stubs (`_open`, `_read`, `_write`, `_sbrk`, `_exit`)
   que só servem a quem usa `printf`, `malloc` ou arquivos.

O terceiro é o interessante. A saída **não** foi um patch: o arquivo é
excluído da lista de fontes no nosso Makefile, o que é **configuração**
— degrau 0 da escada de `doc/submodulos.md` — e não modificação do core.
Precisa de `override` porque o `common.mk` reatribui `CORE_SRC` com `=` e
venceria uma atribuição simples.

Isso funciona porque este firmware é genuinamente freestanding: nenhuma
função de libc, laços explícitos, `wipe()` próprio, sem alocação dinâmica.
Num HSM, "menos coisa que eu não escrevi" é objetivo, não efeito colateral.

Se algum dia for preciso libc de verdade, a saída certa não é reincluir o
arquivo com um patch — é trocar para o toolchain xPack, que embute a newlib
e é o que o upstream testa.

### Protocolo

```
pedido    LEN(2) | CMD(1)    | PAYLOAD | CRC32(4)
resposta  LEN(2) | STATUS(1) | PAYLOAD | CRC32(4)
```

Big-endian. `LEN` cobre CMD/STATUS + PAYLOAD, e não se inclui nem inclui o
CRC. Duas decisões que o `PLANO.md` deixava em aberto e precisavam ser
fixadas antes de o host existir:

- **O CRC32 cobre `LEN` + `CMD` + `PAYLOAD`** — todos os bytes menos os
  quatro do próprio CRC. Incluir o `LEN` importa: é o campo que um atacante
  usaria para induzir leitura fora do buffer.
- **Polinômio IEEE 802.3 refletido** (`0xEDB88320`, init `0xFFFFFFFF`, xor
  final `0xFFFFFFFF`) — idêntico ao `zlib.crc32` do Python, o que torna o
  host trivial e elimina uma fonte clássica de divergência.

Sem tabela de 1 KB: a 115200 baud sobram ~8600 ciclos de 100 MHz por byte
recebido, e o laço de 8 iterações cabe com três ordens de grandeza de folga.
IMEM vale mais que ciclos aqui.

### O parser é a superfície de ataque mais exposta

É o único código que processa entrada arbitrária antes de qualquer
verificação. Por isso é deliberadamente burro: máquina de estados explícita,
todos os limites checados, sem alocação, sem recursão.

**O timeout de inter-byte é o que satisfaz "frame malformado nunca trava a
máquina de estados"** (`PLANO.md` §2). Sem ele, um host que morre no meio de
um frame deixa o parser esperando bytes que nunca chegam e o dispositivo fica
mudo para sempre — negação de serviço com um único byte.

É timeout **entre bytes**, rearmado a cada byte, não do frame inteiro. A
diferença importa para payload grande: um key block TR-31 da Fase 3 leva
~45 ms a 115200 baud, e um timeout de frame teria de ser afrouxado até deixar
de proteger.

`LEN` inválido responde `STATUS_BAD_LEN` e resincroniza pelo timeout — não dá
para saber onde aquele frame termina, e continuar lendo com um `LEN` absurdo
seria seguir o atacante.

### Decisões que valem registrar

**`GET_DNA` está na tabela retornando `STATUS_NOT_IMPLEMENTED`.** O
`DNA_PORT` é primitiva Xilinx e precisa de um caminho até a CPU; como o XBUS
está desligado por decisão de segurança, o caminho será um registrador no
CFS — o mesmo bloco que a Fase 2 usa para AES e SHA. Está na tabela desde já
porque a regra do `CLAUDE.md` é "entrada na tabela, verificação de estado e
teste, nessa ordem". Um opcode que responde `NOT_IMPLEMENTED` é honesto e
testável; um opcode ausente responderia `UNKNOWN_CMD` e mentiria sobre o
roadmap.

**`wipe()` existe antes de haver chave.** Zeroização com ponteiro `volatile` +
barreira de memória, porque um `memset` no fim do escopo é *dead store* e o
compilador o elimina com `-Os`. Os buffers de frame são limpos após cada
comando. A Fase 1 não movimenta chave, mas são esses mesmos buffers que
carregam componente de LMK e key block na Fase 3.

**`state.c` implementa só o enum e a consulta.** O dispositivo nasce e fica em
`UNINITIALIZED`. Existe desde já porque a tabela de comandos carrega máscara
de estados permitidos — é mais barato acertar agora que retroajustar cada
handler depois. `TAMPERED` fica fora de `ST_NORMAL` de propósito: dispositivo
comprometido responde o mínimo possível.

**Sem interrupção.** O caminho de comando é síncrono e de passo único, mais
fácil de auditar que um handler de IRQ mexendo nos mesmos buffers.

**O firmware trava de propósito se o CLINT não estiver disponível**, porque
sem ele não há timeout de resincronização. Melhor não subir do que subir
quebrado.

### `BOOT_MODE_SELECT` foi para 2

Não é mais bootloader. Duas razões que se alinharam:

1. Fecha o buraco de segurança que estava marcado em maiúsculas — com o
   bootloader, quem tem a UART reprograma o dispositivo e contorna a máquina
   de estados inteira.
2. **É o que torna o firmware simulável.** Com a imagem embutida na IMEM, o
   `tb_uart_frame` roda o firmware de verdade; via bootloader seria preciso
   simular o upload por UART, o que é inviável.

Custo: trocar firmware exige regerar o bitstream (~4 min neste projeto).

A imagem vem de `fw/` (`make image`) e é **substituída na lista de arquivos**
pelo build, sem tocar no submódulo — mesma receita do CFS
(`doc/submodulos.md`). O alvo `make install` do NEORV32 copiaria para dentro
de `third_party/`, e por isso o `fw/Makefile` avisa para não usá-lo.

O `sim.sh` inclui o hash da imagem na chave do cache da biblioteca: recompilar
o firmware invalida a lib. Sem isso a simulação rodaria em silêncio contra o
binário anterior — o pior tipo de resultado, verde e mentiroso.

### Verificação

| O quê | Como | Resultado |
|---|---|---|
| Protocolo ponta a ponta | `tb_uart_frame`: firmware real na IMEM, UART a 115200 | PASS |
| Silêncio no boot | `tb_soc_silent` | PASS |
| CRC32 do firmware × `zlib.crc32` | harness no host, 41 vetores (comprimentos 0–40) | conferem |
| CRC32 do testbench Verilog × `zlib.crc32` | `xsim` isolado, frames PING/GET_VERSION/PONG | conferem |

O CRC é o único ponto que **três** implementações independentes precisam
acertar — firmware C, testbench Verilog e host Python. Divergência ali
apareceria como `STATUS_BAD_CRC` intermitente, que é dos sintomas mais
enganosos possíveis. As três concordam, e a terceira (o host) já pode ser
escrita contra `zlib.crc32` sem margem para dúvida.

## Entregável 5: `host/hsmtool.py` (concluído)

```bash
python3 host/hsmtool.py selftest        # sem placa: confere o codec
python3 host/test_hsmtool.py            # sem placa: confere o transporte

python3 host/hsmtool.py ping            # com placa
python3 host/hsmtool.py version
python3 host/hsmtool.py bench -n 10000  # critério de aceitação da Fase 1
```

Dependência: `python3-serial` (pyserial). A porta é detectada sozinha
(primeira `/dev/ttyUSB*`, que é como o CP2102 do core board aparece);
`--port` sobrescreve.

### O codec não depende da porta serial

`build_request()` e `parse_response()` são funções puras. Isso é o que
permite testar o protocolo sem hardware, e é também o que deixa
`tr31.py` e `audit.py` (Fase 3) reaproveitarem a mesma implementação em vez
de escreverem a terceira cópia do enquadramento.

### Duas decisões de robustez

**`transact()` não limpa a entrada antes de enviar.** Seria conveniente e
esconderia problemas: byte inesperado na linha é sintoma de
dessincronização, e engoli-lo em silêncio transformaria o teste de 10.000
pings numa medida sem valor. A limpeza acontece só em `resync()`, depois de
um erro reconhecido.

**`resync()` espera mais que o timeout de inter-byte do firmware** (250 ms)
antes de descartar a entrada. Descartar sem esperar deixaria o firmware ainda
no meio do frame anterior, e o próximo pedido entraria como continuação dele
— o erro se propagaria em vez de terminar.

### Verificação, sem placa

| O quê | Como | Resultado |
|---|---|---|
| Codec | `hsmtool.py selftest`: vetores fixos, CRC corrompido, bit trocado no payload, `LEN` fora de faixa, payload grande demais | 8 de 8 |
| Transporte | `test_hsmtool.py`: pty + modelo do dispositivo, com injeção de falha | 10 de 10 |

Os vetores do `selftest` são **fixos**, não gerados pelo próprio módulo — se
fossem gerados, o teste só provaria que o código concorda consigo mesmo. Os
valores vêm das três implementações independentes já cruzadas (firmware C,
testbench Verilog, `zlib`).

O `test_hsmtool.py` cobre a metade que o codec não alcança, que é onde moram
os bugs chatos: leitura parcial, timeout, resposta truncada, CRC ruim, lixo
na linha, e status de erro válido. Esse último é o caminho que
`hsmtool dna` percorre hoje — confundir "o dispositivo recusou" com "a linha
está ruim" manda o diagnóstico para o lado errado.

O modelo do dispositivo é código nosso e **não prova concordância com o
firmware**; quem prova isso é o `tb_uart_frame`, que roda o firmware de
verdade. Aqui se prova que o cliente se comporta quando a linha se comporta
mal.

### Bug que só o hardware expôs

`default_port()` escolhia a primeira `/dev/ttyUSB*`. Na bancada isso é o
**adaptador JTAG** — o "DLC9LP" é um FT232H que também cria porta serial, e
ela costuma ficar em `ttyUSB0`, antes da placa. O sintoma seria um timeout
sem explicação, apontando para o firmware quando o problema é a escolha do
cabo.

Corrigido: a porta é escolhida por **VID:PID** (CP2102 = `10c4:ea60`), com o
FT232H explicitamente excluído. Nenhum teste sem hardware pegaria isso — o
pty do `test_hsmtool.py` não tem VID:PID e o `selftest` não abre porta.

## Bring-up em hardware (2026-07-31)

Bitstream gravado por JTAG na RAM de configuração (volátil):

```
Load SRAM: [==========================] 100.00%
Done
ir: 1 isc_done 1 isc_ena 0 init 1 done 1
```

`done 1` é o próprio FPGA confirmando que aceitou a configuração.

| Verificação | Resultado |
|---|---|
| D1 piscando a 1 Hz | OK — MMCM entrega 100 MHz, polaridade ativa-baixa certa |
| D2 aceso | OK — `main()` chegou ao laço de comandos |
| `hsmtool ping` | `PONG` em 4,44 ms |
| `hsmtool version` | v0.1.0, estado `UNINITIALIZED` |
| `hsmtool dna` | `STATUS_NOT_IMPLEMENTED` (0x12), como projetado |
| opcode `0xAA` | `STATUS_UNKNOWN_CMD` (0x10) |

### Critério de aceitação da Fase 1 — fechado

```
iteracoes  : 10000 em 44.3 s (226/s)
erros      : 0
latencia   : min 3.97  mediana 4.36  p99 4.85  max 6.50 ms
criterio de aceitacao: OK
```

Zero erros de CRC em 10.000 iterações, e o pior caso em 6,50 ms contra o
limite de 50 ms — margem de 7,7×.

A latência é dominada pelo USB, não pelo dispositivo: 16 bytes a 115200 baud
são 1,4 ms de tempo de linha, e o resto é o timer de latência do
CP2102/pilha USB. Se algum dia a Fase 5 precisar de mais vazão, o ganho está
no lado do host, não no firmware.

### Nota de bancada: o JTAG re-enumerando

Na primeira tentativa de gravação o FPGA respondeu o idcode **uma vez** e
depois **0 de 10**, com o adaptador pulando de Device 041 para 045 no USB —
estava re-enumerando. Depois de religar placa e cabo JTAG: **6 de 6** e
gravação de primeira.

Se `--detect` ficar intermitente, olhar o número do Device em `lsusb` antes
de suspeitar do bitstream: número mudando é conexão física, não configuração.

## Testbenches

Rodar com `scripts/sim.sh` (sem argumento roda todos, pulando os ainda não
implementados).

**Usa `xsim`, não `iverilog`.** O `MMCME2_BASE` é primitiva Xilinx e precisa das
unisims — sem elas o clock de 100 MHz simplesmente não existe na simulação. O
`iverilog` do fluxo descrito no `CLAUDE.md` continua válido para os cores de
cripto puros das fases 2 e 3.

| Testbench | Verifica |
|---|---|
| `tb_clk_rst` | período de 10,0000 ns; reset só libera após `LOCKED`; liberação numa borda de subida; hold de 64 ciclos; reasserção pelo botão e recuperação |
| `tb_debounce` | 12 ressaltos curtos ignorados; pressionamento estável aceito exatamente na janela; ressalto na soltura não derruba a saída |
| `tb_hsm_top` | polaridade ativa-baixa de LEDs e botões; caminho botão → sincronizador → debounce → GPIO do SoC; dual control com os dois botões; display apagado; período do divisor do heartbeat |
| `tb_soc_silent` | o dispositivo não transmite nada sem ser perguntado, **e** está vivo (LED de atividade aceso) |
| `tb_uart_frame` | **protocolo ponta a ponta a 115200**: PING→PONG, GET_VERSION, CRC corrompido→`BAD_CRC`, opcode desconhecido→`UNKNOWN_CMD`, e recuperação depois dos erros |

### `tb_soc_boot` foi removido, e o que ficou no lugar

Ele decodificava o banner do bootloader do NEORV32. Com
`BOOT_MODE_SELECT = 2` não há mais bootloader, e o teste passou a ser
impossível por construção — manter um teste morto é pior que não ter.

O terreno que ele cobria (MMCM, reset, CPU, UART, `CLOCK_FREQUENCY`) é
coberto melhor pelo `tb_uart_frame`, que conversa o protocolo de verdade.

O que sobrou virou `tb_soc_silent`, testando a propriedade **dual**, que vale
por si num dispositivo criptográfico: nada sai pela UART enquanto ninguém
pediu. Um banner de boot vaza versão e identidade para quem só escuta, e um
`printf` de depuração esquecido no firmware é um canal lateral permanente —
este teste falha no dia em que alguém adicionar um.

Silêncio sozinho não provaria nada (firmware travado também fica quieto), por
isso ele exige silêncio **e** vida: `main()` precisa ter passado da
inicialização e aceso o LED de atividade.

O foco do `tb_hsm_top` são as **polaridades**. LEDs e botões da daughterboard
são ativos em nível baixo; uma inversão no lugar errado passa despercebida na
bancada e mente sobre o estado do HSM. Um LED de `TAMPERED` invertido é defeito
de segurança, não detalhe cosmético.

### O que o `tb_soc_boot` prova, em cadeia

Decodificar corretamente a 19200 baud (o baud do bootloader, em
`sw/bootloader/config.h`) implica:

- o MMCM entrega 100 MHz e o reset libera;
- a CPU sai do reset, busca da boot ROM e executa;
- o firmware configurou a UART0 e transmitiu;
- **`CLOCK_FREQUENCY` no wrapper bate com o clock real.** Se não batesse, o
  divisor de baud sairia errado e os bits decodificados seriam lixo. Esse é o
  erro mais fácil de cometer no wrapper e o mais chato de diagnosticar na
  bancada.

Duas armadilhas encontradas ao escrever este testbench, ambas registradas no
código:

1. **A biblioteca expande `\n` em CRLF.** `neorv32_uart_puts()` emite `'\r'`
   antes de todo `'\n'` (`sw/lib/source/neorv32_uart.c:308-312`), então o
   banner sai como `0D 0A 0D 0A 'N' 'E' 'O' 'R' 'V' '3' '2'`, não como LF puro.
2. **A linha dá um pulso curto para baixo quando o firmware habilita a
   UART0**, antes de qualquer dado. Um receptor que aceite qualquer borda de
   descida como start bit se desalinha ali. A correção é validar o start bit
   no meio do período — que é exatamente o que um receptor de UART real faz.

Custo: ~75 s de relógio de parede para 11 bytes, porque cada byte a 19200 baud
são 520 µs de tempo simulado (~52 mil ciclos de 100 MHz). Por isso decodifica
só o começo do banner.

Resultado atual: os quatro `PASS`.

## Síntese — linha base

Vivado 2026.1, `xc7a35tftg256-1`. Relatórios completos em
`doc/utilization_fase1.txt` e `doc/timing_fase1.txt`.

| Recurso | Só clock/reset | SoC + bootloader | **SoC + firmware** | Disponível | % final |
|---|---|---|---|---|---|
| Slice LUTs | 24 | 2247 | **2240** | 20800 | 10,77 |
| Slice Registers | 42 | 1633 | **1633** | 41600 | 3,93 |
| Block RAM | 0 | 8 | **3,5** | 50 | 7,00 |
| DSP | 0 | 0 | 0 | 90 | 0 |
| Bonded IOB | 21 | 22 | 22 | 170 | 12,94 |
| MMCME2_ADV | 1 | 1 | 1 | 5 | 20,00 |

Zero DSP, como pretendido — `CPU_FAST_MUL_EN` está desligado e os 90 DSP48E1
ficam para o RSA da Fase 7.

### A BRAM caiu pela metade, e o motivo é bom

De 8 tiles para 3,5 (1× RAMB36E1 + 5× RAMB18E1) ao trocar
`BOOT_MODE_SELECT` de 0 para 2. Duas causas: sumiu a boot ROM do
bootloader, e a IMEM deixou de ser RAM.

Com `BOOT_MODE_SELECT = 2`, o NEORV32 liga `MEM_INIT => imem_as_rom_c` e a
IMEM vira **memória pré-inicializada somente de leitura**
(`rtl/core/neorv32_imem.vhd`). Como o firmware ocupa 1652 dos 16 KB, a
síntese ainda descarta a maior parte do que sobrou.

Isso é um ganho de segurança que veio de graça: **a memória de código não é
gravável em tempo de execução**. Não há injeção de código nem código
automodificável, independentemente de qualquer bug no parser. Foi efeito
colateral de uma mudança feita por outros dois motivos, mas é o tipo de
propriedade que se paga caro para obter em outros lugares.

Timing: **WNS +0,637 ns** em período de 10 ns, WHS +0,037 ns, 0 endpoints
falhando em 4529. *All user specified timing constraints are met.*

### ⚠ A margem de timing encolheu — acompanhar

De +5,950 ns (só o gerador de clock) para +0,898 (com o SoC) e agora
**+0,637 ns**. Isso é ~6% de folga num período de 10 ns, ou seja Fmax ≈
**107 MHz** contra os 100 MHz exigidos.

O caminho crítico está **dentro da CPU**, não no nosso código:

```
regfile (RAMB36E1) -> 11 niveis de logica (7x CARRY4) -> regfile DIADI[31]
data path 8,749 ns  (logica 4,793 / roteamento 3,956)
```

É a cadeia de carry da ALU realimentando o banco de registradores. Os cores de
cripto da Fase 2 entram como coprocessadores no CFS — datapath separado, então
não alongam *este* caminho. Mas eles adicionam congestionamento, e
congestionamento degrada roteamento, que já é 45% deste atraso.

Se 100 MHz ficar inviável na Fase 2, as alavancas na ordem em que valem a pena:

1. `CPU_RF_ARCH_SEL` — muda a implementação do banco de registradores, que é
   justamente a origem e o destino do caminho crítico
2. `IMEM_OUTREG_EN` / `DMEM_OUTREG_EN` — registrador de saída da BRAM
3. baixar o clock do SoC para 75–80 MHz; a UART e a cripto não precisam de
   100 MHz, e correção vem antes de desempenho (PLANO §3)

Clocks reconhecidos corretamente — `clk_out0` derivado automaticamente do MMCM:

```
sys_clk      20.000 ns    50.000 MHz
  clk_out0   10.000 ns   100.000 MHz
  clkfb_out  20.000 ns    50.000 MHz
```

Esta é a **linha base de recursos**. Regressão a partir daqui é sinal de alerta:
o orçamento de fabric do XC7A35T é apertado para AES + SHA + NEORV32 + key
store.

### Warnings — todos esperados

145 warnings, **0 critical, 0 erros**. Duas categorias:

- 22 do nosso código: `seg_o`/`seg_an_o` dirigidos por constante — o display
  fica apagado até a Fase 3, já que a polaridade não foi verificada
- 122 de dentro do NEORV32: sinais sem carga nos periféricos que desligamos.
  Consequência direta de configurar o SoC no mínimo; some conforme CFS, TRNG
  e SPI forem ligados nas fases seguintes

Se aparecer um warning **novo fora dessas duas categorias**, investigar antes
de seguir.

## Mapa de LEDs — bring-up da Fase 1

Serve para resolver na bancada as duas pendências de `doc/pinout.md`: quais
pinos são quais LEDs, e se a polaridade ativa-baixa está certa. A Fase 3
remapeia para estado do HSM.

| LED | Pino | Hoje | Fase 3 (previsto) |
|---|---|---|---|
| D1 | R6 | heartbeat 1 Hz (hardware) | heartbeat |
| D2 | T5 | GPIO firmware — apagado | atividade UART |
| D3 | R7 | GPIO firmware — apagado | `OPERATIONAL` |
| D4 | T7 | GPIO firmware — apagado | POST/KAT |
| D5 | R8 | GPIO firmware — apagado | `TAMPERED` |

## O que verificar na placa

O dispositivo é **mudo até ser perguntado** — não há banner, por decisão de
projeto (ver `tb_soc_silent`). Um terminal aberto não mostra nada, e isso é o
comportamento correto, não um defeito.

Sinais de vida, em ordem de custo:

1. **D1 piscando a 1 Hz** — MMCM travado, domínio de 100 MHz correndo.
   Gerado em hardware, independente da CPU.
2. **D2 aceso** — `main()` passou da inicialização e chegou ao laço de
   comandos. Se D1 pisca e D2 está apagado, o problema é firmware, não clock.
3. **`PING` responde `PONG`** a 115200 8N1 em `/dev/ttyUSB*` — o caminho
   inteiro funciona. Até o `hsmtool.py` existir (entregável 5), dá para
   mandar os 7 bytes na mão:

   ```
   00 01 01 91 5D D8 C5      -> resposta: 00 05 00 'PONG' <crc32>
   ```

   (`91 5D D8 C5` é `zlib.crc32(b'\x00\x01\x01')`.)

Continuam pendentes de verificação visual (`doc/pinout.md`): cores dos LEDs,
polaridade do 7-seg e a ordem física dos botões no silk. O mapeamento dos
botões agora dá para conferir por firmware, lendo o GPIO.

## Próximos entregáveis da Fase 1

1. ~~`hsm_top.v` com MMCM e reset~~ — feito
2. ~~XDC com clock, UART, botões, LEDs, 7-seg~~ — feito (pinagem resolvida)
3. ~~NEORV32: RV32IMC, IMEM/DMEM em BRAM, UART0, GPIO~~ — feito, com debounce
   dos botões
4. ~~Firmware C: `main.c` + parser de frames, `PING` / `GET_VERSION`~~ — feito
5. ~~`host/hsmtool.py`~~ — feito, com selftest do codec e teste de transporte

**Os cinco entregáveis da Fase 1 estão prontos.** Falta, dos critérios de
aceitação (`PLANO.md` §2), o que só a placa fecha:

- [ ] `hsmtool.py bench -n 10000` — 10.000 pings, nenhum erro de CRC,
      nenhum acima de 50 ms. O comando existe e reporta aprovação ou
      reprovação; falta rodar contra o hardware.
- [ ] `GET_DNA`: hoje responde `STATUS_NOT_IMPLEMENTED`. Precisa de um
      registrador no CFS para chegar ao `DNA_PORT`, já que o XBUS está
      desligado por decisão de segurança. Chega junto com a Fase 2, que liga
      o CFS de qualquer forma para AES e SHA.

Os outros dois critérios já estão fechados em simulação e síntese: frame
malformado responde `STATUS_BAD_CRC` sem travar (`tb_uart_frame`), e o
timing fecha a 100 MHz com utilização arquivada.
