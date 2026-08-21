# CLAUDE.md

Instruções para agentes de codificação trabalhando neste repositório.
Leia `PLANO.md` para o contexto completo. Este arquivo é o resumo operacional.

## O que é este projeto

HSM educacional em FPGA Artix-7 XC7A35T (QMTECH, FTG256). SoC NEORV32 + cores
cripto no fabric, hierarquia de chaves, cerimônia de LMK, key blocks TR-31, API
de host. Objetivo é **aprender arquitetura de HSM**, não proteger nada.

Nenhuma chave de produção entra aqui. Nunca.

## Regras invioláveis

Estas não são preferências. Se uma tarefa pedir qualquer coisa desta lista,
**pare e avise em vez de executar.**

1. **Nada de eFUSE.** Não gerar, sugerir ou executar `program_efuse`,
   `CFG_AES_ONLY`, `W_DIS`/`R_DIS`, ou qualquer flag `-efuse`. É OTP: brick
   permanente. Chave de bitstream só em BBRAM.
2. **Chaves só em BRAM.** LMK e chaves em claro nunca vão para DDR3, nunca para
   SPI flash sem wrap, nunca para um registrador exposto no toplevel.
3. **Nada atravessa a fronteira criptográfica em claro.** Saem apenas: key
   blocks wrapped, KCVs, criptogramas, handles, log. Ver `PLANO.md` §1.
4. **Simulação antes de hardware.** Nenhum módulo vai para a placa sem
   testbench passando. Depurar cripto por UART é a forma mais lenta de
   descobrir um erro de padding.
5. **Não enfraquecer testes para fazer algo passar.** Se um KAT falha, o bug
   está no código, não no vetor. Não ajustar vetor, não relaxar assert, não
   marcar teste como skip. Reportar e parar.

## Fluxo de trabalho

```bash
# simulacao -- xsim, obrigatorio para qualquer coisa que toque no MMCM ou em
# outra primitiva Xilinx (precisa das unisims). Aplica os patches de
# patches/ sozinho, em build/patched/.
./scripts/sim.sh tb_clk_rst     # um testbench
./scripts/sim.sh                # todos os implementados

# iverilog serviria para cores puros, sem primitivas Xilinx -- mas NAO esta
# instalado nesta maquina. Use o sim.sh para tudo.

# vetores embutidos no firmware (POST). Regenerar apos mexer em vectors/:
python3 scripts/mkkat.py            # -> fw/include/kat_vectors.h
python3 scripts/health-cutoffs.py   # cutoffs da SP 800-90B, com a derivacao

# sanidade estatistica sobre saida do RANDOM (NAO valida o gerador):
python3 host/hsmtool.py random -n 1048576 -o /tmp/r.bin
python3 scripts/entstat.py /tmp/r.bin

# sintese + bitstream (Vivado 2026.1 em /opt/AMD)
source /opt/AMD/2026.1/Vivado/settings64.sh
vivado -mode batch -source scripts/build.tcl

# host -- os dois primeiros rodam sem placa
python3 host/hsmtool.py selftest    # codec do protocolo
python3 host/test_hsmtool.py        # transporte (pty + modelo do dispositivo)
python3 host/hsmtool.py ping
python3 host/hsmtool.py post        # reroda o POST no dispositivo
```

Após qualquer mudança de RTL, arquivar utilização e timing em `doc/`. Regressão
de recursos é sinal de alerta num projeto com orçamento apertado de fabric.

## Convenções

- **RTL:** Verilog-2001 no código próprio; cores externos ficam como estão, sem
  reformatação. Sinais `_i`/`_o`/`_n`. Reset síncrono, ativo baixo.
- **Firmware:** C99, sem alocação dinâmica. `uint8_t` para material de chave,
  nunca `char`. Toda função que toca chave leva comentário dizendo em qual lado
  da fronteira ela opera.
- **Wipe:** limpar buffers sensíveis com uma função de zeroização que o
  compilador não possa otimizar (`volatile` ou barreira de memória). Um `memset`
  simples no fim do escopo pode ser eliminado.
- **Comandos novos:** todo opcode novo precisa de entrada na tabela de comandos,
  verificação de estado, e um teste. Nesta ordem.

## Checklist para qualquer comando novo

Antes de implementar, responder no PR/commit:

- [ ] Em quais estados ele é permitido? (`UNINITIALIZED`/`AUTHORIZED`/`OPERATIONAL`)
- [ ] Exige dual control?
- [ ] O que ele pode fazer vazar se for chamado em loop com entradas escolhidas?
- [ ] Respeita `exportability` do slot?
- [ ] Entra no log de auditoria **antes** da execução?

## Estado atual (atualizado 2026-08-21)

**Fase 2 em andamento. O CFS está pronto.** AES-256, SHA-256 e o `DNA_PORT`
são coprocessadores dentro da fronteira criptográfica, verificados contra os
vetores oficiais do NIST — nos cores **e** através do mapa de registradores:

```
tb_aes_kat     405 x 4 (ECB/CBC, cifra/decifra) = 1620 vetores   PASS
tb_sha256_kat  65 mensagens, 74 blocos                            PASS
tb_cfs         ID, DNA, 810 AES-ECB, 65 SHA, escrita-so, WIPE     PASS
tb_uart_frame  agora inclui GET_DNA ponta a ponta                 PASS
```

`GET_DNA`, última sobra da Fase 1, está fechado.

**O TRNG e os health tests estão em RTL e verificados** (2026-08-08):

```
tb_trng_health  fonte travada, borda exata do RCT (41 e nao 40),
                vies que so o APT pega, fonte equilibrada       PASS
tb_cfs          retrato de 1024 amostras brutas pelo barramento,
                fonte travada -> RCT_FAIL visivel pela CPU      PASS
tb_diag         instrumento de bancada, 8N1 + eco + Block RAM   PASS
```

⚠ **O plano dizia "RCT e APT em firmware". Não dá, e a divisão mudou.** A
SP 800-90B exige que os testes *contínuos* vejam **toda** amostra, e a fonte
produz uma por ciclo de 100 MHz — a CPU veria uma em mil. Então: **hardware**
faz os testes contínuos e congela 1024 amostras brutas consecutivas;
**firmware** faz os testes de partida sobre esse retrato e é dono da política
(falha → `TAMPERED`). Os dois testes ficam implementados duas vezes, de forma
independente, e discordância entre eles denuncia erro de interpretação da
norma. Ver `doc/fase2-notas.md`.

⚠ **Cutoffs vêm de `scripts/health-cutoffs.py`, não de tabela lembrada.**
`H = 0,5 bit/amostra` é **hipótese**, não medida — uma validação 90B de
verdade estima H de 1.000.000 de amostras reais. É para isso que existe o
registrador de retrato.

**CTR_DRBG e POST estão implementados** (2026-08-08). O POST roda antes de
aceitar qualquer comando e cobre AES-256, SHA-256, HMAC-SHA-256 e CTR_DRBG
contra vetores oficiais, mais os testes de partida da fonte. Falha leva a
`TAMPERED`, e o dispositivo continua atendendo **só** ao `SELFTEST`. Custo
medido: **5,94 ms** de boot.

⚠ **Vetores do POST vêm de `scripts/mkkat.py`**, que gera
`fw/include/kat_vectors.h` a partir de `vectors/`. **Nunca editar esse
header à mão** — ele é a única coisa que sustenta a regra nº 5.

⚠ **`AES_ENC`, `AES_DEC` e `HMAC` recebem chave no payload e só respondem em
`UNINITIALIZED`.** Não é convenção, é a máscara de estados na tabela. Um
comando que aceita chave em claro não pode coexistir com chave de verdade.
A fase 3 os **substitui** por versões que falam por handle.

**Fase 3 em andamento.** Prontos:

- `CMAC-AES-256` (`fw/src/cmac.c`, SP 800-38B) — deriva KBEK/KBAK da LMK e
  autentica o key block X9.143. Vetores do CAVP em `vectors/cmac/`.
- **Key store em BRAM** (`fw/src/keystore.c`) — 16 slots com os campos do
  header X9.143, mais a LMK em região separada.

⚠ **A API do key store é assimétrica de propósito, e não é para
"simplificar".** `keystore_usa_aes()` carrega a chave no coprocessador e
**não a devolve**; `keystore_exporta()` é a **única** função que devolve
bytes, checa `exportabilidade` e existe só para a camada de key block. Um
`keystore_get_key()` genérico transformaria a checagem em convenção. O tipo
que contém chave nem aparece no header.

⚠ **A LMK fica FORA do vetor de slots** — sem handle, e zeroizá-la apaga
todos os slots junto. Chave derivada não sobrevive à chave que a protege.

⚠ **Os vetores de CMAC do CAVS 11.0 só têm tags truncadas** (Tlen 5 e 10).
O KAT compara os primeiros Tlen bytes, o que é normatizado — mas **não
verifica os últimos 6 bytes da tag**. Não há vetor público de tag cheia.

Falta da fase 2 apenas `dieharder -a`, que não está instalado.
Detalhes em `doc/fase2-notas.md`; **o próximo passo e como retomar estão em
`doc/fase3-notas.md`** — o próximo é o **key store em BRAM**, e a estrutura
do slot precisa nascer com os campos do header X9.143 já modelados.

**Timing fecha em +0,487 ns** (Fmax ≈ 105 MHz), 0 erros e 0 critical
warnings. Não fechava: o CFS entrou com **−2,388 ns**, e 49 dos 58 endpoints
falhando estavam no `sha256_core`. Resolvido com dois patches de retimagem
em `patches/sha256/` (registrar `W` e `K`) mais `phys_opt_design` no fluxo.
Recursos: 7035 LUTs (33,8%), 6235 FF (15,0%), BRAM 3,5, DSP 0.

⚠ **Cores de terceiros agora passam por `scripts/apply-patches.sh`**, que
aplica os patches sobre uma **cópia** em `build/patched/`. `third_party/`
continua byte a byte igual ao upstream — o script falha se não estiver.
Nunca aplicar patch dentro do submódulo.

⚠ **Limite de frequência do `CLK` do `DNA_PORT` não conferido** contra a
UG470. Roda a 100 MHz junto com o resto. Se a leitura vier inconsistente em
hardware, dividir o clock daquele bloco — o conserto é local.

✅ **A placa agora guarda o bitstream**: `./scripts/program.sh flash` grava
na SPI flash e a placa sobe sozinha no power-on. Passou a ser o modo padrão
— e não só por conveniência, ver a seção de bancada abaixo.

✅ **Validado em hardware (2026-08-07, reconfirmado 2026-08-08 pela flash).**
Os tres comandos respondem na placa:

```
ping     PONG  (4,25 ms)
version  v0.1.0, estado UNINITIALIZED
dna      06CA58966E4285C   (57 bits)
```

O `GET_DNA` fecha a ultima sobra da Fase 1 **em hardware**. E o firmware de
producao se recusa a subir se o CFS nao responder com o ID certo: ele subiu,
entao o coprocessador esta integro ponta a ponta.

## Bancada — leia `doc/bancada.md` antes de depurar hardware

**Grave na flash, não na SRAM:**

```bash
./scripts/program.sh flash     # persistente, e o modo certo aqui
```

⚠ **A configuração por JTAG NÃO aplica a inicialização das Block RAMs nesta
bancada.** É de lá que a IMEM do NEORV32 tira o código. Carregado por JTAG:
`Done = 1`, MMCM travado, e a CPU não executa uma instrução — GPIO mudo,
UART muda, heartbeat piscando (porque flip-flop é configurado certo).
Carregado pela flash: `ping`, `version` e `dna` respondem. Mesmo bitstream,
medido nos dois caminhos com `rtl/diag/`.

⚠ **`Done = 1` prova que a sequência de configuração terminou, NÃO que o
dispositivo funciona.** Já custou duas sessões, por duas causas diferentes.

**Existe um bitstream de diagnóstico sem CPU nenhuma** — use-o *antes* de
suspeitar de RTL, síntese ou timing:

```bash
vivado -mode batch -source scripts/build-diag.tcl
BIT=build/hsm_diag.bit ./scripts/program.sh flash
```

Ele pisca D1, faz luz corrida em D2–D5, transmite
`HSM-DIAG nnnn Rrrrr Wwwww Zzzzzzzzz` e ecoa o que receber. `R`/`W` são os
placares do teste de Block RAM e `Z` deve ser `2345678B`.

Firmware que anuncia o boot: `make -C fw HSM_DIAG=1 image`. **Não é build de
produção** — o dispositivo de produção é mudo até ser perguntado.

Discriminadores de falha, medição de VCCINT/temperatura pelo XADC e as
armadilhas de `grep` sobre `openFPGALoader`: `doc/bancada.md`.

## Fase 1 — concluída

**Fase 1: os cinco entregáveis estão prontos e verificados.** MMCM 50→100 MHz,
reset síncrono, XDC com pinagem resolvida, SoC NEORV32 (submódulo v1.13.3)
com UART0/GPIO/debounce, firmware C com o protocolo de frames, e
`host/hsmtool.py`. Cinco testbenches RTL passam, incluindo `tb_uart_frame`
(PING→PONG a 115200 contra o firmware real na IMEM); no host, o selftest do
codec e o teste de transporte também. Síntese com 0 erros e 0 critical
warnings.

**Validado em hardware (2026-07-31).** Bitstream gravado por JTAG, D1 a 1 Hz,
D2 aceso, `ping` → `PONG` em 4,4 ms. Critério de aceitação fechado: 10.000
pings, **0 erros**, mediana 4,36 ms e máximo 6,50 ms contra o limite de 50 ms.

Sobra da Fase 1 apenas `GET_DNA`, que depende do CFS e chega com a Fase 2.

⚠ **Duas `/dev/ttyUSB*` com o gravador ligado.** O adaptador JTAG é um FT232H
e também cria porta serial, normalmente em `ttyUSB0` — *antes* da placa. O
`hsmtool.py` escolhe por VID:PID (CP2102 = `10c4:ea60`); ao usar `--port` na
mão, conferir qual é qual.

**Pontos de atenção** — detalhes em `doc/fase1-notas.md`:

- Folga de timing em **+0,637 ns** (Fmax ≈ 107 MHz). Já caiu duas vezes; os
  cores de cripto da Fase 2 vão apertar mais.
- `BOOT_MODE_SELECT = 2`: a IMEM é **ROM**, então trocar firmware exige
  regerar o bitstream. Em compensação a memória de código não é gravável em
  tempo de execução.
- `GET_DNA` responde `STATUS_NOT_IMPLEMENTED`: o `DNA_PORT` precisa de um
  registrador no CFS, que só chega na Fase 2.

Toolchain do firmware (Debian/Ubuntu) — **dois** pacotes, o compilador
sozinho não basta:

```bash
sudo apt install -y gcc-riscv64-unknown-elf picolibc-riscv64-unknown-elf
make -C fw image        # -> fw/neorv32_imem_image.vhd, exigido pelo build
```

Ver `PLANO.md` §2 para os critérios de aceitação restantes.

## Cores externos

NEORV32 é submódulo em `third_party/neorv32`, **fixado na tag v1.13.3**.
Configuração do processador toda em `rtl/soc/neorv32_wrapper.vhd`, que é
código nosso — inclusive a lista do que está deliberadamente desligado (OCD,
caches, XBUS) e por quê.

Clone novo precisa de `git submodule update --init --recursive`.

**Nunca editar `third_party/` direto.** Uma edição lá não é guardada em lugar
nenhum deste repositório, é descartada em silêncio por `git submodule update`,
e quebra a procedência: o pin continua dizendo `v1.13.3` enquanto o bitstream
contém outra coisa. Ordem para mudar código de terceiros:

1. Configuração (generic no wrapper) — resolve quase sempre
2. Ponto de extensão projetado — **usado**: `rtl/crypto/neorv32_cfs.vhd`
   substitui o CFS do NEORV32 pela lista de arquivos do build, sem patch
3. Patch em `patches/`, aplicado pelo build — **usado**: dois patches de
   retimagem no `sha256_core` (`patches/sha256/`), sem os quais o design não
   fecha 100 MHz. Aplicados por `scripts/apply-patches.sh` sobre uma cópia
   em `build/patched/`, nunca dentro do submódulo
4. Fork + repontar o submódulo — **só** com patch que precise persistir ou
   rebase recorrente. Não forkar por precaução: fork cria obrigação de rebase
   e apodrece

Espelho offline dos cores: `./scripts/mirror-deps.sh` (tarball reproduzível +
SHA-256). Cobre disponibilidade, que é o que o pin por SHA não garante.

## Pinagem — resolvida, com fonte

Os pinos do XDC **não são mais TODO**. Vieram do projeto irmão
`~/Projetos/MSXInArt/msxinart`, que roda na mesma placa, e boa parte foi
verificada em hardware lá. Esquemáticos em `doc/datasheets/`, XDCs oficiais da
QMTECH em `doc/qmtech_official_xdc/`, decisões e procedência em `doc/pinout.md`.

Resumo: clock N11 · reset B7 (SW1) · UART T15/T14 (CP2102, mesma USB) · dual
control M6/P6 (SW2/SW5) · LEDs R6/T5/R7/T7/R8 · 7-seg 3 dígitos.
**Botões e LEDs são ativos em nível baixo.**

Cuidado herdado: `LED.xdc` e `key.xdc` oficiais são do core board **sem**
daughterboard — usam E6/K5, que com a daughterboard montada são CLK e MOSI do
microSD. Não copiar sem ler `doc/pinout.md`.

## Coisas que faltam e que você não deve inventar

Nada de pinagem: LEDs, 7 segmentos e ordem dos botões foram todos
verificados em hardware. Ver `doc/pinout.md`.

- Vetores KAT **já estão em `vectors/`**, com URL e SHA-256 em
  `vectors/MANIFEST.txt` — AES, SHA-256, HMAC, CMAC e CTR_DRBG. Para
  qualquer algoritmo novo, buscar na fonte oficial e registrar o hash.
  Nunca escrever vetor "de memória": é o que sustenta a regra nº 5.
