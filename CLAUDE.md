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
# outra primitiva Xilinx (precisa das unisims)
./scripts/sim.sh tb_clk_rst     # um testbench
./scripts/sim.sh                # todos os implementados

# iverilog serve para cores de cripto puros (fases 2 e 3), sem primitivas:
iverilog -g2012 -o /tmp/tb sim/tb/tb_aes_kat.v rtl/crypto/*.v && vvp /tmp/tb

# sintese + bitstream (Vivado 2026.1 em /opt/AMD)
source /opt/AMD/2026.1/Vivado/settings64.sh
vivado -mode batch -source scripts/build.tcl

# host -- os dois primeiros rodam sem placa
python3 host/hsmtool.py selftest    # codec do protocolo
python3 host/test_hsmtool.py        # transporte (pty + modelo do dispositivo)
python3 host/hsmtool.py ping
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

## Estado atual (atualizado 2026-08-01)

**Fase 2 em andamento.** Vetores KAT baixados das fontes oficiais com hash
registrado (`vectors/MANIFEST.txt`), e os cores de cripto verificados contra
eles em simulação:

```
tb_aes_kat     405 x 4 (ECB/CBC, cifra/decifra) = 1620 vetores   PASS
tb_sha256_kat  65 mensagens, 74 blocos                            PASS
```

Falta, nesta ordem: **CFS** (AES e SHA como coprocessadores — resolve
`GET_DNA` junto), **neoTRNG + health tests RCT/APT**, **CTR_DRBG**, e o
**POST** com os comandos `0x10`–`0x15`. Receita do CFS e detalhes em
`doc/fase2-notas.md`.

⚠ Folga de timing em **+0,637 ns** (Fmax ≈ 107 MHz) antes de entrar cripto
nenhuma. Acompanhar.

⚠ A placa **não guarda nada**: a gravação é volátil e se perde no
desligamento. Para voltar ao ponto, ver "Retomando o trabalho" em
`doc/fase2-notas.md`.

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
2. Ponto de extensão projetado — é o caso do CFS na Fase 2, ver receita em
   `doc/submodulos.md`; troca-se o arquivo na lista do build, sem patch
3. Patch em `patches/`, aplicado pelo build
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

- **Polaridade do 7-seg** (anodo/catodo comum) e o mapeamento bit→segmento não
  foram verificados em hardware. Os pinos estão certos; a tabela de fontes não
  pode ser escrita de palpite.
- **Cores dos LEDs** não documentadas — o `TAMPERED` precisa ser vermelho.
- Vetores KAT em `vectors/` ainda não foram baixados. Não escrever vetores "de
  memória" — buscar nas fontes oficiais (CAVP, FIPS 180-4, RFC 4231).
