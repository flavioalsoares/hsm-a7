# hsm-a7

HSM educacional em FPGA (Artix-7 XC7A35T, QMTECH). Projeto **didatico**:
o objetivo e entender como um HSM funciona construindo um de brinquedo.

**Este dispositivo nao e um HSM.** Sem PUF, sem malha antitamper, sem
sensores, sem RNG certificado, sem validacao FIPS/PCI. Nenhuma chave de
producao entra aqui.

## Para aprender o assunto

**[`doc/hsm-a7-manual.pdf`](doc/hsm-a7-manual.pdf)** — 46 paginas.

  I-II   como um HSM funciona: fronteira, hierarquia de chaves, cerimonia
         de LMK, TR-31, maquina de estados, aleatoriedade, self-test
  III    como HSMs sao atacados: ataques de API, canais laterais, injecao
         de falha, antitamper
  IV     certificacao: FIPS 140-3, PCI, Common Criteria
  V      cada peca deste projeto e o que ela e num HSM real
  VI     o caminho ate a fase 7

Fonte do manual em [`doc/manual/`](doc/manual/) (Markdown); o PDF sai de
`./scripts/mkpdf.sh`. Roteiro de leitura completo em
[`doc/README.md`](doc/README.md).

Antes de mexer no codigo, leia **PLANO.md** -- em especial a secao 0
(restricoes invioláveis: nada de eFUSE, nunca).

Estado: **fase 1 completa e validada em hardware** (10.000 pings, 0 erros).
**Fase 2 em andamento**: AES-256, SHA-256 e o `DNA_PORT` ja estao no
coprocessador (CFS), verificados contra os vetores oficiais do NIST em
simulacao -- nos cores e tambem atraves do barramento. Falta o TRNG, o
CTR_DRBG e o POST. Ver `doc/fase2-notas.md`.

## Dependencias

O core NEORV32 e um submodulo fixado na tag v1.13.3:

```bash
git clone --recurse-submodules <url>
# ou, num clone que ja existe:
git submodule update --init --recursive
```

Toolchain do firmware (Debian/Ubuntu) -- sao dois pacotes, o compilador
sozinho nao traz biblioteca C:

```bash
sudo apt install -y gcc-riscv64-unknown-elf picolibc-riscv64-unknown-elf
sudo apt install -y python3-serial          # CLI do host
```

Vivado 2026.1 (o xsim tambem e usado na simulacao, por causa das unisims e
do VHDL do NEORV32).

## Construindo

```bash
make -C fw image                 # firmware; o build da FPGA depende dele
source /opt/AMD/2026.1/Vivado/settings64.sh

./scripts/sim.sh                 # todos os testbenches implementados
./scripts/sim.sh tb_uart_frame   # um so

vivado -mode batch -source scripts/build.tcl
```

## Host

```bash
python3 host/hsmtool.py selftest        # sem placa: codec do protocolo
python3 host/test_hsmtool.py            # sem placa: transporte

python3 host/hsmtool.py ping            # com placa (115200 8N1)
python3 host/hsmtool.py version
python3 host/hsmtool.py dna             # identidade do die (57 bits)
python3 host/hsmtool.py bench -n 10000  # criterio de aceitacao da fase 1
```

O dispositivo e mudo ate ser perguntado: terminal aberto nao mostra nada, e
isso e o comportamento correto.

Nada vai para a placa sem passar antes no testbench. Ver `CLAUDE.md`.
