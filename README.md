# hsm-a7

HSM educacional em FPGA (Artix-7 XC7A35T, QMTECH). Projeto **didatico**:
o objetivo e entender como um HSM funciona construindo um de brinquedo.

**Este dispositivo nao e um HSM.** Sem PUF, sem malha antitamper, sem
sensores, sem RNG certificado, sem validacao FIPS/PCI. Nenhuma chave de
producao entra aqui.

## Para aprender o assunto

**[`doc/hsm-a7-manual.pdf`](doc/hsm-a7-manual.pdf)** — 62 paginas.

  I-II   como um HSM funciona: fronteira, hierarquia de chaves, cerimonia
         de LMK, key blocks, maquina de estados, aleatoriedade, self-test
  III    como HSMs sao atacados: ataques de API, canais laterais, injecao
         de falha, antitamper
  IV     certificacao: FIPS 140-3, PCI, Common Criteria
  V      cada peca deste projeto e o que ela e num HSM real
  VI     o caminho ate a fase 7
  VII    criptografia de pagamento: PIN blocks ISO 9564 (formatos 0, 1, 3
         e 4), traducao de PIN, PVV e IBM 3624, decimalizacao, DUKPT TDES
         e AES -- e o que deste dominio da para ensinar aqui, e o que nao

Fonte do manual em [`doc/manual/`](doc/manual/) (Markdown); o PDF sai de
`./scripts/mkpdf.sh`. Roteiro de leitura completo em
[`doc/README.md`](doc/README.md).

Antes de mexer no codigo, leia **PLANO.md** -- em especial a secao 0
(restricoes invioláveis: nada de eFUSE, nunca).

Estado: **fases 1 e 2 completas e validadas em hardware.** O POST roda a
cada boot contra vetores oficiais do NIST e do IETF; falha leva o
dispositivo a `TAMPERED`, e a partir dai so o `SELFTEST` responde.

```
python3 host/hsmtool.py post        # reroda o POST no dispositivo
  AES-256                ok
  SHA-256                ok
  HMAC-SHA-256           ok
  CTR_DRBG               ok
  TRNG / health tests    ok
  CMAC-AES-256           ok
  key store              ok
```

**Fase 3 em andamento**: CMAC, o key store em BRAM, a **cerimonia de LMK** e
o **display de estado** estao prontos. Tres componentes por XOR, KCV a cada
passo, dual control pelos dois botoes fisicos, e a placa soletrando
`Uni`/`Aut`/`OPE`/`tPr` com o ponto decimal acendendo enquanto o dual control
esta satisfeito. Faltam os key blocks X9.143, o zeroize e os comandos
`0x22`-`0x2F`. Ver `doc/fase3-notas.md`.

⚠ **Grave na flash, nao na SRAM** -- `./scripts/program.sh flash`. Nesta
bancada a configuracao por JTAG **nao aplica a inicializacao das Block
RAMs**, e e dela que a IMEM tira o codigo. Ver `doc/bancada.md`.

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

python3 host/hsmtool.py lmk-status      # cerimonia de LMK (fase 3)
python3 host/hsmtool.py lmk-load 0 --random
python3 host/hsmtool.py activate
```

⚠ **Aperte os dois botoes e olhe o display**: o ponto decimal acende
enquanto o dual control esta satisfeito. E o jeito mais rapido de saber
quais sao os botoes, e de conferir que o proximo comando sera autorizado
antes de gasta-lo.

⚠ A cerimonia exige **dual control**: os dois botoes (o 2o e o 5o) segurados
no instante em que o comando chega, e um aperto **novo** a cada componente
-- segurar os dois o tempo todo carrega um, nao tres. O `hsmtool.py` pede o
gesto e espera o Enter; se vier `STATUS_NOT_AUTHORIZED`, e porque os botoes
nao estavam apertados, e essa recusa e a prova de que o mecanismo existe.

⚠ A LMK vive em BRAM e **nao sobrevive ao desligamento**. E o que a regra
n° 2 pede; persistencia e a fase 4.

O dispositivo e mudo ate ser perguntado: terminal aberto nao mostra nada, e
isso e o comportamento correto.

Nada vai para a placa sem passar antes no testbench. Ver `CLAUDE.md`.

## Licenca

Codigo e documentacao deste projeto: **Apache License 2.0** (ver `LICENSE`).

Escolhida pela concessao expressa de patente da secao 3 -- nao porque haja
patente envolvida (nao ha: AES, SHA-256, HMAC, CMAC e CTR_DRBG sao normas
livres de royalties, e as patentes de DES expiraram nos anos 1990), mas
porque deixar isso por escrito custa nada.

**Codigo de terceiros nao e redistribuido aqui.** NEORV32, AES e SHA-256
entram como submodulos apontando para o upstream, sob BSD-3 e BSD-2. Ver
`NOTICE` e **[`THIRD-PARTY.md`](THIRD-PARTY.md)**, que tambem registra a
situacao de patente de cada algoritmo e por que implementar uma norma nao
infringe o direito autoral do documento dela.
