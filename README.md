# hsm-a7

HSM educacional em FPGA (Artix-7 XC7A35T, QMTECH). Projeto **didatico**:
o objetivo e entender como um HSM funciona construindo um de brinquedo.

**Este dispositivo nao e um HSM.** Sem PUF, sem malha antitamper, sem
sensores, sem RNG certificado, sem validacao FIPS/PCI. Nenhuma chave de
producao entra aqui.

## Para aprender o assunto

**[`doc/hsm-a7-manual.pdf`](doc/hsm-a7-manual.pdf)** — 69 paginas.

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
cada boot; falha leva o dispositivo a `TAMPERED`, e a partir dai so o
`SELFTEST` responde.

```
python3 host/hsmtool.py post        # reroda o POST no dispositivo
  AES-256                ok
  SHA-256                ok
  HMAC-SHA-256           ok
  CTR_DRBG               ok
  TRNG / health tests    ok
  CMAC-AES-256           ok
  key store              ok
  key block X9.143       ok
```

Os cinco primeiros sao respostas conhecidas contra vetores oficiais do NIST
e do IETF; os tres ultimos sao testes de **funcao critica**, que e coisa
diferente -- nao ha "resposta conhecida" para instalar uma chave, ha
propriedades que se falharem tornam o dispositivo perigoso sem parecer
quebrado.

⚠ **`post` e DESTRUTIVO** num dispositivo carregado: o teste do key store
instala e apaga chaves de verdade e termina com o store vazio, LMK
inclusive.

**Fase 3 em andamento**: CMAC, o key store em BRAM, a **cerimonia de LMK**, o
**display de estado** e o **key block ANSI X9.143** estao prontos. Tres
componentes por XOR, KCV a cada passo, dual control pelos dois botoes
fisicos, e a placa soletrando `Uni`/`Aut`/`OPE`/`tPr` com o ponto decimal
acendendo enquanto o dual control esta satisfeito.

O key block foi escrito **duas vezes** -- em C no firmware, em Python no
host, sobre bibliotecas diferentes -- para que as duas discordem quando
alguem ler a norma errado.

O `ZEROIZE` apaga tudo **e prova que apagou**, por duas vias independentes:
uma varredura byte a byte no firmware, e o KCV no testbench -- refazendo a
cerimonia e exigindo o mesmo vetor do NIST. Um unico bit sobrevivente da
LMK mudaria o KCV.

Os quatro comandos de chave (`GEN_KEY`, `EXPORT_KEY`, `IMPORT_KEY`,
`KEY_INFO`) fecham o ida-e-volta: gerar dentro da fronteira, exportar
embrulhado, reimportar, e o KCV volta igual. Nenhum deles exige dual
control -- dual control e para cerimonia, nao para operacao.

E `ENCRYPT`/`DECRYPT` fecham o resto: a chave e referida por **handle**, e
o material nunca atravessa a linha. Compare com os comandos da fase 2, que
recebiam a chave dentro do pedido. AES-CBC com IV explicito -- ECB para
dados e o erro que a Parte III do manual usa como exemplo.

Faltam um `DELETE_KEY` que nao estava previsto (o key store e gravavel 16
vezes e so o `ZEROIZE` libera), as versoes por handle dos comandos da fase
2, e o log de auditoria. Ver `doc/fase3-notas.md`.

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
source /opt/AMD/2026.1/Vivado/settings64.sh

./scripts/sim.sh                 # todos os testbenches implementados
./scripts/sim.sh tb_uart_frame   # um so

make -C fw image                 # o build da FPGA depende desta imagem
vivado -mode batch -source scripts/build.tcl
```

⚠ **`sim.sh` recompila o firmware sozinho** quando o C esta mais novo que
`fw/neorv32_imem_image.vhd`. Ate isso existir, editar C e simular validava o
binario ANTERIOR -- descoberto quando uma sabotagem deliberada do codigo
passou na simulacao, porque o codigo sabotado nunca chegou a ser compilado.

⚠ **`tb_keystore` leva ~30 min** e e o testbench mais lento da suite: ele
manda key blocks de 144 caracteres a 115200 baud, e cada frame custa ~13 ms
de tempo simulado.

## Host

```bash
python3 host/hsmtool.py selftest        # sem placa: codec do protocolo
python3 host/test_hsmtool.py            # sem placa: transporte
python3 host/test_tr31.py               # sem placa: key block X9.143

python3 host/hsmtool.py ping            # com placa (115200 8N1)
python3 host/hsmtool.py version
python3 host/hsmtool.py dna             # identidade do die (57 bits)
python3 host/hsmtool.py bench -n 10000  # criterio de aceitacao da fase 1

python3 host/hsmtool.py lmk-status      # cerimonia de LMK (fase 3)
python3 host/hsmtool.py lmk-load 0 --random
python3 host/hsmtool.py activate

# depois de OPERATIONAL, nenhum destes pede botao -- e esse e o ponto
python3 host/hsmtool.py gen-key --uso D0 --modo B --exp E
python3 host/hsmtool.py export-key 1
python3 host/hsmtool.py import-key <bloco>
python3 host/hsmtool.py key-info 1
python3 host/hsmtool.py keycycle --lmk <hex>   # o Python confere o firmware
python3 host/hsmtool.py zeroize         # APAGA tudo (dual control)
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
