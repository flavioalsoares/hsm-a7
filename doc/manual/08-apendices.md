# Apêndices

## A. Glossário

**APT** — *Adaptive Proportion Test*. Teste de saúde de fonte de entropia
(SP 800-90B) que dispara quando um valor domina uma janela de amostras.

**BBRAM** — memória volátil do FPGA onde pode ficar a chave de decifra do
bitstream. Perde conteúdo sem alimentação, e por isso é recuperável — ao
contrário do eFUSE.

**BDK** — *Base Derivation Key*. Chave de pagamentos da qual se derivam
chaves de terminal, tipicamente por DUKPT.

**CFS** — *Custom Functions Subsystem*. Slot do NEORV32 projetado para
receber coprocessadores do usuário. É onde AES e SHA entram na Fase 2.

**CMAC** — código de autenticação de mensagem baseado em cifra de bloco.
Usado no TR-31 para autenticar cabeçalho e corpo, e para derivar KBEK/KBAK.

**CMVP** — programa NIST/CCCS que valida módulos contra a FIPS 140-3.

**CSP** — *Critical Security Parameter*. Termo da FIPS para qualquer segredo
cuja divulgação compromete a segurança: chave em claro, dado de autenticação,
estado do gerador.

**Dual control** — nenhuma operação sensível pode ser realizada por uma
pessoa sozinha. Ver seção 7.

**DRBG** — *Deterministic Random Bit Generator*. Gerador determinístico
semeado por entropia física, especificado na SP 800-90A.

**CVV / CVC** — três dígitos derivados de PAN, validade e código de serviço
sob um par de chaves. Inerentemente 3DES, e por isso fora do alcance deste
projeto (seção 38).

**Decimalização** — mapear os dígitos hexadecimais que uma cifra produz
para dígitos decimais, para formar um PIN. A tabela que faz esse mapeamento
foi a origem do ataque de Bond e Zieliński (seções 15.2 e 36.3).

**DUKPT** — *Derived Unique Key Per Transaction*. Esquema em que cada
transação usa uma chave distinta derivada de uma BDK, identificada por um
KSN. Duas normas: X9.24-1 (TDES, legado) e X9.24-3 (AES). Seção 37.

**eFUSE** — memória de programação única do FPGA. **Proibida neste
projeto**: erro vira brick permanente.

**EAL** — *Evaluation Assurance Level*, do Common Criteria. Mede o rigor da
avaliação, **não** a força da segurança.

**Fronteira criptográfica** — o limite físico e lógico dentro do qual
material de chave em claro existe. Ver seção 5.

**KAT** — *Known Answer Test*. Vetor de teste com entrada e saída conhecidas,
usado nos autotestes.

**KBEK / KBAK** — chaves de cifra e de autenticação de key block, derivadas
da LMK por propósito.

**KCV** — *Key Check Value*. Três bytes do resultado de cifrar um bloco de
zeros com a chave. Permite verificar sem revelar.

**KSN** — *Key Serial Number*. Identificador do dispositivo mais o contador
de transação, enviado junto com cada transação DUKPT. Com ele e a BDK, o HSM
rederiva a chave usada. Seção 37.

**KEK** — *Key Encryption Key*. Chave cuja função é proteger outras chaves.

**LMK** — *Local Master Key*. A chave mestra do módulo, no topo da
hierarquia. Nunca sai, nem embrulhada.

**MMCM** — *Mixed-Mode Clock Manager*. Bloco do FPGA Xilinx que sintetiza
clocks. Aqui, 50 → 100 MHz.

**PAN** — *Primary Account Number*. O número do cartão. Entra na formação
do PIN block para amarrar o PIN à conta. **Nunca usar um PAN real neste
projeto** (seção 38.4).

**PIN block** — formato que combina PIN e número da conta para transporte.
Os formatos da ISO 9564 e suas fraquezas estão na seção 34; os ataques
clássicos, na 15.3.

**PVV** — *PIN Verification Value*. Quatro dígitos derivados de PAN e PIN
sob uma chave PVK, guardados pelo emissor no lugar do PIN. Seção 36.1.

**PMP** — *Physical Memory Protection*. Mecanismo RISC-V de restrição de
acesso à memória por região.

**POST** — *Power-On Self-Test*. Bateria de KAT executada no boot, antes de
aceitar comandos.

**PUF** — *Physically Unclonable Function*. Raiz de confiança derivada de
variações de fabricação, em vez de armazenada.

**RCT** — *Repetition Count Test*. Teste de saúde que dispara na repetição
excessiva de uma amostra.

**Split knowledge** — nenhuma pessoa conhece uma chave inteira; ela é
montada de componentes.

**Tamper-evident / resistant / responsive** — a escada de proteção física.
Ver seção 18.1.

**Tradução de PIN** — decifrar um PIN block sob uma chave e recifrá-lo sob
outra, sem que o PIN saia da fronteira. É o comando mais perigoso de um HSM
de pagamento, porque é um oráculo por construção. Seção 35.

**TR-31** — formato de key block da indústria de pagamentos, hoje ANSI
X9.143. É o formato adotado por este projeto (seção 8).

**TRNG** — gerador de números aleatórios verdadeiro, baseado em fenômeno
físico.

**Zeroização** — destruição de material de chave de forma verificável. Ver
seção 12.

## B. Especificação do protocolo

Implementado em `fw/src/cmd.c` (firmware) e `host/hsmtool.py` (host).

### Enquadramento

```
pedido    LEN(2) | CMD(1)    | PAYLOAD | CRC32(4)
resposta  LEN(2) | STATUS(1) | PAYLOAD | CRC32(4)
```

- Todos os campos multi-byte em **big-endian**.
- `LEN` cobre `CMD`/`STATUS` + `PAYLOAD`. Não se inclui nem inclui o CRC.
- `LEN` válido: 1 a 513 (payload máximo de 512 bytes).
- **CRC32** cobre `LEN` + `CMD`/`STATUS` + `PAYLOAD` — todos os bytes menos
  os quatro dele próprio. Polinômio IEEE 802.3 refletido (`0xEDB88320`),
  inicialização `0xFFFFFFFF`, xor final `0xFFFFFFFF`. Idêntico ao
  `zlib.crc32` do Python.
- Timeout entre bytes no dispositivo: 250 ms. Timeout de resposta no host:
  2 s.

### Comandos da Fase 1

| Opcode | Nome | Payload do pedido | Payload da resposta |
|---|---|---|---|
| `0x01` | `PING` | vazio | `"PONG"` |
| `0x02` | `GET_VERSION` | vazio | major, minor, patch, estado |
| `0x03` | `GET_DNA` | vazio | 8 bytes: identidade do die, 57 bits big-endian |

O `GET_DNA` ficou respondendo `NOT_IMPLEMENTED` durante toda a Fase 1 e só
fechou com o CFS da Fase 2 (seção 27) — o `DNA_PORT` é primitiva Xilinx e
precisava de um caminho até a CPU. O valor **não é segredo**: qualquer um com
um cabo JTAG lê o mesmo número, e ele nunca muda. Serve para identificar a
placa em log e inventário. Derivar chave dele é um erro clássico, porque
público e constante são exatamente as duas propriedades que uma chave não
pode ter.

### Códigos de status

| Código | Nome | Significado |
|---|---|---|
| `0x00` | `OK` | |
| `0x01` | `BAD_CRC` | CRC não confere |
| `0x02` | `BAD_LEN` | `LEN` fora da faixa |
| `0x03` | `TIMEOUT` | frame incompleto, resincronizado |
| `0x10` | `UNKNOWN_CMD` | opcode não está na tabela |
| `0x11` | `BAD_PARAM` | tamanho ou conteúdo do payload |
| `0x12` | `NOT_IMPLEMENTED` | na tabela, sem implementação ainda |
| `0x20` | `WRONG_STATE` | comando não permitido neste estado |
| `0x21` | `NOT_AUTHORIZED` | falta dual control |
| `0x22` | `NOT_EXPORTABLE` | exportabilidade do slot proíbe |
| `0x30` | `SELFTEST_FAIL` | |
| `0x31` | `TAMPERED` | |
| `0xFF` | `INTERNAL_ERROR` | |

### Exemplo verificado em hardware

```
    pedido   : 00 01 01 91 5D D8 C5
    resposta : 00 05 00 50 4F 4E 47 FB 28 3D 2A
                     ^^  P  O  N  G
```

`91 5D D8 C5` é `zlib.crc32(b'\x00\x01\x01')`.

## C. Pinagem

Fonte: esquemáticos QMTECH e verificação em hardware. Detalhes e procedência
em `doc/pinout.md`.

| Função | Pino | Estado |
|---|---|---|
| Clock 50 MHz | N11 | verificado em hardware |
| Reset (SW1) | B7 | esquemático; ativo baixo |
| UART RX / TX | T15 / T14 | verificado em hardware |
| Dual control A (SW2) | M6 | verificado em hardware; ativo baixo |
| Dual control B (SW5) | P6 | verificado em hardware; ativo baixo |
| LEDs D1–D5 | R6, T5, R7, T7, R8 | verificados; **ativos baixos**; todos vermelhos |
| 7 segmentos | T10, K13, P11, R11, R10, N9, K12, P9 | `a`…`g`, `dp`; **acende com 0** |
| Dígitos (varredura) | T9, P10, T8 | 3 dígitos; **habilita com 1** |

**Armadilha registrada:** com o gravador ligado existem **duas** portas
seriais. O adaptador JTAG usado é um FT232H que também cria `/dev/ttyUSB*`, e
costuma enumerar **antes** da placa. Escolher a porta por ordem alfabética
acerta o cabo de gravação, e o sintoma é um timeout sem explicação. A
ferramenta de host escolhe por identificador USB por causa disso.

**Nenhuma pendência de pinagem.** As três que existiam — cores dos LEDs,
polaridade do display e ordem física dos botões — foram fechadas por medida
em hardware, e duas delas mudaram o projeto:

- **Os cinco LEDs são vermelhos.** O requisito "LED vermelho para
  `TAMPERED`" está atendido e ao mesmo tempo vazio: **cor não distingue nada
  nesta placa**. Um indicador de estado tem de se separar por *posição* e
  *padrão* — e é o display que carrega a informação de verdade.
- **A polaridade do display estava invertida no código**, por palpite. O
  segmento acende com `0` e o dígito habilita com `1`; o toplevel supunha o
  contrário. Não aparecia porque, com os segmentos desligados, habilitar ou
  não os dígitos dá no mesmo — apareceria no primeiro estado exibido.

O detalhe que fecha o assunto: **um testbench conferia o valor errado e
passou meses verde**, porque afirmava a suposição em vez de uma medida.

## D. Reproduzir o trabalho

### Dependências

```bash
git clone --recurse-submodules <url>

sudo apt install -y gcc-riscv64-unknown-elf picolibc-riscv64-unknown-elf
sudo apt install -y python3-serial openfpgaloader
```

Vivado 2026.1 (o `xsim` também é usado na simulação, por causa das primitivas
Xilinx e do VHDL do NEORV32).

O compilador sozinho não basta: ele fornece apenas os headers freestanding, e
o header do NEORV32 precisa de uma biblioteca C. Não há `libnewlib` para
RISC-V nos repositórios Debian; picolibc é o equivalente.

### Construir e testar

```bash
make -C fw image                 # firmware; o build da FPGA depende dele
source /opt/AMD/2026.1/Vivado/settings64.sh

./scripts/sim.sh                 # todos os testbenches
vivado -mode batch -source scripts/build.tcl

./scripts/program.sh             # grava na RAM de configuração (volátil)

python3 host/hsmtool.py selftest # sem placa
python3 host/test_hsmtool.py     # sem placa
python3 host/hsmtool.py ping
python3 host/hsmtool.py bench -n 10000
```

### Política de código de terceiros

Nunca editar `third_party/` diretamente: a mudança não fica guardada no
repositório, é descartada por `git submodule update`, e quebra a procedência
— o pin continua dizendo `v1.13.3` enquanto o bitstream contém outra coisa.

Ordem para mudar código externo:

1. **Configuração** (generic no wrapper) — resolve quase sempre
2. **Ponto de extensão projetado** — é o caso do CFS na Fase 2
3. **Patch** em `patches/`, aplicado pelo build
4. **Fork** e repontar o submódulo — só com patch que precise persistir

Detalhes em `doc/submodulos.md`. O espelho offline reproduzível dos cores
externos sai de `./scripts/mirror-deps.sh`.

## E. Leitura

### Normas

- **FIPS 140-3** e ISO/IEC 19790 — requisitos de módulo criptográfico
- **NIST SP 800-90A/B/C** — DRBG, fontes de entropia, construções
- **ANSI X9.143** (sucessor do TR-31) — key blocks
- **PCI PIN Security Requirements** e **PCI PTS HSM** — de onde vêm dual
  control e split knowledge como exigência

### Ataques

- Bond, M. — *Attacks on Cryptoprocessor Transaction Sets* (2001)
- Bond, M. e Zieliński, P. — *Decimalisation Table Attacks for PIN Cracking*
  (2003)
- Clulow, J. — *On the Security of Real-World PIN Processing* (2003)
- Boneh, DeMillo e Lipton — *On the Importance of Checking Cryptographic
  Protocols for Faults* (1997) — o ataque Bellcore
- Kocher, P. — *Timing Attacks* (1996) e, com Jaffe e Jun, *Differential
  Power Analysis* (1999)
- Piret e Quisquater — análise diferencial de falhas em AES (2003)

### Livros

- Anderson, R. — *Security Engineering*. Os capítulos sobre APIs de segurança
  e sobre segurança de hardware são a melhor introdução ao assunto da Parte
  III.
- Maes, R. — *Physically Unclonable Functions*. Para o experimento da Fase 6.

### Ferramentas e cores usados

- **NEORV32** — processador RISC-V em VHDL, `github.com/stnolting/neorv32`
- **secworks/aes** e **secworks/sha256** — cores criptográficos para a Fase 2
- **openFPGALoader** — gravação por JTAG

---

::: {.fecho}

*Este documento acompanha o repositório `hsm-a7`. A Parte V reflete o estado
ao fim da Fase 1, validada em hardware. As Partes I a IV são independentes do
projeto e valem por si.*

:::
