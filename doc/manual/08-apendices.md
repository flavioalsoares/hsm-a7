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
projeto (seção 39).

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
projeto** (seção 39.4).

**PIN block** — formato que combina PIN e número da conta para transporte.
Os formatos da ISO 9564 e suas fraquezas estão na seção 35; os ataques
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

### Comandos da Fase 2 — primitivas

| Opcode | Nome | Payload do pedido | Payload da resposta |
|---|---|---|---|
| `0x10` | `AES_ENC` | chave(32) ‖ bloco(16) | bloco(16) |
| `0x11` | `AES_DEC` | chave(32) ‖ bloco(16) | bloco(16) |
| `0x12` | `SHA256` | mensagem | digest(32) |
| `0x13` | `HMAC` | klen(1) ‖ chave ‖ mensagem | mac(32) |
| `0x14` | `RANDOM` | n(2), máximo 256 | n bytes do CTR_DRBG |
| `0x15` | `SELFTEST` | vazio | máscara de falhas(1) |

⚠ **`AES_ENC`, `AES_DEC` e `HMAC` recebem a chave em claro no payload**, e
por isso só respondem em `UNINITIALIZED`. Não é convenção: é a máscara de
estados na tabela de comandos. Um comando que aceita chave em claro não pode
coexistir com chave de verdade no mesmo dispositivo — e no instante em que a
LMK é carregada, os três param de responder sozinhos. A Fase 3 os
**substitui** por versões que falam por handle de slot.

O `SELFTEST` é o único comando que responde em `TAMPERED`, e a exceção é
deliberada: sem ele, um dispositivo que reprovou no boot ficaria mudo sobre
*o que* reprovou, e o operador teria apenas um LED vermelho.

### Comandos da Fase 3 — hierarquia de chaves

| Opcode | Nome | Payload do pedido | Payload da resposta |
|---|---|---|---|
| `0x20` | `LMK_LOAD_COMPONENT` | n(1) ‖ componente(32) | kcv(3) ‖ carregados(1) ‖ estado(1) |
| `0x21` | `LMK_STATUS` | vazio | carregados(1) ‖ completa(1) ‖ kcv(3) |
| `0x26` | `SET_STATE` | estado alvo(1) | estado atual(1) |

O `0x20` e o `0x26` exigem **dual control**: os dois botões pressionados no
instante em que o frame chega, e um aperto *novo* a cada autorização (seção
28). São os únicos comandos do projeto cuja autorização não está no link do
host — o que é o ponto inteiro deles.

O KCV que o `0x20` devolve é o do **componente**, não o da LMK acumulada. O
`0x21` devolve o da LMK, e só quando ela está completa; enquanto incompleta,
os três bytes vêm zerados, e a resposta mantém o comprimento fixo para que o
tamanho do frame não anuncie nada.

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

## E. Operar o dispositivo

O apêndice D ensina a **construir**. Este ensina a **usar** — uma sessão
inteira, do power-on até o dispositivo operacional, com o que cada resposta
significa.

Tudo daqui é feito com `host/hsmtool.py`, que fala o protocolo do apêndice B
pela UART do CP2102 (115200 8N1, a mesma porta USB que alimenta o core
board).

### E.1 Ligar e conferir

O bitstream mora na **flash SPI**, então a placa sobe sozinha na
energização. Não há nada a carregar.

```bash
python3 host/hsmtool.py version
```

```
firmware : v0.1.0
estado   : UNINITIALIZED (0)
```

`UNINITIALIZED` é o estado de fábrica: o dispositivo funciona, mas não
guarda chave nenhuma.

**Antes de qualquer outra coisa, o autoteste.** Ele já rodou no boot — o
`SELFTEST` apenas o repete, e é assim que se confere que o módulo continua
calculando certo *agora*, não só quando ligou:

```bash
python3 host/hsmtool.py post
```

```
AES-256                ok
SHA-256                ok
HMAC-SHA-256           ok
CTR_DRBG               ok
TRNG / health tests    ok
CMAC-AES-256           ok
key store              ok
```

Sete linhas, sete verdades diferentes. As quatro primeiras são respostas
conhecidas contra vetores oficiais (seção 11). A quinta são os testes de
partida da fonte de entropia sobre um retrato de 1024 amostras brutas
(seção 10). A sétima é um teste de *função crítica*, não de algoritmo:
verifica que uma chave marcada como não exportável não sai, que um slot
apagado não responde, e que uma chave de cifrar não é aceita para decifrar.

**Se alguma reprovar**, o dispositivo vai para `TAMPERED` e passa a atender
**só** ao `SELFTEST`. Isso é o comportamento correto, e a exceção é
deliberada: sem ela o operador teria apenas um LED vermelho e nenhuma
informação sobre *o que* falhou.

### E.2 O que dá para fazer antes de haver chave

Em `UNINITIALIZED` o dispositivo é uma caixa de primitivas. Estes comandos
recebem a chave **no payload**, o que um HSM de verdade jamais aceitaria:

```bash
python3 host/hsmtool.py sha256 616263          # SHA-256 de "abc"
python3 host/hsmtool.py aes <chave-hex> <bloco-hex>
python3 host/hsmtool.py random -n 32           # bytes do CTR_DRBG
```

Eles existem para exercitar o hardware antes de existir key store, e **param
de responder no instante em que houver LMK** — não por uma linha de código
que os desligue, mas porque a máscara de estados deles diz `UNINITIALIZED` e
o dispositivo não estará mais lá. Guarde isso: é a demonstração mais limpa
de por que estado importa num HSM.

O `random` é o único dos quatro que continua funcionando depois. Ele não
recebe chave nenhuma.

### E.3 A cerimônia de LMK

A **Local Master Key** é a raiz da hierarquia (seção 7): é ela que embrulha
todas as demais. Ela não é digitada por uma pessoa. Ela nasce de **três
componentes**, cada um sob a guarda de um custodiante diferente, que se
combinam por XOR dentro do dispositivo.

Por que XOR e por que três: nenhum componente isolado revela **nada** sobre
a chave — nem um bit — e conhecer dois de três não ajuda. Três é prática
operacional, não criptografia: dois custodiantes não dão margem se um faltar
no dia, e mais de três transforma a cerimônia em logística.

**O gesto físico.** Cada componente exige dois botões da placa pressionados
no instante em que o comando chega. São o **2º e o 5º** de uma fileira de
cinco, cujo primeiro é o reset:

```
    [reset]  [ * ]   [   ]   [   ]   [ * ]
      SW1     SW2     SW3     SW4     SW5
```

O par mais afastado disponível, para dificultar apertar os dois com uma mão
só. O `hsmtool.py` desenha esse mapa a cada pedido, porque ler silkscreen
minúsculo no meio de uma cerimônia é como se aperta o botão errado. E exige um aperto
**novo**: entre um componente e o seguinte, os dois têm de ser vistos
**soltos**. Segurar os dois durante a cerimônia inteira carrega **um**
componente, não três (seção 28).

```bash
python3 host/hsmtool.py lmk-status
```

```
componentes : 0 de 3
KCV da LMK  : -- (incompleta)
```

Agora cada componente, um de cada vez:

```bash
python3 host/hsmtool.py lmk-load 0 --random
```

O `--random` gera o componente **no host** e o imprime na tela. Isso é uma
concessão de brinquedo, e o próprio comando avisa: material de chave na tela
é exatamente o que um HSM existe para evitar. Num equipamento real cada
componente nasce com o seu custodiante, num cartão ou num dispositivo de
entrada dedicado. Para fornecer um componente existente, passe-o em hex no
lugar de `--random`.

A ferramenta então pede o gesto e espera:

```
Carregar o componente 0 da LMK.
  SOLTE os dois botoes, depois SEGURE SW2 e SW5 juntos
  e tecle Enter sem soltar.
```

Segure os dois, tecle Enter sem soltar, e a resposta volta:

```
KCV do componente : 539062
componentes       : 1 de 3
estado            : UNINITIALIZED (0)
```

**O KCV que volta é o do componente, não o da LMK.** É o que permite ao
custodiante conferir, ali, que digitou o dele e não o do vizinho. Sem esse
passo, um componente trocado só apareceria no KCV final — quando já não dá
para saber qual dos três estava errado. Confira contra o valor que o
custodiante trouxe anotado; se não bater, **pare a cerimônia**.

Repita para os componentes `1` e `2`. Ao terceiro:

```
componentes       : 3 de 3
estado            : AUTHORIZED (1)
```

O estado muda no mesmo comando que completa a chave, e não num comando
separado: *"tenho LMK"* e *"estou em AUTHORIZED"* precisam ser a mesma
afirmação, ou o estado vira opinião.

```bash
python3 host/hsmtool.py lmk-status
```

```
componentes : 3 de 3
KCV da LMK  : 46F2FB
```

Anote esse KCV. Ele é a única coisa derivada da LMK que atravessa a
fronteira, e é como se confere, em qualquer sessão futura, que o dispositivo
tem a chave certa — sem que ninguém veja a chave. Três bytes dão uma
colisão em 16 milhões: basta para pegar erro de digitação, e não basta para
atacar.

**Se `STATUS_NOT_AUTHORIZED` voltar**, os botões não estavam apertados — ou
estavam apertados desde a autorização anterior. Solte, aperte e repita. Essa
recusa é a única prova de que o dual control existe de verdade: é o único
comando do dispositivo cuja autorização não está no link do host.

### E.4 Ativar

`AUTHORIZED` significa "tenho a raiz". `OPERATIONAL` significa "estou em
serviço". A passagem é um ato de cerimônia, também com dual control:

```bash
python3 host/hsmtool.py activate
```

```
estado : OPERATIONAL (2)
```

**Repare no que desapareceu.** Tente agora:

```bash
python3 host/hsmtool.py aes <chave> <bloco>
```

```
dispositivo recusou: STATUS_WRONG_STATE (0x20)
```

O comando que aceitava chave em claro não existe mais neste estado. E a
própria cerimônia também não se repete — não há caminho para trocar a chave
mestra por cima da existente, o que seria substituir a raiz sem apagar o que
ela protege. A escada é de **uma via só**, e descer exige apagar.

### E.5 Os indicadores da placa

Cinco LEDs, e **todos são vermelhos**: a cor não carrega informação nenhuma,
só a posição.

| LED | Significado |
|---|---|
| **D1** | pisca a 1 Hz — o clock de 100 MHz está vivo. É **hardware**, independente da CPU |
| **D2** | aceso — o POST passou e o dispositivo está no laço de comandos |
| **D5** | aceso — `TAMPERED` |

D1 ser hardware é deliberado: se o firmware travar, D1 continua piscando, e
isso distingue "clock morto" de "firmware pendurado". Num dispositivo sem
console, essa distinção é a diferença entre depurar e adivinhar.

Fora isso, o dispositivo é **mudo até ser perguntado**. Um terminal aberto
na porta serial não mostra absolutamente nada, e esse é o comportamento
correto: um módulo criptográfico que conversa sozinho está contando alguma
coisa a alguém.

### E.6 O que ainda não existe

Honestidade sobre o estado do projeto, para que ninguém procure um comando
que não foi escrito:

- **A LMK não sobrevive ao desligamento.** Ela vive em Block RAM, que é
  volátil — e é exatamente o que a regra de projeto pede. Toda sessão que
  precise de LMK refaz a cerimônia. Persistência é a Fase 4, e a ordem é
  essa de propósito: guardar chave antes de saber embrulhá-la seria guardar
  chave em claro.
- **Não há geração, exportação nem importação de chave** (`GEN_KEY`,
  `EXPORT_KEY`, `IMPORT_KEY`). O key store existe e a LMK existe; falta o
  key block X9.143 que embrulha uma na outra.
- **Não há `ZEROIZE` por comando.** Desligar a placa apaga tudo, o que
  funciona mas não é a mesma coisa: um zeroize de verdade prova que apagou.
- **Não há log de auditoria.** É transversal e chega junto com os comandos
  de chave.

## F. Leitura

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
