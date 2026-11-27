# Apêndices

## A. Glossário

**APT** — *Adaptive Proportion Test*. Teste de saúde de fonte de entropia
(SP 800-90B) que dispara quando um valor domina uma janela de amostras.

**ARQC / ARPC** — *Authorization Request / Response Cryptogram*. O ARQC são
8 bytes que o chip do cartão calcula sobre os dados da transação, com a
chave dele; o emissor o confere. O ARPC é a resposta do emissor, que o chip
confere. Seção 40.

**ATC** — *Application Transaction Counter*. O contador de transações do
chip EMV; entra na chave de sessão e nos dados do ARQC. Seção 40.

**BBRAM** — memória volátil do FPGA onde pode ficar a chave de decifra do
bitstream. Perde conteúdo sem alimentação, e por isso é recuperável — ao
contrário do eFUSE.

**BDK** — *Base Derivation Key*. Chave de pagamentos da qual se derivam
chaves de terminal, tipicamente por DUKPT.

**CFS** — *Custom Functions Subsystem*. Slot do NEORV32 projetado para
receber coprocessadores do usuário. É onde AES e SHA entram na Fase 2.

**CMAC** — código de autenticação de mensagem baseado em cifra de bloco.
Usado no TR-31 para autenticar cabeçalho e corpo, e para derivar KBEK/KBAK.
Com AES no key block versão D; com 3DES (CMAC-TDES) na versão B. É o
CBC-MAC com uma subchave secreta no último bloco (seção 8).

**CMVP** — programa NIST/CCCS que valida módulos contra a FIPS 140-3.

**CSP** — *Critical Security Parameter*. Termo da FIPS para qualquer segredo
cuja divulgação compromete a segurança: chave em claro, dado de autenticação,
estado do gerador.

**Dual control** — nenhuma operação sensível pode ser realizada por uma
pessoa sozinha. Ver seção 7.

**DRBG** — *Deterministic Random Bit Generator*. Gerador determinístico
semeado por entropia física, especificado na SP 800-90A.

**CVN** — *Cryptogram Version Number*. A escolha, entre as opções da
especificação EMV, de como o chip calcula o ARQC: com que chave, sobre que
dados, com que preenchimento. Seção 40.

**CVV / CVC** — três dígitos derivados de PAN, validade e código de serviço
sob um par de chaves 3DES (a chave dupla de uso `C0`). O CVV2 (verso) e o
iCVV (chip) saem da mesma conta, com os códigos de serviço `000` e `999`.
Seção 36.

**Decimalização** — mapear os dígitos hexadecimais que uma cifra produz
para dígitos decimais, para formar um PIN. A tabela que faz esse mapeamento
foi a origem do ataque de Bond e Zieliński (seções 15.2 e 35.3).

**DUKPT** — *Derived Unique Key Per Transaction*. Esquema em que cada
transação usa uma chave distinta derivada de uma BDK, identificada por um
KSN. Duas normas: X9.24-1 (TDES, legado) e X9.24-3 (AES). Seção 37.

**HMAC** — código de autenticação de mensagem baseado em função de hash
(FIPS 198-1, RFC 2104): duas passadas de hash, com duas chaves derivadas da
chave. Aqui, HMAC-SHA-256, conferido no autoteste (seção 8).

**IMK** — *Issuer Master Key*. A chave mestra do emissor, da qual se deriva
a chave (MK) de cada cartão de chip. Existe só nos HSMs do emissor. Aqui,
uso `E0`, modo `X`. Seção 40.

**IK** — *Initial Key*, a chave inicial de um terminal DUKPT AES. É o papel
da IPEK no DUKPT AES: vem da BDK e do IKID (os 8 primeiros bytes do KSN), e
tem o tamanho da BDK. O comando `I0` a entrega sob uma KEK AES. Seção 37.3.

**IPEK** — *Initial PIN Encryption Key*, a chave inicial de um terminal
DUKPT. Vem da BDK e do KSN do terminal, e é carregada nele uma vez. O
comando `I0` a entrega sob uma KEK. Seção 37.2.

**ISO 8583** — a norma das mensagens entre terminal, adquirente, bandeira e
emissor: pedido de autorização, resposta, estorno. O HSM não a lê: a
aplicação tira da mensagem os campos de que a conta precisa e monta o
comando do HSM. Seção 24.14.

**eFUSE** — memória de programação única do FPGA. **Proibida neste
projeto**: erro vira brick permanente.

**EAL** — *Evaluation Assurance Level*, do Common Criteria. Mede o rigor da
avaliação, **não** a força da segurança.

**Fronteira criptográfica** — o limite físico e lógico dentro do qual
material de chave em claro existe. Ver seção 5.

**KAT** — *Known Answer Test*. Vetor de teste com entrada e saída conhecidas,
usado nos autotestes.

**KBEK / KBAK** — *Key Block Encryption Key* e *Key Block Authentication
Key*. Chaves de cifra e de autenticação de um key block, derivadas da KBPK
por CMAC, uma por propósito (seção 8).

**KBPK** — *Key Block Protection Key*. A chave que protege um key block: a
LMK, para os blocos guardados pelo equipamento, ou a KEK, numa troca com
outra instituição. Só deriva a KBEK e a KBAK (seção 8).

**KCV** — *Key Check Value*. Três bytes do resultado de cifrar um bloco de
zeros com a chave. Permite verificar sem revelar. O KCV de uma chave 3DES é
calculado com 3DES (seção 39.5).

**3DES / TDES / TDEA** — o DES aplicado três vezes, cifrando, decifrando e
cifrando. Chave de **comprimento duplo** (16 bytes) ou **triplo** (24
bytes). Legado, e ainda o algoritmo dominante em pagamentos. Seção 39.

**Paridade (de chave DES)** — o bit baixo de cada byte de uma chave DES,
ajustado para o byte ter um número ímpar de bits em 1. Detecta chave
corrompida; a cifra não o usa. Seção 39.3.

**KSN** — *Key Serial Number*. Identificador do dispositivo mais o contador
de transação, enviado junto com cada transação DUKPT. Com ele e a BDK, o HSM
rederiva a chave usada. Tem 10 bytes no DUKPT TDES e 12 no AES. Seção 37.

**KEK** — *Key Encryption Key*. Chave cuja função é proteger outras chaves.

**LMK** — *Local Master Key*. A chave mestra do módulo, no topo da
hierarquia. Nunca sai, nem embrulhada.

**MMCM** — *Mixed-Mode Clock Manager*. Bloco do FPGA Xilinx que sintetiza
clocks. Aqui, 50 → 100 MHz.

**PAN** — *Primary Account Number*. O número do cartão. Entra na formação
do PIN block para amarrar o PIN à conta. **Nunca usar um PAN real neste
projeto** (seção 38.4).

**PIN block** — formato que combina PIN e número da conta para transporte.
Os formatos da ISO 9564 e suas fraquezas estão na seção 33; os ataques
clássicos, na 15.3.

**PVV** — *PIN Verification Value*. Quatro dígitos derivados de PAN e PIN
sob uma chave PVK, guardados pelo emissor no lugar do PIN. Seção 35.1.

**PMP** — *Physical Memory Protection*. Mecanismo RISC-V de restrição de
acesso à memória por região.

**POST** — *Power-On Self-Test*. Bateria de KAT executada no boot, antes de
aceitar comandos.

**PUF** — *Physically Unclonable Function*. Raiz de confiança derivada de
variações de fabricação, em vez de armazenada.

**RCT** — *Repetition Count Test*. Teste de saúde que dispara na repetição
excessiva de uma amostra.

**Retail MAC** — o algoritmo 3 da ISO/IEC 9797-1 (a ANSI X9.19): CBC-MAC com
DES simples sob `K`, e 3DES de chave dupla `K ‖ K'` só no último bloco. O
MAC 3DES de mensagem da rede de pagamento. Seção 39.10.

**Split knowledge** — nenhuma pessoa conhece uma chave inteira; ela é
montada de componentes.

**Tamper-evident / resistant / responsive** — a escada de proteção física.
Ver seção 18.1.

**Tradução de PIN** — decifrar um PIN block sob uma chave e recifrá-lo sob
outra, sem que o PIN saia da fronteira. É o comando mais perigoso de um HSM
de pagamento, porque é um oráculo por construção. Seção 34.

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
| `0x04` | `GET_BUILD` | vazio | major, minor, patch, SHA-256 da memória de código (32) |

O `GET_DNA` ficou respondendo `NOT_IMPLEMENTED` durante toda a Fase 1 e só
fechou com o CFS da Fase 2 (seção 25) — o `DNA_PORT` é primitiva Xilinx e
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
| `0x15` | `SELFTEST` | vazio | máscara de falhas(2) |

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
| `0x22` | `GEN_KEY` | uso(2) ‖ alg(1) ‖ modo(1) ‖ exp(1) | handle(1) ‖ kcv(3) |
| `0x23` | `EXPORT_KEY` | handle(1) | key block X9.143 em ASCII |
| `0x24` | `IMPORT_KEY` | key block X9.143 em ASCII | handle(1) ‖ kcv(3) |
| `0x25` | `KEY_INFO` | handle(1) | uso(2) ‖ alg(1) ‖ modo(1) ‖ exp(1) ‖ len(1) ‖ kcv(3) ‖ usos(4) |
| `0x26` | `SET_STATE` | estado alvo(1) | estado atual(1) |
| `0x27` | `ENCRYPT` | handle(1) ‖ iv(16) ‖ dados | dados cifrados |
| `0x28` | `DECRYPT` | handle(1) ‖ iv(16) ‖ dados | dados em claro |
| `0x29` | `MAC_GENERATE` | handle(1) ‖ mensagem | tag(16) |
| `0x2A` | `MAC_VERIFY` | handle(1) ‖ tag(16) ‖ mensagem | vazio — o veredito é o status |
| `0x2B` | `DELETE_KEY` | handle(1) | slots livres(1) |
| `0x2C` | `KEY_FROM_COMPONENTS` | n(1) ‖ total(1) ‖ uso(2) ‖ alg(1) ‖ modo(1) ‖ exp(1) ‖ componente(32 com alg `A`; 16 ou 24 com alg `T`) | kcv(3) ‖ carregados(1) ‖ total(1) ‖ handle(1) |
| `0x2F` | `ZEROIZE` | vazio | estado atual(1) |

**Estados em que cada um responde.** Não é convenção — é uma máscara na
tabela de comandos, e é ela que faz a cerimônia ser uma escada de uma via.

| Comando | Estados |
|---|---|
| `LMK_LOAD_COMPONENT` | só `UNINITIALIZED` |
| `SET_STATE` | só `AUTHORIZED` |
| `GEN_KEY`, `EXPORT_KEY`, `IMPORT_KEY`, `KEY_INFO`, `ENCRYPT`, `DECRYPT`, `MAC_GENERATE`, `MAC_VERIFY`, `DELETE_KEY`, `KEY_FROM_COMPONENTS` | só `OPERATIONAL` |
| `LMK_STATUS` | os três normais |
| `ZEROIZE` | **todos**, `TAMPERED` inclusive |

Carregar os três componentes leva a `AUTHORIZED` e o `0x20` desaparece
sozinho; ativar leva a `OPERATIONAL` e o `0x26` desaparece do mesmo jeito.
Nenhum degrau se repete, e não há como descer sem apagar.

**Quais exigem dual control**, e a divisão diz mais que a lista:

| | |
|---|---|
| exigem | `LMK_LOAD_COMPONENT`, `SET_STATE`, `ZEROIZE`, `KEY_FROM_COMPONENTS` |
| não exigem | `GEN_KEY`, `EXPORT_KEY`, `IMPORT_KEY`, `KEY_INFO`, `ENCRYPT`, `DECRYPT`, `MAC_GENERATE`, `MAC_VERIFY`, `DELETE_KEY` |

Dual control é para **cerimônia**, não para operação. Carregar a chave
mestra, ativar o dispositivo e apagar tudo são eventos raros, com gente na
frente da placa. Gerar, exportar e importar chave é o que um HSM faz o dia
inteiro — exigir dois dedos ali não aumentaria segurança nenhuma, só
garantiria que ninguém usa o equipamento. E um controle que impede o uso
legítimo é desligado no primeiro dia ruim.

O que protege os quatro de baixo é outra coisa, e é estrutural: a chave
nunca sai em claro, o key block é autenticado sobre cabeçalho **mais**
corpo, e `exportabilidade` decide quem pode sair.

⚠ **O `ZEROIZE` tem uma assimetria deliberada.** O comando exige dois
operadores; o gatilho **automático** — autoteste reprovado — não exige
ninguém. Se ele exigisse, bastaria não haver operador na sala para a chave
sobreviver ao comprometimento.

**Notas por comando:**

- **`GEN_KEY`** — a chave vem do CTR_DRBG do dispositivo e **nunca existe
  fora da fronteira**. O host escolhe os metadados e recebe handle e KCV. É
  o contraste que a fase inteira ensina: o `AES_ENC` da Fase 2 recebia a
  chave *no payload*.
- **`EXPORT_KEY`** — o único comando que faz material de chave atravessar a
  fronteira, e ele atravessa embrulhado. Respeita `exportabilidade`: um
  slot marcado `'N'` devolve `NOT_EXPORTABLE`. Exportar o mesmo slot duas
  vezes dá blocos **diferentes**, porque o enchimento é aleatório — dois
  blocos idênticos denunciariam que a mesma chave saiu duas vezes.
- **`IMPORT_KEY`** — os metadados vêm **do bloco**, autenticados pelo MAC.
  Toda recusa devolve o mesmo `BAD_PARAM`: bloco malformado, hexadecimal
  inválido, MAC errado e comprimento impossível são indistinguíveis de
  fora. Distinguir em qual etapa a validação parou é o oráculo de padding
  clássico.
- **`KEY_INFO`** — metadados, nunca chave. Handle inválido e slot vazio
  devolvem o mesmo código: separar permitiria mapear o key store sem
  instalar nada.
- **`ENCRYPT` / `DECRYPT`** — usar a chave guardada, referida por
  **handle**. É o contraste que fecha a fase: os comandos da Fase 2
  recebiam a chave no pedido; aqui vai um número de gaveta.

  **AES-CBC com IV explícito**, e não ECB — ECB para dados é o erro que a
  seção 16 usa como exemplo. O IV vem de quem chama, porque uma função que
  puxa entropia sozinha não é testável de forma determinística.

  O `uso` e o `modo` do slot decidem: só uma chave de dados (`D0`) cifra, e
  uma marcada `'E'` (só cifrar) recusa `DECRYPT` com `BAD_KEY_USE`. E `exportabilidade='N'` **não** impede usar
  — não poder sair é diferente de não poder trabalhar.

  ⚠ **É um oráculo de cifragem, e vale dizer.** Quem tem o handle cifra e
  decifra o que quiser sob aquela chave, em laço. Não há como não ser — é o
  serviço que um HSM presta. O que ele não entrega é a chave, e é para isso
  que o handle existe. O controle real está no `modo` e no log de auditoria.
- **`MAC_GENERATE` / `MAC_VERIFY`** — CMAC-AES sob a chave de um slot. Os
  modos de uso se dividem em **dois grupos que não se cruzam**: `E`/`D`/`B`
  cifram, `G`/`V`/`C` autenticam. Uma chave de cifra não assina, e uma de
  MAC não cifra — é assim que a confusão de tipo de chave se fecha.

  ⚠ **`MAC_VERIFY` devolve um bit**, no status. O dispositivo compara em
  tempo constante, do lado de dentro. Devolver a tag calculada para quem
  perguntou comparar entregaria 128 bits em vez de 1, e reabriria o canal
  lateral de tempo que a comparação interna existe para fechar.
- **`DELETE_KEY`** — apaga **um** slot, e **não pede dual control**. A
  assimetria com o `ZEROIZE` é deliberada: apagar um é reversível, porque o
  key block daquela chave continua existindo fora do equipamento. Apagar
  tudo não é.
- **`KEY_FROM_COMPONENTS`** — a cerimônia da chave mestra aplicada a uma
  chave de trabalho: cada custodiante entra com a sua parte, ninguém vê a
  chave inteira, e o equipamento monta por XOR do lado de dentro.

  **É o único comando de operação que exige dual control**, e por isso: é
  cerimônia, não operação. Aperto novo a cada componente.

  O KCV que volta é o **do componente**, nunca o do acumulado — é o que
  permite ao custodiante conferir que digitou o dele. E a resposta tem
  comprimento fixo, com handle zero enquanto a montagem não termina.

O `0x20` e o `0x26` exigem **dual control**: os dois botões pressionados no
instante em que o frame chega, e um aperto *novo* a cada autorização (seção
26). São os únicos comandos do projeto cuja autorização não está no link do
host — o que é o ponto inteiro deles.

O KCV que o `0x20` devolve é o do **componente**, não o da LMK acumulada. O
`0x21` devolve o da LMK, e só quando ela está completa; enquanto incompleta,
os três bytes vêm zerados, e a resposta mantém o comprimento fixo para que o
tamanho do frame não anuncie nada.

Uma LMK **zerada** é recusada no terceiro componente com `BAD_PARAM`, e a
cerimônia recomeça do componente 0 — não há como saber qual dos três estava
errado. Acontece se o último componente for o XOR dos dois primeiros: cada
um parece aleatório, e a soma é zero. LMK *fraca* (de pouca entropia) não é
checada; a qualidade do componente é responsabilidade do custodiante.

### Comando da Fase 4 — log de auditoria

| Opcode | Nome | Pedido | Resposta | Estados |
|---|---|---|---|---|
| `0x2D` | `AUDIT_READ` | seq inicial (4) | próximo (4) ‖ continuar (4) ‖ até 16 registros de 16 bytes | todos |

Cada registro: `seq(4) | comando(1) | estado(1) | argumento(1) | resultado(1)
| reservado(4) | crc32(4)`. Comando `0x00` é o boot; resultado `0xFF` é
"pendente", um comando que começou e não terminou. Comando `0x0F` é uma
violação de ambiente, com a causa no argumento.

### Comando da Fase 6 — sensores

| Opcode | Nome | Pedido | Resposta | Estados |
|---|---|---|---|---|
| `0x2E` | `ENV_READ` | vazio | retido (1) ‖ agora (1) ‖ válido (1) ‖ temperatura, VCCINT, VCCAUX, VCCBRAM (2 cada) | todos |

Os quatro valores são códigos de 12 bits do XADC, e `hsmtool env` os converte.

### Comando da Fase 8 — tabela de decimalização

| Opcode | Nome | Pedido | Resposta | Estados |
|---|---|---|---|---|
| `0x80` | `TABELA_AUTORIZA` | tabela (16 dígitos ASCII) ‖ KCV da chave V1 (3) | tabela (16) ‖ KCV (3) ‖ MAC (8) | `OPERATIONAL` |

Exige os dois botões. `hsmtool tabela-autoriza TABELA KCV` mostra a resposta
em 32 caracteres, que é o bloco que os comandos `V0` e `V2` da porta host
pedem. O bloco vale só com a chave `V1` daquele KCV. A seção 35.4 explica por
que a tabela precisa de autorização, e por que o KCV entra.

### Porta host — command set ASCII (Fase 5)

Tudo acima é o **console**. A porta **host** usa a mesma UART com mensagens
ASCII, enquadradas pelo mesmo `LEN` de 2 bytes e **sem CRC**:

```
pedido     LEN(2) | cabeçalho(4) | comando(2) | campos
resposta   LEN(2) | cabeçalho(4) | resposta(2) | erro(2) | campos
```

O primeiro byte do corpo separa os protocolos: de `'0'` a `'~'` é ASCII, e
qualquer outro é opcode binário. O cabeçalho é do host e volta igual; a
resposta é o comando com o segundo caractere mais um.


<figure class="fig">
<svg viewBox="0 0 680 180" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="40" class="tb">pedido</text>
<rect class="cxc" x="80" y="22" width="60" height="28"/><text x="110" y="41" text-anchor="middle" class="ts">LEN</text>
<rect class="cxa" x="150" y="22" width="90" height="28"/><text x="195" y="41" text-anchor="middle" class="tm">TB01</text>
<rect class="cxd" x="250" y="22" width="60" height="28"/><text x="280" y="41" text-anchor="middle" class="tm">K2</text>
<rect class="cx" x="320" y="22" width="350" height="28"/><text x="495" y="41" text-anchor="middle" class="tm">D0112D0AB00E0000…  (o key block)</text>
<text x="10" y="100" class="tb">resposta</text>
<rect class="cxc" x="80" y="82" width="60" height="28"/><text x="110" y="101" text-anchor="middle" class="ts">LEN</text>
<rect class="cxa" x="150" y="82" width="90" height="28"/><text x="195" y="101" text-anchor="middle" class="tm">TB01</text>
<rect class="cxd" x="250" y="82" width="60" height="28"/><text x="280" y="101" text-anchor="middle" class="tm">K3</text>
<rect class="cxv" x="320" y="82" width="60" height="28"/><text x="350" y="101" text-anchor="middle" class="tm">00</text>
<rect class="cx" x="390" y="82" width="280" height="28"/><text x="530" y="101" text-anchor="middle" class="tm">D0 A B E  KCV(6)</text>
<g class="ts" text-anchor="middle">
<text x="110" y="130">2 bytes</text><text x="110" y="142">binário</text>
<text x="195" y="130">cabeçalho do</text><text x="195" y="142">host: volta igual</text>
<text x="280" y="130">comando</text><text x="280" y="142">K2 → K3</text>
<text x="350" y="130">erro</text><text x="350" y="142">00 = ok</text>
<text x="530" y="130">campos posicionais,</text><text x="530" y="142">sem separador</text>
</g>
<text x="340" y="172" text-anchor="middle" class="ts">sem CRC e sem sessão: cada pedido leva tudo de que precisa, inclusive a chave, embrulhada</text>
</svg>
<figcaption>Figura B.1 — Uma troca ASCII na porta host: o K2, que confere um key block.</figcaption>
</figure>

A chave de trabalho vai **no comando**, como key block X9.143 sob a LMK. O
comprimento do bloco sai do próprio cabeçalho dele. Dados vão como
comprimento em 4 dígitos decimais seguido de hex.

| Pedido | Resposta | Campos do pedido | Campos da resposta | Estados |
|---|---|---|---|---|
| `D0` | `D1` | — | estado(1) ‖ KCV da LMK(6) ‖ versão(6) | todos menos `TAMPERED` |
| `K0` | `K1` | uso(2) ‖ modo(1) ‖ exportabilidade(1) [‖ algoritmo(1) ‖ comprimento(1)] | key block ‖ KCV(6) | `OPERATIONAL` |
| `K2` | `K3` | key block | uso(2) ‖ alg(1) ‖ modo(1) ‖ exp(1) ‖ KCV(6) | `OPERATIONAL` |
| `K4` | `K5` | bloco da KEK ‖ bloco da chave (os dois sob a LMK) | bloco da chave sob a KEK ‖ KCV(6) | `OPERATIONAL` |
| `K6` | `K7` | bloco da KEK (sob a LMK) ‖ bloco da chave (sob a KEK) | bloco da chave sob a LMK ‖ KCV(6) | `OPERATIONAL` |
| `C0` | `C1` | key block ‖ IV(32, ou 16 com chave 3DES) ‖ dados | dados | `OPERATIONAL` |
| `C2` | `C3` | key block ‖ IV(32, ou 16 com chave 3DES) ‖ dados | dados | `OPERATIONAL` |
| `M0` | `M1` | key block ‖ dados; com chave 3DES, key block ‖ preenchimento(1) ‖ tamanho(1) ‖ dados | MAC(32); com chave 3DES, MAC(8 ou 16) | `OPERATIONAL` |
| `M2` | `M3` | key block ‖ MAC(32) ‖ dados; com chave 3DES, key block ‖ preenchimento(1) ‖ tamanho(1) ‖ MAC(8 ou 16) ‖ dados | — (o veredito é o erro) | `OPERATIONAL` |
| `R0` | `R1` | exportabilidade(1) | key block ‖ n(512) ‖ e(8) | `OPERATIONAL` |
| `R2` | `R3` | key block ‖ digest(64) | assinatura(512) | `OPERATIONAL` |
| `R4` | `R5` | n(512) ‖ e(8) ‖ digest(64) ‖ assinatura(512) | — (o veredito é o erro) | `OPERATIONAL` |
| `E0` | `E1` | exportabilidade(1) | key block ‖ Qx(64) ‖ Qy(64) | `OPERATIONAL` |
| `E2` | `E3` | key block ‖ digest(64) | r(64) ‖ s(64) | `OPERATIONAL` |
| `E4` | `E5` | Qx(64) ‖ Qy(64) ‖ digest(64) ‖ r(64) ‖ s(64) | — (o veredito é o erro) | `OPERATIONAL` |
| `P0` | `P1` | bloco da chave de origem ‖ bloco da chave de destino ‖ formato de origem(1) ‖ formato de destino(1) ‖ tamanho do PAN(2) ‖ PAN ‖ PIN block(16 ou 32) | PIN block(16 ou 32) | `OPERATIONAL` |
| `V0` | `V1` | COMUM ‖ tabela autorizada(32) ‖ dados de validação(16) | tamanho(2) ‖ offset | `OPERATIONAL` |
| `V2` | `V3` | COMUM ‖ tabela autorizada(32) ‖ dados de validação(16) ‖ tamanho(2) ‖ offset | — (o veredito é o erro) | `OPERATIONAL` |
| `V4` | `V5` | COMUM ‖ índice da chave(1) | PVV(4) | `OPERATIONAL` |
| `V6` | `V7` | COMUM ‖ índice da chave(1) ‖ PVV(4) | — (o veredito é o erro) | `OPERATIONAL` |
| `P2` | `P3` | bloco da BDK ‖ bloco da chave de destino ‖ KSN(20 ou 24) ‖ [chave de trabalho(1)] ‖ formato de origem(1) ‖ formato de destino(1) ‖ tamanho do PAN(2) ‖ PAN ‖ PIN block(16 ou 32) | PIN block(16 ou 32) | `OPERATIONAL` |
| `I0` | `I1` | bloco da KEK ‖ bloco da BDK ‖ KSN(20 ou 24) | bloco da chave inicial sob a KEK ‖ KCV(6) | `OPERATIONAL` |
| `M4` | `M5` | bloco da BDK ‖ KSN(20 ou 24) ‖ [chave de trabalho(1)] ‖ [tamanho(1)] ‖ MAC(8, 16 ou 32) ‖ dados | — (o veredito é o erro) | `OPERATIONAL` |
| `M6` | `M7` | bloco da BDK ‖ KSN(20 ou 24) ‖ [chave de trabalho(1)] ‖ [tamanho(1)] ‖ dados | MAC(8, 16 ou 32) | `OPERATIONAL` |
| `C4` | `C5` | bloco da BDK ‖ KSN(20 ou 24) ‖ [chave de trabalho(1)] ‖ IV(16 ou 32) ‖ dados | dados | `OPERATIONAL` |
| `C6` | `C7` | bloco da BDK ‖ KSN(20 ou 24) ‖ [chave de trabalho(1)] ‖ IV(16 ou 32) ‖ dados | dados | `OPERATIONAL` |
| `A0` | `A1` | bloco da IMK ‖ esquema(1) ‖ preenchimento(1) ‖ tamanho do PAN(2) ‖ PAN ‖ PSN(2) ‖ ATC(4) ‖ ARQC(16) ‖ método(1) ‖ [ARC(4)] ‖ [CSU(8) ‖ tamanho(1) ‖ dado próprio] ‖ dados | ARPC(16 ou 8), se o método não é `0` (o veredito é o erro) | `OPERATIONAL` |
| `A2` | `A3` | bloco da KEK ‖ bloco da IMK ‖ tamanho do PAN(2) ‖ PAN ‖ PSN(2) | bloco da MK sob a KEK ‖ KCV(6) | `OPERATIONAL` |
| `W0` | `W1` | bloco da CVK ‖ tamanho do PAN(2) ‖ PAN ‖ validade(4) ‖ código de serviço(3) | código(3) | `OPERATIONAL` |
| `W2` | `W3` | bloco da CVK ‖ tamanho do PAN(2) ‖ PAN ‖ validade(4) ‖ código de serviço(3) ‖ código(3) | — (o veredito é o erro) | `OPERATIONAL` |

COMUM = bloco da chave de PIN ‖ bloco da chave de verificação ‖ formato(1) ‖
tamanho do PAN(2) ‖ PAN ‖ PIN block(16 ou 32).

Erros: `00` sem erro · `01` verificação falhou · `10` key block inválido ·
`11` o uso ou o modo do bloco não permite · `12` chave não exportável · `13` o
bloco de proteção não é KEK · `14` PIN block inválido · `15` dados inválidos · `16` parâmetro
inválido · `17` tabela de decimalização não autorizada · `20` estado não permite · `21` comando desconhecido · `22`
mensagem malformada · `27` falha no log · `90` erro interno · `91` erro grave. Os códigos de
comando e de erro são deste projeto.

Os comandos `R` são de RSA-2048 e os `E`, de ECDSA sobre a curva P-256. Os
comandos `A` são do chip EMV (seção 40). O
digest é SHA-256, calculado pelo host. A seção 30 explica os dois.

No `K0`, os dois últimos campos são opcionais e vêm juntos: `A4` é AES-256,
que também é o padrão sem o campo; `T2` é 3DES de comprimento duplo; `T3` é
3DES de comprimento triplo. Outro valor responde `16`. A seção 39.8 explica
o que cada comando faz com uma chave 3DES.

`P0` traduz um PIN block ISO 9564 de uma chave de PIN para outra, e de um
formato para outro. As duas chaves têm uso `P0`. Cada campo de formato
aceita `4` (AES, PIN block de 32 caracteres) ou `0` (3DES, 16 caracteres), e
a chave tem de ser do algoritmo do formato; se não é, a resposta é `11`. O
tamanho do PAN vai em dois dígitos decimais, e o PAN, em dígitos ASCII: de 1
a 19, e de 13 a 19 quando um dos formatos é o `0`. As seções 34.1 a 34.3
explicam o comando.

`V0` a `V6` são a verificação de PIN (seção 35). O PIN chega num PIN block,
formato `0` ou `4`, sob uma chave de uso `P0`. A chave de verificação é 3DES,
de uso `V1` para o offset (`V0`, `V2`) e `V2` para o PVV (`V4`, `V6`); gerar
pede modo `G` ou `C`, e verificar pede `V` ou `C`. A tabela autorizada são os
16 dígitos da tabela e os 16 caracteres do MAC que o `TABELA_AUTORIZA` do
console devolveu para aquela chave `V1`. Os dados de validação vão em 16 dígitos hexadecimais. O
offset tem de 4 a 12 dígitos, e o tamanho vai em dois dígitos decimais. No
PVV o PAN tem de 12 a 19 dígitos.

`W0` e `W2` são o CVV, o CVV2 e o iCVV (seção 36): o código de serviço
escolhe qual. A CVK é 3DES de comprimento duplo, de uso `C0`; gerar pede
modo `G` ou `C`, e verificar pede `V` ou `C`. O PAN tem de 12 a 19 dígitos.
A validade vai como o emissor a usa, e o equipamento não a interpreta.

`K4` e `K6` trocam chave com outra instituição sob uma **KEK** — chave de
uso `K0` que as duas têm, formada por componentes no console
(`comp-load --uso K0`). `K4` é exportar e recusa `'N'`; `K6` guarda o que
chegou sob a LMK. O `modo` da KEK diz se ela embrulha (`E`), desembrulha
(`D`) ou os dois (`B`).

A KEK pode ser AES-256 ou, desde a etapa 8.7, 3DES dupla ou tripla
(`comp-load --alg T2` ou `T3`). Sob uma KEK AES o bloco trocado é versão D;
sob uma KEK 3DES, versão B (seção 39.9). Uma KEK 3DES só leva chave 3DES de
comprimento igual ou menor: no `K4`, outra chave é `13`; no `K6`, um bloco
assim é `10`, como qualquer bloco recebido inválido.

`P2` e `I0` são o DUKPT (seções 37.2 e 37.3). A BDK tem uso `B0` e modo `X`
(só deriva); outra chave é `11`. O algoritmo da BDK, no cabeçalho do bloco
dela, decide o resto:

- **BDK 3DES dupla (DUKPT TDES).** O KSN vai em 20 dígitos hexadecimais, sem
  o campo da chave de trabalho. O formato de origem do `P2` é `0`. KSN com
  contador zero ou com mais de 10 bits 1 é `16`. O `I0` devolve a IPEK.
- **BDK AES-128 ou AES-256 (DUKPT AES).** O KSN vai em 24 dígitos, seguido
  do tipo da chave de trabalho: `2` (AES-128) ou `4` (AES-256); outro valor
  é `16`. O formato de origem do `P2` é `4`. KSN com contador zero ou com
  mais de 16 bits 1 é `16`. O `I0` devolve a IK, do tamanho da BDK, e só sob
  uma KEK AES (sob uma KEK 3DES, `13`).

O destino do `P2` é `0` ou `4`, sob uma chave de uso `P0`, como no `P0`; o
formato de origem do outro algoritmo é `11`. O `I0` ignora o contador do KSN
e devolve a chave inicial num bloco de uso `B1`, o algoritmo da BDK, modo `X`
e exportabilidade `N`: versão D sob KEK AES, B sob KEK 3DES. A KEK tem uso
`K0` (senão `13`) e modo `E` ou `B` (senão `11`).

No log de auditoria, um comando da porta host aparece com os dois
caracteres dele nos campos `comando` e `argumento` (`K0` = `0x4B`, `0x30`) e
o código de erro em decimal no `resultado`.

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
| `0x23` | `NO_SLOT` | key store cheio |
| `0x24` | `BAD_KEY_USE` | o `uso` ou o `modo` do slot proíbe a operação |
| `0x25` | `MAC_INVALID` | o MAC não confere |
| `0x26` | `STORE_FAIL` | fase 4: a flash não gravou; a operação foi desfeita |
| `0x27` | `LOG_FAIL` | fase 4: sem registro no log, o comando não executa |
| `0x30` | `SELFTEST_FAIL` | |
| `0x32` | `CRYPTO_FAIL` | A dupla execução discordou: nada sai, as chaves ficam e o dispositivo marca erro grave |
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
source /opt/AMD/2026.1/Vivado/settings64.sh

./scripts/sim.sh                 # todos os testbenches; recompila o
                                 # firmware sozinho se o C estiver mais novo
make -C fw image                 # o build da FPGA depende desta imagem
vivado -mode batch -source scripts/build.tcl

./scripts/program.sh flash       # grava na SPI flash

python3 host/hsmtool.py selftest # sem placa: o codec do protocolo
python3 host/test_hsmtool.py     # sem placa: o transporte
python3 host/test_tr31.py        # sem placa: o key block (precisa de
                                 # `cryptography`)
python3 host/hsmtool.py ping
python3 host/hsmtool.py bench -n 10000
```

⚠ **`flash`, e não a RAM de configuração.** O firmware mora na Block RAM de
instruções, cujo conteúdo inicial vem do bitstream. Configurar por JTAG
pode deixar a placa com `Done = 1`, o clock travado e a CPU **sem executar
uma instrução** — porque a inicialização das Block RAMs não foi aplicada.
O sintoma é cruel: tudo indica sucesso e o dispositivo está mudo. Detalhes
e discriminadores de falha em `doc/bancada.md`.

⚠ **`sim.sh` recompila o firmware quando o C está mais novo que a imagem.**
Até isso existir, editar C e simular validava o **binário anterior** — e o
modo como isso foi descoberto está em `doc/fase3-notas.md`: uma sabotagem
deliberada do código passou na simulação, porque o código sabotado nunca
chegou a ser compilado.

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

**Antes de digitar qualquer coisa, olhe o display.** Ele soletra o estado:

```
    U n i      UNINITIALIZED   sem chave mestra
    A u t      AUTHORIZED      LMK carregada, ainda não em serviço
    O P E      OPERATIONAL     em serviço
    t P r      TAMPERED        reprovou, e não sai daí por software
```

Isso é o dispositivo dizendo em que estado está **sem que ninguém pergunte**
— e é a única informação que ele oferece de graça. Confirme depois pela
serial, que é o canal com autoridade:

```bash
python3 host/hsmtool.py version
```

```
firmware : v0.8.3
estado   : UNINITIALIZED (0)
```

`UNINITIALIZED` é o estado de fábrica: o dispositivo funciona, mas não
guarda chave nenhuma.

**Qual firmware está gravado.** Três perguntas diferentes, três comandos:

```bash
python3 host/hsmtool.py version      # a versão e o estado
python3 host/hsmtool.py dna          # a identidade do chip
python3 host/hsmtool.py build        # o firmware, byte a byte
```

```
firmware : v0.8.3
sha-256  : ec881b59196d72873140331a3152baa387f63b0aa43546ba4225559ce2707905
local    : CONFERE com fw/elf.bin (compilado em 2026-11-14 19:32)
```

O **número de versão** diz a etapa: o segundo campo é a fase, e o terceiro,
a etapa entregue dentro dela. Ele responde "que funções este equipamento
tem".

O **hash** responde outra pergunta: "é exatamente este o firmware que eu
compilei?". O equipamento calcula o SHA-256 da própria memória de código,
inteira, na hora do pedido. O `hsmtool` calcula o mesmo sobre o arquivo
compilado no PC e compara. Um byte de diferença muda o hash inteiro.

O hash foi preferido a um número de commit porque o firmware é compilado e
testado **antes** do commit: um número de commit gravado na placa seria
sempre o do commit anterior. O hash identifica o conteúdo, e o `git` diz
depois a que commit aquele conteúdo pertence.

Conferir a integridade do próprio firmware é uma exigência da FIPS 140-3
(seção 11): um módulo validado faz esse teste a cada boot, contra um valor
de referência autenticado. Aqui o equipamento só **informa** o hash, e quem
compara é o host. É diagnóstico, e não defesa: um firmware adulterado
poderia mentir sobre o próprio hash.

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
key block X9.143       ok
RSA-2048               ok
assinatura RSA         roda no primeiro uso
ECDSA P-256            roda no primeiro uso
DES e 3DES             roda no primeiro uso
```

As nove primeiras linhas são testes que rodam no boot. As três últimas são
**autotestes de primeiro uso**: cada um roda antes do primeiro comando que
usa o algoritmo, e a linha só mostra `FALHOU` se ele já reprovou desde o
boot (seções 30 e 39.8).

Das linhas do boot, as oito primeiras dizem oito verdades diferentes.

As cinco primeiras são respostas conhecidas contra vetores oficiais
(seção 11) — exceto a quinta, que são os **testes de partida** da fonte de
entropia sobre um retrato de 1024 amostras brutas (seção 10).

As três últimas são de natureza diferente e vale distinguir, porque a norma
distingue: **testes de função crítica**, não de algoritmo. Não existe
"resposta conhecida" para instalar uma chave — existem propriedades que, se
falharem, tornam o dispositivo perigoso *sem parecer quebrado*:

- **key store** — uma chave marcada como não exportável não sai; um slot
  apagado não responde; uma chave de cifrar não é aceita para decifrar; e a
  zeroização, depois de rodar, não deixou um byte diferente de zero na
  região de chaves;
- **key block X9.143** — um key block de procedência externa é
  desembrulhado e devolve a chave certa; um cabeçalho adulterado é recusado;
  e uma ida-e-volta fecha.

⚠ Sobre esse último vale uma ressalva de procedência que não aparece em
nenhum outro: **o vetor dele não é do CAVP, e não há como ser.** O programa
de validação do NIST valida *algoritmo*, e X9.143 é *formato*; a norma que
traz o exemplo é paga. O que se usa é um valor conhecido de terceiros,
fixado por commit e por hash. Está registrado em `vectors/MANIFEST.txt` em
vez de dissimulado entre os demais.

⚠ **O autoteste zera a memória de trabalho.** O teste do key store instala e
apaga chaves de verdade e termina com o store vazio, chave mestra inclusive.
Um autoteste que poupasse a chave exercitaria um caminho que não é o do boot.
Até a Fase 3, rodá-lo num dispositivo carregado apagava a LMK; desde a Fase 4
o dispositivo restaura tudo da flash em seguida e volta ao estado em que
estava.

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
minúsculo no meio de uma cerimônia é como se aperta o botão errado.

**E o dispositivo confirma.** Aperte os dois: o **ponto decimal** do dígito
da direita acende. Solte: apaga.

```
    U n i.        os dois botões apertados, autorização disponível
    U n i         não
```

Esse ponto é a resposta de bancada para "que botões?" — em vez de confiar
num rótulo, aperte e veja o dispositivo concordar. Se acendeu, o comando
seguinte vai ser autorizado; se não acendeu, seria recusado, e você descobre
isso **antes** de gastar o comando em vez de depois.


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<g>
<rect class="cxc" x="20" y="30" width="56" height="40" rx="6"/><text x="48" y="55" text-anchor="middle" class="ts">reset</text><text x="48" y="86" text-anchor="middle" class="ts">SW1</text>
<rect class="cxd" x="90" y="30" width="56" height="40" rx="6"/><text x="118" y="55" text-anchor="middle" class="tb">✋</text><text x="118" y="86" text-anchor="middle" class="ts tb">SW2</text>
<rect class="cx" x="160" y="30" width="56" height="40" rx="6"/><text x="188" y="86" text-anchor="middle" class="ts">SW3</text>
<rect class="cx" x="230" y="30" width="56" height="40" rx="6"/><text x="258" y="86" text-anchor="middle" class="ts">SW4</text>
<rect class="cxd" x="300" y="30" width="56" height="40" rx="6"/><text x="328" y="55" text-anchor="middle" class="tb">✋</text><text x="328" y="86" text-anchor="middle" class="ts tb">SW5</text>
</g>
<text x="188" y="108" text-anchor="middle" class="ts">o par mais afastado: difícil com uma mão só</text>
<rect x="420" y="20" width="230" height="80" fill="#1a1a1a" rx="6"/>
<text x="470" y="78" text-anchor="middle" font-size="44" fill="#e03030" font-family="DejaVu Sans Mono, monospace">U</text>
<text x="535" y="78" text-anchor="middle" font-size="44" fill="#e03030" font-family="DejaVu Sans Mono, monospace">n</text>
<text x="600" y="78" text-anchor="middle" font-size="44" fill="#e03030" font-family="DejaVu Sans Mono, monospace">i</text>
<circle cx="625" cy="80" r="5" fill="#ff4040"/>
<text x="535" y="118" text-anchor="middle" class="ts">o ponto acende: os dois botões vistos</text>
<g>
<rect class="cxc" x="20" y="150" width="120" height="50" rx="8"/><text x="80" y="172" text-anchor="middle" class="tm tb">Uni</text><text x="80" y="188" text-anchor="middle" class="ts">0 de 3</text>
<rect class="cx" x="190" y="150" width="120" height="50" rx="8"/><text x="250" y="172" text-anchor="middle" class="tm tb">Aut</text><text x="250" y="188" text-anchor="middle" class="ts">LMK completa</text>
<rect class="cxv" x="360" y="150" width="120" height="50" rx="8"/><text x="420" y="172" text-anchor="middle" class="tm tb">OPE</text><text x="420" y="188" text-anchor="middle" class="ts">em operação</text>
<rect class="cxd" x="530" y="150" width="120" height="50" rx="8"/><text x="590" y="172" text-anchor="middle" class="tm tb td">tPr</text><text x="590" y="188" text-anchor="middle" class="ts">violado</text>
</g>
<line class="ln" x1="140" y1="175" x2="188" y2="175" marker-end="url(#seta)"/><text x="164" y="168" text-anchor="middle" class="ts">3 comp.</text>
<line class="ln" x1="310" y1="175" x2="358" y2="175" marker-end="url(#seta)"/><text x="334" y="168" text-anchor="middle" class="ts">ativar</text>
<text x="340" y="222" text-anchor="middle" class="ts">cada passo pede os dois botões, com um aperto novo; o display soletra o estado</text>
</svg>
<figcaption>Figura E.1 — A cerimônia na bancada: os botões de dual control, o ponto decimal que confirma, e o display a cada estado.</figcaption>
</figure>

Ele não vaza nada: quem está apertando os botões já está na frente da placa,
e não há observador remoto para quem a informação seja novidade.

E exige um aperto
**novo**: entre um componente e o seguinte, os dois têm de ser vistos
**soltos**. Segurar os dois durante a cerimônia inteira carrega **um**
componente, não três (seção 26).

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

**O display de 7 segmentos é o indicador que importa**, e há um motivo
concreto: os cinco LEDs desta placa são **todos vermelhos**. A cor não
carrega informação nenhuma, só a posição — o requisito "LED vermelho para
`TAMPERED`" está atendido e vazio.

| O que mostra | Significado |
|---|---|
| `Uni` `Aut` `OPE` `tPr` | o estado da máquina (seção 8) |
| ponto decimal aceso | dual control satisfeito **neste instante** |

Um detalhe de projeto que vale registrar: se os dois bits de estado
chegarem corrompidos, o display mostra `tPr`. O `default` do decodificador é
`TAMPERED`, e não `Uni` nem apagado — falhar para o lado seguro vale também
para o painel. Um display que mostrasse "sem chave" quando não sabe seria
pior que um display apagado.

E o que ele **nunca** vai mostrar: KCV, handle, qualquer coisa derivada de
chave. Ótico é o único canal do dispositivo que não aparece numa captura de
UART, então é o canal em que um vazamento passaria despercebido por mais
tempo. O módulo recebe dois bits de estado e um de autorização, e não tem
caminho nenhum até material de chave.

Os LEDs, que sobraram como indicadores grosseiros:

| LED | Significado |
|---|---|
| **D1** | pisca a 1 Hz — o clock de 100 MHz está vivo. É **hardware**, independente da CPU |
| **D2** | aceso — o POST passou e o dispositivo está no laço de comandos |
| **D5** | aceso — `TAMPERED` |

D1 ser hardware é deliberado: se o firmware travar, D1 continua piscando, e
isso distingue "clock morto" de "firmware pendurado". Num dispositivo sem
console, essa distinção é a diferença entre depurar e adivinhar.

O display, ao contrário, é dirigido pelo firmware — ele mostra o que a CPU
diz. As duas coisas se complementam: **D1 prova que o hardware vive, o
display prova que o firmware sabe onde está.** Display congelado com D1
piscando é firmware pendurado; os dois parados é clock morto.

Fora isso, o dispositivo é **mudo até ser perguntado**. Um terminal aberto
na porta serial não mostra absolutamente nada, e esse é o comportamento
correto: um módulo criptográfico que conversa sozinho está contando alguma
coisa a alguém.

### E.6 Trabalhar com chaves

Depois de `OPERATIONAL`, **nenhum comando pede botão** — e isso é o ponto,
não uma economia. A cerimônia acabou; o que vem agora é operação.

```bash
hsmtool.py gen-key --uso D0 --modo B --exp E
#   handle : 1
#   KCV    : 7ED838
```

A chave veio do gerador do dispositivo e **nunca existiu fora da
fronteira**. O que voltou foi um handle e três bytes de KCV. Compare com o
`aes` da Fase 2, onde a chave ia no pedido: é a mesma diferença entre um
cofre e uma gaveta.

```bash
hsmtool.py export-key 1
#   D0144D0AB00E0000B82679114F470F54...
```

São 144 caracteres de texto: dezesseis de cabeçalho legível, o corpo
cifrado, e o MAC. Exporte de novo e o bloco será **diferente** — o
enchimento é aleatório, e dois blocos idênticos denunciariam que a mesma
chave saiu duas vezes.

```bash
hsmtool.py import-key D0144D0AB00E0000...
#   handle : 2
#   KCV    : 7ED838      <- o mesmo
```

Mesmo KCV, outro handle: a chave voltou inteira. E o experimento que vale a
pena fazer é o negativo — troque **um caractere** do bloco, em qualquer
posição, e tente importar. O dispositivo recusa. O caractere na posição 11
é a exportabilidade; reescrevê-lo à mão é literalmente o ataque que o MAC
sobre o cabeçalho existe para impedir.

```bash
hsmtool.py gen-key --exp N
hsmtool.py export-key 3
#   dispositivo recusou: STATUS_NOT_EXPORTABLE
```

Uma chave marcada `'N'` não sai. Não por convenção: existe **um único
caminho** para os bytes deixarem um slot, e é ele que consulta o campo.

```bash
hsmtool.py key-info 1
#   uso D0 · algoritmo A · modo B · exportabilidade E · 32 bytes
#   KCV 7ED838 · usos 0
```

Metadados, nunca chave. Não existe "me devolva o slot inteiro".

E finalmente **usar** a chave — que é o que separa um cofre de um depósito:

```bash
hsmtool.py encrypt 1 <iv 16 bytes> <dados múltiplos de 16>
hsmtool.py decrypt 1 <mesmo iv>    <o criptograma>
```

A chave é referida por **handle**. Compare com o que a Fase 2 fazia: lá a
chave ia dentro do pedido. Aqui vai um número de gaveta, e o material nunca
atravessa a linha.

O experimento que fecha o assunto: exporte uma chave, reimporte, e cifre o
**mesmo bloco com o mesmo IV** usando os dois handles. Os criptogramas têm de
ser idênticos — é a prova de que a chave voltou bit a bit, e é bem mais forte
que comparar os três bytes do KCV.

E o negativo, que ensina mais:

```bash
hsmtool.py gen-key --modo E        # 'E' = só cifrar
hsmtool.py decrypt <handle> ...    # -> BAD_KEY_USE
```

**Confusão de tipo de chave** é a origem de uma família inteira de ataques de
API (seção 15). A defesa é o campo `modo`, e a verificação vive num lugar só
— dentro do key store, não espalhada pelos comandos.

⚠ Uma distinção que confunde: `exportabilidade='N'` **não** impede usar.
Impede **sair**. Uma chave que nunca sai e trabalha o dia inteiro é o caso
mais comum de uma chave bem configurada.

E autenticar, que é o outro serviço:

```bash
hsmtool.py gen-key --uso M0 --modo C --exp E   # 'C' = gerar e verificar MAC
hsmtool.py mac 5 <mensagem hex>
hsmtool.py mac-verify 5 <tag> <mensagem>       # "MAC confere"
```

O veredito vem do **status**, não do payload: o equipamento compara e diz
sim ou não. Devolver a tag calculada para você comparar entregaria 128 bits
em vez de um, e é o tipo de conveniência que abre canal lateral.

E repare no `--modo C`. Os modos se dividem em **dois grupos que não se
cruzam**:

| grupo | valores | o que faz |
|---|---|---|
| cifra | `E` `D` `B` | `encrypt` / `decrypt` |
| MAC | `G` `V` `C` | `mac` / `mac-verify` |

Tente `mac` numa chave `--modo B` e veja `BAD_KEY_USE`. Tente `encrypt`
numa `--modo C` e veja o mesmo.

O `uso` manda junto: `encrypt` exige `D0`, e `mac` exige um uso da família
`M`. Por isso a chave acima é `--uso M0`, e não só `--modo C`. Gere uma
`--uso K0 --modo B` e tente `encrypt`: o modo deixaria, o uso não deixa.

Essa separação não é burocracia de campo — é a defesa contra **confusão de
tipo de chave**, que é a origem de uma família inteira de ataques de API
(seção 15). Uma KEK que decifrasse "dados" entregaria as chaves que ela
protege.

### E.7 Liberar um slot, e montar uma chave a várias mãos

O key store tem dezesseis slots. Para devolver um:

```bash
hsmtool.py delete-key 5
#   apagado. slots livres: 12
```

**Sem dual control**, ao contrário do `zeroize`. A razão é que apagar um
slot é **reversível**: se você guardou o key block daquela chave,
reimportar devolve tudo. Apagar o equipamento inteiro não é reversível, e
por isso pede duas pessoas.

E a operação que fecha o capítulo — montar uma chave que **ninguém conhece
inteira**:

```bash
hsmtool.py comp-load 0 2 --random --uso K0 --modo B --exp E
hsmtool.py comp-load 1 2 --random --uso K0 --modo B --exp E
#   handle : 6  <- chave montada e instalada
```

É a cerimônia da chave mestra aplicada a uma chave de trabalho. Cada
custodiante entra com a sua parte, sob dual control, e o equipamento
combina por XOR **do lado de dentro**. É assim que uma chave combinada
entre duas instituições entra num HSM sem que nenhuma das duas a conheça.

Três detalhes que valem reparar:

- **É o único comando de operação que pede os dois botões.** Os outros são
  trabalho; este é cerimônia.
- **O KCV que volta é o do componente**, não o da chave em construção.
  Serve para o custodiante conferir a parte dele. O do acumulado seria um
  oráculo sobre a chave que ainda está sendo montada.
- **Começar pelo componente 0 reinicia a montagem.** É como se abandona uma
  cerimônia que saiu errada, sem precisar de um comando para isso.
- **A chave pode ser 3DES** (etapa 8.7): `--alg T2` (componentes de 16
  bytes) ou `--alg T3` (24). O KCV de cada componente é então o do 3DES, e
  `hsmtool.py kcv --tdes` faz a mesma conta no PC. É assim que nasce a KEK
  3DES de troca com um parceiro que ainda usa 3DES (seção 39.9).
- **A BDK do DUKPT nasce do mesmo jeito** (etapa 8.8a): `comp-load --alg T2
  --uso B0 --modo X`. O modo `X` diz "só deriva": a BDK não cifra nem faz
  MAC, e só os comandos `P2` e `I0` a usam (seção 37.2). Ela fica num slot
  e na flash como as outras, e sai para a porta host como key block sob a
  LMK, pelo `EXPORT_KEY`.
- **A BDK do DUKPT AES também** (etapa 8.8b): `comp-load --alg A128 --uso B0
  --modo X` para AES-128 (componentes de 16 bytes), ou `--alg A` para
  AES-256. O equipamento só aceita uma chave AES-128 com esse cabeçalho, e o
  KCV de cada componente é o do AES-128 (seção 37.3).

E o comando que desfaz tudo:

```bash
hsmtool.py zeroize      # com os dois botões
```

Apaga os 16 slots e a LMK, **e confere que apagou** antes de dizer que
apagou. Funciona em qualquer estado — inclusive em `TAMPERED`, e ali ele
apaga a chave sem tirar o dispositivo de `TAMPERED`: um HSM que se cura de
tamper não detectou tamper nenhum.

### E.8 Desligar, religar e ler o log *(fase 4)*

```bash
# depois da cerimônia e de gerar chaves: desligue e ligue a placa
python3 host/hsmtool.py version
#   estado   : OPERATIONAL (2)      <- sem cerimônia
python3 host/hsmtool.py lmk-status
#   KCV da LMK  : (o mesmo de antes)
python3 host/hsmtool.py key-info 1  # mesmo handle, mesmo KCV

python3 host/hsmtool.py audit
#      0  BOOT                 Uni  sem registro persistente   OK
#      1  LMK_LOAD_COMPONENT   Uni  arg=0x00                   OK
#    ...
#     14  BOOT                 OPE  restaurado                 OK
```

Cada linha do `audit` é um comando, gravado **antes** de executar. A coluna
de estado é o estado em que o dispositivo estava quando o comando chegou. Um
`GEN_KEY` tentado em `Uni` aparece com o resultado `WRONG_STATE`: tentativas
recusadas também entram.

O `post` continua zerando a memória de trabalho, mas agora restaura tudo da
flash em seguida, e o dispositivo volta ao estado em que estava. Só o
`zeroize` apaga de vez: ele limpa a LMK e as chaves da flash e mantém o log,
que é o registro de quem zeroizou.

### E.9 O que ainda não existe

Honestidade sobre o estado do projeto, para que ninguém procure um comando
que não foi escrito:

- **A LMK sobrevive ao desligamento, mas não está protegida.** Desde a
  Fase 4 ela fica na flash, que o projeto *trata* como memória segura. Quem
  tiver um gravador SPI a lê. É uma decisão didática diante do hardware
  disponível, explicada no §27.
- **Não há anti-rollback.** Regravar a flash com uma imagem antiga faz uma
  chave apagada voltar, e o dispositivo não percebe.
- **Não há exportação em formato legado.** Só em key block X9.143. Por
  isso `exportabilidade='S'` se comporta como `'E'` — e está certo: na
  norma, `'S'` é o valor *mais permissivo*, que libera também formatos
  legados (criptograma simétrico, embrulho RSA). Como eles não existem
  aqui, `'S'` e `'E'` liberam o mesmo caminho.
- **O log de auditoria detecta corrupção, não adulteração.** O CRC de cada
  registro pega um bit trocado por acidente; quem editar a flash de
  propósito recalcula o CRC.
- **`hsmtool keycycle` precisa da LMK em claro**, o que um HSM de verdade
  nunca permitiria. Serve para as duas implementações do formato de key
  block se conferirem; é bancada, não operação.

## F. Os programas

O apêndice E mostra uma sessão de trabalho. Este apêndice é a referência:
ele lista os programas que o usuário roda e explica cada subcomando, cada
parâmetro e cada controle. Os programas estão em `host/` e em `scripts/`.

<figure class="fig">
<svg viewBox="0 0 680 250" xmlns="http://www.w3.org/2000/svg">
<rect class="cx" x="10" y="20" width="300" height="210" rx="6"/>
<text x="160" y="40" text-anchor="middle" class="tb">PC</text>
<rect class="cxa" x="30" y="55" width="130" height="34"/><text x="95" y="77" text-anchor="middle" class="tm">hsmtool.py</text>
<text x="170" y="70" class="ts">console:</text><text x="170" y="82" class="ts">protocolo binário</text>
<rect class="cxd" x="30" y="110" width="130" height="34"/><text x="95" y="132" text-anchor="middle" class="tm">hsmhost.py</text>
<text x="170" y="125" class="ts">host:</text><text x="170" y="137" class="ts">command set ASCII</text>
<rect class="cxc" x="30" y="170" width="130" height="34"/><text x="95" y="192" text-anchor="middle" class="tm">hsm_ponte.py</text>
<text x="170" y="185" class="ts">TCP 1500 ↔ serial,</text><text x="170" y="197" class="ts">sem entender</text>
<line x1="95" y1="144" x2="95" y2="170" class="ln"/>
<text x="100" y="161" class="ts">TCP</text>
<rect class="cxv" x="450" y="80" width="210" height="110" rx="6"/>
<text x="555" y="105" text-anchor="middle" class="tb">placa</text>
<text x="555" y="128" text-anchor="middle" class="ts">uma UART, 115 200 8N1</text>
<text x="555" y="146" text-anchor="middle" class="ts">o 1º byte separa</text>
<text x="555" y="160" text-anchor="middle" class="ts">binário de ASCII</text>
<line x1="310" y1="72" x2="450" y2="120" class="ln"/>
<line x1="310" y1="187" x2="450" y2="150" class="ln"/>
<text x="318" y="70" class="ts">serial (CP2102)</text>
<text x="318" y="200" class="ts">serial (CP2102)</text>
<text x="340" y="242" text-anchor="middle" class="ts">só um programa abre a serial por vez: com a ponte rodando, o hsmtool não fala</text>
</svg>
<figcaption>Figura F.1 — Os dois clientes e a ponte. O hsmhost fala pela ponte (padrão) ou direto na serial (--serial).</figcaption>
</figure>

| Programa | Para quê | Precisa da placa |
|---|---|---|
| `host/hsmtool.py` | o console: cerimônia, estado, chaves de slot, log, diagnóstico | sim, menos `selftest` e `kcv` |
| `host/hsmhost.py` | a porta host: os comandos ASCII e as conferências contra o Python | sim, menos `selftest` |
| `host/hsm_ponte.py` | a ponte TCP ↔ UART que o `hsmhost.py` usa | sim |
| `host/regressao.py` | a regressão inteira na placa | sim |
| `host/test_*.py` | os testes no PC, C contra Python e contra os valores publicados | não |
| `host/glitch.py`, `host/puf.py` | as medidas de ataque e do PUF | sim, com bitstream próprio |
| `scripts/*.sh`, `scripts/*.py` | simular, construir, gravar, gerar vetores e o PDF | só o `program.sh` |

Todos os programas Python devolvem 0 quando tudo deu certo e 1 quando o
dispositivo recusou ou uma conferência falhou. O `hsmtool.py` devolve 2
quando a porta serial falha.

### F.1 `hsmtool.py`, o console

```
python3 host/hsmtool.py [-p PORTA] [-b BAUD] [-t SEGUNDOS] SUBCOMANDO ...
```

| Opção | Padrão | O que faz |
|---|---|---|
| `-p`, `--port` | a do CP2102 | a porta serial. Sem ela, o programa escolhe pelo VID:PID do CP2102 (`10c4:ea60`), e nunca o gravador JTAG, que também cria uma `/dev/ttyUSB*` |
| `-b`, `--baud` | 115 200 | a velocidade da UART |
| `-t`, `--timeout` | 2,0 | quanto esperar a resposta, em segundos |

Os valores de chave, de mensagem e de MAC entram em hexadecimal. Um
`handle` é o número do slot (1 a 16) que o `gen-key`, o `import-key` e o
`comp-load` devolvem.

**Sem placa**

| Subcomando | O que faz |
|---|---|
| `selftest` | confere o codec do protocolo (enquadramento e CRC) |
| `kcv [--tdes] [--mostra] COMP ...` | calcula o KCV de cada componente e o do XOR deles: é a conta do custodiante. `--tdes` usa o KCV do 3DES (componentes de 16 ou 24 bytes). `--mostra` imprime também a chave montada |

**Identificação e diagnóstico**

| Subcomando | O que faz |
|---|---|
| `ping` | `PONG` e o tempo de ida e volta |
| `version` | a versão do firmware e o estado |
| `dna` | o identificador de fábrica do FPGA (57 bits) |
| `build` | o SHA-256 da memória de código, comparado com `fw/elf.bin`: `CONFERE` diz que o firmware gravado é o que foi compilado |
| `post` | roda o autoteste de novo e mostra cada teste. Reprovar leva a `TAMPERED`, como no boot |
| `env` | temperatura, tensões e alarmes de ambiente |
| `sha256 [HEX]` | o SHA-256 de uma mensagem, calculado no coprocessador |
| `random [-n N] [-o ARQ]` | N bytes do gerador aleatório (padrão 32). `-o` grava num arquivo |
| `bench [-n N] [--limit MS]` | N pings (padrão 10 000), com o limite por ping (padrão 50 ms): o teste de aceitação da fase 1 |
| `audit [--desde SEQ]` | lê o log de auditoria, do registro `SEQ` em diante (padrão: o mais antigo guardado) |

**Cerimônia e estado** (todos exigem os dois botões, salvo `lmk-status`)

| Subcomando | O que faz |
|---|---|
| `lmk-status` | quantos componentes da LMK entraram, e o KCV dela |
| `lmk-load [--random] N [COMP]` | carrega o componente N (0 a 2) da LMK, 32 bytes. `--random` gera o componente no PC e o imprime |
| `activate` | `AUTHORIZED` → `OPERATIONAL` |
| `tabela-autoriza TABELA KCV` | autoriza uma tabela de decimalização (16 dígitos) para a chave `V1` daquele KCV (6 hex). A resposta é o bloco que o `V0` e o `V2` pedem |
| `zeroize [--sim]` | apaga toda chave, LMK inclusive. Pede para digitar `apagar`; `--sim` pula essa pergunta, mas não os botões |

Os botões de dual control são o 2º e o 5º da fileira. Eles têm de estar
apertados quando o comando chega, e soltos entre duas autorizações (seção
7). Rode esses comandos num terminal de verdade: sem terminal, o programa
envia antes de você apertar.

**Chaves de slot**

| Subcomando | O que faz |
|---|---|
| `gen-key [--uso U] [--modo M] [--exp X]` | gera uma chave AES-256 dentro do dispositivo e devolve o handle e o KCV |
| `comp-load [--random] [--alg A] [--uso U] [--modo M] [--exp X] N TOTAL [COMP]` | monta uma chave de trabalho a partir de TOTAL componentes; este é o N (0 a TOTAL−1). Exige os botões a cada componente. `N = 0` recomeça a montagem |
| `export-key [-o ARQ] HANDLE` | exporta o slot como key block sob a LMK. `-o` grava num arquivo |
| `import-key [-f ARQ] [BLOCO]` | importa um key block, da linha de comando ou do arquivo `-f` |
| `key-info HANDLE` | uso, algoritmo, modo, exportabilidade, tamanho, KCV e contador de uso. Nunca a chave |
| `delete-key HANDLE` | apaga um slot, sem botões |
| `encrypt HANDLE IV DADOS` | AES-CBC com a chave do slot. IV de 16 bytes; dados em múltiplos de 16 |
| `decrypt HANDLE IV DADOS` | o inverso |
| `mac HANDLE [DADOS]` | CMAC-AES-256 com a chave do slot |
| `mac-verify HANDLE TAG [DADOS]` | confere a tag (16 bytes) dentro do dispositivo e responde com um bit |

As opções de chave valem para o `gen-key` e o `comp-load`:

| Opção | Valores | Padrão | O que é |
|---|---|---|---|
| `--uso` | `B0` `K0` `D0` `M0` `P0` | `D0` | o uso X9.143: BDK, KEK, dados, MAC, PIN (seção 8) |
| `--modo` | `E` `D` `B` `G` `V` `C` `X` `N` | `B` | o modo de uso: `E`/`D`/`B` cifram, `G`/`V`/`C` fazem MAC, `X` só deriva |
| `--exp` | `E` `N` `S` | `E` | a exportabilidade: `N` não sai |
| `--alg` (só `comp-load`) | `A` `A128` `T2` `T3` | `A` | AES-256; AES-128 (só BDK, modo `X`); 3DES duplo; 3DES triplo |

**Bancada**

| Subcomando | O que faz |
|---|---|
| `keycycle --lmk HEX [-n N] [-v]` | gera, exporta e reimporta N chaves (padrão 100), e o Python abre cada bloco com a LMK. Precisa da LMK em claro, o que um HSM de verdade nunca permitiria |
| `raw --op OP [--payload HEX]` | envia um opcode qualquer e mostra a resposta crua |

### F.2 `hsmhost.py`, a porta host

```
python3 host/hsmhost.py [--tcp HOST:PORTA | --serial [--porta PORTA]] [--cab CCCC] SUBCOMANDO ...
```

| Opção | Padrão | O que faz |
|---|---|---|
| `--tcp` | `127.0.0.1:1500` | fala pela ponte (F.3) |
| `--serial` | | fala direto na serial, sem a ponte |
| `--porta` | a do CP2102 | a porta serial, com `--serial` |
| `--cab` | `0000` | o cabeçalho de 4 caracteres, que volta igual na resposta (apêndice B) |

O programa não guarda nada. Os key blocks entram e saem pela linha de
comando: o host é quem os guarda. Uma recusa mostra o código de erro do
apêndice B e o texto dele.

**Comandos avulsos**

| Subcomando | Comando | O que faz |
|---|---|---|
| `selftest` | | confere o codec, sem placa |
| `diag` | `D0` | estado, KCV da LMK e versão |
| `gen [--uso U] [--modo M] [--exp X] [--alg A]` | `K0` | gera uma chave e devolve o key block e o KCV. `--alg`: `A4` AES-256 (padrão), `T2`/`T3` 3DES duplo/triplo |
| `check BLOCO` | `K2` | confere o bloco e mostra o cabeçalho e o KCV |
| `export KEK BLOCO` | `K4` | passa a chave de sob a LMK para sob a KEK |
| `import KEK BLOCO` | `K6` | o inverso |
| `encrypt BLOCO IV DADOS` | `C0` | cifra. Com chave 3DES, IV de 8 bytes |
| `decrypt BLOCO IV DADOS` | `C2` | decifra |
| `mac BLOCO DADOS` | `M0` | CMAC (AES) ou retail MAC (3DES) |
| `mac-verify BLOCO MAC DADOS` | `M2` | o veredito é o código: `00` ou `01` |
| `rsa-gen [--exp X]` | `R0` | gera um par RSA-2048 |
| `rsa-sign BLOCO DIGEST` | `R2` | assina o digest SHA-256 |
| `rsa-verify N E DIGEST S` | `R4` | confere uma assinatura |
| `ecdsa-gen [--exp X]` | `E0` | gera um par P-256 |
| `ecdsa-sign BLOCO DIGEST` | `E2` | assina |
| `ecdsa-verify QX QY DIGEST R S` | `E4` | confere |
| `pin-traduz [--formatos OD] ORIGEM DESTINO PAN BLOCO` | `P0` | traduz um PIN block. `--formatos`: origem e destino, `4` (AES) ou `0` (3DES); padrão `44` |

**Conferências.** Cada uma faz N voltas com dados ao acaso, e o Python
refaz por conta própria o que o equipamento fez. As que pedem `--lmk` abrem
os key blocks com a LMK de desenvolvimento: um host de verdade nunca tem a
chave mestra. Os PANs são inventados, com o prefixo `999999`.

| Subcomando | Voltas | Comandos | O que o Python faz |
|---|---|---|---|
| `confere --lmk HEX [-n N]` | 10 | `K0` `K2` `C0` `C2` `M0` `M2` | abre os blocos, refaz o AES e o CMAC |
| `tdes-confere --lmk HEX [-n N]` | 5 | `K0` `K2` `K4` com 3DES | refaz o KCV e o bloco versão B |
| `rsa-confere [-n N]` | 3 | `R0` `R2` `R4` | verifica as assinaturas só com `n` e `e` |
| `rsa-cavp [--lmk HEX]` | | `R4`, e `R2` com a LMK | os vetores do CAVP, e um bit trocado |
| `ecdsa-confere [-n N]` | 3 | `E0` `E2` `E4` | verifica só com o ponto público |
| `ecdsa-cavp [--lmk HEX]` | | `E4`, e `E2` com a LMK | os vetores do CAVP, e chaves públicas inválidas |
| `pkcs8-confere --lmk HEX [-n N]` | 3 | `R0` `E0` `R2` `E2` `R4` `E4` | troca chaves com a biblioteca `cryptography`, nos dois sentidos |
| `pin-confere --lmk HEX [-n N]` | 10 | `P0` | faz o papel do terminal e do destino |
| `pinv-confere --lmk HEX [-n N] [--tabela B --kcv K]` | 10 | `V0` `V2` `V4` `V6` | refaz o offset e o PVV. Com `--tabela` (o bloco do `tabela-autoriza`) e o `--kcv` da chave `V1`, confere também o MAC dessa tabela |
| `cvv-confere --lmk HEX [-n N]` | 10 | `W0` `W2` | refaz o CVV, o CVV2 e o iCVV |
| `dukpt-confere --lmk HEX [-n N]` | 10 | `P2` `I0` `M4` `M6` `C4` `C6` | faz o papel do terminal, TDES e AES |
| `arqc-confere --lmk HEX [-n N]` | 10 | `A0` `A2` | faz o papel do chip: calcula o ARQC e confere o ARPC |

Os comandos `V*`, `W*`, `P2`, `I0`, `M4` a `C6`, `A0` e `A2` não têm
subcomando avulso: eles entram pelas conferências e pelo `regressao.py`.

### F.3 `hsm_ponte.py`, a ponte

```
python3 host/hsm_ponte.py [--endereco IP] [--porta N] [--serial DEV]
```

| Opção | Padrão | O que faz |
|---|---|---|
| `--endereco` | `127.0.0.1` | onde escutar. O padrão aceita só esta máquina |
| `--porta` | 1500 | a porta TCP |
| `--serial` | a do CP2102 | a porta serial da placa |

A ponte repassa `LEN(2)` + mensagem nos dois sentidos e não interpreta
nada. Quem interpreta o ASCII é o firmware, dentro da fronteira. Com a
ponte rodando, a serial fica com ela: pare a ponte antes de usar o
`hsmtool.py`. Ctrl+C a encerra.

### F.4 `regressao.py`

```
python3 host/regressao.py --lmk HEX [--rapido] [--porta DEV]
```

| Opção | O que faz |
|---|---|
| `--lmk` | a LMK de desenvolvimento, em hex. Obrigatória |
| `--rapido` | menos voltas em cada passo |
| `--porta` | a porta serial |

Roda na placa o que a seção 48 descreve: os subcomandos do `hsmtool.py` e
do `hsmhost.py`, um passo por função, e confere o resultado de cada um. A
placa tem de estar em `OPERATIONAL`, e a ponte, parada. Ele não aperta
botão, não provoca falha e não vê sinal interno: não substitui a simulação.
Leva cerca de 7 minutos.

### F.5 Os testes no PC

Rodam sem placa e sem parâmetro: `python3 host/test_X.py`. Cada um
imprime `PASS` ou a lista de falhas. Os que conferem o firmware compilam o
C com o `gcc` do PC.

| Teste | O que confere |
|---|---|
| `test_hsmtool.py` | o transporte, com um modelo do dispositivo num pseudoterminal |
| `test_tr31.py`, `test_tr31b.py` | o key block X9.143, versões D e B |
| `test_cmac_tdes.py`, `test_des.py`, `test_retail_mac.py` | o CMAC-TDES, o DES e o retail MAC |
| `test_ecc.py`, `test_pkcs8.py` | o ECDSA e o leitor de PKCS#8 do firmware |
| `test_pinblock.py`, `test_pinverif.py`, `test_cvv.py` | PIN block, verificação de PIN, CVV |
| `test_dukpt.py` | o DUKPT TDES e AES |
| `test_emv.py` | o ARQC e o ARPC |

### F.6 Construir, simular e gravar

| Comando | O que faz | Controles |
|---|---|---|
| `./scripts/sim.sh [TB ...]` | simula um testbench, alguns, ou todos (sem argumento). Resultado em `build/sim/<tb>/`, tempos em `build/sim/tempos.csv` | `SIM_JOBS` (padrão 3): quantos ao mesmo tempo. `SIM_TIMEOUT`: o limite de cada um, em segundos |
| `make -C fw image` | compila o firmware e gera a imagem da memória de código | |
| `vivado -mode batch -source scripts/build.tcl` | síntese e bitstream | antes, `source /opt/AMD/2026.1/Vivado/settings64.sh` |
| `./scripts/program.sh [flash]` | grava o bitstream: sem argumento, na RAM de configuração; com `flash`, na flash SPI, que é o modo certo nesta placa | `BIT` (padrão `build/hsm_top.bit`), `CABLE` (padrão `digilent_hs2`), `CABLE_FREQ` (padrão 1 MHz) |
| `python3 scripts/mkkat.py` | gera `fw/include/kat_vectors.h` a partir de `vectors/` | |
| `./scripts/fetch-vectors.sh [--check]` | baixa os vetores das fontes e confere o hash. `--check` só confere o que já está no repositório | |
| `./scripts/mkpdf.sh` | gera este manual em PDF | |
| `python3 scripts/entstat.py ARQ` | estatística simples sobre bytes do `random`. Não valida o gerador | |

### F.7 As medidas de ataque e do PUF

Os dois programas pedem bitstreams próprios, que não são o de produção (seção
29).

`glitch.py` varre o injetor de falha de clock:

| Opção | Padrão | O que é |
|---|---|---|
| `--alvo` | `selftest` | o comando atacado: `selftest`, `encrypt` ou `mac-verify` |
| `--handle` | 1 | o slot, para `encrypt` e `mac-verify` |
| `--de`, `--ate`, `--passo` | 0, 1 000 000, 50 000 | a faixa de atraso do glitch, em ciclos |
| `--largura` | 40 | a largura do glitch |
| `--repete` | 1 | quantas vezes em cada atraso |
| `--cabo` | `digilent_hs2` | o cabo JTAG |
| `-o`, `--saida` | `glitch.csv` | o resultado: atraso, largura e classe de cada tentativa (`ok`, `detectou`, `ERRADO`, `mudo` e outras) |

`puf.py [--porta DEV] SUBCOMANDO` mede o RO-PUF:

| Subcomando | O que faz |
|---|---|
| `ler [-n N] [--carga C] -o ARQ` | N varreduras dos 64 anéis (padrão 100), com a carga térmica no nível C (padrão 0, desligada) |
| `termica [-n N] [--espera S] -o ARQ` | sobe a carga térmica nível a nível. Em cada nível, olha a temperatura a cada S segundos (padrão 20) até ela parar de subir, e lê N varreduras. Para perto de 70 °C |
| `analisa ARQ ...` | as frequências dos anéis e as métricas de uma ou mais medidas |
| `deriva BASE MEDIDA` | a taxa de bits errados contra a medida de referência, por nível de carga |
| `compara A B` | quantos bits diferem entre as respostas de referência de duas medidas |
| `corretor --ber P [--uniformidade U] [--falha F]` | escolhe o código BCH(255) que corrige a taxa de erro P (%) com probabilidade de falha F (padrão 10⁻⁶), e conta a entropia que sobra com a uniformidade U (padrão 50 %) |

## G. Leitura

### Normas

- **FIPS 140-3** e ISO/IEC 19790 — requisitos de módulo criptográfico
- **NIST SP 800-90A/B/C** — DRBG, fontes de entropia, construções
- **ANSI X9.143** (sucessor do TR-31) — key blocks, versões D (AES) e B
  (3DES)
- **NIST SP 800-38B** — o CMAC, com AES e com 3DES
- **ANSI X9.24-1** — DUKPT TDES (a edição de 2009, anexo A.4, traz os
  valores de teste); **ANSI X9.24-3** — DUKPT AES
- **NIST SP 800-57 Parte 1** — a força de segurança de cada algoritmo; a
  3DES dupla tem cerca de 80 bits, a tripla 112
- **RFC 8017** (PKCS #1 v2.2) — RSA, e o enchimento de assinatura v1.5
- **PCI PIN Security Requirements** e **PCI PTS HSM** — de onde vêm dual
  control e split knowledge como exigência
- **PCI DSS** — entre outras coisas, a proibição de guardar o CVV2 depois
  da autorização
- **ISO/IEC 9797-1** — os MACs de cifra de bloco; o algoritmo 3 é o *retail
  MAC* (seção 39.10), a mesma conta do CVV

### Ataques

- Bond, M. — *Attacks on Cryptoprocessor Transaction Sets* (2001)
- Preneel, B. e van Oorschot, P. C. — *A key recovery attack on the ANSI
  X9.19 retail MAC*, Electronics Letters 32(17), pp. 1568–1569 (1996)
- Bond, M. e Zieliński, P. — *Decimalisation Table Attacks for PIN Cracking*,
  relatório técnico UCAM-CL-TR-560, University of Cambridge (2003) — o
  ataque, as três variantes e a seção de prevenção
- Clulow, J. — *The Design and Analysis of Cryptographic Application
  Programming Interfaces for Security Devices*, dissertação de mestrado,
  University of Natal, Durban (2003) — ataques a PIN blocks
- Berkman, O. e Ostrovsky, O. M. — *The Unbearable Lightness of PIN
  Cracking*, Financial Cryptography 2007, LNCS 4886 — ataques pela função
  de tradução
- Boneh, DeMillo e Lipton — *On the Importance of Checking Cryptographic
  Protocols for Faults* (1997) — o ataque Bellcore
- Kocher, P. — *Timing Attacks* (1996) e, com Jaffe e Jun, *Differential
  Power Analysis* (1999)
- Piret e Quisquater — análise diferencial de falhas em AES (2003)
- Schindler, W. — *A Timing Attack against RSA with the Chinese Remainder
  Theorem* (2000), e Walter, C. e Thompson, S. — *Distinguishing Exponent
  Digits by Observing Modular Subtractions* (2001) — a subtração final do
  produto de Montgomery como canal lateral
- Ali, M. A., Arief, B., Emms, M. e van Moorsel, A. — *Does the Online Card
  Payment Landscape Unwittingly Facilitate Fraud?*, IEEE Security & Privacy
  15(2), 2017 — a adivinhação distribuída do CVV2
- Bleichenbacher, D. — falsificação de assinaturas RSA com `e = 3` contra
  verificadores que interpretam o enchimento (2006); registro público:
  CVE-2006-4339

### Aritmética

- Montgomery, P. — *Modular Multiplication Without Trial Division* (1985)
- Koç, Ç., Acar, T. e Kaliski, B. — *Analyzing and Comparing Montgomery
  Multiplication Algorithms* (1996) — de onde vem o FIOS

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
