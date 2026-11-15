# Fase 8: criptografia de pagamento

A teoria — PIN blocks, tradução de PIN, verificação de PIN, DUKPT — está no
manual, Parte VII. Aqui ficam as peças, as decisões, as medidas e o que falta.

## Plano e decisões

Planejada em 2026-11-14, e replanejada no mesmo dia: **o 3DES entra**. O critério
do usuário é aproximar o equipamento, o máximo possível, do mercado de meios de
pagamento.

| Etapa | Entrega | Situação |
|---|---|---|
| 8.1 | PIN block ISO 9564-1 formato 4 e tradução de PIN (`P0`) | pronta, validada na placa |
| 8.2 | Motor DES e 3DES, com autoteste nos vetores do NIST | pronta, validada na placa em 2026-11-15 |
| 8.3 | Chave 3DES no key store: algoritmo `T` no key block, paridade, KCV | pronta, validada na placa em 2026-11-15 |
| 8.4 | PIN block formato 0, tradução entre formatos e entre chaves | a fazer |
| 8.5 | Verificação de PIN: offset com tabela de decimalização, o ataque, e PVV | a fazer |
| 8.6 | CVV: gerar e verificar | a fazer |
| 8.7 | Troca de chaves 3DES: chave de troca 3DES e key block para 3DES | a fazer |
| 8.8 | DUKPT TDES e AES, e a tradução de PIN de terminal para chave de zona | a fazer |
| 8.9 | MAC de mensagem e cifra de dados com 3DES | a fazer |

Candidatos para depois: criptogramas EMV do chip e emissão de PIN.

Decisões do usuário:

- **3DES em todos os papéis em que o mercado o usa**: chaves de trabalho, chaves
  de troca entre instituições e dados. Motor em C. Comprimento duplo e triplo.
- **A LMK continua AES-256.** A LMK em 3DES com variantes é ideia registrada.
- **Uma chave nunca sai embrulhada por outra mais fraca.**
- **Vetores de terceiros valem** onde não há vetor oficial público, fixados por
  hash e marcados como tal.
- **A verificação de PIN usa o método real**, sobre DES.

A primeira versão do plano, da manhã de 2026-11-14, deixava o 3DES para o fim e
fazia a verificação de PIN com AES. Dela ficou a etapa 8.1.

⚠ **Rever o plano e a decisão sobre vetores ao terminar o DUKPT** (etapa 8.8).

## Etapa 8.1: formato 4 e tradução de PIN

✅ **Validada em hardware 2026-11-14.** `hsmhost.py pin-confere` com 100 de 100
voltas: em cada uma, três traduções abertas pelo Python e oito recusas. O
`confere` das chaves simétricas, o `ecdsa-confere` e o `rsa-cavp` seguem
passando. Firmware: 39 172 bytes de código, 1 504 a mais. Sem RTL novo; timing
+0,369 ns, 0 critical warnings.

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/pinblock.c` | a forma do bloco: monta o campo do PAN e confere o campo do PIN. Não vê chave |
| `fw/src/keystore.c` | `keystore_pin_abre()` e `keystore_pin_fecha()`: decifram e cifram o bloco, e guardam o campo do PIN em claro entre uma e outra |
| `fw/src/cmd_ascii.c` | o comando `P0` |
| `host/pinblock.py` | o formato de novo, em Python, com a cifra |
| `host/hsmhost.py` | `pin-traduz` e `pin-confere` |

O layout do formato está no manual, seção 33.4, e no cabeçalho de
`fw/include/pinblock.h`.

### O comando

| Pedido | Resposta | Entrada | Saída | Log |
|---|---|---|---|---|
| `P0` traduzir PIN block | `P1` | bloco da chave de origem · bloco da chave de destino · formato de origem(1) · formato de destino(1) · tamanho do PAN(2) · PAN · PIN block(32) | PIN block(32) | sim |

Erros: `10` key block inválido, `11` a chave não é `P0` ou o modo não permite,
`14` o bloco aberto não é um formato 4 bem formado, `16` formato diferente de
`4` ou PAN inválido, `22` pedido malformado, `91` as duas execuções
discordaram.

A chave de origem precisa de modo `D` ou `B`. A de destino, `E` ou `B`.

### Onde o PIN em claro existe

O slot efêmero guarda uma chave por vez, e a tradução usa duas. O comando abre
o bloco com a primeira, apaga a chave e só então carrega a segunda. Entre as
duas, o campo do PIN fica em `g_pin`, dentro de `keystore.c`:

- nenhum handler o recebe, e ele não passa pela pilha de `cmd_ascii.c`;
- `keystore_pin_fecha()` o apaga ao terminar;
- o despachante chama `keystore_pin_apaga()` no fim de todo comando;
- `keystore_init()` o apaga, e `keystore_prova_zeroizacao()` o varre.

⚠ **`keystore_efemera_apaga()` não apaga `g_pin`.** Ela é chamada quando a
segunda chave entra no slot, e apagaria o PIN no meio da tradução. O campo tem
a sua própria função de apagar.

### Decisões de implementação

- **A conferência do formato não desvia pelo valor.** `pinblock_campo_valido()`
  acumula as diferenças por máscara e decide no fim.
- **Os 8 bytes aleatórios são sorteados de novo** do DRBG no fechamento.
- **Dupla execução nas duas pontas**, com a chave carregada antes de cada
  passada, como na fase 6.
- **O uso é `P0` exato**, e não a família `P`. O `keystore_usa_aes()` já
  recusava chave de PIN para cifrar dados.
- **PAN de 1 a 19 dígitos.** Com menos de 12, o campo recebe zeros à esquerda.
- **Não há KAT do formato no POST.** Não existe vetor com AES-256, e a cifra do
  bloco é o AES que o POST já cobre.

### Vetores

`vectors/pinblock/iso9564_f4.rsp`: três valores do arquivo de testes de uma
biblioteca aberta, fixados por commit e por hash (`vectors/MANIFEST.txt`).

⚠ **É fonte secundária, e não cobre o firmware.** A ISO 9564-1 é paga. Uma
segunda biblioteca aberta traz o mesmo bloco cifrado, com os mesmos dados de
entrada, e por isso não conta como fonte independente. A chave do bloco cifrado
é AES-128, que o coprocessador não faz. A cadeia de confiança é:

1. o valor de terceiros valida `host/pinblock.py`;
2. `host/test_pinblock.py` compila `fw/src/pinblock.c` e o compara com o Python
   na forma dos dois campos;
3. o `tb_pin` e a placa conferem a cifra do firmware contra o Python.

### Testes

| Teste | O que prova | Tempo |
|---|---|---|
| `host/test_pinblock.py` | **no PC**: os três valores de terceiros; ida e volta com AES-256 para todo tamanho de PIN e de PAN; PAN ou chave trocados reprovam no formato; campos malformados; o C do firmware concorda com o Python na forma dos campos | 2 s |
| `tb_pin` | o `P0` pela UART, com o firmware real: recusado antes da cerimônia (`20`); um bloco feito pelo Python é traduzido, e o `C2` com a chave de destino embrulhada como chave de dados abre o resultado e mostra o mesmo campo do PIN, com os bytes aleatórios trocados; o mesmo pedido dá outro bloco; bloco, PAN e chave trocados (`14`); chave que não é `P0` (`11`); formato desconhecido (`16`); key block adulterado (`10`); pedido curto (`22`) | 1 h 22 |

⚠ **O `tb_pin` abre o bloco traduzido com um truque que só a LMK permite**: a
chave de destino embrulhada uma segunda vez, como chave de dados. Dois `C2` de
um bloco, com IV zero, refazem a decifração do formato 4. Quem tem a LMK faz
qualquer bloco; é por isso que ela é a raiz de tudo.

`hsmhost.py pin-confere --lmk LMK [-n N]` repete a prova na placa: o Python
faz o papel do terminal e o do destino.

## Etapas 8.2 e 8.3: motor 3DES e chave 3DES

As duas etapas andam juntas: o motor sozinho não tem comando que o exercite. O
primeiro uso dele é o KCV de uma chave 3DES.

A teoria está no manual, seção 38. O que o equipamento faz com uma chave 3DES
está na seção 38.8.

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/des.c` | DES e 3DES em C: permutações, caixas S, escalonamento, EDE, CBC, paridade e a lista de chaves fracas |
| `fw/src/kat.c` | `kat_tdes()`, autoteste de primeiro uso, bit `0x800` da máscara |
| `fw/src/keystore.c` | algoritmo `T` no slot efêmero, KCV em 3DES, e a recusa de chave 3DES nas funções que carregam o coprocessador |
| `fw/src/tr31.c`, `host/tr31.py` | algoritmo `T` no key block, com 16 ou 24 bytes |
| `fw/src/cmd_ascii.c` | `K0` com o campo opcional `A4`/`T2`/`T3`; autoteste antes de abrir um bloco 3DES |
| `host/des.py` | o DES e o 3DES de novo, em Python |
| `host/hsmhost.py` | `gen --alg`, `tdes-confere` |

### Decisões de implementação

- **Motor em C, com uma rotina só de permutação de bits.** É pequeno (2,9 KB)
  e lento, e isso basta: o 3DES aqui cifra blocos de 8 bytes.
- **As tabelas são as da FIPS 46-3.** Os 19 KATs de substituição da SP 800-20
  exercitam cada entrada das caixas S, e por isso entram todos no autoteste.
- **Autoteste no primeiro uso**, pela decisão de 2026-11-13 para os KATs
  caros: no boot, ele custaria tempo de simulação a todos os testbenches.
- **Chave 3DES só no slot efêmero.** Os slots do console e o registro na flash
  seguem só com AES-256, até a etapa 8.7.
- **A checagem de algoritmo mora em `uso_dados()`, `uso_mac()` e `uso_pin()`.**
  O coprocessador lê 32 bytes de chave; uma chave 3DES de 16 bytes ali seria
  lida além do fim. Cada etapa que estender uma função ao 3DES mexe na função
  de uso correspondente.
- **Um contexto 3DES para o firmware inteiro** (`tdes_ctx_comum()`): são 288
  bytes de subchaves, e a memória de dados é curta.
- **Paridade não é exigida na importação.** O MAC do key block já garante que a
  chave é a que foi embrulhada. A geração sempre acerta a paridade.
- **Chaves fracas e partes iguais são recusadas na geração**, com novo sorteio.
  A lista das 16 chaves foi conferida por programa: cifrar duas vezes com uma
  fraca devolve o texto, e cada semifraca desfaz a sua par.

### Vetores

`vectors/tdes/`: os KATs da SP 800-20 e os MMT do CAVP, nos modos ECB e CBC,
1000 vetores. São oficiais. O Python e o C do firmware passam em todos, no PC.

### Medidas

| Medida | Valor |
|---|---|
| `des.c` | 2 940 bytes de código, e 288 de dados para o contexto |
| Firmware | 43 656 bytes de código (67% da IMEM de 64 KB) |
| Dados | 14 276 bytes; sobravam 2 108 para a pilha, com a DMEM de 16 KB |

⚠ **A memória de dados é a margem mais curta do projeto.** O caminho mais fundo
da pilha usa cerca de 1,1 KB. Buffer novo vai para `static`, com conta. Foi o
que levou a DMEM a 32 KB, com o PKCS#8 (ver adiante).

### Testes

| Teste | O que prova | Tempo |
|---|---|---|
| `host/test_des.py` | **no PC**: os 1000 vetores do NIST no Python; acordo com a biblioteca `cryptography`; paridade e KCV | 3 s |
| `host/test_tr31.py` | chave 3DES de 16 e de 24 bytes em ida e volta; 8 e 32 bytes recusados | |
| `tb_tdes` | pela UART, com o firmware real: o KCV de uma chave tripla e de uma dupla feitas pelo Python (é o 3DES do firmware contra o do Python, e roda o autoteste de primeiro uso); `K0` com `T2` e `T3`, com o bloco de volta ao `K2`; `T1` (`16`); campo pela metade (`22`); `C0` com chave 3DES (`11`) | 1 h 08 |

`hsmhost.py tdes-confere --lmk LMK [-n N]` é a prova na placa: tamanho,
paridade, KCV, exportação sob KEK AES e as recusas.

✅ **Validado na placa em 2026-11-15**: `tdes-confere` com 10 voltas, dentro da
regressão.

## PKCS#8 no key block

Decisão do usuário em 2026-11-14: o conteúdo do key block de uma chave RSA ou de
ECDSA deixa de ser um layout deste projeto e passa a ser **PKCS#8** (RFC 5958), em
DER. O motivo é a interoperabilidade: aberto o bloco, a chave é legível pelo
`openssl` e por qualquer biblioteca. A teoria está no manual, seção 30.

Estado: pronto. Suíte completa e placa em 2026-11-15.

⚠ **Não é alegação de conformidade com a X9.143.** A norma é paga, e este projeto
não confirmou qual codificação ela manda usar para chave assimétrica. As
implementações abertas de key block que examinei aceitam os algoritmos `R` e `E`
no cabeçalho e tratam o conteúdo como bytes opacos.

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/pkcs8.c` | um escritor e um leitor de DER do tamanho exato do que precisa; monta e lê a chave RSA-2048 (RFC 8017, A.1.2) e a P-256 (RFC 5915). Só bytes: não usa o coprocessador, e por isso roda também no PC |
| `fw/src/keystore.c` | `g_der`, a área do PKCS#8 entre o bloco e o formato interno; `assim_abre()` lê, `keystore_rsa_gera()` e `keystore_ec_gera()` montam |
| `host/pkcs8.py` | o mesmo, com a biblioteca `cryptography` |
| `host/hsmhost.py` | `pkcs8-confere` |

### Decisões de implementação

- **O formato interno não mudou.** `rsa.c` e `ecc.c` seguem com `e p q dp dq qinv`
  (644 bytes) e `d Qx Qy` (96). O PKCS#8 existe só na borda, dentro do key store.
- **O leitor é estrito.** Só DER: comprimento definido e na forma mais curta,
  inteiro sem zero sobrando, nenhum byte depois do fim. Só a versão 0, sem
  atributos. Só RSA de dois primos, com módulo de 2048 bits e primos de 1024. Só a
  curva P-256. O que o MAC do bloco deixou passar e o leitor recusa responde `10`.
- **`n` e `d` do bloco recebido são lidos e descartados.** O equipamento recalcula
  `n = p · q` e verifica toda assinatura com `e` antes de entregá-la; uma chave
  inconsistente não assina.
- **Ao gerar, o firmware calcula `d`**, que o PKCS#8 exige: `d = e⁻¹ mod (p−1)(q−1)`,
  com contas de número pequeno, porque `e` é pequeno. Antes de montar o bloco, ele
  confere que `n` é o produto dos dois primos.
- **A chave pública da curva é opcional na entrada**, como no formato. Sem ela, o
  equipamento calcula `Q = d · G`. Na saída, ela sempre vai.
- **O `d` do firmware e o de outras bibliotecas podem diferir.** As duas formas
  valem: módulo `(p−1)(q−1)` ou módulo o mínimo múltiplo comum. A assinatura é a
  mesma.

### O que cresceu

| Item | Antes | Agora |
|---|---|---|
| Key block de chave RSA | 1360 caracteres | até 2512 (o DER tem tamanho variável) |
| Key block de chave ECDSA | 272 caracteres | 336 |
| Limite de mensagem | 2048 bytes | 3072 bytes |
| Memória de dados (DMEM) | 16 KB | 32 KB |
| Firmware | 43 656 bytes | 46 944 bytes (72% da IMEM) |

A DMEM de 32 KB é mudança de RTL: pediu novo fechamento de timing e a suíte
completa. Timing **+0,572 ns**, 0 critical warnings, 8081 LUTs, 7914 FF, BRAM 25,5,
DSP 4 (`doc/timing_fase8.txt`, `doc/utilization_fase8.txt`). Os dados ocupam 19 148
dos 32 768 bytes.

⚠ **Key blocks de RSA e de ECDSA feitos antes desta mudança deixam de abrir.**

⚠ **`wipe()` passou a escrever uma palavra por vez.** Com três buffers de 3072
bytes para apagar depois de cada resposta, o laço de bytes levaria mais de 1 ms, e
nesse tempo o firmware não olha os botões. Os testbenches soltam e apertam os
botões em 1 ms.

### Testes

| Teste | O que prova | Tempo |
|---|---|---|
| `host/test_pkcs8.py` | **no PC**: o `pkcs8.c` do firmware contra a biblioteca `cryptography`. O que um monta, o outro abre, nos dois sentidos; o DER do firmware é igual ao da biblioteca, byte a byte; 75 alterações de um byte na estrutura, DER truncado, lixo no fim, outra curva e outros tamanhos são recusados; `n` que não é `p · q` não vira bloco | 40 s |
| `tb_rsa`, `tb_ecdsa` | os mesmos testes da fase 7, com as chaves do CAVP em PKCS#8, codificadas pelo Python | 4 h 19 e 9 h 15 |

`hsmhost.py pkcs8-confere --lmk LMK` é a prova na placa, nos dois sentidos: o
equipamento gera, a biblioteca assina e o equipamento verifica; a biblioteca gera,
o equipamento assina e a biblioteca verifica.

✅ **Validado na placa em 2026-11-15**: `pkcs8-confere` com 3 voltas, dentro da
regressão. O bloco maior custou tempo de simulação: o `tb_rsa` foi de 3 h 27 a
4 h 19, e o `tb_ecdsa`, de 8 h 46 a 9 h 15.

## Versão e identificação do firmware

Pedido do usuário em 2026-11-14: poder saber qual sistema está gravado na placa.
Até então o equipamento respondia `v0.1.0`, um número fixo desde a Fase 1.

Estado: pronto. Na placa em 2026-11-15, `hsmtool build` respondeu `v0.8.3` e o hash
`ec881b59…2707905`, igual ao de `fw/elf.bin`.

- **`fw/include/versao.h`** é o único lugar do número. `MINOR` é a fase e `PATCH`
  é a etapa entregue. O `GET_VERSION`, o `GET_BUILD` e o `D0` leem dali. A versão
  atual é a `0.8.3`.
- **Comando novo no console, `0x04 GET_BUILD`:** devolve a versão e o SHA-256 dos
  64 KB da memória de código, calculado na hora pelo coprocessador. Responde em
  todo estado normal, sem dual control e fora do log, como os outros informativos.
  Não vaza nada: o firmware não é segredo.
- **`hsmtool build`** mostra os dois e compara o hash com o de `fw/elf.bin`.
- **`scripts/mkfwhash.py`** calcula o mesmo hash no PC. O `sim.sh` o chama depois
  de compilar o firmware, e o `tb_uart_frame` cobra que o `GET_BUILD` devolva esse
  valor.
- **O `regressao.py` começa por aí:** se o firmware da placa não é o que está
  compilado no PC, o resto da regressão testaria outra coisa.

Decisões:

- **Hash, e não número de commit.** O firmware é compilado e testado antes do
  commit; o número gravado seria sempre o do commit anterior.
- **Sem data de compilação dentro do firmware.** Ela mudaria o hash a cada dia sem
  mudança de código, e a comparação com o arquivo deixaria de valer. O `hsmtool`
  mostra a data do arquivo local que confere.
- **É diagnóstico, e não teste de integridade.** Quem compara é o host. O teste de
  integridade de firmware da FIPS 140-3, no boot e contra referência autenticada,
  não está feito.
- **O bitstream não é identificado à parte.** O firmware está dentro dele, então o
  hash distingue uma gravação da outra, salvo mudança só de RTL.

## Regressão na placa

Desde 2026-11-14, uma mudança só de firmware não espera a suíte completa. Ela
passa pelo testbench novo e pelos que cobrem o código alterado, e a regressão
do resto roda na placa, com `host/regressao.py`: 17 passos em 219 s (medido em 2026-11-15, com o 3DES, o
PKCS#8 e a conferência do firmware). A suíte
completa roda quando o RTL muda e no fim da fase. A tabela está no `CLAUDE.md`.

A suíte completa de 2026-11-15 tem 28 testbenches e levou 11 h 46, com 3 por vez.
O `tb_ecdsa` é o mais lento (9 h 15), seguido do `tb_rsa` (4 h 19) e do `tb_tamper`
(3 h 53).

O script acusa falha: com uma LMK errada, os quatro passos que dependem dela
reprovam, e os demais passam.
