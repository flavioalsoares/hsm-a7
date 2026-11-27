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
| 8.4 | PIN block formato 0, tradução entre formatos e entre chaves | pronta, validada na placa em 2026-11-15 |
| 8.5 | Verificação de PIN: offset com tabela de decimalização, o ataque, e PVV | validada na placa em 2026-11-15 |
| 8.6 | CVV: gerar e verificar | validada na placa em 2026-11-21 |
| 8.7 | Troca de chaves 3DES: chave de troca 3DES e key block para 3DES | validada na placa em 2026-11-22 |
| 8.8 | DUKPT TDES e AES, e a tradução de PIN de terminal para chave de zona | validada na placa em 2026-11-23 |
| 8.9 | MAC de mensagem e cifra de dados com 3DES | a fazer |
| 8.10 | ARQC: gerar e verificar o criptograma EMV, e o ARPC | a fazer |

Candidato para depois: emissão de PIN.

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

A teoria está no manual, seção 39. O que o equipamento faz com uma chave 3DES
está na seção 39.8.

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
  seguem só com AES-256, até a etapa 8.7. *A etapa 8.7 tirou essa restrição:
  ver abaixo.*
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

## Etapa 8.4: formato 0 e tradução entre formatos

Estado: pronto. Na placa em 2026-11-15: `hsmtool build` respondeu `v0.8.4` e CONFERE; `regressao.py` passou nos 17 passos em 232 s, com 50 voltas do `pin-confere` em 64,5 s. Firmware de 47 916 bytes (73% da IMEM). Timing +0,572 ns, 0 critical warnings.

O `P0` passa a aceitar o formato 0 da ISO 9564-1, com chave de PIN 3DES, e a
traduzir entre o formato 0 e o formato 4, nos dois sentidos. A teoria está no
manual: seção 33.1 (o formato, com exemplo numérico), 34.2 (a tradução entre
formatos e o que a norma restringe) e 34.3 (o que o erro `14` revela).

### As peças

| Arquivo | O que mudou |
|---|---|
| `fw/src/pinblock.c` | `pinblock_campo_pan0()`; `pinblock_f0_para_f4()`, que confere um campo formato 0 e o converte; `pinblock_f4_para_f0()`, o caminho de volta. A conferência dos dois formatos é uma função só, com o controle e o enchimento como parâmetros |
| `fw/src/keystore.c` | `keystore_pin_abre()` e `keystore_pin_fecha()` ganham o parâmetro `formato`. `pin_passada0()` é a cifra do formato 0, com o 3DES de `des.c`. `uso_pin()` passa a exigir o algoritmo do formato |
| `fw/src/cmd_ascii.c` | o `P0` lê os dois formatos, monta o campo do PAN de cada lado e aceita PIN block de 16 ou de 32 caracteres |
| `host/pinblock.py` | o formato 0 em Python: `cifra0()`, `decifra0()` e os campos |
| `host/hsmhost.py` | `pin-traduz --formatos`, e o `pin-confere` com os dois formatos |

### Decisões de implementação

- **Dentro do key store o PIN tem uma forma só**, a do campo do formato 4.
  Abrir um bloco formato 0 converte para ela; fechar em formato 0 converte de
  volta. `g_pin` não mudou de tamanho nem de regra: continua sendo o único lugar
  do PIN em claro.
- **A conversão não desvia pelo valor do PIN.** O tamanho decide, por máscara, o
  que é dígito e o que é enchimento, como na conferência.
- **O algoritmo da chave é conferido com o formato**, em `uso_pin()`: AES para o
  4, 3DES para o 0. A recusa é `11`, a mesma de uma chave que não é de PIN.
- **As subchaves do 3DES são derivadas a cada execução** e apagadas na saída.
  É o equivalente, no motor em C, de carregar a chave de novo no coprocessador
  antes de cada uma das duas contas (fase 6).
- **Um PAN por pedido**, para a origem e para o destino. Um segundo PAN faria do
  comando uma forma de amarrar o PIN de uma conta a outra.
- **PAN de 13 a 19 dígitos no formato 0.** A norma define enchimento com zeros
  para PAN mais curto; a implementação de referência dos valores conhecidos
  recusa, e o equipamento também. Cartão de pagamento tem 13 dígitos ou mais.
- **Formatos 1 e 3 ficaram fora.** O 1 não leva o PAN, e a tradução para ele é a
  que a norma restringe. O 3 é o 0 com enchimento aleatório.

### O checklist do `P0`, refeito

O `CLAUDE.md` pedia para refazer o item de vazamento quando entrasse outro
formato. Os outros itens não mudaram: `OPERATIONAL`, sem dual control, nenhuma
chave sai, log antes.

**Vazamento.** Com o formato 0, o erro `14` revela parte do PIN a quem pode
informar um PAN alterado. Medido por `host/test_pinblock.py`, com 108 pedidos
por bloco:

| O que sai | Quanto |
|---|---|
| O tamanho do PIN | sempre |
| Cada dígito, do terceiro em diante | de 10 candidatos sobram 3,92 em média; 2 quando o dígito do PAN na mesma posição é 8 ou 9 |
| Os dois primeiros dígitos | nada |
| O último bit de cada dígito | nada |

Não há conserto dentro do formato, e o equipamento não tenta um: fundir o `14`
com outro código não muda o que o atacante vê, que é sucesso ou recusa. O
controle é o log, que registra cada pedido recusado, e o acesso à porta host. É
o que a categoria faz. O handler tem a conta escrita no comentário.

Outro ponto, que não é vazamento do comando e sim do formato: o formato 0 não
tem aleatório. Quem vê dois PIN blocks iguais sob a mesma chave e o mesmo PAN
sabe que o PIN é o mesmo.

### Vetores

Onze valores do formato 0, do mesmo arquivo de terceiros do formato 4 (mesmo
commit e mesmo hash no `MANIFEST.txt`), extraídos sem cálculo por
`scripts/_extrai_pinblock.py` para `vectors/pinblock/iso9564_f0.rsp`. São blocos
**em claro**: seis bem formados e cinco malformados. A cifra é um bloco de 3DES,
coberta pelos vetores do NIST.

### Medidas

| Medida | Valor |
|---|---|
| Firmware | 47 916 bytes de código, 972 a mais |
| RTL | sem mudança |

### Testes

| Teste | O que prova | Tempo |
|---|---|---|
| `host/test_pinblock.py` | **no PC**: os onze valores de terceiros; ida e volta com 3DES duplo e triplo, para todo tamanho de PIN e de PAN; o dígito verificador não entra; o C do firmware contra o Python no campo do PAN, na conferência e nas duas conversões; a medida do vazamento | 3 s |
| `tb_pin0` | pela UART, com o firmware real. Formato 0 para 0, de 3DES dupla para tripla, e formato 4 para 0: o bloco de saída é igual, byte a byte, ao que o Python calculou. Formato 0 para 4: o `C2` abre o bloco e o campo do PIN confere. Dígito verificador trocado: mesmo bloco. Bloco adulterado e PAN trocado (`14`); algoritmo da chave diferente do formato, nos quatro casos (`11`); PAN de 12 dígitos e formato `1` (`16`) | 2 h 21, 730 ms simulados |
| `tb_pin` | os passos da etapa 8.1, com o código novo | 1 h 27 |
| `tb_tdes` | sem mudança; roda de novo porque o código vizinho mudou | 1 h 08 |

`hsmhost.py pin-confere --lmk LMK [-n N]` é a prova na placa. A cada volta,
além dos passos do formato 4: tradução `00` com o bloco de saída previsto pelo
Python, `04` aberta pelo Python, `40` de volta ao bloco original, e doze recusas.

## Etapa 8.5: verificação de PIN, offset e PVV

Estado: pronto. Na placa em 2026-11-15: `hsmtool build` respondeu `v0.8.5` e CONFERE; `regressao.py` passou nos 18 passos em 311 s, com o `pinv-confere` em 46,5 s. Firmware de 51 336 bytes (78% da IMEM). Timing +0,572 ns, 0 critical warnings. `TABELA_AUTORIZA` com os botões de verdade na mesma data: ver "Na bancada, com os botões".

Quatro comandos na porta host (`V0` gerar offset, `V2` verificar offset, `V4`
gerar PVV, `V6` verificar PVV) e um no console (`0x80 TABELA_AUTORIZA`). A
teoria está no manual: seção 35 (os dois métodos, com exemplo numérico, o
ataque de decimalização e a defesa) e 42.3 (os testes e a matemática deles).

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/pinverif.c` | as contas sem chave: decimalização, soma e subtração do offset, montagem do bloco de entrada do PVV e extração do PVV. Tudo por máscara, sem desvio pelo valor |
| `fw/src/keystore.c` | `keystore_pin_offset()` e `keystore_pin_pvv()`, sobre o PIN que `keystore_pin_abre()` deixou em `g_pin`; `keystore_tabela_autoriza()` e `keystore_tabela_confere()`, o MAC da tabela sob chave derivada da LMK |
| `fw/src/cmd_ascii.c` | os handlers `V0`, `V2`, `V4` e `V6`, e o erro `17` |
| `fw/src/cmd.c` | o handler do `TABELA_AUTORIZA`, com dual control |
| `host/pinverif.py` | os dois métodos e o MAC da tabela, em Python |
| `host/hsmtool.py` | `tabela-autoriza` |
| `host/hsmhost.py` | os quatro comandos, e o `pinv-confere` |

### Decisões

- **A tabela de decimalização só vale autorizada** (decisão do usuário,
  2026-11-15). O console devolve a tabela com um MAC, com dual control, e a
  porta host recusa tabela sem MAC válido (`17`). A primeira proposta era
  conferir a forma da tabela. O relatório de Bond e Zieliński (2003), seção 6,
  diz que essa conferência barra as duas primeiras variantes do ataque e não
  barra a terceira, que usa a tabela legítima com uma entrada alterada. A
  proteção completa, segundo o relatório, é a tabela protegida por criptografia.
- **A tabela autorizada vale para UMA chave de verificação** (decisão do usuário,
  2026-11-15, depois da revisão de código). O MAC cobre a tabela e o KCV da
  chave `V1`, e o `V0`/`V2` o conferem contra o KCV da chave que abriram. Sem o
  KCV, duas tabelas autorizadas sob a mesma LMK se combinariam na variante 3 do
  ataque, e uma tabela autorizada não teria como ser revogada sem trocar a LMK.
  Revogar uma tabela passa a ser trocar a chave de verificação.
- **O equipamento não julga a tabela, nem lembra o que autorizou.** Ele exige 16
  dígitos decimais e os dois botões. Duas tabelas diferentes autorizadas para a
  mesma chave reabrem a variante 3 para ela: isso fica com os custodiantes.
- **A chave do MAC é derivada da LMK com rótulo próprio** (`HSM-A7 DECTAB`),
  pela SP 800-108 em modo contador com CMAC, que é a construção do key block. O
  MAC são os 8 primeiros bytes do CMAC da tabela seguida do KCV. Trocar a LMK
  invalida as tabelas autorizadas.
- **O PIN chega sempre em PIN block.** Não há comando que receba PIN em claro.
  Cada pedido leva dois key blocks, o da chave de PIN e o da chave de
  verificação, que passam um por vez pelo slot efêmero.
- **Usos `V1` (offset) e `V2` (PVV), só 3DES.** São os códigos da X9.143 para os
  dois métodos. O modo é do grupo de MAC: `G` gera, `V` verifica, `C` os dois.
  Uma chave `V1` não calcula PVV, e o contrário.
- **O offset tem o tamanho do PIN**, de 4 a 12 dígitos. No `V2`, offset de
  tamanho diferente do PIN responde `01`, o mesmo código do PIN errado.
- **O PVV usa os 4 primeiros dígitos do PIN** e os 11 dígitos do PAN antes do
  verificador. PAN com menos de 12 dígitos: `16`.
- **Os dados de validação vêm do host**, em 16 dígitos hexadecimais. A regra
  de montagem a partir do PAN é do emissor.
- **Cada veredito é calculado duas vezes**, como o do `M2` (fase 6): a
  conferência do MAC da tabela, com a chave do MAC derivada de novo; a cifra,
  com as subchaves derivadas de novo; e a comparação final do `V2` e do `V6`,
  uma a partir de cada cifra. O offset e o PVV gerados também saem de duas
  contas. Discordou: `91`, nada sai, erro grave marcado. A primeira versão
  dobrava só a cifra; a revisão de código apontou que uma falha na comparação
  única viraria um `01` em `00`, ou deixaria passar uma tabela não autorizada.
- **A abertura do PIN block mora numa função só**, `abre_pin()` em
  `cmd_ascii.c`, usada pelo `P0` e pelos `V*`. Ela é o único lugar que liga o
  resultado de `keystore_pin_abre()` a um código ASCII: o `14` é o oráculo de
  formato, e o mesmo PIN block tem de dar a mesma resposta nos dois comandos.
- **O opcode do console é `0x80`.** A faixa `0x20` a `0x2F` está cheia, e a
  faixa `0x30` a `0x7E` é do protocolo ASCII.

### O checklist

| Item | `V0` a `V6` | `TABELA_AUTORIZA` |
|---|---|---|
| Estados | `OPERATIONAL` | `OPERATIONAL` |
| Dual control | não: é operação | sim, com aperto novo |
| Exportabilidade | não se aplica: nenhuma chave sai | não se aplica |
| Log | antes; o `01` fica registrado | antes |

**Vazamento.**

- `V2` e `V6` devolvem um bit. Com um PIN block na mão, quem escolhe o offset
  acha o certo em até 10ⁿ pedidos. É a busca que o método admite; o controle é
  o contador de tentativas do emissor e o log.
- O atalho era a tabela: 15 pedidos em média, pelo relatório. Com a tabela
  autorizada, ele depende de os custodiantes assinarem uma tabela ruim.
- `V0` e `V4` são funções de emissão. Quem as chama com um PIN block de PIN
  conhecido aprende o PIN natural. O controle é o modo da chave: com modo `V`
  elas respondem `11`.
- O `14` é o oráculo de formato do `P0`, com o mesmo custo no formato 0.
- O tamanho do PIN sai no `V0`. É do método.
- O `TABELA_AUTORIZA` entrega um MAC de 64 bits por par (tabela, chave `V1`), e
  só com os botões. O KCV já é público.

### Vetores

24 valores de terceiros, do arquivo de testes da mesma biblioteca aberta dos
PIN blocks, no mesmo commit, com hash no `MANIFEST.txt`:
`vectors/pinverif/psec_pin.rsp`. O `MANIFEST.txt` diz o que eles cobrem e o que
não cobrem. O PAN deles é um padrão de teste do arquivo de origem.

### Medidas

| Medida | Valor |
|---|---|
| Firmware | 51 336 bytes de código, 3 420 a mais (78% da IMEM) |
| RTL | sem mudança |

### Testes

| Teste | O que prova | Tempo |
|---|---|---|
| `host/test_pinverif.py` | **no PC**: os 24 valores de terceiros; o C do firmware contra o Python na decimalização, nos 100 pares de dígitos do offset, no bloco de entrada do PVV e na extração, com 5 100 blocos construídos para toda quantidade de decimais; ida e volta com chave dupla e tripla; o MAC da tabela | 2 s |
| `tb_pinv` | pela UART, com o firmware real. `TABELA_AUTORIZA` sem botões (recusa), com letra na tabela e sem o KCV (recusa sem gastar o aperto) e com botões: o MAC é o do Python, feito com a LMK e o KCV. `V0`: offset igual ao do Python. `V2`: certo, um dígito trocado e tamanho errado. Tabela alterada, MAC alterado e MAC da mesma tabela feito para outra chave (`17`). `V4` igual ao do Python; `V6` certo e errado. Chave só de verificar no `V0`, chave do offset no `V4` (`11`); PIN block adulterado (`14`). `V6` com PIN block formato 4 | 3 h 21 |
| `tb_pin0` | os passos da etapa 8.4; o `P0` passou a abrir o PIN pela função comum | 2 h 26 |
| `tb_pin` | os passos da etapa 8.1, pelo mesmo motivo | 1 h 27 |
| `tb_keystore` | o console, com o comando novo na tabela (rodada anterior, sem mudança no console desde então) | 1 h 47 |

`hsmhost.py pinv-confere --lmk LMK [-n N]` é a prova na placa. A cada volta:
os quatro comandos conferidos com o Python, nos formatos 0 e 4, com três
tabelas; a tabela autorizada para outra chave `V1`, recusada (`17`), e aceita
com a chave dela; cada dígito do offset e do PVV trocado; e as recusas `17`, `11` e `14`.
Com `--tabela BLOCO --kcv KCV`, confere também um bloco que o console devolveu.

### Na bancada, com os botões

A `regressao.py` não aperta os botões. Por isso o `TABELA_AUTORIZA` foi provado na
placa à parte, em 2026-11-15, num terminal com TTY, com o operador nos botões:

| Passo | Comando | Resultado |
|---|---|---|
| 1 | `hsmhost.py --serial gen --uso V1 --modo C --alg T2` | key block da chave de verificação, KCV `45A280` |
| 2 | `hsmtool.py tabela-autoriza 0123456789012345 45A280`, com os dois botões | `0123456789012345604928C6D4E27F0B` |
| 3 | `hsmhost.py --serial pinv-confere --lmk LMK --tabela 0123456789012345604928C6D4E27F0B --kcv 45A280` | "o MAC confere com o Python"; 10 de 10 voltas |

O passo 3 prova que a placa e o Python derivam da LMK a mesma chave de MAC e
amarram a tabela ao mesmo KCV. Até então o comando só tinha passado na simulação,
com botões simulados.

O bloco do passo 2 vale só com a chave `V1` de KCV `45A280`. Com outra chave
`V1`, os `V0`/`V2` o recusam (`17`).

⚠ **O `--lmk` não vai para a placa.** O `pinv-confere` usa a LMK no PC, como
conferente independente: abre os key blocks e refaz as contas em Python. Antes
de começar, ele compara o KCV da LMK informada com o do `D0` e para se não
conferem. Sem a LMK, ninguém faz essa conferência. Em produção ela não existe,
porque ninguém tem a LMK inteira: aqui ela é de desenvolvimento.

## Etapa 8.6: CVV, CVV2 e iCVV

Estado: pronto. Na placa em 2026-11-21: `hsmtool build` respondeu `v0.8.6` e CONFERE; `regressao.py` passou nos 19 passos em 353 s, com o `cvv-confere` em 16,5 s. Firmware de 52 772 bytes (81% da IMEM). Timing +0,572 ns, 0 critical warnings.

Dois comandos na porta host: `W0` (gerar o código) e `W2` (verificar). O
código de serviço escolhe qual dos três: o da tarja para o CVV, `000` para o
CVV2, `999` para o iCVV. A teoria está no manual: seção 36 (o método, com
exemplo numérico nos três códigos, a ligação com o retail MAC, a busca de
1 000 valores e o ataque de adivinhação distribuída) e 42.4 (os testes e a
matemática deles).

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/cvv.c` | as contas sem chave: montagem dos 16 bytes de entrada e extração dos 3 dígitos, por máscara |
| `fw/src/keystore.c` | `keystore_cvv()`: a cifra (DES sob `A`, XOR, 3DES sob `A` e `B`), feita duas vezes, e o veredito duplo |
| `fw/src/cmd_ascii.c` | os handlers `W0` e `W2` |
| `host/cvv.py` | o método em Python |
| `host/hsmhost.py` | os dois comandos, e o `cvv-confere` |
| `scripts/_extrai_cvv.py` | copia os 7 valores das três fontes para `vectors/cvv/cvv.rsp` |

### Decisões

- **Os vetores vêm de três fontes** (decisão do usuário, 2026-11-21). A
  primeira busca achou só 2 valores, na mesma biblioteca da 8.5. O usuário
  pediu uma busca mais funda antes de começar, e ela achou mais 5, em duas
  bibliotecas independentes. Os 7 concordam com o mesmo algoritmo.
- **Uso `C0`, 3DES de comprimento duplo.** É o código da X9.143 para a chave
  de verificação de cartão, e o par "CVK A, CVK B" do mercado. O método usa a
  metade `A` sozinha; chave tripla responde `11`.
- **Um par de comandos para os três códigos.** O método é o mesmo, e o
  código de serviço entra na conta. Os comandos são do projeto: `W0`/`W2`,
  letra que nenhum outro comando usa.
- **O DES de `A` sai do motor de 3DES com a chave `A ‖ A`.** Com `K1 = K2`, o
  segundo passo desfaz o primeiro, e sobra o DES de `A`. O firmware tem um
  contexto de 3DES só (`tdes_ctx_comum()`); as subchaves são preparadas duas
  vezes por conta.
- **As contas sem chave ficam em `cvv.c`, e não em `pinverif.c`.** A extração
  é a do PVV com 3 dígitos em vez de 4, mas generalizar a função do PVV
  mudaria código validado e pediria de novo o `tb_pinv` (3 h 21). São 20
  linhas repetidas, com comentário apontando a origem.
- **A validade vai como o emissor a usa** (`AAMM` ou `MMAA`). O equipamento não
  a interpreta.
- **O PAN tem de 12 a 19 dígitos.** 19 + 4 + 3 = 26 dígitos, que cabem nos 32
  dos dois blocos.
- **Cada veredito é calculado duas vezes**, como no `V2` e no `V6`: a cifra,
  com as subchaves preparadas de novo, e a comparação final, uma a partir de
  cada cifra. O código gerado também sai de duas contas.
- **A cópia local do código é apagada** no fim do handler: o CVV2 é dado
  sensível de autenticação, e o PCI DSS proíbe guardá-lo.

### O checklist

| Item | `W0` e `W2` |
|---|---|
| Estados | `OPERATIONAL` |
| Dual control | não: é operação |
| Exportabilidade | não se aplica: nenhuma chave sai |
| Log | antes; o `01` fica registrado |

**Vazamento.**

- `W2` devolve um bit. Quem tem o bloco da chave acha o código de um cartão em
  até 1 000 pedidos. Não há conserto dentro do método; o controle é o
  contador de tentativas do emissor e o log.
- `W0` é função de emissão: dá o CVV2 de qualquer cartão de que se tenha o
  número e a validade. O controle é o modo da chave: com modo `V`, `W0`
  responde `11`.
- O código de serviço é escolha do chamador. Com uma chave `C`, `W0` com
  `000` dá o CVV2 de um cartão de que se tenha só a tarja. Por isso o emissor
  separa a chave de emitir (`G`) da de autorizar (`V`).
- Uma chave de outro uso não calcula CVV (`11`), e a CVK não serve a outro
  comando: os outros comandos conferem o uso deles.

### Vetores

7 valores de terceiros, de três fontes, em `vectors/cvv/cvv.rsp`. Os cinco
arquivos de origem estão fixados por commit e por hash no `MANIFEST.txt`, que
diz o que os valores cobrem e o que não cobrem. Os PANs deles são padrões de
teste publicados; os testes deste projeto usam o prefixo `999999`.

O testbench leva as chaves das fontes para dentro de key blocks, e exige do
firmware o código publicado. Abrir um bloco 3DES não confere paridade nem
chave fraca, e por isso a chave `A = B` do `jmeter-iso8583` entra sem ajuste.

### Medidas

| Medida | Valor |
|---|---|
| Firmware | 52 772 bytes de código, 1 436 a mais (81% da IMEM) |
| RTL | sem mudança |

### Testes

| Teste | O que prova | Tempo |
|---|---|---|
| `host/test_cvv.py` | **no PC**: os 7 valores de terceiros, e o KCV das chaves do jPOS; recusas de forma; o C do firmware contra o Python na montagem da entrada (PAN de 12 a 19) e na extração, com 5 100 blocos construídos para toda quantidade de decimais; a chance do caso raro | 0,3 s |
| `tb_cvv` | pela UART, com o firmware real. `W0` com as chaves e as entradas das fontes: os 4 códigos publicados (um da `psec`, e o CVV, o CVV2 e o iCVV de um cartão do `jmeter-iso8583`). `W0` com PAN inventado de 19 e de 12 dígitos: o código do Python. `W2`: certo nos três códigos, primeiro e último dígito trocados. Recusas: modo `V` no `W0`, modo `G` no `W2`, chave tripla e chave `V2` (`11`); PAN de 11 dígitos e letra na validade (`16`); key block adulterado (`10`) | 2 h 36 |
| `tb_ascii` | a porta host inteira; a tabela de comandos ganhou duas entradas | 2 h 38 |

`hsmhost.py cvv-confere --lmk LMK [-n N]` é a prova na placa. A cada volta: um
cartão inventado, com PAN de 12 a 19 dígitos; os três códigos gerados e
conferidos com o Python; cada dígito trocado, recusado; outra validade; e as
recusas `11` (modos, chave tripla, chave AES, chave `V2`) e `16`.

## Etapa 8.7: troca de chaves 3DES

Estado: validada na placa em 2026-11-22. `regressao.py` com 19 passos em 398 s; o passo de 3DES e KEK 3DES (`tdes-confere`) em 27,4 s. Firmware `0.8.7`, 56 104 bytes (86% da IMEM). Timing +0,572 ns, 0 critical warnings, RTL sem mudança. `tb_kek3` levou 5 h 52, sozinho, e é o segundo mais lento da suíte, depois do `tb_ecdsa`. Na bancada, com os botões, em 2026-11-22: KEK 3DES por componentes, KCV `F7BAA8` antes e depois de religar.

Uma KEK (uso `K0`) pode ser 3DES, dupla ou tripla, e troca chave com outra
instituição em key block **versão B**. A KEK 3DES nasce por componentes no
console e fica na flash, como a AES. A teoria, com o exemplo numérico da
derivação e do bloco aberto, está no manual, seção 39.9; os testes e a
matemática deles, na 43.7.

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/cmac_tdes.c` | CMAC sobre 3DES (SP 800-38B, bloco de 64 bits, constante `1B`), sem coprocessador |
| `fw/src/tr31.c` | a versão B: `tr31b_deriva()`, `tr31b_embrulha()`, `tr31b_desembrulha()` e o autoteste `tr31b_selftest()`. A versão D não mudou, exceto o parâmetro de versão de `cab_le()` e `cab_escreve()` |
| `fw/src/kat.c` | `kat_tdes()` chama `tr31b_selftest()`: vetor de CMAC-TDES do CAVP, o bloco B de terceiros, um bit trocado e ida e volta |
| `fw/src/keystore.c` | chave 3DES em qualquer slot; `keystore_kek_deriva()` com KEK 3DES; `keystore_kek_transporta()`, a regra de força; `embrulha_slot_b()`; componentes 3DES; o registro com blocos de 112 caracteres |
| `fw/src/cmd.c` | `KEY_FROM_COMPONENTS` aceita componente de 16 ou 24 bytes com algoritmo `T` |
| `fw/src/cmd_ascii.c` | `K4` e `K6` escolhem a versão pela KEK (`abre_sob_n()`) |
| `fw/src/main.c` | autoteste do 3DES reprovado na restauração: zeroiza e `TAMPERED` |
| `host/tr31.py` | a versão B em Python, com o 3DES e o CMAC da biblioteca `cryptography` |
| `host/hsmtool.py` | `comp-load --alg T2/T3`, `kcv --tdes` |
| `host/hsmhost.py` | `tdes-confere` com a KEK 3DES |
| `scripts/_extrai_tr31b.py` | copia os 6 blocos B do `psec` para `vectors/tr31/x9143_B_TDES.rsp` |

### Decisões

Do usuário, em 2026-11-21:

- **Só a versão B.** É a que o mercado usa com KEK 3DES. As versões A e C
  (variante) são obsoletas na norma.
- **Os vetores do `psec` bastam**, com o CMAC-TDES do NIST. O arquivo do
  `psec` é o mesmo do vetor da versão D (o hash é igual, em outro commit).
- **A chave 3DES entra no console e na flash.** A KEK de troca nasce por
  componentes, como a AES; um K0 3DES gerado na porta host também serve.

De implementação:

- **A regra de força** aplica a decisão de 2026-11-14 ("uma chave nunca sai
  embrulhada por outra mais fraca"): KEK AES leva tudo; KEK 3DES tripla leva
  3DES dupla e tripla; KEK 3DES dupla só leva dupla. A força efetiva é a da
  SP 800-57 (80 bits a dupla, 112 a tripla). Uma função, no key store,
  usada pelo `K4` e pelo `K6`.
- **Os códigos de recusa não são novos.** No `K4`, `13` ("esta KEK não serve
  para esta chave"), que já era a resposta a uma KEK 3DES antes desta etapa.
  No `K6`, `10`, o código único de todo bloco recebido inválido.
- **A versão vem de quem chama, não do bloco.** `cab_le()` recebe a versão
  esperada: sob a LMK, D; sob uma KEK 3DES, B. Aceitar a que o bloco
  declarar deixaria o host escolher a primitiva.
- **A versão B tem funções próprias**, e não a D com parâmetros: a D está no
  POST de todo boot, e as duas têm a mesma ordem de passos para serem lidas
  lado a lado.
- **O CMAC-TDES fica em arquivo próprio**, sem coprocessador, e compila no
  PC: `host/test_cmac_tdes.py` o confere contra os 192 vetores do NIST.
- **O componente 3DES tem 16 ou 24 bytes**, e o tamanho diz o comprimento da
  chave. Todos os componentes de uma montagem têm o mesmo algoritmo e o
  mesmo tamanho; o KCV de cada um é o do algoritmo.
- **A paridade dos componentes não é conferida**, como não é a da LMK: a
  qualidade do componente é do custodiante.
- **No registro da flash a entrada continua com 144 caracteres.** O bloco de
  uma chave 3DES tem 112; o resto vai com `'0'`, e a carga lê o tamanho do
  cabeçalho do bloco. O formato do registro não mudou, e uma flash gravada
  pela 8.6 carrega sem conversão.
- **O autoteste do 3DES roda antes do primeiro uso**, também na restauração
  do boot (o KCV da instalação usa o motor) e no primeiro componente 3DES,
  antes do dual control, para uma reprovação não gastar o aperto.

### O checklist

Nenhum comando novo. Mudaram `K4`, `K6` e `KEY_FROM_COMPONENTS`:

| Item | `K4`/`K6` com KEK 3DES | `KEY_FROM_COMPONENTS` com `T` |
|---|---|---|
| Estados | `OPERATIONAL` | `OPERATIONAL` |
| Dual control | não: é operação | sim, a cada componente |
| Exportabilidade | `K4` recusa `'N'` (`12`), pela mesma função do console | não se aplica |
| Log | antes | antes |

**Vazamento.** Em laço, `K4` devolve a mesma chave sob a KEK com enchimento
novo a cada vez: nada que o primeiro bloco não desse. O MAC da versão B tem
64 bits, e por isso a regra de força não deixa uma chave AES viajar sob ela.
`K6` devolve um código só para toda recusa do bloco recebido.

### Vetores

- `vectors/tr31/x9143_B_TDES.rsp`: os 6 blocos B do `psec`, literalmente.
  O equipamento aceita 3 (blocos 1, 2, 3) e recusa 3 (DES simples e blocos
  opcionais), de propósito; o `MANIFEST.txt` diz qual é qual.
- `vectors/cmac/CMACGenTDES2.rsp` e `CMACGenTDES3.rsp`, do mesmo zip do CAVP
  que já estava fixado. O de chave dupla só tem tags truncadas.

### Medidas

| Medida | Valor |
|---|---|
| Firmware | 56 104 bytes de código, 3 332 a mais (86% da IMEM) |
| RTL | sem mudança |

### Testes

| Teste | O que prova | Tempo |
|---|---|---|
| `host/test_cmac_tdes.py` | **no PC**: o C do firmware e a `cryptography` nos 192 vetores do NIST; verificação e recusas | 0,4 s |
| `host/test_tr31b.py` | **no PC**: os 6 blocos de terceiros no Python e no C; o autoteste do firmware; subchaves C = Python; 24 blocos iguais caractere a caractere com o mesmo enchimento; um bit trocado em cada uma das 96 posições | 0,6 s |
| `tb_kek3` | pela UART, com o firmware real. KEK 3DES por dois componentes no console, com o KCV 3DES de cada um e da KEK; componente de 32 bytes com `T` recusado sem gastar o aperto; religar e achar a KEK no mesmo handle; `K6` com os blocos 1, 2 e 3 de terceiros (KCV da chave publicada); `K4` dá bloco B e volta pelo `K6`; tripla sob tripla; recusas `13` (AES, tripla sob dupla) e `10` (DES simples, blocos opcionais, bloco adulterado, outra KEK) | 5 h 52 |
| `tb_ascii` | a porta host inteira; `K4` e `K6` mudaram | 2 h 52 |
| `tb_keystore` | o key store do console; `KEY_FROM_COMPONENTS` mudou | 1 h 44 |
| `tb_persist` | desligar e religar; o registro mudou | 58 min |
| `tb_tdes` | o 3DES pela porta host; o autoteste cresceu | 1 h 46 |
| `tb_zeroize` | a prova de zeroização ganhou dois campos | 38 min |
| `tb_tr31_block` | o key block D no POST; `tr31.c` mudou | 11 min |

`hsmhost.py tdes-confere --lmk LMK [-n N]` é a prova na placa. A cada volta e
para cada comprimento: uma KEK 3DES gerada na porta host; `K4` de chaves 3DES
dupla e tripla, aberto pelo Python com a KEK, e `K6` de volta; `K6` de blocos B
que o Python fechou (com exportabilidade `N`, que tem de ser preservada); e as
recusas da regra de força, nos dois sentidos.

**Na bancada, com os botões** (2026-11-22, num terminal com TTY): os dois
componentes do `tb_kek3`, com `comp-load --alg T2 --uso K0 --modo B`. Os KCVs
dos componentes são `FE0973` e `840617`, iguais aos de `kcv --tdes`. A chave
ficou no handle 3, com `K0`, `T`, `B`, `E`, 16 bytes e KCV `F7BAA8`, que é o
KCV publicado da KBPK do bloco 3 do `psec`. Depois de religar, o handle 3 tem
o mesmo KCV.

## Etapa 8.8a: DUKPT TDES

Estado: validada na placa em 2026-11-23. Simulação dos seis testbenches que cobrem a mudança, todos PASS; bitstream com WNS +0,572 ns e 0 critical warnings; `hsmtool build` CONFERE com o firmware `0.8.8` (58 892 bytes); `regressao.py` com 20 passos em 368 s, o `dukpt-confere` em 14,9 s.

O equipamento faz o lado do adquirente do DUKPT TDES (ANSI X9.24-1). Do KSN
que chega com a transação e da BDK, ele refaz a chave de PIN do terminal e
traduz o PIN para uma chave de zona (`P2`). Ele também gera a IPEK de um
terminal e a entrega sob uma KEK, para a carga do terminal (`I0`). A teoria,
com o exemplo numérico do anexo A.4, está no manual, seção 37.2; os testes e
a matemática deles, na 43.8.

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/dukpt.c` | as contas sem política: `dukpt_tdes_ipek()`, `dukpt_tdes_chave_pin()`, `dukpt_ksn_valido()` e o autoteste `dukpt_selftest()`. Compila no PC |
| `fw/src/keystore.c` | `keystore_dukpt_pin_abre()` (abre o PIN block do terminal; o PIN fica em `g_pin`, como no `P0`) e `keystore_dukpt_ipek()` (deriva a IPEK duas vezes, compara e a embrulha sob a KEK). O modo `X` no `header_valido()`. `pin_passada0()` passou a chamar `pin_passada0_chave()`, porque a chave de PIN do DUKPT não mora em slot |
| `fw/src/tr31.c`, `host/tr31.py` | aceitam o modo `X` |
| `fw/src/kat.c` | `kat_tdes()` chama `dukpt_selftest()`: a IPEK do anexo e o PIN block de uma transação |
| `fw/src/cmd_ascii.c` | os comandos `P2` e `I0` |
| `host/dukpt.py` | o DUKPT TDES em Python, com o DES da biblioteca `cryptography` |
| `host/hsmtool.py` | `--modo X` |
| `host/hsmhost.py` | `dukpt-confere` |
| `scripts/_extrai_dukpt_tdes.py` | copia a IPEK e as 34 transações do `openemv/dukpt` para `vectors/dukpt/x924_1_tdes.rsp` |

### Decisões

Do usuário, em 2026-11-22 (no `PLANO.md`):

- **O DUKPT AES aceita BDK e chave de trabalho AES-128 ou AES-256**, na
  8.8b, como o mercado usa. O coprocessador só faz AES-256; o AES-128 entra
  como motor em C, só para o DUKPT. A primeira decisão era só AES-256; o
  usuário perguntou se isso seguia o mercado, e a mudou no mesmo dia.
- **Entram a tradução e a IPEK.** MAC e dados com chave DUKPT ficam para a
  8.9.
- **Duas subetapas**: 8.8a TDES, 8.8b AES, cada uma com placa e commit.
- **Uma fonte de vetores basta**: o `openemv/dukpt`.

De implementação:

- **A BDK é uma chave de slot como as outras**: uso `B0`, 3DES duplo e modo
  `X`, o modo "só deriva" da X9.143. Nasce por componentes no console ou
  pelo `K0`, e chega à porta host como key block sob a LMK. Só o `P2` e o
  `I0` usam uma chave `B0`; o `K2`, o `K4` e o `EXPORT_KEY` a tratam como
  qualquer chave.
- **O modo `X` entrou nos três lugares que validam o modo**: o key store,
  `tr31.c` e `tr31.py`. Uma BDK não cifra nem faz MAC por dois motivos: o
  uso `B0` não passa em `uso_dados()`, `uso_mac()` nem `uso_pin()`; e o
  modo `X` não está no grupo de cifra (`E`/`D`/`B`) nem no de MAC
  (`G`/`V`/`C`). Uma chave de outro uso com modo `X` também não faz nada.
- **O que se deriva da BDK nunca entra em slot.** A IPEK e a chave de PIN
  existem em variável local durante a conta, e saem apagadas.
- **`P2` é o `P0` com a chave de origem trocada.** Mesmo formato de pedido
  (mais o KSN), mesmos códigos, mesmo fechamento (`keystore_pin_fecha()`).
  O formato de origem é o `0`; o `4` com BDK TDES é `11`, e fica para a
  BDK AES da 8.8b.
- **KSN inválido é `16`**, antes de qualquer conta: contador zero (é a
  própria IPEK) ou com mais de 10 bits 1 (um terminal que segue a norma
  nunca o usa).
- **A IPEK sai com uso `B1`, modo `X` e exportabilidade `N`.** O destino é o
  terminal, e de lá ela não sai. A versão do bloco segue a KEK, e a regra
  de força do `K4` vale: qualquer KEK deste equipamento leva uma chave 3DES
  dupla.
- **A IPEK é derivada duas vezes e comparada** antes de ser embrulhada, como
  o que sai ao host nos outros comandos. Uma IPEK errada só apareceria na
  primeira transação do terminal, em campo.
- **O `I0` ignora o contador do KSN**: a IPEK só depende do resto dele.
- **A chave de transação é refeita do zero a cada pedido.** Não há cache de
  chaves por terminal: o HSM não guarda estado de terminal nenhum.

### O checklist

| Item | `P2` | `I0` |
|---|---|---|
| Estados | `OPERATIONAL` | `OPERATIONAL` |
| Dual control | não: é operação | não: é operação, como o `K4` |
| Exportabilidade | não se aplica: nenhuma chave sai | a IPEK sai com `N`; a BDK não sai por ele |
| Log | antes | antes |

**Vazamento.** `P2`: o mesmo `14` do `P0`, com o mesmo oráculo do formato 0
quando o host altera o PAN (manual, seção 34.3). O KSN vem do host e escolhe
a chave: com um KSN errado o bloco abre num valor ao acaso, que passa como
formato 0 cerca de uma vez em 2²⁴, e a recusa não diz nada sobre o PIN.
`I0`: em laço, quem tem os dois blocos tira a IPEK de qualquer KSN sob
aquela KEK. É o serviço, e a KEK existe para o limitar. A IPEK de um
terminal não revela a BDK nem a IPEK de outro.

### Vetores

- `vectors/dukpt/x924_1_tdes.rsp`: a BDK, o KSN inicial, a IPEK, o PIN block
  em claro e as 34 transações do anexo A.4 da X9.24-1:2009, copiados do
  arquivo de testes do `openemv/dukpt` (LGPL-2.1), fixado por commit e por
  hash. O `MANIFEST.txt` diz o que eles cobrem e o que não cobrem.

### Medidas

| Medida | Valor |
|---|---|
| Firmware | 58 892 bytes de código, 2 788 a mais (90% da IMEM) |
| RTL | sem mudança |

### Testes

| Teste | O que prova | Tempo |
|---|---|---|
| `host/test_dukpt.py` | **no PC**: o Python e o C do firmware na IPEK, nas 34 chaves de transação e nos 34 PIN blocks do anexo; o autoteste; 300 BDKs e KSNs ao acaso, C = Python; as recusas de KSN | 0,5 s |
| `tb_dukpt` | pela UART, com o firmware real. `P2` com a BDK do anexo e a transação de contador `0FF800`, a saída comparada inteira; `I0` da IPEK do anexo sob KEK 3DES, cabeçalho e KCV; recusas `16` (KSN de contador zero), `11` (BDK sem modo `X`), `14` (PIN block adulterado), `13` (chave de zona como KEK) | PASS, 3 h 53 |
| `tb_ascii` | a porta host inteira; dois comandos novos | PASS, 2 h 40 |
| `tb_pin0` | o formato 0; `pin_passada0()` mudou | PASS, 3 h 15 |
| `tb_tdes` | o 3DES pela porta host; o autoteste cresceu | PASS, 2 h 01 |
| `tb_keystore` | o key store do console; `header_valido()` mudou | PASS, 1 h 31 |
| `tb_tr31_block` | o key block D no POST; `tr31.c` mudou | PASS, 10 min |

`hsmhost.py dukpt-confere --lmk LMK [-n N]` é a prova na placa. Primeiro, a BDK
do anexo A.4 entra por `K6`, e o equipamento tem de achar o PIN `1234` em
quatro transações publicadas e a IPEK publicada. Depois, a cada volta: uma
BDK gerada pelo `K0`; um terminal simulado pelo Python (KSN com 1 a 10 bits
1, PIN de 4 a 12 dígitos, PAN inventado); o `P2` para uma chave de zona 3DES
e para uma AES; o `I0` sob uma KEK AES (bloco D) e sob uma 3DES (bloco B),
com a IPEK aberta pelo Python; e as recusas.

## Etapa 8.8b: DUKPT AES

Estado: validada na placa em 2026-11-23. Simulação dos sete testbenches que cobrem a mudança, todos PASS (583 min, 2 por vez); bitstream com WNS +0,572 ns, 0 critical warnings, 8081 LUTs e BRAM 25,5; `hsmtool build` CONFERE com o firmware `0.8.9` (62 784 bytes); `regressao.py` com 20 passos em 376 s, o passo do DUKPT TDES e AES em 22,0 s.

O equipamento faz o lado do adquirente do DUKPT AES (ANSI X9.24-3), com os
mesmos comandos da 8.8a: o `P2` traduz o PIN de um terminal DUKPT AES para
uma chave de zona, e o `I0` entrega a chave inicial (IK) de um terminal sob
uma KEK AES. O algoritmo da BDK, no cabeçalho do bloco dela, diz qual DUKPT
o comando faz. A teoria, com o exemplo numérico do suplemento da norma, está
no manual, seção 37.3; os testes e a matemática deles, na 43.9.

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/aes128.c` | AES-128 em software (FIPS 197), só para o DUKPT. Caixas S calculadas da definição por um script. Compila no PC |
| `fw/src/dukpt.c` | `dukpt_aes_ik()`, `dukpt_aes_chave_pin()`, `dukpt_aes_ksn_valido()` e o autoteste `dukpt_aes_selftest()`. A derivação usa o `aes128.c` com chave de 16 bytes e o coprocessador com 32 |
| `fw/src/keystore.c` | a chave AES-128 só com uso `B0` e modo `X` (`aes128_permitida()`), e o KCV dela (`kcv_aes128()`); `bdk_tipo()` separa a BDK TDES da AES; `keystore_dukpt_pin_abre()` e `keystore_dukpt_ipek()` recebem o tamanho do KSN (e da chave de trabalho). A abertura do formato 4 sob a chave da transação é uma função nova, `pin_abre4_chave()`: `pin_passada4()`, validada com a chave do slot, não mudou |
| `fw/src/kat.c`, `kat.h` | o bit `KAT_FALHA_DUKPT_AES` (`0x1000`), de primeiro uso |
| `fw/src/cmd_ascii.c` | `P2` e `I0` leem o algoritmo da BDK e o tamanho do KSN; o `P2` lê o tipo da chave de trabalho. O autoteste roda antes de abrir uma BDK AES ou uma chave AES-128 |
| `fw/src/cmd.c` | o `KEY_FROM_COMPONENTS` aceita componentes AES-128 |
| `fw/src/main.c` | a restauração do boot com chave AES-128 roda o autoteste, como com chave 3DES |
| `host/dukpt.py` | o DUKPT AES em Python |
| `host/hsmtool.py` | `comp-load --alg A128`; o nome do bit `0x1000` |
| `host/hsmhost.py` | a parte AES do `dukpt-confere` |
| `scripts/_extrai_dukpt_aes.py` | copia as duas BDKs, a IK e as 15 transações de cada uma do `openemv/dukpt` para `vectors/dukpt/x924_3_aes128.rsp` e `x924_3_aes256.rsp` |

### Decisões

Do usuário, em 2026-11-22: BDK e chave de trabalho AES-128 ou AES-256, com
o AES-128 em C, só para o DUKPT (ver a 8.8a).

De implementação:

- **AES-128 só na BDK.** O coprocessador faz só AES-256, e uma chave de
  dados AES-128 pareceria instalada e não cifraria certo. A regra mora em
  `instala_em()`, num lugar só: chave AES de 16 bytes só com uso `B0` e modo
  `X`. Chega por componentes ou por key block; outro cabeçalho é recusado
  ao entrar.
- **O KCV da chave AES-128 é o mesmo método do AES-256**: os 3 primeiros
  bytes da cifra de um bloco de zeros, pelo motor de 128 bits.
- **O mesmo `P2` e o mesmo `I0`.** O algoritmo no cabeçalho da BDK diz o
  tamanho do KSN (10 ou 12 bytes) e se vem o tipo da chave de trabalho. O
  cabeçalho é público, e é autenticado em seguida, ao abrir o bloco: um
  cabeçalho trocado reprova no MAC.
- **O tipo da chave de trabalho usa os códigos de algoritmo da norma**: `2`
  (AES-128) e `4` (AES-256). Outro valor é `16`. A norma permite também
  chave de trabalho 3DES e AES-192; ficaram fora, como a decisão do usuário
  diz.
- **O PIN block do terminal é o formato 4**, que é o par do DUKPT AES. O
  formato 0 com BDK AES é `11`, como o formato 4 com BDK TDES.
- **A IK só sai sob KEK AES.** É a regra de força do `K4`
  (`keystore_kek_transporta()`): uma chave AES nunca sai sob uma KEK 3DES.
  Recusa `13`.
- **Um autoteste de primeiro uso para o AES-128 e o DUKPT AES**, com bit
  próprio. Roda antes do primeiro uso de uma BDK AES (de 16 ou de 32 bytes)
  ou de uma chave AES-128 (KCV na instalação, na restauração do boot e nos
  componentes). Reprovado: o destino de um POST reprovado.
- **KSN inválido é `16`**: contador zero, ou com mais de 16 bits 1.

### O checklist

| Item | `P2` com BDK AES | `I0` com BDK AES |
|---|---|---|
| Estados | `OPERATIONAL` | `OPERATIONAL` |
| Dual control | não: é operação | não: é operação |
| Exportabilidade | não se aplica: nenhuma chave sai | a IK sai com `N`, só sob KEK AES; a BDK não sai por ele |
| Log | antes | antes |

**Vazamento.** `P2`: com o formato 4 de origem, o `14` revela pouco (manual,
seção 34.3). Um bloco aberto sob um KSN errado passa como campo de PIN
válido com chance de cerca de 2⁻²⁴ (seção 37.3). `I0`: o mesmo da 8.8a; a IK
de um terminal não revela a BDK nem a IK de outro.

### Vetores

- `vectors/dukpt/x924_3_aes128.rsp` e `x924_3_aes256.rsp`: as BDKs, os IKIDs,
  as IKs e 15 transações de cada, do suplemento de vetores da X9.24-3:2017,
  copiados do arquivo de testes do `openemv/dukpt` (o mesmo commit da 8.8a).
- `vectors/aes/ECB*128.rsp`: os vetores ECB de 128 bits do CAVP, do mesmo
  `KAT_AES.zip` já fixado.

### Medidas

| Medida | Valor |
|---|---|
| Firmware | 62 784 bytes de código, 3 892 a mais (95,8% da IMEM; sobram 2 752) |
| RTL | sem mudança |

### Testes

| Teste | O que prova | Tempo |
|---|---|---|
| `host/test_dukpt.py` | **no PC**: o `aes128.c` nos 568 vetores ECB de 128 bits; o Python e o C na IK, nas 30 chaves de transação, nas 24 chaves de PIN e nos 8 PIN blocks publicados; o autoteste; 400 casos ao acaso, C = Python; as recusas de KSN | 0,9 s |
| `tb_dukpt_aes` | pela UART, com o firmware real. `P2` com a BDK AES-128 publicada (motor em C) e com a AES-256 (coprocessador), a saída comparada inteira; `I0` da IK publicada sob KEK AES, cabeçalho e KCV; recusas `13` (IK sob KEK 3DES), `16` (KSN de contador zero), `11` (origem formato 0), `10` (chave AES-128 de dados) | PASS, 2 h 44 |
| `tb_dukpt` | o DUKPT TDES; o `P2` e o `I0` mudaram | PASS, 4 h 06 |
| `tb_ascii` | a porta host inteira; `abre_sob_n()` mudou | PASS, 2 h 37 |
| `tb_keystore` | o key store do console; a instalação e os componentes mudaram | PASS, 1 h 35 |
| `tb_kek3` | os componentes 3DES e a restauração com chave 3DES | PASS, 7 h 16 |
| `tb_persist` | a restauração do boot; `main.c` mudou | PASS, 52 min |
| `tb_tr31_block` | o POST e a máscara dele | PASS, 10 min |

`hsmhost.py dukpt-confere` ganhou a parte AES: as duas BDKs publicadas
entram por `K6`; o equipamento tem de achar a IK publicada e o PIN `1234` nos
8 PIN blocks publicados; a cada volta, uma BDK ao acaso por `K6`, numa das
quatro combinações de tamanho de BDK e de chave de trabalho, o `P2` para
zonas 3DES e AES, o `I0`, e as recusas.

## IMEM de 128 KB

Decisão do usuário em 2026-11-23, ao fechar a etapa 8.8. O DUKPT AES deixou o
firmware em 62 784 de 65 536 bytes (95,8%), e a etapa 8.9 não cabia.

O pedido foi 96 KB, e o NEORV32 não faz 96 KB. Ele arredonda `IMEM_SIZE` para a
potência de 2 de cima (`imem_size_c := 2**index_size_f(IMEM_SIZE)`, em
`neorv32_top.vhd`), e o datasheet pede potência de 2. Com `96*1024` o hardware
teria 128 KB, e o linker e o `GET_BUILD` teriam 96 KB, sem aviso. A outra saída
era um patch no NEORV32, na decodificação de endereço: código de terceiros num
caminho crítico. O usuário escolheu 128 KB.

| | Antes | Depois |
|---|---|---|
| IMEM (espaço de endereço) | 64 KB | 128 KB |
| ROM física | 64 KB, 16 BRAM36 | 64 KB, 16 BRAM36 (veja abaixo) |
| BRAM usada | 25,5 de 50 | 25,5 de 50 |
| Firmware | 62 784 bytes (95,8%) | 62 788 bytes (47,9% de 131 072) |
| Timing (WNS) | +0,572 ns | +0,434 ns, 0 critical warnings |
| LUTs | 8081 | 8085 (7914 FF, DSP 4) |
| `GET_BUILD` | SHA-256 de 64 KB | SHA-256 de 128 KB |

O tamanho mora em quatro lugares, que têm de casar: `IMEM_SIZE` em
`rtl/soc/neorv32_wrapper.vhd`, `__neorv32_rom_size` em `fw/Makefile`,
`HSM_IMEM_BYTES` em `fw/include/versao.h` e `IMEM_BYTES` em
`scripts/mkfwhash.py`. O `hsmtool build` usa o modelo do `mkfwhash.py` (antes,
tinha 64 KB fixo). Firmware `0.8.10`.

### A ROM tem o tamanho da imagem, e o resto da IMEM a espelha

A suíte acusou o `GET_BUILD` no `tb_uart_frame`: o hash calculado pelo firmware
diferia do hash do arquivo em 30 de 32 bytes. O firmware estava certo. O modelo
da memória no `mkfwhash.py` estava errado.

O NEORV32 v1.13.3 não dimensiona a ROM pela IMEM. `neorv32_imem_rom.vhd` a
dimensiona pela **imagem** (`image_size_c`), arredondada para a potência de 2 de
cima, e decodifica só os bits de endereço dela. Com 62 788 bytes de firmware, a
ROM tem 64 KB. Os endereços de 64 KB a 128 KB leem a imagem de novo:

```
 0x00000  imagem (62 788 bytes) + zeros    ROM física, 64 KB
 0x10000  a mesma ROM, outra vez           espelho
 0x1FFFF
```

O `GET_BUILD` calcula o SHA-256 dos 128 KB que a CPU lê, com o espelho. O
`mkfwhash.py` supunha zeros acima da imagem. Agora ele monta a mesma vista:
imagem, zeros até a potência de 2, e a repetição até 128 KB. A simulação
devolveu `35f7263a…b989`, o valor que o modelo novo calcula.

Duas consequências:

- **A IMEM de 128 KB não custa BRAM enquanto o firmware couber em 64 KB.** A
  BRAM ficou em 25,5. Quando o firmware passar de 65 536 bytes, a ROM passa a
  128 KB, 16 BRAM36 a mais (41,5 de 50), e o espelho some.
- **O hash continua cobrindo cada byte do firmware.** O espelho só repete o que
  já foi contado.

Mudança de RTL: a suíte completa rodou, 34 testbenches em 20 h 36, 3 por vez.
Duas falhas:

- **`tb_uart_frame`**: o `GET_BUILD`, pela ROM espelhada (acima). Com o modelo
  corrigido, PASS em 26 min, sozinho.
- **`tb_pinv`**: passou do limite de 4 h no último passo, sem nenhuma conferência
  falhando. O teste cresceu na revisão da 8.5 (a tabela de outra chave) e o
  limite não acompanhou: o tempo simulado foi de 957 para 1326 unidades. Limite
  de 6 h por decisão do usuário (2026-11-24); PASS em 4 h 01, sozinho.

Os outros 32 passaram; os mais lentos: `tb_ecdsa` 9 h 17, `tb_kek3` 7 h 27,
`tb_dukpt` 4 h 07, `tb_tamper` 3 h 51.

Estado: ✅ **validada na placa em 2026-11-24.** `hsmtool build` respondeu
v0.8.10 com o hash `35f7263a…b989`, o mesmo da simulação: CONFERE. Isso prova o
espelho também no hardware. `regressao.py --lmk` com 20 passos em 391 s. Timing
+0,434 ns, 0 critical warnings, 8085 LUTs, 7914 FF, BRAM 25,5, DSP 4.

## Etapa 8.9a: dados e MAC com chave 3DES

Estado: validada na placa em 2026-11-25. Simulação dos seis testbenches que cobrem a mudança, todos PASS; bitstream com WNS +0,434 ns, 0 critical warnings, 8085 LUTs e BRAM 25,5; `hsmtool build` CONFERE com o firmware `0.8.11` (64 544 bytes); `regressao.py` com 20 passos em 388 s, o passo das chaves 3DES, com dados e MAC 3DES, em 51,4 s.

O equipamento cifra dados e calcula MAC de mensagem com chave 3DES, pelos
mesmos comandos do AES. O algoritmo da chave, no cabeçalho do key block,
escolhe a conta: `C0`/`C2` fazem 3DES-CBC com IV de 8 bytes, e `M0`/`M2`
fazem o retail MAC (ISO/IEC 9797-1, algoritmo 3; ANSI X9.19), com dois campos
novos, o preenchimento e o tamanho do MAC. A teoria, com o exemplo numérico
da ISO/IEC 9797-1 B.4 e o ataque de Preneel e van Oorschot, está no manual,
seção 39.10; os testes, na 43.10.

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/mac_tdes.c`, `mac_tdes.h` | `retail_mac()`: a cadeia em DES de `K`, o último bloco em 3DES de `K ‖ K'`, preenchimentos 1 e 2. Sem política; compila no PC |
| `fw/src/keystore.c` | `keystore_tdes_cbc_confere()` (uso `D0`, algoritmo `T`, o mesmo controle de modo do AES, dupla execução com a chave preparada de novo) e `keystore_retail_mac()` (chave dupla da família `M`, modo `G`/`V`/`C`, MAC e veredito calculados duas vezes, comparação em tempo constante) |
| `fw/src/kat.c` | o KAT do 3DES (primeiro uso) inclui dois retail MACs publicados, um de cada preenchimento |
| `fw/src/cmd_ascii.c` | `C0`/`C2` leem o tamanho do IV pelo algoritmo do cabeçalho; `M0`/`M2` leem o preenchimento e o tamanho com bloco 3DES (`le_rmac()`) |
| `scripts/mkkat.py` | os dois retail MACs do KAT |
| `host/mac_tdes.py` | o retail MAC e o 3DES-CBC em Python, com o DES da `cryptography` |
| `host/hsmhost.py` | `mac()`/`mac_verifica()` com `rmac=(preenchimento, tamanho)`; o `tdes-confere` confere `C0`/`C2`/`M0`/`M2` com chave 3DES |
| `scripts/_extrai_retail_mac.py` | copia os 6 valores do `psec` e do RustCrypto para `vectors/mac/retail_mac.rsp` |

### Decisões

Do usuário, em 2026-11-23 (`PLANO.md`): só o retail MAC, com os
preenchimentos 1 e 2 e MAC de 4 ou 8 bytes; dados em CBC pelos mesmos
`C0`/`C2`; e, da 8.9 em diante, vetor de terceiros de pelo menos duas fontes
independentes.

De implementação, seguindo decisões anteriores:

- **O uso da chave de MAC é a família `M`**, sem conferir o código exato,
  como no CMAC (decisão de 2026-11-04). O exemplo do manual usa `M3`, que é o
  código da X9.143 para o algoritmo 3 da ISO 9797-1.
- **Chave tripla de MAC responde `11`**: o algoritmo usa o par `K`, `K'`,
  como o CVV.
- **Mensagem vazia responde `15`.** O preenchimento 1 da norma trata a
  mensagem vazia como caso à parte, e nenhuma fonte de valores o cobre.
- **O algoritmo é lido do cabeçalho antes de abrir o bloco**, só para saber
  o formato do pedido (tamanho do IV, campos do MAC). O cabeçalho é
  autenticado ao abrir, e a conta é escolhida pelo `info.algoritmo` do bloco
  aberto. É o mesmo desenho do `P2` com o tamanho do KSN.
- **A paridade da chave não é conferida**, como em toda chave 3DES importada
  (só a geração a acerta). As chaves do `psec` têm paridade par.

### O checklist

`C0`, `C2`, `M0` e `M2` com chave 3DES; nenhum opcode novo.

- **Estados:** só `OPERATIONAL`, como os demais comandos da porta host.
- **Dual control:** não. É operação.
- **Vazamento em laço:** `C0`/`C2` são o oráculo de cifra do serviço, como
  com AES; o limite é o modo da chave (`E`/`D`/`B`). `M0` é o oráculo de MAC.
  Com o retail MAC há um custo a mais, que o manual (39.10) descreve: cerca
  de 2^32,5 pares conhecidos de mensagem e MAC levam às duas chaves com
  esforço de DES simples. O controle é o log e a troca da chave. O `M2`
  devolve um bit, compara em tempo constante e não devolve o MAC calculado.
- **Exportabilidade:** não se aplica: nenhuma chave sai.
- **Log:** entra antes da execução, pelo despachante ASCII.

### Vetores

`vectors/mac/retail_mac.rsp`: 6 valores de duas fontes, o teste da função do
`psec` (mesmo commit do CVV) e o exemplo do crate `retail-mac` do RustCrypto,
que transcreve a ISO/IEC 9797-1:2011 B.4. O 3DES-CBC é o dos MMT do NIST, já
em `vectors/tdes/`. Procedência, leituras e o que não cobrem: no
`MANIFEST.txt`.

### Testes

| Teste | O que cobre | Resultado |
|---|---|---|
| `host/test_retail_mac.py` | Python e C contra os 6 valores; o 3DES-CBC contra os MMT do NIST; o C contra o Python em 2 000 casos ao acaso e em todo tamanho de 1 a 40 bytes; as recusas | PASS, 0,8 s |
| `tb_mac3` | pela UART, com o firmware real: o MAC da B.4 no `M0` e no `M2`; o MAC de 4 bytes do `psec` no `M2` (confere, e não confere com um caractere trocado); o `C0`/`C2` do NIST com chave tripla; sete recusas | PASS, 3 h 40 |
| `tb_ascii` | a porta host inteira; `cripto()`, `h_m0()` e `h_m2()` mudaram | PASS, 2 h 59 |
| `tb_kek3` | o KAT do 3DES no primeiro componente 3DES e na restauração | PASS, 8 h 00 |
| `tb_cvv` | o KAT do 3DES no primeiro uso, e `modo_mac_ok()`, que o retail MAC também usa | PASS, 3 h 34 |
| `tb_tdes` | a chave 3DES no key store; o passo 6 mudou (abaixo) | PASS, 2 h 40 |
| `tb_tr31_block` | o POST e a máscara dele | PASS, 13 min |

As simulações rodaram 3 por vez. O `tb_cvv` passou do limite de 4 h quando
rodou com outras três simulações ao mesmo tempo, e passou na repetição, sem
mudança, com menos carga na máquina.

⚠ **O `tb_tdes` conferia que o `C0` recusava chave 3DES (`11`).** Era a regra
da 8.3, quando o `C0` só fazia AES, e a 8.9a a mudou. A simulação acusou
`22`: o teste mandava IV de 16 bytes, e com chave 3DES o IV tem 8, então o
pedido sobrava. Por decisão do usuário (2026-11-24), o passo virou três
conferências: `C0` com IV de 8 bytes cifra, o `C2` devolve o texto, e IV de 16
bytes com chave 3DES é `22`.

## Etapa 8.9b: MAC e dados com DUKPT

Estado: validada na placa em 2026-11-26. Simulação dos seis testbenches que cobrem a mudança, todos PASS (3 por vez); bitstream com WNS +0,280 ns, 0 critical warnings, 8086 LUTs e BRAM 41,5; `hsmtool build` CONFERE com o firmware `0.8.12` (68 028 bytes); `regressao.py` com 20 passos em 426 s, o passo do DUKPT, agora com `M4`/`M6`/`C4`/`C6`, em 43,5 s.

O equipamento faz o lado do adquirente do MAC e da cifra de dados com DUKPT,
TDES e AES. Quatro comandos ASCII novos: `M4` confere o MAC de pedido, `M6`
faz o MAC de resposta, `C4` decifra os dados de pedido e `C6` cifra os dados
de resposta. A BDK é a mesma do `P2`, e o algoritmo dela escolhe a conta: no
TDES, retail MAC (preenchimento 1, 4 ou 8 bytes) e 3DES-CBC sob as variantes
da norma, com a função de mão única nas chaves de dados; no AES, CMAC e
AES-CBC sob as chaves de uso `2000`, `2001`, `3000` e `3001`. A teoria, com
o exemplo numérico, está no manual, seção 37.4; os testes, na 43.11.

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/dukpt.c`, `dukpt.h` | `dukpt_tdes_chave_uso()` e `dukpt_aes_chave_uso()`: a chave de cada uso, sem política; `dukpt_aes_cmac()` e `dukpt_aes_cbc()`, no motor AES-128 ou, com 32 bytes, no coprocessador. O autoteste do DUKPT inclui um MAC de pedido TDES e as chaves de MAC e de dados AES-128 publicados |
| `fw/src/keystore.c` | `keystore_dukpt_mac()` e `keystore_dukpt_dados()`: abrem a BDK, conferem o KSN, derivam a chave de uso e calculam duas vezes, com a derivação refeita, antes de algo sair |
| `fw/src/cmd_ascii.c` | `M4`, `M6`, `C4` e `C6` |
| `scripts/mkkat.py` | os valores do autoteste, de `dukpt_mac_dados.rsp` |
| `host/dukpt.py`, `host/hsmhost.py` | as mesmas contas em Python; o `dukpt-confere` passa a cobrar os quatro comandos |
| `scripts/_extrai_dukpt_mac.py` | copia os 63 valores das duas fontes para `vectors/dukpt/dukpt_mac_dados.rsp` |

### Decisões

Do usuário, em 2026-11-23 (`PLANO.md`): MAC e dados com a chave da
transação, TDES e AES; no TDES, retail MAC sob a variante; no AES, CMAC e
AES-CBC; sem HMAC. Vetores do `openemv/dukpt` e do `moov-io/dukpt`. Os
valores de resposta (dados TDES, CMAC e dados AES) só existem no `moov-io`,
e entraram com uma fonte por decisão do usuário.

De implementação, seguindo decisões anteriores:

- **Só o lado do adquirente.** Não há comando para fazer o MAC de um pedido,
  conferir o de uma resposta, cifrar um pedido ou decifrar uma resposta: isso
  é papel do terminal. Um HSM que fizesse os dois lados permitiria forjar
  mensagens de terminal.
- **A chave de uso nunca entra em slot**, como a chave de PIN da 8.8. Vive em
  variável local dentro de `keystore.c` e sai apagada.
- **O KSN é conferido antes da conta**, pela mesma regra do `P2` (`16`).
- **O `M4` devolve um bit**, com comparação em tempo constante e veredito
  calculado duas vezes. O MAC calculado não sai.

### O checklist

`M4`, `M6`, `C4` e `C6`, comandos ASCII novos; nenhum opcode binário.

- **Estados:** só `OPERATIONAL`, como os demais comandos da porta host.
- **Dual control:** não. É operação.
- **Vazamento em laço:** `M6` e `C6` são oráculos de MAC e de cifra sob a
  chave de uma transação, e `C4` é um oráculo de decifra. O alcance é uma
  chave de uso de um KSN: a BDK e a chave da transação não saem, e a função
  de mão única impede voltar da chave de dados TDES à chave da transação. O
  controle é o log. O `M4` vaza um bit, inerente à verificação.
- **Exportabilidade:** não se aplica: nenhuma chave sai.
- **Log:** entra antes da execução, pelo despachante ASCII.

### Vetores

`vectors/dukpt/dukpt_mac_dados.rsp`: 63 transações de duas fontes, o
`openemv/dukpt` (C, os mesmos arquivos da 8.8) e o `moov-io/dukpt` (Go),
com a mesma mensagem, `4012345678909D987`. Onde as duas se cruzam, elas
concordam. Procedência, o que tem uma fonte só e o que não cobrem: no
`MANIFEST.txt`.

### A ROM de 128 KB

O firmware passou de 64 KB (68 028 bytes). Como previsto na seção "IMEM de
128 KB", a ROM física foi a 128 KB, sem espelho, e a BRAM foi de 25,5 a 41,5
de 50 blocos (83%). O timing caiu de +0,434 para +0,280 ns. O `tb_uart_frame`
confere o hash do `GET_BUILD` sobre a ROM sem espelho, e o `hsmtool build`
confere na placa.

### Testes

| Teste | O que cobre | Resultado |
|---|---|---|
| `host/test_dukpt.py` | Python e C contra os 63 valores; C contra Python em 200 BDKs TDES e 200 casos AES ao acaso | PASS, 0,9 s |
| `tb_dukpt_mac` | pela UART, com o firmware real: os quatro comandos com os valores publicados, TDES e AES-128; CMAC com um caractere trocado dá `01`; quatro recusas | PASS, 4 h 58 |
| `tb_dukpt` | o DUKPT TDES da 8.8a; `keystore.c` e `dukpt.c` mudaram | PASS, 4 h 51 |
| `tb_dukpt_aes` | o DUKPT AES da 8.8b | PASS, 3 h 31 |
| `tb_ascii` | a porta host inteira; a tabela de comandos mudou | PASS, 2 h 42 |
| `tb_uart_frame` | o `GET_BUILD` com a ROM de 128 KB | PASS, 27 min |
| `tb_tr31_block` | o POST e a máscara dele | PASS, 11 min |

As simulações rodaram 3 por vez.

## Etapa 8.10: ARQC e ARPC

Estado: validada na placa em 2026-11-26. Simulação dos seis testbenches que cobrem a mudança, todos PASS (3 por vez); bitstream com WNS +0,280 ns, 0 critical warnings, 8086 LUTs e BRAM 41,5 (iguais aos da 8.9b); `hsmtool build` CONFERE com o firmware `0.8.13` (71 824 bytes); `regressao.py` com 21 passos em 454 s, o passo novo do ARQC em 28,8 s.

O equipamento faz o lado do emissor do criptograma do chip EMV, com 3DES.
Dois comandos ASCII novos. O `A0` confere o ARQC que o chip mandou e, se
ele conferir, devolve o ARPC, a resposta que o chip confere; se não
conferir, devolve `01` e nenhum ARPC. O `A2` entrega a MK de um cartão sob
uma KEK, para a personalização. A chave mestra do emissor (IMK) é uso `E0`,
modo `X`, 3DES duplo. A teoria, com o exemplo numérico e os casos de uso,
está no manual, seção 40; os testes, na 43.12.

### As peças

| Arquivo | O que faz |
|---|---|
| `fw/src/emv.c`, `emv.h` | as contas, sem política: a MK pela Opção A, a chave de sessão comum (CSK), o criptograma (retail MAC, preenchimento 1 ou 2) e o ARPC pelos métodos 1 e 2. `emv_selftest()` entra no KAT do 3DES, com um caso CVN 10 (jPOS) e um CVN 18 (`pyemv`) |
| `fw/src/keystore.c` | `keystore_emv_arqc()` e `keystore_emv_mk()`: conferem o uso da IMK e o PAN, calculam duas vezes, com a derivação refeita, e comparam antes de algo sair |
| `fw/src/cmd_ascii.c` | `A0` e `A2` |
| `scripts/mkkat.py` | os valores do autoteste, de `arqc.rsp` |
| `host/emv.py` | as mesmas contas em Python, e o chip de teste (`gera_arqc()`) |
| `host/hsmhost.py` | `arqc-confere`: o Python faz o papel do chip, com PAN `999999`, e o HSM confere |
| `scripts/_extrai_emv.py` | copia os 18 valores das duas fontes para `vectors/emv/arqc.rsp` |

### Decisões

Do usuário, em 2026-11-26 (`PLANO.md`):

- Só a Opção A (PAN de até 16 dígitos); PAN maior é recusado com `15`.
- Só 3DES.
- Dois esquemas: a chave de sessão comum (EMV Book 2, A1.3) e o CVN 10, em
  que o criptograma sai da MK direto. O CVN 10 responde só pelo ARPC método
  1; método 2 com ele é `16`.
- ARPC métodos 1 e 2.
- O HSM não gera ARQC: isso é do chip.
- Um comando só para conferir e responder. O ARPC sai só se o ARQC conferiu.
- A MK sai sob KEK, com uso `E0`, modo `X` e exportabilidade `N`, como a
  IPEK do `I0`.
- Vetores de duas fontes.

De implementação, seguindo decisões anteriores:

- **O que se deriva da IMK nunca entra em slot.** A MK e a chave de sessão
  vivem em variável local dentro de `keystore.c` e saem apagadas.
- **O ARQC calculado não sai.** O `A0` vaza um bit, como o `M2`: confere ou
  não confere. O ARPC é calculado sobre o ARQC recebido, que é o que o chip
  vai conferir.
- **Tudo é calculado duas vezes**, com a derivação refeita: a chave, o ARQC,
  o ARPC e o veredito. Discordou: `91` e erro grave marcado.

### O checklist

`A0` e `A2`, comandos ASCII novos; nenhum opcode binário.

- **Estados:** só `OPERATIONAL`, como os demais comandos da porta host.
- **Dual control:** não. É operação.
- **Vazamento em laço:** o `A0` vaza um bit por pedido. Achar um ARQC por
  tentativa custa 2^64 pedidos, e cada um fica no log. Um ARPC para um ARQC
  falso ajudaria quem o forjou, e por isso o ARPC só sai se o ARQC conferiu.
  O `A2` é função de emissão: entrega, sob KEK, a MK de qualquer PAN. O
  controle é o uso da KEK e o log.
- **Exportabilidade:** a MK sai com `N`. Ela vai para o chip, e de lá não
  sai mais. A IMK não sai.
- **Log:** entra antes da execução, pelo despachante ASCII.

### Vetores

`vectors/emv/arqc.rsp`: 18 casos de duas fontes independentes, o `pyemv`
(Python, 8 casos) e o jPOS (Java, 10 casos). As duas não têm entradas em
comum, e cada uma confere a implementação sozinha. Procedência e o que ficou
fora (Opção B, MCHIP): no `MANIFEST.txt`.

### Testes

| Teste | O que cobre | Resultado |
|---|---|---|
| `host/test_emv.py` | Python e C contra os 18 valores; C contra Python em 500 casos ao acaso; recusas; o autoteste | PASS, 3,5 s |
| `tb_arqc` | pela UART, com o firmware real: o `A0` com os valores do jPOS e do `pyemv`, nos dois esquemas e nos dois métodos; ARQC trocado dá `01` sem ARPC; o `A2` com o cabeçalho `E0`/`T`/`X`/`N` e o KCV publicado; três recusas | PASS, 4 h 45 |
| `tb_kek3` | a KEK 3DES, que o `A2` usa; `keystore.c` mudou | PASS, 8 h 25 |
| `tb_tdes` | o KAT do 3DES, que agora inclui o `emv_selftest()` | PASS, 3 h 07 |
| `tb_ascii` | a porta host inteira; a tabela de comandos mudou | PASS, 2 h 46 |
| `tb_uart_frame` | o `GET_BUILD` | PASS, 24 min |
| `tb_tr31_block` | o POST e a máscara dele | PASS, 11 min |

As simulações rodaram 3 por vez.

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
  atual é a `0.8.4`.
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
do resto roda na placa, com `host/regressao.py`: 20 passos em 376 s (medido em 2026-11-23, com o 3DES, o
PKCS#8, a conferência do firmware, a verificação de PIN, o CVV, a KEK 3DES e o DUKPT TDES e AES). A suíte
completa roda quando o RTL muda e no fim da fase. A tabela está no `CLAUDE.md`.

A suíte completa de 2026-11-15 tem 28 testbenches e levou 11 h 46, com 3 por vez.
O `tb_ecdsa` é o mais lento (9 h 15), seguido do `tb_rsa` (4 h 19) e do `tb_tamper`
(3 h 53).

O script acusa falha: com uma LMK errada, os quatro passos que dependem dela
reprovam, e os demais passam.
