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
ataque de decimalização e a defesa) e 41.3 (os testes e a matemática deles).

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
do resto roda na placa, com `host/regressao.py`: 18 passos em 311 s (medido em 2026-11-15, com o 3DES, o
PKCS#8, a conferência do firmware e a verificação de PIN). A suíte
completa roda quando o RTL muda e no fim da fase. A tabela está no `CLAUDE.md`.

A suíte completa de 2026-11-15 tem 28 testbenches e levou 11 h 46, com 3 por vez.
O `tb_ecdsa` é o mais lento (9 h 15), seguido do `tb_rsa` (4 h 19) e do `tb_tamper`
(3 h 53).

O script acusa falha: com uma LMK errada, os quatro passos que dependem dela
reprovam, e os demais passam.
