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
matemática deles, na 42.7.

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
do resto roda na placa, com `host/regressao.py`: 19 passos em 398 s (medido em 2026-11-22, com o 3DES, o
PKCS#8, a conferência do firmware, a verificação de PIN, o CVV e a KEK 3DES). A suíte
completa roda quando o RTL muda e no fim da fase. A tabela está no `CLAUDE.md`.

A suíte completa de 2026-11-15 tem 28 testbenches e levou 11 h 46, com 3 por vez.
O `tb_ecdsa` é o mais lento (9 h 15), seguido do `tb_rsa` (4 h 19) e do `tb_tamper`
(3 h 53).

O script acusa falha: com uma LMK errada, os quatro passos que dependem dela
reprovam, e os demais passam.
