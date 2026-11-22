# Parte VII — Criptografia de pagamento

Esta parte existe porque o modelo de referência deste projeto passou a ser
um **HSM de pagamento comercial**. Entender o que
esses equipamentos fazem o dia inteiro é o que separa "sei o que é uma
fronteira criptográfica" de "sei por que aquele comando existe".

O equipamento implementa uma parte do que está aqui: os PIN blocks formato
0 e 4 e a tradução de PIN (seções 33 e 34), a verificação de PIN (seção 35),
o CVV (seção 36), as chaves 3DES (seção 39) e a troca de chaves 3DES com
outra instituição (seção 39.9). A seção 38 explica o que é
implementável, o que não é, e por quê. O resto do material é para entender
o domínio.

> **Independência e fontes.** Este capítulo **não nomeia fabricante nem
> produto**, de propósito. O modelo de estudo é a *categoria* — HSM de
> pagamento — e nada aqui alega vínculo, endosso ou compatibilidade com
> equipamento comercial algum.
>
> Todo o conteúdo vem de **normas públicas** (ISO 9564, ANSI X9.24 e X9.143,
> NIST SP 800-38B) e de **literatura acadêmica publicada**. Nada é derivado
> de documentação proprietária: tabela de comandos, código de erro e esquema
> de chave de manual de fabricante são material licenciado e **não entram
> aqui**.

> **Sobre os layouts de bytes.** Descrevo a *estrutura* e o *porquê* de cada
> construção, não o mapa exato de nibbles. Isso é deliberado: os layouts
> normativos estão na ISO 9564, na ANSI X9.24 e nas especificações das
> bandeiras, e a regra deste projeto proíbe escrever valor normativo de
> memória. Quem for implementar tem de ler a norma — e essa é a lição, não
> um contratempo. A exceção é o formato 4, que o equipamento implementa: o
> layout dele está na seção 33.4, conferido contra valores publicados por
> uma implementação aberta.

---

## 33. PIN blocks — por que um PIN não viaja sozinho

Um PIN de quatro dígitos tem 10.000 valores possíveis. Cifrar isso
diretamente com uma chave, sozinho, é um desastre: o mesmo PIN produz sempre
o mesmo criptograma, e um dicionário de 10.000 entradas quebra tudo em
tempo nenhum.

A solução é o **PIN block**: um bloco de tamanho fixo que combina o PIN com
o **número da conta** (PAN) antes de cifrar. Duas consequências, e as duas
importam:

1. O criptograma de um mesmo PIN é **diferente para cada conta**. O
   dicionário morre.
2. O PIN block fica **amarrado à conta**. Um PIN block capturado numa
   transação não serve para outra conta — pelo menos é essa a intenção.

A ISO 9564-1 padroniza vários formatos. Interessam três.

### 33.1 Formato 0 (ANSI X9.8) — o que existe em todo lugar

O mais antigo e o mais difundido. A ideia:

```
   campo do PIN   comprimento + digitos do PIN + preenchimento fixo
   campo do PAN   parte do numero da conta, alinhada
   PIN block      cifra( campo_PIN  XOR  campo_PAN )
```

Bloco de 64 bits, porque nasceu para DES.

**Onde ele é fraco, e não é na cifra:**

- **O preenchimento é fixo.** Sabendo o formato, o atacante conhece boa
  parte do bloco em claro antes de começar.
- **O bloco não é autenticado.** Nada prova que aquele PIN block é o que o
  emissor mandou. Autenticidade vem de fora, se vier.
- **64 bits é pouco.** Com DES, o tamanho de bloco vira problema estatístico
  antes de o tamanho de chave virar.
- **O PAN é fornecido por quem chama.** Esta é a pior. Se o atacante
  controla o PAN que entra no XOR, ele controla metade do bloco — e é daí
  que saem os ataques de tradução da seção 15.3.

**Os campos, nibble a nibble.** Um nibble é meio byte, um dígito
hexadecimal. O bloco tem 16.

```
   campo do PIN    0 | N | P P P P ... | F F F ... F
                   |   |   |             +-- enchimento F ate o fim
                   |   |   +-- os N digitos do PIN
                   |   +-- tamanho do PIN, de 4 a 12
                   +-- controle: formato 0

   campo do PAN    0 0 0 0 | os 12 digitos do PAN a direita,
                             sem o ultimo
```

O último dígito do PAN é o dígito verificador, calculado dos outros. Ele
não entra, porque não acrescenta nada.

**Um exemplo, com números.** PIN `48213`, PAN inventado `9999990123456789`,
chave 3DES dupla `0123456789ABCDEF FEDCBA9876543210`:

```
   campo do PIN   0 5 4 8 2 1 3 F F F F F F F F F
   campo do PAN   0 0 0 0 9 9 9 0 1 2 3 4 5 6 7 8
   XOR            0 5 4 8 B 8 A F E D C B A 9 8 7
   3DES           2DC3F05263417865                  (o PIN block)
```

Olhe a linha do XOR. Os quatro primeiros nibbles são os do campo do PIN,
intactos: o campo do PAN é zero ali. O controle, o tamanho e os **dois
primeiros dígitos do PIN** não se misturam com nada. Do terceiro dígito em
diante, cada nibble é um dígito do PIN, ou um `F`, combinado com um dígito
do PAN.

Quem abre o bloco desfaz a cifra, refaz o XOR com o campo do PAN e confere:
controle `0`, tamanho de 4 a 12, dígitos de 0 a 9, enchimento `F`.

**Três diferenças para o formato 4**, que a seção 33.4 descreve:

| | Formato 0 | Formato 4 |
|---|---|---|
| Cifra e bloco | 3DES, 8 bytes | AES, 16 bytes |
| Aleatório | nenhum: mesmo PIN, mesmo PAN e mesma chave dão sempre o mesmo bloco | 8 bytes novos a cada bloco |
| Como o PAN entra | por XOR, **antes** da única cifragem | por XOR, **entre** duas cifragens |

A terceira linha é a que decide a segurança. No formato 0, trocar um dígito
do PAN troca um nibble conhecido do bloco em claro. No formato 4, trocar um
dígito do PAN embaralha o bloco inteiro, porque há uma cifragem depois. A
seção 34.3 mostra o que isso custa.

Um bloco ao acaso passa na conferência do formato 0 com a mesma chance do
formato 4, cerca de uma vez em 2²⁴: os dois formatos têm o mesmo número de
campos válidos, e a metade aleatória do formato 4 não é conferida.

**Neste equipamento**, o formato 0 usa uma chave de PIN 3DES, dupla ou
tripla, e o PAN tem de 13 a 19 dígitos.

### 33.2 Formato 1 — quando não há conta

Usa preenchimento **aleatório** e não inclui o PAN. Existe para o caso em
que o número da conta não está disponível no momento de formar o bloco.

O preço é exatamente o que o formato 0 comprava: **o bloco não está amarrado
a conta nenhuma**. Um PIN block formato 1 capturado vale para qualquer conta
que aceite formato 1. Por isso ele é restrito a trechos onde outra coisa
garante o vínculo.

### 33.3 Formato 3 — o remendo intermediário

Como o formato 0, mas com preenchimento **aleatório** em vez de fixo. Tapa o
buraco do "atacante já conhece metade do bloco" sem mexer no resto. Continua
com bloco de 64 bits e continua não autenticado.

### 33.4 Formato 4 — o de AES, e o que este equipamento faz

Reprojetado para AES, bloco de 128 bits. A estrutura tem **duas passagens de
cifra**, e é isso que importa:

```
   bloco A   controle + comprimento + digitos do PIN + preenchimento ALEATORIO
   bloco B   campo do PAN, alinhado em 128 bits
   
   intermediario = AES( K, bloco A )
   bloco C       = intermediario XOR bloco B
   PIN block     = AES( K, bloco C )
```

Compare com o formato 0, que é **uma** cifra sobre um XOR. A diferença não é
cosmética:

- No formato 0, controlar o campo do PAN é controlar diretamente a entrada
  da cifra. No formato 4, o XOR com o PAN acontece **depois** de uma
  passagem de AES — o atacante não controla mais a entrada, controla a
  entrada de uma função que ele não sabe inverter.
- O preenchimento aleatório faz o mesmo PIN, na mesma conta, produzir blocos
  diferentes a cada vez.
- 128 bits de bloco elimina o problema estatístico do DES.

**Este é o formato que o equipamento implementa**, porque é o único que usa
AES — e AES é o que existe no fabric.

Os dois blocos de entrada, nibble a nibble:

```
   bloco A (campo do PIN), 16 bytes
       nibble 0        4             controle: formato 4
       nibble 1        tamanho do PIN, de 4 a 12
       nibbles 2-15    o PIN, um dígito por nibble, e depois o enchimento A
       bytes 8-15      aleatórios

   bloco B (campo do PAN), 16 bytes
       nibble 0        tamanho do PAN menos 12
       nibbles 1-19    o PAN, um dígito por nibble
       o resto         zeros
```

Um exemplo completo, com uma chave AES-128 de teste, o PIN `1234`, o PAN
inventado `1234567890123456789` e os 8 bytes aleatórios fixados em `FF`:

```
   chave        00112233445566778899AABBCCDDEEFF

   bloco A      44 1234 AAAAAAAAAA FFFFFFFFFFFFFFFF
                |  |    |          aleatório
                |  |    enchimento
                |  o PIN
                controle 4, tamanho 4

   bloco B      7 1234567890123456789 000000000000
                |  o PAN, 19 dígitos
                19 − 12 = 7

   AES(A)       CCFFA14C0DDB760827CA556A7C87F137
   XOR com B    BDDCE42B84DA554D4043556A7C87F137      (bloco C)
   AES(C)       28B41FDDD29B743E93124BD8E32D921E      (o PIN block)
```

Com outros 8 bytes aleatórios, o bloco A muda na segunda metade, e o PIN
block inteiro muda: a cifra espalha a diferença por todos os bits.

O enchimento `A` não é dígito decimal. Quem abre o bloco confere o controle,
o tamanho, os dígitos e o enchimento. Um bloco aberto com a chave errada, ou
com o PAN errado, é um bloco ao acaso, e passa nessa conferência uma vez em
cerca de 2²⁴, ou 17 milhões. Quem domina a conta é o PIN de 12 dígitos, que
só deixa dois nibbles de enchimento para conferir. A seção 42.2 faz a conta.

⚠ **A ISO 9564-1 é paga, e não há vetor oficial público do formato 4.** O
equipamento foi conferido contra valores publicados por uma implementação
aberta, fixados por hash. A chave desses valores é AES-128, e o coprocessador
só faz AES-256: eles validam a implementação em Python, e o firmware é
conferido contra o Python.

---

## 34. Tradução de PIN — o comando mais perigoso que existe

Uma transação com cartão atravessa domínios de chave diferentes: terminal,
adquirente, bandeira, emissor. Cada domínio tem a sua chave. O PIN precisa
chegar do primeiro ao último **sem nunca aparecer em claro fora de um HSM**.

Quem faz isso é a **tradução de PIN block**. O comando:

1. recebe o PIN block cifrado sob a chave de entrada,
2. decifra **dentro** da fronteira,
3. recifra sob a chave de saída (possivelmente noutro formato),
4. devolve o novo PIN block.

O PIN existe em claro por microssegundos, dentro do módulo, e nunca sai.

**Por que é o comando mais perigoso:** ele é, por construção, um oráculo. O
chamador escolhe as chaves, escolhe o PAN, escolhe os formatos, e observa se
a operação teve sucesso. Todos os ataques da seção 15.3 nascem daí — o
módulo nunca revela o PIN, revela apenas *se deu certo*, e isso basta quando
se pode perguntar milhares de vezes.

Se você entender um único comando de HSM de pagamento a fundo, que seja
este.

### 34.1 A tradução neste equipamento: o comando `P0`

O `P0` recebe duas chaves de PIN, o PAN e o PIN block, e devolve o PIN block
sob a segunda chave:

| Pedido | Resposta | Entrada | Saída |
|---|---|---|---|
| `P0` traduzir | `P1` | key block de origem · key block de destino · formato de origem(1) · formato de destino(1) · tamanho do PAN(2) · PAN · PIN block(16 ou 32) | PIN block(16 ou 32) |

As regras:

- **As duas chaves têm uso `P0`** no key block, o código da norma para chave
  de PIN. Uma chave de dados (`D0`) no lugar responde `11`. O contrário
  também vale: o `C2` recusa uma chave de PIN. Sem essa separação, decifrar
  um PIN block seria só "decifrar dados".
- **O modo conta.** A chave de origem precisa decifrar (`D` ou `B`), e a de
  destino precisa cifrar (`E` ou `B`). Uma chave de modo `E` serve a um
  equipamento que só envia PINs adiante, e nunca abre o que recebe.
- **O formato escolhe a cifra.** O formato `4` pede chave AES, e o formato
  `0`, chave 3DES. Chave de PIN do algoritmo errado responde `11`. O PIN
  block tem 32 caracteres hexadecimais no formato 4, e 16 no formato 0.
- **O formato é conferido.** Se o bloco aberto não é um campo bem formado do
  formato de origem, a resposta é `14` e nada sai. É o veredito de "deu
  certo" de que a seção fala. Com o formato 4 ele revela pouco: não separa
  um PIN de outro, e um bloco forjado ao acaso só passa uma vez em 17
  milhões. Isso não é barreira contra quem pergunta em laço: o controle é o
  log. Com o formato 0 ele revela parte do PIN, e a seção 34.3 faz a conta.
- **O aleatório é novo.** No formato 4, o bloco de saída não herda os 8
  bytes aleatórios do bloco de entrada: dois pedidos iguais dão duas saídas
  diferentes. O formato 0 não tem aleatório, e dois pedidos iguais dão a
  mesma saída.
- **Um PAN só.** O pedido leva um PAN, que vale para abrir e para fechar.
- **O resultado é calculado duas vezes**, na abertura e no fechamento, como
  tudo o que sai ao host (seção 29).

O PIN em claro fica numa área do key store, entre abrir com uma chave e
fechar com a outra. Ele não passa pelo código que interpreta o comando, e é
apagado no fim do comando, qualquer que seja o resultado.

### 34.2 Traduzir entre formatos

Um terminal novo cifra o PIN em formato 4, com AES. A rede que leva a
transação ao emissor, em muitos casos, só fala formato 0, com 3DES. Alguém
no caminho tem de converter, e esse alguém é o HSM do adquirente. É o uso
mais comum da tradução hoje.

O `P0` aceita as quatro combinações:

| Formatos | Origem | Destino | Uso típico |
|---|---|---|---|
| `44` | AES | AES | de uma chave de zona AES para outra |
| `40` | AES | 3DES | do terminal novo para a rede antiga |
| `04` | 3DES | AES | da rede antiga para um emissor novo |
| `00` | 3DES | 3DES | de uma chave de zona 3DES para outra |

Dentro do equipamento o PIN fica sempre na mesma forma, qualquer que seja o
formato de fora. Abrir converte para essa forma; fechar converte dela para o
formato de destino. A conversão troca o controle e o enchimento, e mantém o
tamanho e os dígitos.

**O que a norma restringe, e por quê.** A ISO 9564-1 não deixa traduzir de
qualquer formato para qualquer formato. A regra geral: um bloco amarrado à
conta não pode virar um bloco sem conta. Os formatos 0, 3 e 4 levam o PAN, e
a tradução entre eles é permitida. O formato 1 não leva. Traduzir do 0 para
o 1 soltaria o PIN da conta, e o bloco resultante valeria para qualquer
cartão. O sentido contrário também é perigoso: Berkman e Ostrovsky (2007)
mostraram um ataque que só usa a tradução, do formato 1 para o formato 0,
com o PAN escolhido pelo atacante e uma tabela de blocos já vistos. Este
equipamento só tem o 0 e o 4, e as quatro combinações estão dentro da regra.

A segunda restrição é sobre o PAN: a tradução não pode trocar a conta. Um
comando que abre o bloco com um PAN e o fecha com outro amarra o PIN de um
cliente ao cartão de outro. Por isso o `P0` leva um PAN só.

**Do forte para o fraco.** A tradução `40` tira o PIN de um bloco AES e o
põe num bloco 3DES. A regra da seção 38.2, "uma chave nunca sai embrulhada
por outra mais fraca", vale para **chaves**, e não para PINs: o PIN segue o
caminho que a rede tem. O formato 4 no terminal protege o trecho do
terminal, e não o caminho inteiro.

### 34.3 O que o erro `14` revela no formato 0

A seção 34 diz que o comando revela "se deu certo", e que isso basta. Aqui
está a conta, para o formato 0. O ataque é público, e é conhecido como
ataque de modificação do PAN: está na dissertação de Clulow, de 2003
(referência no Apêndice).

**O que o atacante tem.** Um PIN block formato 0 capturado, o PAN daquela
conta, e acesso ao comando de tradução. Ele não tem chave nenhuma em claro.

**O que ele faz.** Pede a tradução do bloco, mas informa o PAN com **um
dígito trocado**. O equipamento abre o bloco, e faz o XOR com o campo do
PAN informado, e não com o verdadeiro. O resultado é o campo do PIN com um
nibble alterado:

```
   nibble que o equipamento ve  =  nibble verdadeiro  XOR  d

   d  =  digito verdadeiro do PAN  XOR  digito informado
```

O atacante conhece `d`, porque conhece os dois dígitos. Ele não vê o
nibble. Vê só se o equipamento respondeu `00` ou `14`.

**Sob o enchimento**, qualquer troca estraga o `F`, e a resposta é `14`.
**Sob um dígito do PIN**, a resposta depende do dígito: sai `14` quando o
resultado passa de 9. Com o exemplo da seção 33.1, em que o terceiro dígito
do PIN é `2` e está sob um `9` do PAN:

| PAN informado, naquela posição | `d` | O equipamento vê | Resposta |
|---|---|---|---|
| `9` (o verdadeiro) | 0 | `2` | `00` |
| `8` | 1 | `2 XOR 1 = 3` | `00` |
| `1` | 8 | `2 XOR 8 = A` | `14` |
| `3` | A | `2 XOR A = 8` | `00` |
| `0` | 9 | `2 XOR 9 = B` | `14` |

A terceira e a quarta linhas, juntas, dizem que o dígito é 2 ou 3: são os
únicos valores que dão mais que 9 com `d = 8` e não com `d = A`.

**O que sai, medido por programa** (`host/test_pinblock.py` faz o papel do
atacante, com 9 trocas em cada uma das 12 posições, 108 pedidos):

- **O tamanho do PIN, sempre.** Trocar o dígito do PAN por ele mesmo `XOR 1`
  mantém válido um dígito de PIN, porque `XOR 1` leva dígito em dígito, e
  estraga um enchimento. A última posição que responde `00` é o fim do PIN.
- **Parte de cada dígito, do terceiro em diante.** Quanto, depende do dígito
  do PAN que está na mesma posição:

| Dígito do PAN | O atacante separa o dígito do PIN em |
|---|---|
| 0 ou 1 | {0,1} {2,3,4,5,6,7} {8,9} |
| 2 ou 3 | {2,3} {0,1,4,5,6,7} {8,9} |
| 4 ou 5 | {4,5} {0,1,2,3,6,7} {8,9} |
| 6 ou 7 | {6,7} {0,1,2,3,4,5} {8,9} |
| 8 ou 9 | {0,1} {2,3} {4,5} {6,7} {8,9} |

  Em média, de 10 candidatos sobram 3,9. Com um 8 ou um 9 no PAN, sobram 2.
- **O último bit de cada dígito nunca sai.** `XOR 1` nunca muda a resposta.
- **Os dois primeiros dígitos nunca saem.** O campo do PAN é zero ali, e o
  atacante não tem o que trocar.

Para um PIN de 4 dígitos, o atacante sai com os dois últimos dígitos
reduzidos, em média, de 100 combinações para cerca de 15. Não é o PIN
inteiro. O ataque completo, na literatura, junta este veredito com outros
comandos, e com outros formatos, até fechar o PIN.

**Por que o formato 4 não tem esse problema.** Nele, o PAN entra depois de
uma cifragem. Trocar um dígito do PAN muda um nibble do bloco **cifrado**
intermediário, e a segunda decifragem espalha a mudança pelo bloco inteiro.
A resposta é `14` com probabilidade de quase 1, qualquer que seja o PIN.

**Por que o equipamento não conserta.** Não há conserto dentro do formato.
Esconder o `14` atrás de outro código não muda nada: a resposta continua
sendo sucesso ou recusa. Recusar PAN "diferente do verdadeiro" é impossível:
o equipamento não sabe qual é o verdadeiro. O que o mercado faz é de fora:

- restringir quem fala com o HSM, e por qual rede;
- registrar e vigiar as recusas: 108 erros `14` sobre o mesmo bloco não
  acontecem em operação normal;
- migrar para o formato 4, onde o veredito não diz nada.

Neste equipamento, toda recusa do `P0` entra no log de auditoria, com o
código de erro. É o único controle que ele tem contra este ataque, e é o
mesmo que um equipamento comercial tem.

---

## 35. Verificação de PIN — o offset e o PVV

O emissor precisa decidir se o PIN digitado está certo. Ele não guarda os
PINs. Ele guarda, para cada conta, um **valor de referência** de poucos
dígitos, que não é segredo. Na hora de verificar, o equipamento refaz uma
conta com uma chave secreta e compara.

Dois métodos dominam o mercado. Os dois usam um bloco de 3DES sob uma chave
própria, a **chave de verificação de PIN**. Este equipamento faz os dois.

| | Método do offset | PVV |
|---|---|---|
| Origem | o caixa eletrônico dos anos 1970 | bandeira de cartão |
| Entra na cifra | dados de validação, tirados da conta | conta, índice da chave e **PIN** |
| O PIN entra na cifra? | não | sim, os 4 primeiros dígitos |
| Valor de referência | offset, um dígito por dígito de PIN | PVV, sempre 4 dígitos |
| Parâmetro delicado | tabela de decimalização | nenhum |
| Uso da chave no key block | `V1` | `V2` |

### 35.1 O método do offset

A ideia original era o caixa eletrônico calcular o PIN a partir do número da
conta, com uma chave só, sem consultar ninguém.

1. **Dados de validação.** O emissor tira 16 dígitos hexadecimais do número
   da conta. A regra de montagem é do emissor.
2. **Cifra.** Um bloco de 3DES sob a chave de verificação. Saem 16 dígitos
   hexadecimais.
3. **Decimalização.** Um teclado numérico não tem as letras de `A` a `F`.
   Uma tabela leva cada dígito hexadecimal a um decimal. O resultado é o
   **PIN natural**.
4. **Offset.** O cliente quer escolher o PIN. O emissor guarda a diferença,
   dígito a dígito e módulo 10, entre o PIN escolhido e o PIN natural.

```
   natural = tabela( 3DES( dados de validação ) )
   offset  = PIN − natural      dígito a dígito, módulo 10
   PIN     = natural + offset   idem
```

A tabela usual:

```
   hex:    0 1 2 3 4 5 6 7 8 9 A B C D E F
   tabela: 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
```

**Exemplo, com os valores conferidos por programa** (`host/test_pinverif.py`).
A chave é `0123456789ABCDEF FEDCBA9876543210`, o PIN é `48213` e os dados de
validação são `9999990123456789`:

```
   dados de validação    9999990123456789
   cifrado               C391C921EB0FE15C
   decimalizado          2391292141054152     C→2, B→1, F→5, E→4
   PIN natural           23912                os 5 primeiros: o PIN tem 5
   PIN do cliente        48213
   offset                25301                4−2, 8−3, 2−9+10, 1−1, 3−2
```

Para verificar, o equipamento soma o offset ao PIN natural e compara com o
PIN que chegou no PIN block: `23912 + 25301 = 48213`, dígito a dígito, sem
vai-um.

**O offset não é segredo.** Ele fica na base do emissor e já foi gravado na
tarja do cartão. Sem a chave, ele não diz nada sobre o PIN. A consequência é
que **o PIN natural vale tanto quanto o PIN**: quem conhece o natural de uma
conta e lê o offset dela tem o PIN.

**O PIN natural não é uniforme.** A tabela usual leva 16 valores a 10: os
dígitos de 0 a 5 saem com probabilidade 2/16 cada um, e os de 6 a 9 com
1/16.

```
   entropia de um dígito natural   3,25 bits     (uniforme: 3,32)
   tentativas até acertar, média   3 307         (uniforme: 5 000)
   chance de acertar em 3          7,3 em 10 000 (uniforme: 3 em 10 000)
```

O offset escolhido pelo cliente esconde esse desvio. Num emissor que entrega
o PIN natural ao cliente, sem offset, ele fica exposto.

### 35.2 O PVV

O PVV põe o PIN **dentro** da cifra, e dispensa a tabela.

1. Monta-se um bloco de 16 dígitos: os 11 dígitos da conta antes do dígito
   verificador, um dígito de **índice da chave**, e os 4 primeiros dígitos do
   PIN.
2. Cifra-se com 3DES sob a chave de verificação.
3. Percorrem-se os 16 dígitos hexadecimais do resultado, da esquerda para a
   direita, e tomam-se os **4 primeiros que são decimais**.
4. Se não houver 4, percorre-se de novo, tomando as letras, com `A`→0 até
   `F`→5.

**Exemplo**, com a mesma chave, o PAN inventado `9999990123456789`, índice 1
e PIN `48213`:

```
   conta, 11 dígitos     99012345678
   índice                1
   PIN, 4 dígitos        4821
   bloco de entrada      9901234567814821
   cifrado               6368D8454667BA39
   PVV                   6368                os 4 primeiros decimais
```

O índice permite ao emissor trocar de chave aos poucos: cada cartão diz com
qual chave o PVV dele foi feito.

**A segunda passada é rara.** Um dígito hexadecimal é decimal com
probabilidade 10/16. A chance de um bloco de 16 ter menos de 4 decimais é a
cauda de uma binomial:

```
   soma, k de 0 a 3, de  C(16,k) · (10/16)^k · (6/16)^(16−k)  =  1 em 2 214
```

Por isso o teste de PC não espera o acaso: ele constrói blocos com toda
quantidade de decimais, de 0 a 16 (seção 42.3).

**O PVV não determina o PIN.** Há 10 000 PINs de 4 dígitos e 10 000 PVVs,
e a cifra espalha uns sobre os outros ao acaso. Para um PIN qualquer, a
chance de outro PIN dar o mesmo PVV é `1 − (1 − 1/10 000)^9 999 = 63%`. Quem
acerta o PVV por tentativa pode ter achado um PIN que não é o do cliente, e
ele funciona do mesmo jeito.

**Só 4 dígitos do PIN entram.** Num PIN de 6 dígitos, os dois últimos não
mudam o PVV.

### 35.3 A decimalização, e por que ela é o ponto fraco

A tabela parece detalhe de formatação. Ela é a origem do ataque mais
instrutivo da literatura de HSM: **Bond e Zieliński, 2003** (seção 15.2).

Nas APIs da época, o chamador mandava a tabela em cada pedido de
verificação. O ataque usa isso:

- Com uma tabela que leva um dígito a 1 e todos os outros a 0, o veredito
  "confere / não confere" diz se aquele dígito aparece no PIN natural.
- Em poucos pedidos sai o conjunto de dígitos, e em mais alguns, a posição
  de cada um.

Os números do relatório, para um PIN de 4 dígitos:

| Variante | O que o atacante precisa | Pedidos, média | Pior caso |
|---|---|---|---|
| Inicial | PIN blocks de PINs de teste | cerca de 24 | 46 |
| Adaptativa | idem | 15 | 24 |
| Pelo offset | **um** PIN block capturado, e o offset | 16,5 | não informado |
| Força bruta, para comparar | | 5 000 | 10 000 |

A terceira variante é a que importa para a defesa. Ela não usa tabelas
absurdas: usa a tabela legítima com **uma** entrada alterada, e compensa no
offset. Uma conferência de forma ("a tabela tem dígitos variados?") barra as
duas primeiras e deixa passar a terceira. O relatório conclui que a proteção
completa é a tabela **protegida por criptografia**, para que só tabela
autorizada seja aceita.

> Um parâmetro que parece configuração inofensiva pode ser a superfície de
> ataque inteira.

### 35.4 A verificação neste equipamento

Quatro comandos na porta host, e um no console.

| Comando | Faz | Devolve |
|---|---|---|
| `V0` | gera o offset de um PIN | o offset |
| `V2` | verifica um PIN pelo offset | `00` confere, `01` não confere |
| `V4` | gera o PVV de um PIN | o PVV |
| `V6` | verifica um PIN pelo PVV | `00` confere, `01` não confere |
| `TABELA_AUTORIZA` (console) | autoriza uma tabela de decimalização para uma chave de verificação | a tabela com um MAC |

**O PIN nunca chega em claro.** Ele vem num PIN block, formato 0 ou 4, sob
uma chave de PIN, como no `P0`. O equipamento abre o bloco dentro do key
store, faz a conta e apaga o PIN. O pedido leva dois key blocks: o da chave
de PIN e o da chave de verificação.

**A tabela autorizada.** Os comandos `V0` e `V2` só aceitam tabela com MAC
válido, e o MAC vale para **uma** chave de verificação. O MAC sai do console,
com os dois botões. O operador informa a tabela e o KCV da chave `V1`, que o
`K2` da porta host mostra:

```bash
python3 host/hsmtool.py tabela-autoriza 0123456789012345 <KCV da chave V1>
```

```
chave V1 (KCV)    : <KCV>
tabela autorizada : 0123456789012345<16 caracteres de MAC>
```

O host guarda esse bloco de 32 caracteres e o manda em cada pedido, junto
com a chave `V1` daquele KCV. O equipamento confere o MAC contra o KCV da
chave que ele abriu do key block, e não contra um KCV que o host informe.
Tabela alterada, MAC alterado, ou MAC feito para outra chave: erro `17`.

```
   MAC = 8 primeiros bytes de CMAC_K( tabela (16) ‖ KCV da chave V1 (3) )
   K   = chave derivada da LMK com o rótulo "HSM-A7 DECTAB"
```

**Por que o KCV entra.** Sem ele, uma tabela autorizada valeria para toda
chave. Com duas tabelas autorizadas sob a mesma LMK, o host combinaria as
duas. Isso acontece sem má-fé: uma troca de tabela, ou uma tabela digitada
errado e depois corrigida. Se a segunda difere da primeira em uma entrada,
ela é exatamente a tabela da variante 3 do ataque (seção 35.3), e o PIN sai
em algumas dezenas de pedidos. Com o KCV no MAC:

- uma tabela vale só para a chave para a qual foi autorizada;
- revogar uma tabela é trocar a chave de verificação, como se troca
  qualquer chave;
- a tabela errada autorizada para uma chave não serve para outra.

O que continua com os custodiantes: autorizar **duas** tabelas diferentes
para a **mesma** chave reabre a variante 3 para aquela chave. O equipamento
não lembra o que já autorizou.

- A chave do MAC é derivada da LMK só para isso, com um rótulo próprio. Um
  MAC de tabela não serve de MAC de key block.
- O equipamento **não julga** a tabela. Ele exige 16 dígitos decimais e
  dois custodiantes. Quem autoriza uma tabela ruim reabre o ataque.
- O MAC não é segredo. Trocar a LMK invalida todas as tabelas autorizadas.

**Cada veredito é calculado duas vezes.** A conferência do MAC da tabela, a
cifra e a comparação final do `V2` e do `V6` rodam duas vezes, cada uma a
partir da sua própria conta. Se discordam, nada sai, a resposta é `91` e o
erro grave fica marcado (seção 45.2). Um veredito é o que uma falha
provocada quer inverter: um `01` que vira `00`, ou uma tabela recusada que
passa.

**O modo da chave separa quem emite de quem verifica.** A chave de
verificação tem modo `G` (só gera), `V` (só verifica) ou `C` (os dois).

- `V0` e `V4` são funções de **emissão**. Quem as chama com um PIN block de
  PIN conhecido aprende o PIN natural (PIN − offset), e daí o PIN de toda
  conta de que tenha o offset. Não há conserto dentro do método.
- O controle é o modo: o sistema que só autoriza transações recebe a chave
  com modo `V`, e com ela `V0` e `V4` respondem `11`.
- Uma chave `V1` não calcula PVV, e uma `V2` não calcula offset: `11`.

**O que `V2` e `V6` revelam.** Um bit por pedido. Com um PIN block na mão,
quem escolhe o offset acha o offset certo em até 10ⁿ pedidos. É a busca que
o método admite. O controle é de fora: o contador de tentativas no sistema
do emissor, e o log, que registra cada `01`.

**O tamanho do PIN aparece em `V0`**, no tamanho do offset. É do método.

**Exemplo de uso**, com as ferramentas de teste:

```bash
python3 host/hsmhost.py --serial pinv-confere --lmk <LMK em hex> -n 24
```

Cada volta gera chaves, cifra um PIN, pede os quatro comandos e confere os
resultados com uma segunda implementação em Python.

---

## 36. CVV — o código de verificação do cartão

O cartão traz um código de 3 dígitos que só o emissor sabe calcular. O
emissor não guarda esse código. Ele guarda uma chave, e refaz a conta a cada
transação. Um único método produz três códigos diferentes:

| Código | Onde fica | Código de serviço | Contra o quê |
|---|---|---|---|
| CVV (ou CVC) | na tarja magnética | o da tarja (ex.: `101`, `201`) | tarja inventada a partir só do número do cartão |
| CVV2 (ou CVC2) | impresso no verso | `000` | compra sem o cartão com dados copiados da tarja |
| iCVV | no chip, na imagem da tarja | `999` | dados do chip copiados para uma tarja falsa |

O nome muda com a bandeira. O método é o mesmo.

### 36.1 O método

1. **Dados.** Junte o PAN, a validade (4 dígitos) e o código de serviço (3
   dígitos). Complete com `0` à direita até 32 dígitos. São dois blocos de
   DES, `D1` e `D2`.
2. **Primeiro passo.** Cifre `D1` com DES simples, sob a metade esquerda da
   chave (`A`). Faça o XOR com `D2`.
3. **Segundo passo.** Cifre o resultado com 3DES, sob a chave inteira
   (`A` e `B`).
4. **Extração.** Tome os 3 primeiros dígitos decimais do resultado, da
   esquerda para a direita. Se não houver 3, complete com as letras, na
   ordem, com `A`→0 até `F`→5. É a extração do PVV, com 3 dígitos.

```
   D   = PAN ‖ validade ‖ código de serviço ‖ 0…0          32 dígitos
   X   = DES_A(D1) ⊕ D2
   C   = 3DES_AB(X)
   CVV = os 3 primeiros dígitos decimais de C
```

**Exemplo, com os valores conferidos por programa.** A chave é a do exemplo
da seção 35, `0123456789ABCDEF FEDCBA9876543210`. O PAN inventado é
`9999990123456789`, e a validade é `2812`:

```
                      CVV (101)          CVV2 (000)         iCVV (999)
   D1                 9999990123456789   9999990123456789   9999990123456789
   D2                 2812101000000000   2812000000000000   2812999000000000
   DES_A(D1)          A77E2DB5E4AE7B1F   A77E2DB5E4AE7B1F   A77E2DB5E4AE7B1F
   X                  8F6C3DA5E4AE7B1F   8F6C2DB5E4AE7B1F   8F6CB425E4AE7B1F
   C                  0374D7040AA393CD   0C8F36353390AEAB   3B2FEBA87A91B08B
   código             037                083                328
```

Com um PAN de 16 dígitos, `D1` é o mesmo nos três códigos. Só `D2` muda. Mas
a cifra espalha a diferença, e os três códigos não têm relação visível entre
si.

**A conta é um MAC.** Os passos 2 e 3 são o *retail MAC* da ISO/IEC 9797-1
(algoritmo 3) sobre `D1 ‖ D2`, sem enchimento: DES encadeado sob `A`, e no
último bloco decifrar sob `B` e cifrar sob `A`. Conferido por programa em
2 000 chaves ao acaso. O CVV é um MAC de 64 bits sobre os dados do cartão,
reduzido a 3 dígitos decimais.

**Por que três códigos com um método.** O código de serviço entra na conta.
Quem copia a tarja leva o CVV, e não o CVV2, que não está na tarja. Quem
copia o chip leva o iCVV, que não é o CVV da tarja: uma tarja falsa feita com
os dados do chip é recusada.

**A segunda passada é rara.** Faltam decimais quando há 0, 1 ou 2 entre os 16
dígitos:

```
   soma, k de 0 a 2, de  C(16,k) · (10/16)^k · (6/16)^(16−k)  =  1 em 18 113
```

Nenhum dos valores publicados por terceiros cai nesse caso. O teste de PC
constrói os blocos (seção 42.4).

**Três dígitos são pouco.** São 1 000 valores. Quem pode pedir a verificação
acha o código em 500 pedidos, em média, e em 1 000 no pior caso. A defesa não
está no método. Ela está em quem conta as tentativas:

- o emissor bloqueia o cartão depois de algumas tentativas erradas;
- o **ataque de adivinhação distribuída** (Ali, Arief, Emms e van Moorsel,
  2017) mostrou que esse controle falha quando cada loja virtual confere o
  cartão do seu jeito e conta só as próprias tentativas: o atacante espalha
  os pedidos por centenas de lojas, e nenhuma delas vê o padrão. A partir do
  número do cartão, a validade e o CVV2 saíram campo a campo. Na rede que
  contava as tentativas num ponto central, o ataque foi detectado em menos de
  10 tentativas.

**O CVV2 não pode ser guardado.** O PCI DSS proíbe guardar o código depois
da autorização, mesmo cifrado. Por isso a verificação só pode ser feita
refazendo a conta, e a chave só existe dentro do HSM.

### 36.2 O CVV neste equipamento

Dois comandos na porta host, para os três códigos:

| Comando | Pedido | Devolve |
|---|---|---|
| `W0` | key block da chave · PAN · validade · código de serviço | o código, 3 dígitos |
| `W2` | o mesmo · o código | `00` confere, `01` não confere |

**A chave.** Uso `C0` (chave de verificação de cartão), 3DES de comprimento
**duplo**: é o par "CVK A, CVK B" do mercado. O método usa a metade `A`
sozinha, e uma chave tripla não tem lugar nele: `11`.

**O modo separa quem emite de quem autoriza.** `W0` é função de **emissão**:
com ele, quem tem o número e a validade de um cartão calcula o CVV2 dele, que
é o que se pede numa compra sem o cartão. A chave entregue ao sistema que só
autoriza tem modo `V`, e com ela `W0` responde `11`. Uma chave de outro uso
(a de PIN, a de verificação de PIN) não calcula CVV, e a chave de CVV não
serve a outro comando.

**A validade vai como o emissor a usa.** Pode ser `AAMM` ou `MMAA`. O
equipamento não a interpreta. Quem gera e quem verifica têm de usar a mesma
ordem, ou o código não confere.

**O que `W2` revela.** Um bit por pedido, e é o serviço. O controle é o de
fora: o emissor conta as tentativas por cartão, e o log registra cada `01`.

**Cada veredito é calculado duas vezes**, como no `V2` e no `V6`. A cifra e a
comparação rodam duas vezes, e uma discordância dá `91`, com o erro grave
marcado.

**Exemplo de uso**, com as ferramentas de teste:

```bash
python3 host/hsmhost.py --serial cvv-confere --lmk <LMK em hex> -n 16
```

Cada volta gera uma chave, pede os três códigos de um cartão inventado e
confere cada um com uma segunda implementação em Python.

---

## 37. DUKPT — uma chave por transação

Imagine um milhão de terminais em campo. Se todos compartilham a mesma
chave, um terminal aberto na bancada de alguém compromete a rede inteira.
Se cada um tem chave própria, é preciso distribuir e gerenciar um milhão de
chaves.

**DUKPT** (*Derived Unique Key Per Transaction*) resolve os dois de uma vez:

- Existe uma **BDK** (*Base Derivation Key*), que fica só no HSM do
  adquirente e **nunca vai para o terminal**.
- Cada terminal recebe, na personalização, uma chave inicial derivada da BDK
  com o identificador dele.
- A cada transação, o terminal deriva uma **chave nova** e **apaga a
  anterior**.
- O terminal envia o **KSN** (*Key Serial Number*) — identificador do
  dispositivo mais um contador de transação. Com o KSN e a BDK, o HSM do
  adquirente rederiva exatamente a mesma chave.

As três propriedades que isso compra:

1. **Compromisso isolado.** Abrir um terminal não dá nada sobre os outros.
2. **Sigilo do passado.** As chaves usadas já foram apagadas no terminal;
   quem o abrir agora não decifra o que passou por ele ontem.
3. **Nada para distribuir.** O HSM rederiva; não existe base de um milhão de
   chaves para sincronizar.

### 37.1 X9.24-1 (TDES) e X9.24-3 (AES)

| | TDES DUKPT (X9.24-1) | AES DUKPT (X9.24-3) |
|---|---|---|
| Cifra | 3DES de duas chaves | AES-128/192/256 |
| Registradores de chave futura | 21 | 32 |
| Derivação | esquema próprio, histórico | função de derivação uniforme |
| Situação | legado, em desativação | o caminho adiante |

A variante AES não é só "a mesma coisa com outra cifra": a derivação foi
reescrita para ser uniforme e para suportar chaves de propósitos diferentes
a partir da mesma raiz — separação de chaves construída no esquema, em vez
de convencionada por fora.

**A variante AES é implementável neste projeto.** A TDES não, e o motivo é
o assunto da próxima seção.

---

## 38. O que este projeto pode e o que não pode ensinar

A separação não é por dificuldade. É por **hardware** e por **procedência
de vetor de teste**.

| Assunto | Aqui? | O que decide |
|---|---|---|
| PIN block formato 4 | **feito** | é AES, e AES é o que existe no fabric |
| Chaves 3DES: gerar, conferir, exportar | **feito** | motor em software, com vetores oficiais (seção 39.8) |
| PIN block formato 0 | **feito** (seção 33.1) | a cifra é o 3DES, que entra no equipamento |
| Tradução de PIN | **feita** (`P0`, formatos 0 e 4) | o valor está no formato do comando e no oráculo, não na cifra |
| Verificação de PIN e ataque de decimalização | **feito** (seção 35) | é ataque de **API**, sobre o método real |
| DUKPT AES (X9.24-3) | **planejado** | é AES |
| CVV, CVV2 e iCVV | **feito** (seção 36) | inerentemente 3DES; não há variante AES em uso |
| PVV | **feito** (seção 35.2) | idem |
| DUKPT TDES (X9.24-1) | **planejado** | idem |
| Criptogramas EMV, emissão de PIN | fora, por enquanto | são funções de emissor, maiores que as demais |

### 38.1 Um HSM precisa de 3DES?

A resposta depende de qual HSM, e a diferença ensina mais que a resposta.

**HSM de propósito geral, hoje: não.** O NIST desautorizou o TDEA para
*cifrar* a partir de 2024 (SP 800-131A Rev. 2). Ele sobrevive apenas como
algoritmo de **decifração legada** — para abrir o que foi cifrado antes.
Projeto novo usa AES, e um módulo que ofereça 3DES para cifrar dados novos
está oferecendo um pé no passado.

**HSM de pagamento em produção: sim, na prática.** Um módulo sem 3DES
não conversa com a rede. PIN blocks sob ZPK de 3DES, PVV e CVV sob chaves
3DES, terminais DUKPT TDES aos milhões em campo — tudo isso existe agora, em
operação, movendo dinheiro. Um módulo que só faça AES é inútil como
substituto de um que está instalado.

**E aqui está o ponto que vale o capítulo:** a migração para key blocks e
para AES foi mandatada em fases pelo PCI e levou **mais de uma década**.
Não porque AES seja difícil, mas porque trocar criptografia numa rede com
milhões de pontas não é decisão técnica — é logística, contrato e prazo
regulatório. Terminal em campo não se atualiza por vontade; norma de
mensagem não muda sozinha; e cada elo da cadeia precisa aceitar o novo
formato *antes* que o anterior possa ser desligado.

É por isso que criptografia obsoleta sobrevive tanto em pagamentos. Não é
descuido: é o custo real de mover um ecossistema.

**Este projeto: sim.** O objetivo dele é aprender como o mercado de meios
de pagamento trabalha, e o mercado trabalha com 3DES. Um equipamento só de
AES ensinaria o destino da migração, e não o caminho em que todo mundo
ainda está.

### 38.2 Como o 3DES entra aqui

O coprocessador deste projeto amarra o tamanho de chave em **AES-256, sem
caminho para AES-128** — porque um modo mais fraco alcançável por escrita em
registrador é um *downgrade* de graça para quem tomar o barramento. O 3DES
não mexe nisso: ele é um **motor separado**, em software, rotulado como
legado. É o que um HSM de pagamento real tem.

Três regras cercam o motor legado:

- **A LMK continua AES-256.** As chaves 3DES são guardadas sob ela, em key
  block. É a configuração atual do mercado.
- **Uma chave nunca sai embrulhada por outra mais fraca.** Uma chave de
  troca 3DES transporta chaves 3DES, e nunca uma chave AES. Sem essa regra,
  a chave mais fraca do sistema define a força de todas.
- **DES simples não existe.** As chaves têm comprimento duplo ou triplo.

A seção 39 explica o DES e o 3DES.

### 38.3 O obstáculo maior são os vetores

A regra inviolável deste projeto diz que, se um teste de resposta conhecida
falha, **o erro está no código, não no vetor** — e isso só vale se a
procedência do vetor for verificável por terceiros. AES, SHA, HMAC, CMAC e
CTR_DRBG têm vetores públicos do NIST e do IETF, com hash registrado.

Criptografia de pagamento não tem esse luxo. Os vetores da ANSI X9.24-3
estão atrás de paywall; os de CVV e PVV vivem em documentação de bandeira e
em manual de fabricante. Sem vetor autoritativo não há KAT, e "implementei e
parece certo" é exatamente o que a regra existe para proibir.

**Consequência prática:** onde não houver vetor público, o item não entra —
ou entra explicitamente marcado como não verificado. Há um caminho do meio,
usado no key block e no formato 4: um valor publicado por uma implementação
aberta e independente, fixado por hash e marcado como **fonte secundária**.
Ele não tem a autoridade de uma norma, mas é um número que este projeto não
escolheu. Preferir a lacuna
honesta à cobertura fingida é o mesmo critério que orienta o resto do
documento.

### 38.4 Uma regra que não se negocia

⚠ **Nenhum número de cartão real, nunca.** Pela mesma razão que nenhuma
chave de produção. Gerar CVV ou PIN para um PAN que existe deixa de ser
exercício, e o fato de o dispositivo ser de brinquedo não muda isso.

---

## 39. DES e 3DES — a cifra que o mercado ainda usa

O AES tem seção própria na Parte I. O DES entra aqui, na Parte VII, porque é
em pagamentos que ele sobrevive. Quem opera um HSM de pagamento lida com
chaves 3DES todos os dias, e precisa saber o que elas são, o que os termos
"comprimento duplo" e "paridade" querem dizer, e por que a cifra está sendo
aposentada.

### 39.1 A rede de Feistel

O DES é uma **rede de Feistel**. A ideia resolve um problema de projeto:
como construir uma cifra que se desfaz, a partir de uma função que não
precisa ser desfeita.

O bloco é cortado em duas metades, `L` e `R`. Cada rodada faz:

```
    novo L = R
    novo R = L XOR f(R, subchave)
```

A metade `R` passa intacta, e a função `f` só é usada para mascarar a outra
metade. Para desfazer a rodada, basta calcular `f` de novo sobre o mesmo
`R`, que está à vista, e repetir o XOR. A função `f` nunca é invertida.

A consequência prática: **decifrar é cifrar com as subchaves na ordem
inversa.** O mesmo circuito faz as duas coisas, o que valia ouro no hardware
dos anos 1970.

Um exemplo de brinquedo, com bloco de 8 bits, três rodadas, subchaves
`3, 12, 9` e a função `f(R, k) = ((R + k) · 7 + 3) mod 16`:

```
    cifrar A6:                         L    R
        entrada                        A    6
        rodada 1   f(6, 3)  = 2        6    A XOR 2 = 8
        rodada 2   f(8, 12) = F        8    6 XOR F = 9
        rodada 3   f(9, 9)  = 1        9    8 XOR 1 = 9
        troca final das metades        9    9          cifrado: 99

    decifrar 99, com as subchaves 9, 12, 3:
        rodada 1   f(9, 9)  = 1        9    9 XOR 1 = 8
        rodada 2   f(8, 12) = F        8    9 XOR F = 6
        rodada 3   f(6, 3)  = 2        6    8 XOR 2 = A
        troca final das metades        A    6          de volta: A6
```

Repare que essa `f` não tem inversa única, e a cifra se desfaz do mesmo
jeito.

### 39.2 O DES por dentro

O DES (FIPS 46, de 1977) cifra blocos de **64 bits** com uma chave de **56
bits**, em **16 rodadas** de Feistel.

```
    bloco de 64 bits
         │
    permutação inicial (IP)
         │
    L (32 bits)   R (32 bits)
         │   16 rodadas: L, R = R, L XOR f(R, subchave da rodada)
         │
    troca das metades
         │
    permutação final (o inverso da IP)
         │
    bloco cifrado
```

A função `f` de cada rodada tem quatro passos:

1. **Expansão.** Os 32 bits de `R` viram 48, repetindo alguns bits. Cada bit
   de entrada passa a influenciar mais de uma caixa S.
2. **Mistura da chave.** XOR com a subchave de 48 bits da rodada.
3. **Caixas S.** Os 48 bits são cortados em oito grupos de 6. Cada grupo
   entra numa tabela diferente, de 64 posições, e sai com 4 bits. São oito
   tabelas: as **caixas S**.
4. **Permutação P.** Os 32 bits que saem são embaralhados, para que a saída
   de uma caixa S alimente várias caixas na rodada seguinte.

As caixas S são o coração da cifra. Tudo o mais é XOR e troca de posição de
bits, que são operações lineares: uma cifra só com elas se resolve como um
sistema de equações. As caixas S são a única parte **não linear**.

As tabelas não foram escolhidas ao acaso. A equipe que projetou o DES na
IBM já conhecia, nos anos 1970, o ataque que a comunidade acadêmica só
publicou em 1990, a **criptoanálise diferencial** (Biham e Shamir), e
desenhou as caixas S para resistir a ele. Isso só foi confirmado em 1994
(Coppersmith). O DES resistiu à criptoanálise por décadas: o melhor ataque
publicado, a criptoanálise linear (Matsui, 1993), precisa de cerca de 2⁴³
pares de texto conhecidos. O que derrubou o DES foi outra coisa.

**As subchaves.** A chave de 56 bits é cortada em duas metades de 28. A cada
rodada as metades giram um ou dois bits, e uma tabela escolhe 48 dos 56 bits
para formar a subchave. Em 16 rodadas, cada bit da chave é usado cerca de 14
vezes.

### 39.3 A chave: 64 bits que são 56

Uma chave DES é escrita com 8 bytes, mas a cifra só usa 7 bits de cada
byte. O bit mais baixo é de **paridade**: ele é ajustado para que o byte
tenha um número ímpar de bits em 1.

```
    byte da chave       0000 000?      os 7 bits altos são a chave
    paridade ímpar      0000 0001      o bit baixo completa a conta

    exemplo             0123456789ABCDEF     tem paridade ímpar em todo byte
```

A paridade não protege nada: ela só detecta uma chave corrompida na
digitação ou no transporte. A cifra ignora esses bits, e duas chaves que só
diferem neles cifram igual. Quem gera uma chave DES acerta a paridade, e
muitos equipamentos recusam uma chave que chega sem ela.

O DES tem ainda um pequeno conjunto de **chaves fracas**: quatro chaves com
todas as subchaves iguais, em que cifrar duas vezes devolve o texto
original, e seis pares de chaves semifracas. Um gerador de chaves as evita.

### 39.4 Por que o DES caiu

Pela chave. 56 bits são 2⁵⁶ chaves, cerca de 72 quatrilhões, e isso é pouco
para busca exaustiva:

- **1998.** Uma máquina construída para isso, com custo de cerca de 250 mil
  dólares, achou uma chave DES em **56 horas** (*Cracking DES*, Electronic
  Frontier Foundation).
- **1999.** A mesma máquina, com uma rede de computadores voluntários,
  levou **22 horas**.
- **2005.** O NIST retirou a FIPS 46.

A cifra não foi quebrada: ela foi alcançada. A lição se repete no projeto de
qualquer sistema: uma cifra sem defeito conhecido ainda cai se o espaço de
chaves for pequeno.

### 39.5 O 3DES

O remédio foi usar o DES três vezes, com chaves diferentes. É o **3DES**,
também chamado **TDES** ou **TDEA** (SP 800-67):

```
    cifrar:     C = E(K3,  D(K2,  E(K1, P)))        cifra, decifra, cifra
    decifrar:   P = D(K1,  E(K2,  D(K3, C)))
```

**Por que não duas vezes?** Parece que duas chaves de 56 bits dariam 112
bits. Não dão, por causa do ataque de **encontro no meio**: com um par de
texto claro e cifrado conhecido, o atacante cifra o claro com todas as 2⁵⁶
chaves, guarda os resultados, decifra o cifrado com todas as 2⁵⁶ chaves e
procura uma coincidência no meio. O custo é de cerca de 2⁵⁷ operações, e não
2¹¹². Cifrar duas vezes quase não ganha força. Cifrar três vezes ganha.

**Por que decifrar no meio?** Por compatibilidade. Com `K1 = K2 = K3`, as
duas primeiras operações se cancelam e sobra um DES simples. Um equipamento
3DES conversava com um equipamento DES antigo só repetindo a chave.

**Os dois tamanhos de chave**, que o mercado chama pelo comprimento:

| Nome | Chaves | Bytes | Força |
|---|---|---|---|
| comprimento triplo | `K1`, `K2`, `K3` diferentes | 24 | cerca de 112 bits: o encontro no meio tira uma das três |
| comprimento duplo | `K1`, `K2`, e `K3 = K1` | 16 | 112 bits no papel; o NIST a avalia em cerca de 80 bits quando o atacante tem muitos pares |
| comprimento simples | `K1 = K2 = K3` | 8 | 56 bits: é o DES simples |

O **comprimento duplo** é o mais comum em pagamentos, por herança: 16 bytes
cabiam onde os equipamentos antigos guardavam chaves. O NIST deixou de
aceitá-lo para cifrar em 2015, e o comprimento triplo, depois de 2023
(SP 800-131A). A rede de pagamento segue outro calendário, o do PCI, e ainda
está migrando (seção 38.1).

**O KCV de uma chave 3DES** é calculado com o próprio 3DES: cifram-se 8
bytes de zeros, e os primeiros 3 bytes do resultado são o KCV. A chave de
comprimento duplo `0123456789ABCDEF FEDCBA9876543210` tem KCV `08D7B4`.

### 39.6 O bloco de 64 bits

O 3DES consertou a chave, e não o bloco. Com blocos de 64 bits, depois de
cerca de 2³² blocos cifrados com a mesma chave (32 GB), dois blocos cifrados
iguais passam a ser prováveis, e cada coincidência revela o XOR de dois
blocos de texto claro. É o ataque **Sweet32** (Bhargavan e Leurent, 2016,
CVE-2016-2183), que tirou o 3DES das conexões da internet.

Em pagamentos o efeito é outro. Um PIN block é **um** bloco, e uma chave de
PIN nunca cifra gigabytes. O problema do bloco pequeno aparece de outra
forma: no formato 0, sem enchimento aleatório, o mesmo PIN na mesma conta dá
sempre o mesmo bloco cifrado (seção 33.1). O formato 4 resolve isso com o
bloco de 128 bits do AES, que tem espaço para o enchimento aleatório.

### 39.7 DES, 3DES e AES, lado a lado

| | DES | 3DES | AES |
|---|---|---|---|
| Ano | 1977 | 1998 (como norma) | 2001 |
| Estrutura | Feistel, 16 rodadas | três DES em sequência | substituição e permutação, 10 a 14 rodadas |
| Bloco | 64 bits | 64 bits | 128 bits |
| Chave | 56 bits | 112 ou 168 bits | 128, 192 ou 256 bits |
| Força real | 56 bits | 80 a 112 bits | igual ao tamanho da chave |
| Paridade na chave | sim | sim | não |
| Custo em software | base | três vezes o DES | menor que o do DES |
| Situação no NIST | retirado em 2005 | proibido para cifrar dados novos depois de 2023 | em vigor |
| Situação em pagamentos | proibido | dominante, em migração | o destino da migração |

Duas linhas resumem a diferença de projeto. O DES é feito de permutações de
bits, baratas em hardware e caras em software; o AES foi escolhido num
concurso público que cobrava desempenho em software. E o AES não tem bits de
paridade nem chaves fracas: toda sequência de bits do tamanho certo é uma
chave boa.

### 39.8 O 3DES neste equipamento

O 3DES é um **motor separado, em software**, ao lado do AES do coprocessador.
Ele serve às funções de pagamento, e a LMK continua AES-256 (seção 38.2).

**Gerar uma chave 3DES.** O `K0` ganhou um campo opcional no fim do pedido:

| Campo | Chave gerada |
|---|---|
| ausente, ou `A4` | AES-256 (32 bytes) |
| `T2` | 3DES de comprimento duplo (16 bytes) |
| `T3` | 3DES de comprimento triplo (24 bytes) |

O dígito é o tamanho da chave em blocos de 8 bytes. `T1` seria DES simples,
e o equipamento responde `16`: DES simples não existe aqui.

```
    pedido      K0  P0 B E T2            chave de PIN, cifra e decifra,
                                         exportável, 3DES duplo
    resposta    K1  00  D0112P0TB00E0000...  KCV
                        |    | |
                        |    | algoritmo T
                        |    uso P0
                        key block de 112 caracteres, sob a LMK
```

O que o equipamento garante sobre a chave que gera:

- **Paridade ímpar** em todo byte (seção 39.3).
- **Nenhuma chave fraca.** Se alguma das partes cair numa das 16 chaves
  fracas ou semifracas do DES, ou se duas partes saírem iguais, o
  equipamento sorteia de novo. A chance é desprezível; a regra está na
  SP 800-67, e um gerador que a ignora não passa numa avaliação.
- **KCV calculado com 3DES**, como na seção 39.5. O `K2` devolve o mesmo
  KCV para o mesmo bloco, e o host o confere sem conhecer a chave.

**A chave 3DES no key block.** O cabeçalho leva o algoritmo `T`, e o bloco
tem 112 caracteres, para os dois comprimentos. O bloco é protegido pela LMK
AES-256, com as mesmas subchaves e o mesmo MAC das chaves AES: uma chave
mais forte protege uma mais fraca, e nunca o contrário.

**O que uma chave 3DES ainda não faz.** O tipo da chave trava os comandos, e
cada trava cai quando a função correspondente entra:

| Comando | Com chave 3DES | Quando muda |
|---|---|---|
| `K0`, `K2` | gera e confere | — |
| `K4`, `K6` sob uma KEK AES | exporta e importa | — |
| `K4`, `K6` com uma KEK 3DES | exporta e importa, em bloco versão B | feito na etapa 8.7, seção 39.9 |
| `P0` | traduz no formato 0; no formato 4, recusa (`11`) | feito na etapa 8.4, seção 34.2 |
| `C0`, `C2`, `M0`, `M2` | recusa (`11`) | com a cifra de dados e o MAC em 3DES |

A recusa não é só política. O coprocessador só faz AES-256: uma chave de 16
bytes entregue a ele seria lida além do fim. A checagem do algoritmo fica no
key store, no mesmo lugar em que ficam as de uso e de modo.

**O autoteste.** O 3DES é testado **no primeiro uso** depois do boot, e não
no boot, como a assinatura RSA e o ECDSA (seção 30). São 25 vetores
oficiais do NIST: os 19 que exercitam cada entrada das caixas S, e seis
mensagens que cobrem a chave dupla, a tripla, o modo CBC e as duas direções.
Se o teste reprova, o equipamento apaga as chaves, vai para `TAMPERED` e
responde `91`.

**Tempo constante.** O motor consulta as caixas S por índice, e o índice
depende da chave. Num processador com cache, isso cria um canal de tempo.
O processador deste equipamento não tem cache, e toda consulta leva o mesmo
tempo.

### 39.9 A troca de chaves 3DES: a KEK 3DES e o key block versão B

A seção 28 mostra como duas instituições trocam uma chave: as duas formam a
mesma **KEK** (chave de troca, uso `K0`) por componentes, e uma chave viaja
entre elas cifrada sob essa KEK, num key block. Ali a KEK é AES-256. Muitas
redes de pagamento ainda trocam chaves sob uma KEK **3DES**: o parceiro do
outro lado tem equipamento antigo, ou a rede ainda não migrou. Um HSM de
pagamento precisa falar com esse parceiro. Esta seção mostra como.

**O key block versão B.** O formato X9.143 tem uma versão para cada tipo de
chave de proteção. Este equipamento usa duas:

| | Versão D | Versão B |
|---|---|---|
| chave de proteção (KBPK) | AES (aqui, AES-256) | 3DES duplo ou triplo |
| onde se usa aqui | sob a LMK, e sob uma KEK AES | só sob uma KEK 3DES |
| subchaves KBEK e KBAK | CMAC-AES, 16 bytes por chamada | CMAC-TDES, 8 bytes por chamada |
| cifra do corpo | AES-CBC, bloco de 16 bytes | 3DES-CBC, bloco de 8 bytes |
| MAC | 16 bytes (32 caracteres) | 8 bytes (16 caracteres) |
| bloco de uma chave 3DES dupla | 112 caracteres | 80 caracteres |
| bloco de uma chave 3DES tripla | 112 caracteres | 96 caracteres |

O resto é igual: o cabeçalho de 16 caracteres entra no MAC, o MAC é
calculado sobre o corpo em claro e depois serve de IV do CBC, e o
enchimento é aleatório. As versões A e C, mais antigas, derivam as
subchaves por um XOR com uma constante (variante), e a norma as dá por
obsoletas. Este equipamento não as faz.

**O CMAC-TDES.** O CMAC (NIST SP 800-38B) é o código de autenticação que o
equipamento usa com AES no key block versão D. Ele encadeia a mensagem em
CBC e, no último bloco, mistura uma de duas subchaves internas, conforme o
bloco esteja cheio ou tenha enchimento: é isso que o protege contra o
ataque de extensão do CBC-MAC puro. O CMAC-TDES é o mesmo algoritmo com o
bloco de 64 bits do 3DES. Muda uma constante: na dobra que gera as
subchaves internas, o XOR depois do deslocamento é com `1B` (o polinômio de
grau 64 da norma), e não com `87`, o de grau 128. O equipamento confere o
CMAC-TDES contra os vetores do NIST.

**A derivação das subchaves.** Cada chamada do CMAC-TDES recebe 8 bytes e
devolve 8. Para uma KBPK dupla (16 bytes) são duas chamadas por subchave;
para uma tripla, três. Os 8 bytes de entrada são:

```
    contador(1) . propósito(2) . 00 . algoritmo(2) . bits(2)

    propósito   0000 = KBEK (cifra)        0001 = KBAK (MAC)
    algoritmo   0000 = 3DES duplo          0001 = 3DES triplo
    bits        0080 = 128                 00C0 = 192
```

Um exemplo com números, do bloco publicado pela biblioteca `psec` (valor de
terceiros, seção 42.1). A KBPK é `DD7515F2BFC17F85CE48F3CA25CB21F6`, dupla:

```
    KBEK, 1a chamada   CMAC(KBPK, 0100000000000080) = 698832F8778A7CFC
    KBEK, 2a chamada   CMAC(KBPK, 0200000000000080) = BC79559DAB07B88A
    KBAK, 1a chamada   CMAC(KBPK, 0100010000000080) = DD6CEEC1782D8453
    KBAK, 2a chamada   CMAC(KBPK, 0200010000000080) = 671BF8358AF9DB47

    KBEK = 698832F8778A7CFC BC79559DAB07B88A
    KBAK = DD6CEEC1782D8453 671BF8358AF9DB47
```

Só o terceiro byte da entrada muda entre KBEK e KBAK, e as duas subchaves
não têm nada em comum.

**O bloco, aberto.** O bloco publicado é:

```
    B0080P0TE00E0000  94B420079CC80BA3 461F86FE26EFC4A3 B8E4FA4C5F534117  6EED7B727B8A248E
    cabeçalho         corpo cifrado, 24 bytes                             MAC, 8 bytes
```

Decifrar o corpo com a KBEK em 3DES-CBC, com o MAC como IV, dá:

```
    0080  3F419E1CB7079442AA37474C2EFBF8B8  1C2965473CE2
    bits  a chave, 16 bytes                 enchimento, 6 bytes
```

O CMAC-TDES com a KBAK sobre o cabeçalho e esse corpo em claro dá
`6EED7B727B8A248E`, o MAC do bloco: ele é íntegro. A chave tem KCV `57C409`.
O corpo tem 2 + 16 + 6 = 24 bytes, múltiplo de 8, e o bloco tem
16 + 2 × 24 + 2 × 8 = 80 caracteres. Todos esses números foram conferidos
por programa (`host/test_tr31b.py`).

**A regra de força.** Uma chave nunca sai embrulhada por outra mais fraca
(decisão de projeto da seção 38.2). Para a KEK, a regra fica assim:

| KEK | Transporta | Não transporta |
|---|---|---|
| AES-256 | chave AES e chave 3DES | — |
| 3DES tripla | chave 3DES dupla e tripla | chave AES |
| 3DES dupla | chave 3DES dupla | chave 3DES tripla, chave AES |

A dupla não leva a tripla porque a força efetiva da 3DES dupla é menor: a
SP 800-57 dá cerca de 80 bits à dupla e 112 à tripla. A checagem mora no key
store, numa função só, e vale para os dois sentidos.

**A KEK 3DES neste equipamento.**

1. **Formar a KEK.** No console, por componentes, com dual control a cada
   um, como a KEK AES. O algoritmo e o tamanho vêm do pedido: componentes
   de 16 bytes dão uma 3DES dupla, de 24 uma tripla. O equipamento devolve o
   KCV de cada componente, calculado com 3DES, para o custodiante conferir o
   seu.

   ```
   python3 host/hsmtool.py comp-load 0 2 --alg T2 --uso K0 --modo B --exp E <16 bytes hex>
   python3 host/hsmtool.py comp-load 1 2 --alg T2 --uso K0 --modo B --exp E <16 bytes hex>
   python3 host/hsmtool.py kcv --tdes <componente 0> <componente 1>   # a conta, no PC
   ```

2. **Guardar.** A KEK fica num slot do console e vai para a flash,
   embrulhada sob a LMK, como as chaves AES. Desligar e religar não a perde.
3. **Levar à porta host.** `export-key` devolve a KEK num bloco versão D sob
   a LMK, que o host guarda.
4. **Exportar uma chave.** `K4` com o bloco da KEK 3DES e o da chave devolve
   a chave num bloco **versão B** sob a KEK, e o KCV. Chave AES, ou tripla
   sob KEK dupla: `13`, "esta KEK não serve para esta chave".
5. **Importar uma chave.** `K6` com o bloco da KEK 3DES e um bloco versão B
   recebido devolve a chave sob a LMK, e o KCV. Bloco de outra versão, chave
   que a regra de força recusa, MAC errado: `10`, o mesmo código para toda
   recusa do bloco recebido.

**O que o equipamento não aceita num bloco B.** Chave de DES simples (8
bytes) e blocos opcionais no cabeçalho. Os dois são válidos na norma, e o
equipamento os recusa de propósito: DES simples não existe aqui, e um bloco
opcional que o firmware ignorasse continuaria dentro do MAC, que fecharia
sobre um campo que ninguém leu.

**O autoteste.** O autoteste de primeiro uso do 3DES (seção 39.8) passou a
incluir um vetor de CMAC-TDES do NIST, a abertura do bloco publicado acima,
um bit trocado no cabeçalho, que tem de ser recusado, e uma ida e volta. Ele
roda também quando o boot restaura da flash uma chave 3DES.
