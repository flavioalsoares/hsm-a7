# Parte VII — Criptografia de pagamento

Esta parte existe porque o modelo de referência deste projeto passou a ser
um **HSM de pagamento comercial**. Entender o que
esses equipamentos fazem o dia inteiro é o que separa "sei o que é uma
fronteira criptográfica" de "sei por que aquele comando existe".

O equipamento implementa uma parte do que está aqui: os PIN blocks formato
0 e 4 e a tradução de PIN (seções 33 e 34), a verificação de PIN (seção 35),
o CVV (seção 36), o DUKPT (seção 37), as chaves 3DES (seção 39), a troca de
chaves 3DES com outra instituição (seção 39.9) e o MAC e a cifra de dados com
3DES (seção 39.10). A seção 38 explica o que é
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


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="37" class="ts">campo do PIN</text><rect class="cxa" x="150" y="20" width="28" height="24"/><text x="164" y="37" text-anchor="middle" class="tm">0</text><rect class="cxa" x="180" y="20" width="28" height="24"/><text x="194" y="37" text-anchor="middle" class="tm">5</text><rect class="cxa" x="210" y="20" width="28" height="24"/><text x="224" y="37" text-anchor="middle" class="tm">4</text><rect class="cxa" x="240" y="20" width="28" height="24"/><text x="254" y="37" text-anchor="middle" class="tm">8</text><rect class="cxa" x="270" y="20" width="28" height="24"/><text x="284" y="37" text-anchor="middle" class="tm">2</text><rect class="cxa" x="300" y="20" width="28" height="24"/><text x="314" y="37" text-anchor="middle" class="tm">1</text><rect class="cxa" x="330" y="20" width="28" height="24"/><text x="344" y="37" text-anchor="middle" class="tm">3</text><rect class="cxa" x="360" y="20" width="28" height="24"/><text x="374" y="37" text-anchor="middle" class="tm">F</text><rect class="cxa" x="390" y="20" width="28" height="24"/><text x="404" y="37" text-anchor="middle" class="tm">F</text><rect class="cxa" x="420" y="20" width="28" height="24"/><text x="434" y="37" text-anchor="middle" class="tm">F</text><rect class="cxa" x="450" y="20" width="28" height="24"/><text x="464" y="37" text-anchor="middle" class="tm">F</text><rect class="cxa" x="480" y="20" width="28" height="24"/><text x="494" y="37" text-anchor="middle" class="tm">F</text><rect class="cxa" x="510" y="20" width="28" height="24"/><text x="524" y="37" text-anchor="middle" class="tm">F</text><rect class="cxa" x="540" y="20" width="28" height="24"/><text x="554" y="37" text-anchor="middle" class="tm">F</text><rect class="cxa" x="570" y="20" width="28" height="24"/><text x="584" y="37" text-anchor="middle" class="tm">F</text><rect class="cxa" x="600" y="20" width="28" height="24"/><text x="614" y="37" text-anchor="middle" class="tm">F</text>
<text x="10" y="73" class="ts">campo do PAN</text><rect class="cx" x="150" y="56" width="28" height="24"/><text x="164" y="73" text-anchor="middle" class="tm">0</text><rect class="cx" x="180" y="56" width="28" height="24"/><text x="194" y="73" text-anchor="middle" class="tm">0</text><rect class="cx" x="210" y="56" width="28" height="24"/><text x="224" y="73" text-anchor="middle" class="tm">0</text><rect class="cx" x="240" y="56" width="28" height="24"/><text x="254" y="73" text-anchor="middle" class="tm">0</text><rect class="cx" x="270" y="56" width="28" height="24"/><text x="284" y="73" text-anchor="middle" class="tm">9</text><rect class="cx" x="300" y="56" width="28" height="24"/><text x="314" y="73" text-anchor="middle" class="tm">9</text><rect class="cx" x="330" y="56" width="28" height="24"/><text x="344" y="73" text-anchor="middle" class="tm">9</text><rect class="cx" x="360" y="56" width="28" height="24"/><text x="374" y="73" text-anchor="middle" class="tm">0</text><rect class="cx" x="390" y="56" width="28" height="24"/><text x="404" y="73" text-anchor="middle" class="tm">1</text><rect class="cx" x="420" y="56" width="28" height="24"/><text x="434" y="73" text-anchor="middle" class="tm">2</text><rect class="cx" x="450" y="56" width="28" height="24"/><text x="464" y="73" text-anchor="middle" class="tm">3</text><rect class="cx" x="480" y="56" width="28" height="24"/><text x="494" y="73" text-anchor="middle" class="tm">4</text><rect class="cx" x="510" y="56" width="28" height="24"/><text x="524" y="73" text-anchor="middle" class="tm">5</text><rect class="cx" x="540" y="56" width="28" height="24"/><text x="554" y="73" text-anchor="middle" class="tm">6</text><rect class="cx" x="570" y="56" width="28" height="24"/><text x="584" y="73" text-anchor="middle" class="tm">7</text><rect class="cx" x="600" y="56" width="28" height="24"/><text x="614" y="73" text-anchor="middle" class="tm">8</text>
<text x="10" y="109" class="tb">XOR</text><rect class="cxd" x="150" y="92" width="28" height="24"/><text x="164" y="109" text-anchor="middle" class="tm">0</text><rect class="cxd" x="180" y="92" width="28" height="24"/><text x="194" y="109" text-anchor="middle" class="tm">5</text><rect class="cxd" x="210" y="92" width="28" height="24"/><text x="224" y="109" text-anchor="middle" class="tm">4</text><rect class="cxd" x="240" y="92" width="28" height="24"/><text x="254" y="109" text-anchor="middle" class="tm">8</text><rect class="cx" x="270" y="92" width="28" height="24"/><text x="284" y="109" text-anchor="middle" class="tm">B</text><rect class="cx" x="300" y="92" width="28" height="24"/><text x="314" y="109" text-anchor="middle" class="tm">8</text><rect class="cx" x="330" y="92" width="28" height="24"/><text x="344" y="109" text-anchor="middle" class="tm">A</text><rect class="cx" x="360" y="92" width="28" height="24"/><text x="374" y="109" text-anchor="middle" class="tm">F</text><rect class="cx" x="390" y="92" width="28" height="24"/><text x="404" y="109" text-anchor="middle" class="tm">E</text><rect class="cx" x="420" y="92" width="28" height="24"/><text x="434" y="109" text-anchor="middle" class="tm">D</text><rect class="cx" x="450" y="92" width="28" height="24"/><text x="464" y="109" text-anchor="middle" class="tm">C</text><rect class="cx" x="480" y="92" width="28" height="24"/><text x="494" y="109" text-anchor="middle" class="tm">B</text><rect class="cx" x="510" y="92" width="28" height="24"/><text x="524" y="109" text-anchor="middle" class="tm">A</text><rect class="cx" x="540" y="92" width="28" height="24"/><text x="554" y="109" text-anchor="middle" class="tm">9</text><rect class="cx" x="570" y="92" width="28" height="24"/><text x="584" y="109" text-anchor="middle" class="tm">8</text><rect class="cx" x="600" y="92" width="28" height="24"/><text x="614" y="109" text-anchor="middle" class="tm">7</text>
<path class="lnd" d="M150,124 V134 H268 V124"/>
<text x="209" y="148" text-anchor="middle" class="ts td">controle, tamanho e os 2</text>
<text x="209" y="160" text-anchor="middle" class="ts td">primeiros dígitos: sem mistura</text>
<line class="ln" x1="390" y1="124" x2="390" y2="160" marker-end="url(#seta)"/>
<text x="400" y="146" class="ts">3DES sob a chave de PIN</text>
<rect class="cxv" x="300" y="162" width="190" height="28"/><text x="395" y="181" text-anchor="middle" class="tm">2DC3F05263417865</text>
<text x="500" y="181" class="ts">o PIN block</text>
<text x="340" y="206" text-anchor="middle" class="ts">PIN 48213, PAN inventado 9999990123456789: o campo do PAN usa os 12 dígitos antes do último</text>
</svg>
<figcaption>Figura 33.1 — O formato 0, nibble a nibble. Um XOR antes de uma única cifra; mesmo PIN, mesma conta e mesma chave dão sempre o mesmo bloco.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 220" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="20" width="270" height="34"/><text x="20" y="35" class="ts">bloco A: PIN e aleatório</text><text x="20" y="48" class="tm ts">441234AAAAAAAAAAFFFFFFFFFFFFFFFF</text>
<line class="ln" x1="145" y1="54" x2="145" y2="78" marker-end="url(#seta)"/>
<rect class="cxd" x="95" y="80" width="100" height="28"/><text x="145" y="99" text-anchor="middle" class="tb">AES_K</text>
<line class="ln" x1="195" y1="94" x2="303" y2="94" marker-end="url(#seta)"/>
<text x="250" y="88" text-anchor="middle" class="ts tm">CCFFA14C…</text>
<circle class="cx" cx="320" cy="94" r="15"/><text x="320" y="99" text-anchor="middle" class="tb">⊕</text>
<rect class="cx" x="380" y="20" width="290" height="34"/><text x="390" y="35" class="ts">bloco B: o PAN</text><text x="390" y="48" class="tm ts">71234567890123456789000000000000</text>
<line class="ln" x1="460" y1="54" x2="335" y2="88" marker-end="url(#seta)"/>
<line class="ln" x1="335" y1="94" x2="398" y2="94" marker-end="url(#seta)"/>
<text x="460" y="88" class="ts">bloco C</text><text x="460" y="112" class="ts tm">BDDCE42B…</text>
<line class="ln" x1="460" y1="116" x2="460" y2="138" marker-end="url(#seta)"/>
<rect class="cxd" x="410" y="140" width="100" height="28"/><text x="460" y="159" text-anchor="middle" class="tb">AES_K</text>
<line class="ln" x1="460" y1="168" x2="460" y2="186" marker-end="url(#seta)"/>
<rect class="cxv" x="360" y="188" width="300" height="26"/><text x="510" y="206" text-anchor="middle" class="tm ts">28B41FDDD29B743E93124BD8E32D921E</text>
<text x="20" y="160" class="ts">o PAN entra ENTRE as duas cifras:</text>
<text x="20" y="174" class="ts">trocar um dígito do PAN embaralha</text>
<text x="20" y="188" class="ts">o bloco inteiro na abertura</text>
</svg>
<figcaption>Figura 33.2 — O formato 4, com o exemplo do texto (chave AES-128 de teste, PIN 1234). Duas cifras, e o PAN no meio.</figcaption>
</figure>

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
O caminho inteiro, com a aplicação de cada instituição entre a rede e o
HSM, está na seção 24.14.


<figure class="fig">
<svg viewBox="0 0 680 170" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="50" width="100" height="50"/><text x="60" y="72" text-anchor="middle" class="tb">terminal</text><text x="60" y="88" text-anchor="middle" class="ts">cifra o PIN</text>
<rect class="fr" x="150" y="40" width="130" height="70"/><text x="215" y="62" text-anchor="middle" class="tb">HSM</text><text x="215" y="78" text-anchor="middle" class="ts">adquirente</text><text x="215" y="94" text-anchor="middle" class="ts tm">P0</text>
<rect class="fr" x="320" y="40" width="130" height="70"/><text x="385" y="62" text-anchor="middle" class="tb">HSM</text><text x="385" y="78" text-anchor="middle" class="ts">bandeira</text><text x="385" y="94" text-anchor="middle" class="ts tm">P0</text>
<rect class="fr" x="490" y="40" width="180" height="70"/><text x="580" y="62" text-anchor="middle" class="tb">HSM</text><text x="580" y="78" text-anchor="middle" class="ts">emissor</text><text x="580" y="94" text-anchor="middle" class="ts tm">verifica (V2, V6)</text>
<line class="ln" x1="110" y1="75" x2="148" y2="75" marker-end="url(#seta)"/>
<line class="ln" x1="280" y1="75" x2="318" y2="75" marker-end="url(#seta)"/>
<line class="ln" x1="450" y1="75" x2="488" y2="75" marker-end="url(#seta)"/>
<text x="130" y="130" text-anchor="middle" class="ts">chave do terminal</text>
<text x="300" y="130" text-anchor="middle" class="ts">chave de zona 1</text>
<text x="470" y="130" text-anchor="middle" class="ts">chave de zona 2</text>
<text x="340" y="160" text-anchor="middle" class="ts">em cada trecho, um PIN block sob outra chave; o PIN em claro só existe dentro de um HSM</text>
</svg>
<figcaption>Figura 34.1 — O caminho de um PIN. Cada HSM traduz do domínio de chave anterior para o seguinte.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 250" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="30" class="tb">quanto do dígito do PIN o erro 14 entrega, por dígito do PAN na mesma posição</text>
<line class="ln" x1="200" y1="210" x2="640" y2="210"/>
<g class="ts"><text x="200" y="226" text-anchor="middle">0</text><text x="310" y="226" text-anchor="middle">2,5</text><text x="420" y="226" text-anchor="middle">5</text><text x="530" y="226" text-anchor="middle">7,5</text><text x="640" y="226" text-anchor="middle">10</text></g>
<line class="grade" x1="420" y1="40" x2="420" y2="210"/>
<text x="190" y="62" text-anchor="end">sem ataque</text><rect x="200" y="50" width="440" height="18" fill="#888"/><text x="610" y="64" class="ts" fill="#fff">10</text>
<text x="190" y="96" text-anchor="end">PAN 0 a 7</text><rect x="200" y="84" width="193.6" height="18" fill="#2d4f73"/><text x="398" y="98" class="ts">4,4</text>
<text x="190" y="130" text-anchor="end">média</text><rect x="200" y="118" width="172.5" height="18" fill="#7a1f1f"/><text x="378" y="132" class="ts">3,9</text>
<text x="190" y="164" text-anchor="end">PAN 8 ou 9</text><rect x="200" y="152" width="88" height="18" fill="#2d4f73"/><text x="294" y="166" class="ts">2</text>
<text x="190" y="198" text-anchor="end">2 primeiros dígitos</text><rect x="200" y="186" width="440" height="18" fill="#2f5f2f"/><text x="560" y="200" class="ts" fill="#fff">10: nada sai</text>
<text x="420" y="244" text-anchor="middle" class="ts">candidatos que sobram para um dígito do PIN (média)</text>
</svg>
<figcaption>Figura 34.2 — O ataque de modificação do PAN no formato 0. Do terceiro dígito em diante, cada dígito do PIN cai de 10 candidatos para cerca de 4.</figcaption>
</figure>
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


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="20" width="150" height="40"/><text x="85" y="36" text-anchor="middle" class="ts">dados de validação</text><text x="85" y="51" text-anchor="middle" class="tm ts">9999990123456789</text>
<line class="ln" x1="160" y1="40" x2="198" y2="40" marker-end="url(#seta)"/>
<rect class="cxd" x="200" y="20" width="80" height="40"/><text x="240" y="44" text-anchor="middle" class="tb">3DES</text>
<line class="ln" x1="280" y1="40" x2="318" y2="40" marker-end="url(#seta)"/>
<rect class="cx" x="320" y="20" width="150" height="40"/><text x="395" y="36" text-anchor="middle" class="ts">cifrado</text><text x="395" y="51" text-anchor="middle" class="tm ts">C391C921EB0FE15C</text>
<line class="ln" x1="470" y1="40" x2="508" y2="40" marker-end="url(#seta)"/>
<rect class="cx" x="510" y="20" width="160" height="40"/><text x="590" y="36" text-anchor="middle" class="ts">decimalizado (tabela)</text><text x="590" y="51" text-anchor="middle" class="tm ts">2391292141054152</text>
<line class="ln" x1="590" y1="60" x2="590" y2="88" marker-end="url(#seta)"/>
<rect class="cxd" x="510" y="90" width="160" height="40"/><text x="590" y="106" text-anchor="middle" class="ts">PIN natural (5 dígitos)</text><text x="590" y="121" text-anchor="middle" class="tm tb">23912</text>
<rect class="cxa" x="300" y="90" width="150" height="40"/><text x="375" y="106" text-anchor="middle" class="ts">PIN do cliente</text><text x="375" y="121" text-anchor="middle" class="tm tb">48213</text>
<rect class="cxv" x="300" y="150" width="370" height="40"/><text x="485" y="166" text-anchor="middle" class="ts">offset = PIN − natural, dígito a dígito, módulo 10</text><text x="485" y="181" text-anchor="middle" class="tm tb">25301  (guardado; não é segredo)</text>
<line class="ln" x1="590" y1="130" x2="590" y2="148" marker-end="url(#seta)"/>
<line class="ln" x1="375" y1="130" x2="375" y2="148" marker-end="url(#seta)"/>
<text x="20" y="110" class="ts">o natural vale tanto quanto o PIN:</text>
<text x="20" y="124" class="ts">quem tem o natural e o offset,</text>
<text x="20" y="138" class="ts">tem o PIN</text>
</svg>
<figcaption>Figura 35.1 — O método do offset, com o exemplo do texto. A chave e a tabela fazem o PIN natural; o offset faz o PIN escolhido.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="70" y1="170" x2="640" y2="170"/>
<line class="grade" x1="70" y1="50" x2="640" y2="50"/><line class="grade" x1="70" y1="110" x2="640" y2="110"/>
<text x="62" y="54" text-anchor="end" class="ts">2/16</text><text x="62" y="114" text-anchor="end" class="ts">1/16</text>
<rect x="80" y="50" width="40" height="120" fill="#2d4f73"/><text x="100" y="186" text-anchor="middle" class="tb">0</text><rect x="135" y="50" width="40" height="120" fill="#2d4f73"/><text x="155" y="186" text-anchor="middle" class="tb">1</text><rect x="190" y="50" width="40" height="120" fill="#2d4f73"/><text x="210" y="186" text-anchor="middle" class="tb">2</text><rect x="245" y="50" width="40" height="120" fill="#2d4f73"/><text x="265" y="186" text-anchor="middle" class="tb">3</text><rect x="300" y="50" width="40" height="120" fill="#2d4f73"/><text x="320" y="186" text-anchor="middle" class="tb">4</text><rect x="355" y="50" width="40" height="120" fill="#2d4f73"/><text x="375" y="186" text-anchor="middle" class="tb">5</text><rect x="410" y="110" width="40" height="60" fill="#7a1f1f"/><text x="430" y="186" text-anchor="middle" class="tb">6</text><rect x="465" y="110" width="40" height="60" fill="#7a1f1f"/><text x="485" y="186" text-anchor="middle" class="tb">7</text><rect x="520" y="110" width="40" height="60" fill="#7a1f1f"/><text x="540" y="186" text-anchor="middle" class="tb">8</text><rect x="575" y="110" width="40" height="60" fill="#7a1f1f"/><text x="595" y="186" text-anchor="middle" class="tb">9</text>
<line x1="70" y1="98" x2="640" y2="98" stroke="#2f5f2f" stroke-dasharray="5 3"/><text x="636" y="92" text-anchor="end" class="ts" fill="#2f5f2f">uniforme: 1/10</text>
<text x="355" y="206" text-anchor="middle" class="ts">dígito do PIN natural: 0 a 5 vêm de dois hexadecimais (0 e A, 1 e B…); 6 a 9, de um só</text>
</svg>
<figcaption>Figura 35.2 — A distribuição de um dígito do PIN natural com a tabela usual. O desvio cai a busca média de 5 000 para 3 307 tentativas.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 190" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="150" y="20" width="110" height="34"/><text x="205" y="35" text-anchor="middle" class="ts">conta, 11 dígitos</text><text x="205" y="48" text-anchor="middle" class="tm ts">99012345678</text>
<rect class="cx" x="262" y="20" width="60" height="34"/><text x="292" y="35" text-anchor="middle" class="ts">índice</text><text x="292" y="48" text-anchor="middle" class="tm ts">1</text>
<rect class="cxd" x="324" y="20" width="90" height="34"/><text x="369" y="35" text-anchor="middle" class="ts">PIN, 4 dígitos</text><text x="369" y="48" text-anchor="middle" class="tm ts">4821</text>
<line class="ln" x1="290" y1="54" x2="290" y2="72"/><text x="300" y="70" class="ts">3DES sob a chave V2</text>
<line class="ln" x1="290" y1="72" x2="290" y2="96" marker-end="url(#seta)"/>
<rect class="cxv" x="150" y="100" width="28" height="24"/><text x="164" y="117" text-anchor="middle" class="tm">6</text><rect class="cxv" x="180" y="100" width="28" height="24"/><text x="194" y="117" text-anchor="middle" class="tm">3</text><rect class="cxv" x="210" y="100" width="28" height="24"/><text x="224" y="117" text-anchor="middle" class="tm">6</text><rect class="cxv" x="240" y="100" width="28" height="24"/><text x="254" y="117" text-anchor="middle" class="tm">8</text><rect class="cxc" x="270" y="100" width="28" height="24"/><text x="284" y="117" text-anchor="middle" class="tm">D</text><rect class="cx" x="300" y="100" width="28" height="24"/><text x="314" y="117" text-anchor="middle" class="tm">8</text><rect class="cx" x="330" y="100" width="28" height="24"/><text x="344" y="117" text-anchor="middle" class="tm">4</text><rect class="cx" x="360" y="100" width="28" height="24"/><text x="374" y="117" text-anchor="middle" class="tm">5</text><rect class="cx" x="390" y="100" width="28" height="24"/><text x="404" y="117" text-anchor="middle" class="tm">4</text><rect class="cx" x="420" y="100" width="28" height="24"/><text x="434" y="117" text-anchor="middle" class="tm">6</text><rect class="cx" x="450" y="100" width="28" height="24"/><text x="464" y="117" text-anchor="middle" class="tm">6</text><rect class="cx" x="480" y="100" width="28" height="24"/><text x="494" y="117" text-anchor="middle" class="tm">7</text><rect class="cxc" x="510" y="100" width="28" height="24"/><text x="524" y="117" text-anchor="middle" class="tm">B</text><rect class="cxc" x="540" y="100" width="28" height="24"/><text x="554" y="117" text-anchor="middle" class="tm">A</text><rect class="cx" x="570" y="100" width="28" height="24"/><text x="584" y="117" text-anchor="middle" class="tm">3</text><rect class="cx" x="600" y="100" width="28" height="24"/><text x="614" y="117" text-anchor="middle" class="tm">9</text>
<text x="10" y="117" class="ts">cifrado</text>
<text x="150" y="146" class="ts">os 4 primeiros dígitos decimais, da esquerda para a direita:</text>
<rect class="cxv" x="150" y="152" width="120" height="28"/><text x="210" y="171" text-anchor="middle" class="tm tb">PVV = 6368</text>
<text x="290" y="171" class="ts">sem 4 decimais (1 em 2 214): segunda passada, A→0 … F→5</text>
</svg>
<figcaption>Figura 35.3 — O PVV, com o exemplo do texto. O PIN entra na cifra, e a extração escolhe os decimais.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="20" width="160" height="40"/><text x="90" y="36" text-anchor="middle" class="ts">D1: o PAN</text><text x="90" y="51" text-anchor="middle" class="tm ts">9999990123456789</text>
<rect class="cxa" x="10" y="110" width="160" height="40"/><text x="90" y="126" text-anchor="middle" class="ts">D2: validade, serviço, zeros</text><text x="90" y="141" text-anchor="middle" class="tm ts">2812101000000000</text>
<line class="ln" x1="170" y1="40" x2="208" y2="40" marker-end="url(#seta)"/>
<rect class="cxd" x="210" y="22" width="90" height="36"/><text x="255" y="38" text-anchor="middle" class="tb">DES</text><text x="255" y="52" text-anchor="middle" class="ts">sob A</text>
<line class="ln" x1="300" y1="40" x2="340" y2="40"/><line class="ln" x1="340" y1="40" x2="340" y2="113" marker-end="url(#seta)"/>
<text x="350" y="76" class="tm ts">A77E2DB5E4AE7B1F</text>
<circle class="cx" cx="340" cy="130" r="15"/><text x="340" y="135" text-anchor="middle" class="tb">⊕</text>
<line class="ln" x1="170" y1="130" x2="323" y2="130" marker-end="url(#seta)"/>
<line class="ln" x1="355" y1="130" x2="408" y2="130" marker-end="url(#seta)"/>
<text x="380" y="122" class="ts">X</text>
<rect class="cxd" x="410" y="112" width="90" height="36"/><text x="455" y="128" text-anchor="middle" class="tb">3DES</text><text x="455" y="142" text-anchor="middle" class="ts">sob A ‖ B</text>
<line class="ln" x1="500" y1="130" x2="528" y2="130" marker-end="url(#seta)"/>
<rect class="cx" x="530" y="112" width="140" height="36"/><text x="600" y="128" text-anchor="middle" class="ts">C</text><text x="600" y="142" text-anchor="middle" class="tm ts">0374D7040AA393CD</text>
<line class="ln" x1="600" y1="148" x2="600" y2="168" marker-end="url(#seta)"/>
<rect class="cxv" x="530" y="170" width="140" height="30"/><text x="600" y="190" text-anchor="middle" class="tm tb">CVV = 037</text>
<text x="10" y="186" class="ts">é o retail MAC sobre D1 ‖ D2 (seção 39.10), reduzido a 3 dígitos;</text>
<text x="10" y="200" class="ts">o código de serviço em D2 separa CVV (101), CVV2 (000) e iCVV (999)</text>
</svg>
<figcaption>Figura 36.1 — O CVV, com o exemplo do texto. Um MAC de 64 bits sobre os dados do cartão, reduzido a 3 dígitos decimais.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<rect class="fr" x="430" y="20" width="240" height="190"/>
<text x="660" y="36" text-anchor="end" class="ts td">HSM do adquirente</text>
<rect class="cxd" x="450" y="50" width="90" height="34"/><text x="495" y="72" text-anchor="middle" class="tb">BDK</text>
<rect class="cx" x="450" y="110" width="200" height="40"/><text x="550" y="127" text-anchor="middle" class="ts">BDK + KSN → chave inicial</text><text x="550" y="141" text-anchor="middle" class="ts">→ chave da transação</text>
<rect class="cxv" x="450" y="164" width="200" height="34"/><text x="550" y="185" text-anchor="middle" class="ts">a mesma chave do terminal</text>
<line class="ln" x1="495" y1="84" x2="495" y2="108" marker-end="url(#seta)"/>
<line class="ln" x1="550" y1="150" x2="550" y2="162" marker-end="url(#seta)"/>
<g>
<rect class="cxa" x="10" y="20" width="160" height="50"/><text x="90" y="40" text-anchor="middle" class="tb">terminal 1</text><text x="90" y="56" text-anchor="middle" class="ts">chave inicial própria</text>
<rect class="cxa" x="10" y="85" width="160" height="50"/><text x="90" y="105" text-anchor="middle" class="tb">terminal 2</text><text x="90" y="121" text-anchor="middle" class="ts">a cada transação,</text>
<rect class="cxa" x="10" y="150" width="160" height="50"/><text x="90" y="170" text-anchor="middle" class="tb">terminal 1 000 000</text><text x="90" y="186" text-anchor="middle" class="ts">deriva e apaga a anterior</text>
</g>
<line class="ln" x1="170" y1="110" x2="428" y2="128" marker-end="url(#seta)"/>
<rect class="cx" x="200" y="88" width="200" height="30"/><text x="300" y="107" text-anchor="middle" class="ts">PIN block + KSN (em claro)</text>
<text x="300" y="150" text-anchor="middle" class="ts">a BDK nunca vai ao terminal;</text>
<text x="300" y="164" text-anchor="middle" class="ts">o HSM não guarda chave de terminal</text>
<text x="300" y="178" text-anchor="middle" class="ts">nenhuma: ele refaz a conta</text>
</svg>
<figcaption>Figura 37.1 — O DUKPT. Uma BDK no HSM, uma chave por transação em cada terminal, e o KSN dizendo qual.</figcaption>
</figure>

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

As duas variantes entram neste equipamento: a TDES na seção 37.2, a AES na
37.3. A AES aceita BDK e chave de trabalho AES-128 ou AES-256, como o
mercado usa. O coprocessador só faz AES-256; o AES-128 entra como um motor
em software, como o do DES, e só para o DUKPT.

### 37.2 O DUKPT TDES neste equipamento

O HSM faz o lado do **adquirente**. Ele recebe o KSN que veio com a
transação, refaz a chave que o terminal usou e traduz o PIN para a chave de
zona. As chaves futuras do terminal ficam no terminal: o HSM não guarda
registro nenhum.

**O KSN.** São 10 bytes. Os 21 bits da direita são o **contador** de
transações. O resto identifica a BDK e o terminal.

```
    KSN   FFFF9876543210E00001
          |------ identificacao ------||- contador (21 bits) -|
                                         0 0001  ->  contador 1
```

**Passo 1: a IPEK** (*Initial PIN Encryption Key*, chave inicial do
terminal). Ela vem da BDK e do KSN com o contador zerado. São duas
cifragens 3DES do mesmo valor: uma sob a BDK, outra sob a BDK com uma
máscara fixa (`C0C0C0C0 00000000 C0C0C0C0 00000000`).

**Passo 2: a chave da transação.** Para cada bit 1 do contador, do mais
alto para o mais baixo, o bit entra num registrador, e a chave passa pelo
**processo não reversível** da norma. Cada passo faz dois DES simples: um
com a metade da esquerda da chave, outro com a metade da esquerda da chave
com a máscara. São no máximo 10 passos, porque o contador de um KSN válido
nunca tem mais de 10 bits 1.

O processo não volta: da chave da transação 5 não se calcula a da 4. É isso
que dá o sigilo do passado.


<figure class="fig">
<svg viewBox="0 0 680 280" xmlns="http://www.w3.org/2000/svg">
<rect class="cxd" x="20" y="40" width="80" height="34"/><text x="60" y="61" text-anchor="middle" class="tb">IPEK</text><line class="ln" x1="60" y1="74" x2="110" y2="106" marker-end="url(#seta)"/><line class="ln" x1="60" y1="74" x2="260" y2="106" marker-end="url(#seta)"/><line class="ln" x1="260" y1="134" x2="260" y2="166" marker-end="url(#seta)"/><line class="ln" x1="60" y1="74" x2="480" y2="106" marker-end="url(#seta)"/><line class="ln" x1="480" y1="134" x2="480" y2="166" marker-end="url(#seta)"/><line class="ln" x1="480" y1="134" x2="580" y2="166" marker-end="url(#seta)"/><line class="ln" x1="580" y1="194" x2="580" y2="226" marker-end="url(#seta)"/><rect class="cx" x="70" y="106" width="80" height="28"/><text x="110" y="125" text-anchor="middle" class="tm">001</text><rect class="cx" x="220" y="106" width="80" height="28"/><text x="260" y="125" text-anchor="middle" class="tm">010</text><rect class="cx" x="220" y="166" width="80" height="28"/><text x="260" y="185" text-anchor="middle" class="tm">011</text><rect class="cx" x="440" y="106" width="80" height="28"/><text x="480" y="125" text-anchor="middle" class="tm">100</text><rect class="cx" x="440" y="166" width="80" height="28"/><text x="480" y="185" text-anchor="middle" class="tm">101</text><rect class="cx" x="540" y="166" width="80" height="28"/><text x="580" y="185" text-anchor="middle" class="tm">110</text><rect class="cx" x="540" y="226" width="80" height="28"/><text x="580" y="245" text-anchor="middle" class="tm">111</text>
<text x="340" y="30" text-anchor="middle" class="ts">contador de 3 bits (no DUKPT TDES são 21): cada seta é um passo não reversível</text>
<text x="20" y="200" class="ts">a chave de 101 nasce de 100,</text>
<text x="20" y="214" class="ts">que nasce da IPEK: 2 passos,</text>
<text x="20" y="228" class="ts">um por bit 1 do contador</text>
<text x="420" y="270" class="ts">111: 3 passos; da chave de 111 não se volta à de 110</text>
</svg>
<figcaption>Figura 37.2 — A árvore de derivação do contador. O pai de cada contador é ele com o bit 1 mais baixo apagado.</figcaption>
</figure>

**Passo 3: a variante de PIN.** A chave da transação é combinada por XOR
com `00000000000000FF 00000000000000FF`. A chave de PIN é diferente da
chave de MAC e da chave de dados da mesma transação, porque cada uma tem a
sua variante.

**Exemplo com os valores do anexo A.4 da X9.24-1** (valores de terceiros,
ver `vectors/MANIFEST.txt`). Conferido pelo programa, `host/dukpt.py`:

```
    BDK                 0123456789ABCDEF FEDCBA9876543210
    KSN                 FFFF9876543210E00001        (contador 1)

    1. IPEK
       k = KSN com o contador zerado, 8 bytes da esquerda
                        FFFF9876543210E0
       esquerda = 3DES(BDK, k)                    = 6AC292FAA1315B4D
       BDK ^ mascara    C1E385A789ABCDEF 3E1C7A5876543210
       direita  = 3DES(BDK ^ mascara, k)          = 858AB3A3D7D5933A
       IPEK                6AC292FAA1315B4D 858AB3A3D7D5933A

    2. contador 1: um bit 1, um passo. registrador = 9876543210E00001
       nova direita  = DES(esq. da IPEK, reg ^ dir.) ^ dir.
                     = DES(6AC292FAA1315B4D, 1DFCE791C735933B) ^ dir.
                     = ED54258B07ECE8F3 ^ 858AB3A3D7D5933A
                     = 68DE9628D0397BC9
       IPEK ^ mascara      AA02523AA1315B4D 454A7363D7D5933A
       nova esquerda = DES(AA02523AA1315B4D, DD3C2751C735933B) ^ 454A7363D7D5933A
                     = 416C15D746515C99 ^ 454A7363D7D5933A
                     = 042666B49184CFA3
       chave da transacao  042666B49184CFA3 68DE9628D0397BC9

    3. variante de PIN     042666B49184CF5C 68DE9628D0397B36

    PIN block em claro (PIN 1234, PAN do anexo)   041274EDCBA9876F
    cifrado em 3DES com a chave de PIN            1B9C1845EB993A7A
```

O valor final e a chave da transação são os publicados no anexo.

**Os comandos.** A BDK é uma chave de uso `B0`, 3DES de comprimento duplo,
com modo `X`. O modo `X` da X9.143 diz "esta chave só deriva outras". Uma
BDK não cifra nem faz MAC, e nenhuma outra chave deriva.

| Comando | Entra | Sai |
|---|---|---|
| `P2` | BDK, chave de zona (`P0`), KSN, formatos, PAN, PIN block do terminal | PIN block sob a chave de zona |
| `I0` | KEK (`K0`), BDK, KSN | IPEK sob a KEK, KCV da IPEK |

O `P2` é o `P0` com a chave de origem trocada: em vez de uma chave de PIN,
a BDK e o KSN. O PIN block do terminal é o formato 0. O destino é o formato
0 ou o 4, como no `P0`.

O `I0` é a carga de chave do terminal. A IPEK sai embrulhada sob a KEK do
dispositivo de injeção, num key block com uso `B1` (chave inicial de
DUKPT), modo `X` e exportabilidade `N`: o destino é o terminal, e de lá ela
não sai. A versão do bloco segue a KEK: D sob KEK AES, B sob KEK 3DES
(seção 39.9).

**Os KSNs que o HSM recusa** (`16`, antes de qualquer conta):

- o contador zero: é a própria IPEK, que nunca cifra transação;
- o contador com 11 bits 1 ou mais: um terminal que segue a norma nunca o
  usa.

Quantos contadores sobram? Os de 1 a 10 bits 1 entre 21 posições:

```
    C(21,1) + C(21,2) + ... + C(21,10) = 1 048 575
```

É a metade dos 2²¹ − 1 contadores diferentes de zero, porque C(21,k) =
C(21,21−k). Um terminal faz no máximo 1 048 575 transações com a mesma
IPEK. Depois, ele precisa de uma carga nova.


<figure class="fig">
<svg viewBox="0 0 680 240" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="55" y1="190" x2="660" y2="190"/>
<rect x="60" y="190.0" width="22" height="0.0" fill="#2d4f73"/><text x="71" y="204" text-anchor="middle" class="ts">1</text><rect x="88" y="189.9" width="22" height="0.1" fill="#2d4f73"/><text x="99" y="204" text-anchor="middle" class="ts">2</text><rect x="116" y="189.4" width="22" height="0.6" fill="#2d4f73"/><text x="127" y="204" text-anchor="middle" class="ts">3</text><rect x="144" y="187.5" width="22" height="2.5" fill="#2d4f73"/><text x="155" y="204" text-anchor="middle" class="ts">4</text><rect x="172" y="181.3" width="22" height="8.7" fill="#2d4f73"/><text x="183" y="204" text-anchor="middle" class="ts">5</text><rect x="200" y="166.9" width="22" height="23.1" fill="#2d4f73"/><text x="211" y="204" text-anchor="middle" class="ts">6</text><rect x="228" y="140.5" width="22" height="49.5" fill="#2d4f73"/><text x="239" y="204" text-anchor="middle" class="ts">7</text><rect x="256" y="103.5" width="22" height="86.5" fill="#2d4f73"/><text x="267" y="204" text-anchor="middle" class="ts">8</text><rect x="284" y="65.0" width="22" height="125.0" fill="#2d4f73"/><text x="295" y="204" text-anchor="middle" class="ts">9</text><rect x="312" y="40.0" width="22" height="150.0" fill="#2d4f73"/><text x="323" y="204" text-anchor="middle" class="ts">10</text><rect x="340" y="40.0" width="22" height="150.0" fill="#bbb"/><text x="351" y="204" text-anchor="middle" class="ts">11</text><rect x="368" y="65.0" width="22" height="125.0" fill="#bbb"/><text x="379" y="204" text-anchor="middle" class="ts">12</text><rect x="396" y="103.5" width="22" height="86.5" fill="#bbb"/><text x="407" y="204" text-anchor="middle" class="ts">13</text><rect x="424" y="140.5" width="22" height="49.5" fill="#bbb"/><text x="435" y="204" text-anchor="middle" class="ts">14</text><rect x="452" y="166.9" width="22" height="23.1" fill="#bbb"/><text x="463" y="204" text-anchor="middle" class="ts">15</text><rect x="480" y="181.3" width="22" height="8.7" fill="#bbb"/><text x="491" y="204" text-anchor="middle" class="ts">16</text><rect x="508" y="187.5" width="22" height="2.5" fill="#bbb"/><text x="519" y="204" text-anchor="middle" class="ts">17</text><rect x="536" y="189.4" width="22" height="0.6" fill="#bbb"/><text x="547" y="204" text-anchor="middle" class="ts">18</text><rect x="564" y="189.9" width="22" height="0.1" fill="#bbb"/><text x="575" y="204" text-anchor="middle" class="ts">19</text><rect x="592" y="190.0" width="22" height="0.0" fill="#bbb"/><text x="603" y="204" text-anchor="middle" class="ts">20</text><rect x="620" y="190.0" width="22" height="0.0" fill="#bbb"/><text x="631" y="204" text-anchor="middle" class="ts">21</text>
<text x="355" y="222" text-anchor="middle" class="ts">bits 1 no contador de 21 bits</text>
<text x="70" y="30" class="ts" fill="#2d4f73">válidos: 1 a 10 bits 1, 1 048 575 contadores</text>
<text x="400" y="30" class="ts" fill="#888">recusados (16): 11 ou mais</text>
<text x="330" y="60" class="ts">C(21, k): simétrico,</text>
<text x="330" y="74" class="ts">por isso exatamente a metade</text>
</svg>
<figcaption>Figura 37.3 — Quantos contadores têm k bits 1. O DUKPT TDES usa a metade esquerda: no máximo 10 passos por transação.</figcaption>
</figure>

**O que o host pode tentar.** O KSN vem do host e escolhe a chave. Com um
KSN que não é o da transação, o bloco abre sob outra chave, e o resultado é
um bloco ao acaso. Um bloco ao acaso passa como formato 0 cerca de uma vez
em 2²⁴ (seção 33.1). Na recusa, o `14` diz o mesmo que o `P0` com uma chave
errada: nada sobre o PIN. O `14` com o PAN alterado é o mesmo oráculo do
formato 0 da seção 34.3, e o controle é o mesmo: o log.

### 37.3 O DUKPT AES neste equipamento

O papel é o mesmo da seção 37.2: o lado do adquirente. Muda a conta, e o
PIN block do terminal passa a ser o formato 4.

**O KSN.** São 12 bytes: o **IKID** (8 bytes, identifica a BDK e o
terminal) e o **contador** de transações (4 bytes, 32 bits).

```
    KSN   1234567890123456 00000001
          |---- IKID ----| |contador|
```

**A função de derivação.** Toda chave do DUKPT AES sai da mesma conta: um
AES de 16 bytes de dados sob a chave mãe. Os dados dizem o que se está
derivando:

```
    01 . bloco(1) . uso(2) . algoritmo(2) . bits(2) . 8 bytes

    uso         8001 = chave inicial   8000 = derivação   1000 = PIN
    algoritmo   0002 = AES-128         0004 = AES-256
    bits        0080 = 128             0100 = 256
```

O algoritmo e os bits são os da chave **derivada**. Uma chave AES-256 sai
de dois AES, com o byte de bloco 01 e 02. A separação de chaves está nos
dados: a chave de PIN e a de MAC da mesma transação diferem no campo de
uso, e não por uma máscara combinada depois, como no TDES.


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<text x="340" y="28" text-anchor="middle" class="ts">os 16 bytes que a chave mãe cifra, para cada chave derivada</text>
<rect class="cxc" x="20" y="40" width="38" height="40"/><text x="39.0" y="57" text-anchor="middle" class="tm ts">01</text><text x="39.0" y="72" text-anchor="middle" class="ts">versão</text><rect class="cxc" x="58" y="40" width="38" height="40"/><text x="77.0" y="57" text-anchor="middle" class="tm ts">01</text><text x="77.0" y="72" text-anchor="middle" class="ts">bloco</text><rect class="cxd" x="96" y="40" width="76" height="40"/><text x="134.0" y="57" text-anchor="middle" class="tm ts">8001</text><text x="134.0" y="72" text-anchor="middle" class="ts">uso</text><rect class="cxa" x="172" y="40" width="76" height="40"/><text x="210.0" y="57" text-anchor="middle" class="tm ts">0002</text><text x="210.0" y="72" text-anchor="middle" class="ts">algoritmo</text><rect class="cxa" x="248" y="40" width="76" height="40"/><text x="286.0" y="57" text-anchor="middle" class="tm ts">0080</text><text x="286.0" y="72" text-anchor="middle" class="ts">bits</text><rect class="cx" x="324" y="40" width="300" height="40"/><text x="474.0" y="57" text-anchor="middle" class="tm ts">1234567890123456</text><text x="474.0" y="72" text-anchor="middle" class="ts">IKID ou IKID[4:8] ‖ contador</text>
<text x="20" y="112" class="tb">a cadeia, com o exemplo do texto</text>
<rect class="cxd" x="20" y="124" width="110" height="34"/><text x="75" y="145" text-anchor="middle" class="tb">BDK</text>
<line class="ln" x1="130" y1="141" x2="178" y2="141" marker-end="url(#seta)"/><text x="154" y="134" text-anchor="middle" class="ts">8001</text>
<rect class="cx" x="180" y="124" width="110" height="34"/><text x="235" y="139" text-anchor="middle" class="tb">IK</text><text x="235" y="152" text-anchor="middle" class="tm ts">1273671E…</text>
<line class="ln" x1="290" y1="141" x2="338" y2="141" marker-end="url(#seta)"/><text x="314" y="134" text-anchor="middle" class="ts">8000</text>
<rect class="cx" x="340" y="124" width="130" height="34"/><text x="405" y="139" text-anchor="middle" class="tb">transação</text><text x="405" y="152" text-anchor="middle" class="tm ts">4F21B565…</text>
<line class="ln" x1="470" y1="141" x2="518" y2="141" marker-end="url(#seta)"/><text x="494" y="134" text-anchor="middle" class="ts">1000</text>
<rect class="cxv" x="520" y="124" width="140" height="34"/><text x="590" y="139" text-anchor="middle" class="tb">chave de PIN</text><text x="590" y="152" text-anchor="middle" class="tm ts">AF8CB133…</text>
<text x="340" y="186" text-anchor="middle" class="ts">um passo 8000 por bit 1 do contador (aqui, contador 1: um passo); MAC e dados mudam só o campo de uso</text>
</svg>
<figcaption>Figura 37.4 — A função de derivação do DUKPT AES. A separação de chaves está no campo de uso, e não numa máscara combinada depois.</figcaption>
</figure>

**Passo 1: a chave inicial (IK).** Os 8 bytes de dados são o IKID, e a
chave mãe é a BDK.

**Passo 2: a chave da transação.** Para cada bit 1 do contador, do mais
alto para o mais baixo, o bit entra num registrador, e a chave passa por
uma derivação de uso `8000`. Os 8 bytes de dados são os 4 bytes da direita
do IKID e o registrador.

**Passo 3: a chave de trabalho.** Uma derivação de uso `1000` (PIN) sob a
chave da transação, com os 4 bytes da direita do IKID e o contador. O
tamanho da chave de PIN é escolha do terminal, e independe do da BDK.

**Exemplo com os valores do suplemento da X9.24-3** (valores de terceiros,
ver `vectors/MANIFEST.txt`). BDK AES-128, contador 1, chave de PIN
AES-128. Conferido pelo programa, `host/dukpt.py`:

```
    BDK                 FEDCBA9876543210 F1F1F1F1F1F1F1F1
    KSN                 1234567890123456 00000001

    1. IK       dados   01 01 8001 0002 0080 1234567890123456
                IK    = AES(BDK, dados)  = 1273671EA26AC29AFA4D1084127652A1

    2. contador 1: um bit 1, um passo. registrador = 00000001
                dados   01 01 8000 0002 0080 90123456 00000001
                chave = AES(IK, dados)   = 4F21B565BAD9835E112B6465635EAE44

    3. PIN      dados   01 01 1000 0002 0080 90123456 00000001
                chave de PIN             = AF8CB133A78F8DC2D1359F18527593FB

    PIN block formato 4 (PIN 1234, PAN 4111111111111111):
       campo do PIN        441234AAAAAAAAAA 2F69ADDE2E9E7ACE
       AES(chave de PIN)   DE84127CF6DCA7DF E47BDE89057CB820
       ^ campo do PAN      9A95036DE7CDB6CE F47BDE89057CB820
       AES(chave de PIN)   A912150391AB65A6 7E52883D81CE2D15
```

A IK, a chave da transação, a chave de PIN e o PIN block cifrado são os
publicados.

**Os comandos.** São os mesmos `P2` e `I0` da seção 37.2. O algoritmo da
BDK, no cabeçalho do bloco dela, diz qual DUKPT o comando faz:

| | BDK 3DES | BDK AES |
|---|---|---|
| BDK | 3DES duplo | AES-128 ou AES-256 |
| KSN no pedido | 20 caracteres | 24 caracteres, mais o tipo da chave de trabalho (`2` AES-128, `4` AES-256) |
| PIN block do terminal | formato 0 | formato 4 |
| `I0` devolve | a IPEK, 3DES | a IK, do tamanho da BDK |
| KEK do `I0` | qualquer | só AES (a IK nunca sai sob chave mais fraca) |

O tipo da chave de trabalho usa os códigos de algoritmo da própria norma.

**Uma chave AES-128, só aqui.** O coprocessador faz só AES-256, e uma chave
de dados AES-128 pareceria instalada e não cifraria certo. Por isso o key
store só aceita uma chave AES-128 com uso `B0` e modo `X`: a BDK do DUKPT
AES. Uma chave AES-128 com outro cabeçalho é recusada ao entrar (`10`). A
BDK AES-128 nasce por componentes no console (`comp-load --alg A128 --uso
B0 --modo X`) ou chega por `K6` sob uma KEK. O KCV dela é o do AES-128: os
3 primeiros bytes da cifra de um bloco de zeros.

**Os KSNs que o HSM recusa** (`16`, antes de qualquer conta): o contador
zero, e o contador com 17 bits 1 ou mais. Os contadores válidos são os de 1
a 16 bits 1 entre 32 posições:

```
    C(32,1) + C(32,2) + ... + C(32,16) = (2³² + C(32,16)) / 2 − 1
                                       = 2 448 023 842
```

São 57% dos 2³² contadores. Um terminal faz cerca de 2,4 bilhões de
transações com a mesma IK.

**O que o host pode tentar.** É o mesmo raciocínio da seção 37.2, com o
formato 4. Um bloco ao acaso passa como campo de PIN válido com chance de
cerca de 2⁻²⁴: o controle tem de ser `4` (1/16), o tamanho de 4 a 12
(9/16), os dígitos de 0 a 9 (10/16 cada) e o enchimento `A` (1/16 por
posição). A soma sobre os tamanhos dá 6,0 × 10⁻⁸. E o PAN não abre o
oráculo do formato 0: no formato 4 ele entra numa camada de AES, não por XOR
direto no PIN (seção 34.3).

### 37.4 MAC e dados com DUKPT

O PIN não é a única coisa que o terminal protege. A mensagem da transação
leva um **MAC**, e alguns campos (a trilha do cartão, por exemplo) vão
**cifrados**. Com DUKPT, as duas proteções usam chaves da mesma transação, e
cada chave serve a um uso só.

**Pedido e resposta.** O terminal manda um **pedido** e recebe uma
**resposta**. Cada sentido tem a sua chave de MAC e a sua chave de dados. Os
nomes são do ponto de vista do terminal: ele faz o MAC e cifra o pedido; o
HSM do adquirente confere esse MAC e decifra, e faz o MAC e cifra a
resposta.

<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="60" width="130" height="90"/><text x="75" y="84" text-anchor="middle" class="tb">terminal</text><text x="75" y="102" text-anchor="middle" class="ts">MAC de pedido</text><text x="75" y="116" text-anchor="middle" class="ts">cifra o pedido</text><text x="75" y="136" text-anchor="middle" class="ts">confere a resposta</text>
<rect class="fr" x="470" y="40" width="200" height="140"/>
<text x="570" y="60" text-anchor="middle" class="tb">HSM do adquirente</text>
<rect class="cx" x="485" y="72" width="170" height="24"/><text x="570" y="89" text-anchor="middle" class="ts">M4: confere o MAC de pedido</text>
<rect class="cx" x="485" y="100" width="170" height="24"/><text x="570" y="117" text-anchor="middle" class="ts">C4: decifra o pedido</text>
<rect class="cx" x="485" y="128" width="170" height="24"/><text x="570" y="145" text-anchor="middle" class="ts">M6: faz o MAC de resposta</text>
<rect class="cx" x="485" y="156" width="170" height="20"/><text x="570" y="171" text-anchor="middle" class="ts">C6: cifra a resposta</text>
<line class="ln" x1="140" y1="85" x2="468" y2="85" marker-end="url(#seta)"/>
<text x="300" y="78" text-anchor="middle" class="ts">pedido + MAC + KSN</text>
<line class="ln" x1="468" y1="140" x2="140" y2="140" marker-end="url(#seta)"/>
<text x="300" y="133" text-anchor="middle" class="ts">resposta + MAC</text>
<text x="340" y="210" text-anchor="middle" class="ts">gerar um MAC de pedido ou decifrar uma resposta é papel do terminal: o HSM não oferece</text>
</svg>
<figcaption>Figura 37.5 — Os quatro usos de MAC e de dados numa transação DUKPT, e o comando do HSM para cada um.</figcaption>
</figure>

**No DUKPT TDES**, cada uso tem a sua variante: um XOR de `FF` em dois bytes
da chave da transação, como na chave de PIN. Nas chaves de dados, a norma
acrescenta uma **função de mão única**: cada metade da chave com a variante
é cifrada em 3DES sob ela mesma. Quem tem a chave de dados não volta à
chave da transação.

```
    uso                 bytes com FF     depois
    PIN                 7 e 15           nada
    MAC de pedido       6 e 14           nada
    MAC de resposta     4 e 12           nada
    dados de pedido     5 e 13           função de mão única
    dados de resposta   3 e 11           função de mão única
```

O MAC é o **retail MAC** da seção 39.10, com o preenchimento 1. Os dados vão
em 3DES-CBC.

**Exemplo, com o anexo A.4 da X9.24-1** (valores de terceiros, de duas
fontes; conferido por programa, `host/dukpt.py`). Contador 1, a mensagem
publicada `4012345678909D987`:

```
    chave da transação     042666B49184CFA3 68DE9628D0397BC9

    MAC de pedido          042666B4918430A3 68DE9628D03984C9     bytes 6 e 14
    MAC de resposta        042666B46E84CFA3 68DE96282F397BC9     bytes 4 e 12
    dados de pedido        042666B4917BCFA3 68DE9628D0C67BC9     bytes 5 e 13
      mão única            448D3F076D830403 6A55A3D7E0055A78

    MAC do pedido          9CCC78173FC4FB64     (o terminal manda 9CCC7817)
    MAC da resposta        20364223C1FF00FA
```

**No DUKPT AES**, a separação já está na derivação: a chave de MAC e a de
dados são derivações da chave da transação com outro campo de uso (seção
37.3). O MAC é o **CMAC** com AES, e os dados vão em AES-CBC.

```
    uso                     campo de uso     chave, BDK AES-128, contador 1
    MAC de pedido           2000             A2DC23DE6FDE0824A2BC321E08E4B8B7
    MAC de resposta         2001             DBB463945B286C07CD3AD82EE96FD9C9
    dados de pedido         3000             A35C412EFD41FDB98B69797C02DCD08F
    dados de resposta       3001             16292C6EA8F64C5420A0584BFBC577BE

    CMAC do pedido          A2EB5C1C35809E58404E873C3C411E31
```

**Os comandos.** A BDK é a mesma do `P2`, e o algoritmo dela escolhe a
variante:

| Comando | Faz | BDK 3DES | BDK AES |
|---|---|---|---|
| `M4` | confere o MAC de pedido | retail MAC de 4 ou 8 bytes | CMAC de 16 bytes |
| `M6` | faz o MAC de resposta | idem | idem |
| `C4` | decifra os dados de pedido | 3DES-CBC, IV de 8 bytes | AES-CBC, IV de 16 bytes |
| `C6` | cifra os dados de resposta | idem | idem |

```
    pedido      M4  <BDK>  KSN  [trabalho]  [tamanho]  MAC  dados
                M6  <BDK>  KSN  [trabalho]  [tamanho]  dados
                C4  <BDK>  KSN  [trabalho]  IV  dados
                C6  <BDK>  KSN  [trabalho]  IV  dados

    trabalho    só com BDK AES: 2 = AES-128, 4 = AES-256
    tamanho     só com BDK 3DES: 4 ou 8 bytes de MAC
```

As regras:

- **Só o lado do adquirente.** Não há comando para fazer o MAC de um pedido
  nem para cifrar um pedido: isso é o terminal. Um HSM que fizesse os dois
  lados permitiria forjar mensagens de terminal.
- **O `M4` devolve um bit**, e compara em tempo constante: `00` confere, `01`
  não confere. O MAC calculado não sai.
- **O KSN é conferido antes da conta**, como no `P2`: contador zero, ou com
  bits 1 demais, responde `16`.
- **A chave de uso, o MAC e os dados são calculados duas vezes**, com a
  derivação refeita, e comparados. Uma discordância responde `91`.
- **Mensagem vazia**, ou dados fora do múltiplo do bloco, respondem `15`.
- **O autoteste** do DUKPT TDES passou a conferir um MAC de pedido publicado,
  e o do DUKPT AES, as chaves de MAC e de dados publicadas.

⚠ **Fonte única em três valores.** Os dados de resposta TDES e o CMAC e os
dados de resposta AES só têm valores publicados numa fonte (`moov-io/dukpt`).
A conta é a dos valores de pedido, que têm duas fontes, com outra constante
da norma. A decisão de aceitar está registrada (seção 38.3).

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
| DUKPT AES (X9.24-3) | **feito** (seção 37.3) | AES-256 no coprocessador; AES-128 por motor em software, só para o DUKPT |
| CVV, CVV2 e iCVV | **feito** (seção 36) | inerentemente 3DES; não há variante AES em uso |
| PVV | **feito** (seção 35.2) | idem |
| DUKPT TDES (X9.24-1) | **feito** (seção 37.2) | 3DES, com vetores de terceiros do anexo A.4 |
| MAC e dados com DUKPT, TDES e AES | **feito** (seção 37.4) | duas fontes, e uma só nas respostas, por decisão |
| MAC de mensagem e dados com 3DES | **feito** (seção 39.10) | retail MAC da ISO 9797-1 e 3DES-CBC, com vetores de duas fontes e do NIST |
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

Um **vetor de teste** é um caso de entrada com a saída correta conhecida:
esta chave, esta mensagem, este resultado. O teste de resposta conhecida
(KAT) dá a entrada ao equipamento e compara a saída. A regra nº 5 do projeto
diz que, se um KAT falha, **o erro está no código, não no vetor**. Essa regra
só se sustenta quando o vetor vem de alguém que não é o próprio projeto, e
quando a procedência dele pode ser conferida.

**Por que a criptografia de pagamento não tem vetor oficial.** O NIST valida
**algoritmos**: AES, SHA, CMAC, DES, RSA, ECDSA. O programa de validação dele
(o CAVP) publica milhares de vetores, de graça. Mas um PIN block, um CVV, um
DUKPT ou um retail MAC não são algoritmos novos: são **esquemas** que usam o
DES ou o AES de um jeito definido. Esses esquemas estão em outros lugares:

| Onde está a definição | Exemplos | Acesso |
|---|---|---|
| Normas ANSI e ISO | X9.24 (DUKPT), X9.143 (key block), ISO 9564 (PIN block), ISO/IEC 9797-1 (MAC) | pagas, com licença por leitor |
| Documentação das bandeiras | CVV, PVV, iCVV | só para licenciados |
| Manuais de fabricantes de HSM | tabelas de comandos, exemplos | licenciados; proibidos neste projeto |

Um fabricante de HSM compra as normas, recebe das bandeiras os casos de
teste de certificação e passa por laboratórios credenciados (PCI PTS HSM,
FIPS 140-3). Este projeto não tem nada disso. Ele tem o que é público.

**A escada de confiança.** Entre o vetor oficial e o "parece certo" há
degraus. Cada função do equipamento está num deles, e a Figura 38.1 mostra
quais.

<figure class="fig">
<svg viewBox="0 0 680 330" xmlns="http://www.w3.org/2000/svg">
<rect class="cxv" x="10"  y="20"  width="250" height="52"/>
<text x="20" y="40" class="tb">1. Vetor oficial público</text>
<text x="20" y="58" class="ts">NIST (CAVP) e IETF: a saída é a da norma</text>
<rect class="cxc" x="70"  y="82"  width="250" height="52" style="stroke-dasharray:5 3"/>
<text x="80" y="102" class="tb">2. A própria norma</text>
<text x="80" y="120" class="ts">paga; um fabricante a compra. Não usada aqui</text>
<rect class="cxa" x="130" y="144" width="250" height="52"/>
<text x="140" y="164" class="tb">3. Duas fontes independentes</text>
<text x="140" y="182" class="ts">bibliotecas abertas diferentes que concordam</text>
<rect class="cx"  x="190" y="206" width="250" height="52"/>
<text x="200" y="226" class="tb">4. Uma fonte</text>
<text x="200" y="244" class="ts">uma biblioteca aberta, fixada por commit e hash</text>
<rect class="cxd" x="250" y="268" width="250" height="52"/>
<text x="260" y="288" class="tb">5. Só as duas implementações</text>
<text x="260" y="306" class="ts">o C e o Python deste projeto concordam</text>
<line class="ln" x1="522" y1="300" x2="522" y2="35" marker-end="url(#seta)"/>
<text x="534" y="170" class="ts" transform="rotate(-90 534 170)" text-anchor="middle">mais confiança</text>
<text x="548" y="48"  class="ts">AES, SHA, HMAC, CMAC,</text>
<text x="548" y="61"  class="ts">DRBG, RSA, ECDSA, 3DES</text>
<text x="548" y="170" class="ts">CVV, retail MAC,</text>
<text x="548" y="183" class="ts">DUKPT MAC (pedido)</text>
<text x="548" y="232" class="ts">key block, PIN block,</text>
<text x="548" y="245" class="ts">PVV, DUKPT, offset</text>
<text x="548" y="294" class="ts">casos que nenhuma</text>
<text x="548" y="307" class="ts">fonte cobre</text>
</svg>
<figcaption>Figura 38.1 — A escada de confiança de um vetor de teste. À direita, as funções deste equipamento em cada degrau.</figcaption>
</figure>

**O que uma fonte secundária vale.** Uma biblioteca aberta que publica
valores de teste (o `psec`, o `openemv/dukpt`, o `moov-io/dukpt`, o
RustCrypto) leu a norma, ou outra fonte, e escreveu o resultado. Ela não tem
a autoridade da norma, e nem sempre diz de onde tirou cada número. Mas ela
dá um número que **este projeto não escolheu**. Esse é o ponto: um vetor que
o próprio projeto calcula não acusa nada, porque o mesmo erro está no
cálculo e no código.

**Duas implementações, e o limite delas.** O projeto escreve cada esquema
duas vezes, em C (o firmware) e em Python (o host), com motores de cifra
diferentes, e exige que os dois concordem. Isso pega erro de programação:
um índice trocado, um byte a mais no preenchimento. Não pega erro de
**leitura**: se as duas implementações seguem a mesma fonte, e a fonte está
errada, as duas erram igual e concordam. A Figura 38.2 mostra os dois casos.

<figure class="fig">
<svg viewBox="0 0 680 250" xmlns="http://www.w3.org/2000/svg">
<text x="160" y="18" class="tb" text-anchor="middle">Erro de programação: pego</text>
<rect class="cxv" x="100" y="30" width="120" height="34"/>
<text x="160" y="52" text-anchor="middle">fonte certa</text>
<line class="ln" x1="130" y1="64" x2="80" y2="104" marker-end="url(#seta)"/>
<line class="ln" x1="190" y1="64" x2="240" y2="104" marker-end="url(#seta)"/>
<rect class="cxd" x="20" y="106" width="120" height="34"/>
<text x="80" y="122" text-anchor="middle">C</text>
<text x="80" y="135" class="ts" text-anchor="middle">um índice trocado</text>
<rect class="cx" x="180" y="106" width="120" height="34"/>
<text x="240" y="128" text-anchor="middle">Python</text>
<line class="ln" x1="80" y1="140" x2="150" y2="180" marker-end="url(#seta)"/>
<line class="ln" x1="240" y1="140" x2="170" y2="180" marker-end="url(#seta)"/>
<rect class="cxv" x="90" y="182" width="140" height="40"/>
<text x="160" y="200" text-anchor="middle" class="tb">discordam</text>
<text x="160" y="214" text-anchor="middle" class="ts">o teste reprova</text>
<line class="lnt" x1="340" y1="10" x2="340" y2="240"/>
<text x="510" y="18" class="tb" text-anchor="middle">Erro de leitura: passa</text>
<rect class="cxd" x="450" y="30" width="120" height="34"/>
<text x="510" y="52" text-anchor="middle">fonte errada</text>
<line class="lnd" x1="480" y1="64" x2="430" y2="104" marker-end="url(#seta-d)"/>
<line class="lnd" x1="540" y1="64" x2="590" y2="104" marker-end="url(#seta-d)"/>
<rect class="cx" x="370" y="106" width="120" height="34"/>
<text x="430" y="128" text-anchor="middle">C</text>
<rect class="cx" x="530" y="106" width="120" height="34"/>
<text x="590" y="128" text-anchor="middle">Python</text>
<line class="ln" x1="430" y1="140" x2="500" y2="180" marker-end="url(#seta)"/>
<line class="ln" x1="590" y1="140" x2="520" y2="180" marker-end="url(#seta)"/>
<rect class="cxd" x="440" y="182" width="140" height="40"/>
<text x="510" y="200" text-anchor="middle" class="tb td">concordam no erro</text>
<text x="510" y="214" text-anchor="middle" class="ts">o teste passa</text>
</svg>
<figcaption>Figura 38.2 — Duas implementações pegam o erro de programação, e não o erro da fonte. Contra o erro da fonte, só uma segunda fonte independente.</figcaption>
</figure>

Por isso uma segunda fonte vale mais que uma segunda implementação. Duas
bibliotecas de autores diferentes, em linguagens diferentes, que chegam ao
mesmo número, raramente leram a norma do mesmo jeito errado. Não é
impossível: as duas podem ter copiado da mesma fonte intermediária. Mas é o
melhor que se consegue sem a norma.

**A regra deste projeto**, por decisão do usuário:

1. Onde há vetor oficial, ele é obrigatório.
2. Onde não há, desde a etapa 8.9, um valor de terceiros precisa de **duas
   fontes independentes**. Com uma só, a decisão volta ao usuário, caso a
   caso (aconteceu na 8.9b, com as respostas do DUKPT, seção 37.4).
3. Toda fonte é fixada por commit e por hash em `vectors/MANIFEST.txt`, que
   diz o que ela cobre e o que não cobre.
4. O que nenhuma fonte cobre é conferido entre o C e o Python, e o manual diz
   isso (Parte VIII).

O critério do usuário é didático: o equipamento precisa funcionar, e se
comportar como um HSM real se comporta. A certificação de cada número fica
para quem fabrica. A Figura 38.3 mostra onde cada função está.

<figure class="fig">
<svg viewBox="0 0 680 370" xmlns="http://www.w3.org/2000/svg">
<text x="345" y="28" text-anchor="middle" class="ts">oficial</text>
<text x="425" y="28" text-anchor="middle" class="ts">duas ou mais</text>
<text x="505" y="28" text-anchor="middle" class="ts">uma fonte</text>
<text x="600" y="28" text-anchor="middle" class="ts">só C × Python</text>
<line class="grade" x1="20" y1="36" x2="660" y2="36"/>
<g>
<text x="20" y="58">AES, SHA, HMAC, CMAC, DRBG</text><circle cx="345" cy="54" r="7" fill="#2f5f2f"/>
<text x="20" y="82">RSA e ECDSA</text><circle cx="345" cy="78" r="7" fill="#2f5f2f"/>
<text x="20" y="106">DES e 3DES, CMAC-TDES</text><circle cx="345" cy="102" r="7" fill="#2f5f2f"/>
<text x="20" y="130">Key block versões D e B (abrir)</text><circle cx="505" cy="126" r="7" fill="#555"/>
<text x="20" y="154">Key block (embrulhar: enchimento aleatório)</text><circle cx="600" cy="150" r="7" fill="#7a1f1f"/>
<text x="20" y="178">PIN block formatos 0 e 4</text><circle cx="505" cy="174" r="7" fill="#555"/>
<text x="20" y="202">Offset IBM 3624 e PVV</text><circle cx="505" cy="198" r="7" fill="#555"/>
<text x="20" y="226">CVV, CVV2 e iCVV</text><circle cx="425" cy="222" r="7" fill="#2d4f73"/><text x="440" y="226" class="ts">3</text>
<text x="20" y="250">DUKPT TDES e AES: chaves e PIN</text><circle cx="505" cy="246" r="7" fill="#555"/>
<text x="20" y="274">Retail MAC (ISO 9797-1, alg. 3)</text><circle cx="425" cy="270" r="7" fill="#2d4f73"/><text x="440" y="274" class="ts">2</text>
<text x="20" y="298">DUKPT: MAC e dados de pedido</text><circle cx="425" cy="294" r="7" fill="#2d4f73"/><text x="440" y="298" class="ts">2</text>
<text x="20" y="322">DUKPT: MAC e dados de resposta</text><circle cx="505" cy="318" r="7" fill="#555"/>
<text x="20" y="346">AES-128 (só o DUKPT)</text><circle cx="345" cy="342" r="7" fill="#2f5f2f"/>
</g>
<line class="grade" x1="305" y1="36" x2="305" y2="356"/>
<line class="grade" x1="385" y1="36" x2="385" y2="356"/>
<line class="grade" x1="465" y1="36" x2="465" y2="356"/>
<line class="grade" x1="545" y1="36" x2="545" y2="356"/>
</svg>
<figcaption>Figura 38.3 — De onde vem a resposta conhecida de cada função. O número ao lado do ponto é a quantidade de fontes independentes.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 220" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="150" y="20" width="120" height="30"/><text x="210" y="40" text-anchor="middle" class="tb">L</text>
<rect class="cxa" x="410" y="20" width="120" height="30"/><text x="470" y="40" text-anchor="middle" class="tb">R</text>
<line class="ln" x1="470" y1="50" x2="470" y2="95"/>
<rect class="cxd" x="320" y="80" width="60" height="30"/><text x="350" y="100" text-anchor="middle" class="tb">f</text>
<line class="ln" x1="470" y1="95" x2="382" y2="95" marker-end="url(#seta)"/>
<text x="350" y="128" text-anchor="middle" class="ts">subchave</text><line class="ln" x1="350" y1="120" x2="350" y2="112" marker-end="url(#seta)"/>
<circle class="cx" cx="210" cy="95" r="14"/><text x="210" y="100" text-anchor="middle" class="tb">⊕</text>
<line class="ln" x1="210" y1="50" x2="210" y2="79" marker-end="url(#seta)"/>
<line class="ln" x1="320" y1="95" x2="226" y2="95" marker-end="url(#seta)"/>
<line class="ln" x1="210" y1="109" x2="470" y2="168" marker-end="url(#seta)"/>
<line class="ln" x1="470" y1="95" x2="470" y2="110"/><line class="ln" x1="470" y1="110" x2="210" y2="168" marker-end="url(#seta)"/>
<rect class="cxa" x="150" y="170" width="120" height="30"/><text x="210" y="190" text-anchor="middle" class="tb">novo L = R</text>
<rect class="cxa" x="410" y="170" width="120" height="30"/><text x="470" y="190" text-anchor="middle" class="tb">novo R = L ⊕ f(R)</text>
<text x="560" y="96" class="ts">f nunca é invertida:</text>
<text x="560" y="110" class="ts">para desfazer, basta</text>
<text x="560" y="124" class="ts">calcular f de novo</text>
</svg>
<figcaption>Figura 39.1 — Uma rodada de Feistel. Metade do bloco passa intacta e serve de entrada à função que mascara a outra metade.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 220" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="90" width="80" height="34"/><text x="50" y="111" text-anchor="middle" class="ts">R, 32 bits</text>
<line class="ln" x1="90" y1="107" x2="118" y2="107" marker-end="url(#seta)"/>
<rect class="cx" x="120" y="90" width="90" height="34"/><text x="165" y="104" text-anchor="middle" class="tb">expansão</text><text x="165" y="117" text-anchor="middle" class="ts">32 → 48</text>
<line class="ln" x1="210" y1="107" x2="238" y2="107" marker-end="url(#seta)"/>
<circle class="cx" cx="254" cy="107" r="14"/><text x="254" y="112" text-anchor="middle" class="tb">⊕</text>
<rect class="cxd" x="214" y="20" width="80" height="30"/><text x="254" y="40" text-anchor="middle" class="ts">subchave 48</text>
<line class="ln" x1="254" y1="50" x2="254" y2="91" marker-end="url(#seta)"/>
<line class="ln" x1="268" y1="107" x2="296" y2="107" marker-end="url(#seta)"/>
<g><rect class="cxd" x="300" y="80" width="30" height="54"/><text x="315" y="104" text-anchor="middle" class="tb">S1</text><text x="315" y="122" text-anchor="middle" class="ts">6→4</text><rect class="cxd" x="334" y="80" width="30" height="54"/><text x="349" y="104" text-anchor="middle" class="tb">S2</text><text x="349" y="122" text-anchor="middle" class="ts">6→4</text><rect class="cxd" x="368" y="80" width="30" height="54"/><text x="383" y="104" text-anchor="middle" class="tb">S3</text><text x="383" y="122" text-anchor="middle" class="ts">6→4</text><rect class="cxd" x="402" y="80" width="30" height="54"/><text x="417" y="104" text-anchor="middle" class="tb">S4</text><text x="417" y="122" text-anchor="middle" class="ts">6→4</text><rect class="cxd" x="436" y="80" width="30" height="54"/><text x="451" y="104" text-anchor="middle" class="tb">S5</text><text x="451" y="122" text-anchor="middle" class="ts">6→4</text><rect class="cxd" x="470" y="80" width="30" height="54"/><text x="485" y="104" text-anchor="middle" class="tb">S6</text><text x="485" y="122" text-anchor="middle" class="ts">6→4</text><rect class="cxd" x="504" y="80" width="30" height="54"/><text x="519" y="104" text-anchor="middle" class="tb">S7</text><text x="519" y="122" text-anchor="middle" class="ts">6→4</text><rect class="cxd" x="538" y="80" width="30" height="54"/><text x="553" y="104" text-anchor="middle" class="tb">S8</text><text x="553" y="122" text-anchor="middle" class="ts">6→4</text></g>
<line class="ln" x1="572" y1="107" x2="598" y2="107" marker-end="url(#seta)"/>
<rect class="cx" x="600" y="90" width="70" height="34"/><text x="635" y="104" text-anchor="middle" class="tb">P</text><text x="635" y="117" text-anchor="middle" class="ts">32 bits</text>
<text x="436" y="160" text-anchor="middle" class="ts td">as caixas S: a única parte não linear da cifra</text>
<text x="340" y="196" text-anchor="middle" class="ts">a função f de uma rodada; o DES faz 16 rodadas, com permutação no início e no fim</text>
</svg>
<figcaption>Figura 39.2 — A função f do DES. Sem as oito caixas S, a cifra seria um sistema de equações lineares.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 130" xmlns="http://www.w3.org/2000/svg">
<text x="20" y="28" class="ts">a chave 0123456789ABCDEF, bit a bit</text>
<rect class="cxa" x="20" y="40" width="10" height="22"/><text x="25" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="30" y="40" width="10" height="22"/><text x="35" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="40" y="40" width="10" height="22"/><text x="45" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="50" y="40" width="10" height="22"/><text x="55" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="60" y="40" width="10" height="22"/><text x="65" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="70" y="40" width="10" height="22"/><text x="75" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="80" y="40" width="10" height="22"/><text x="85" y="56" text-anchor="middle" class="ts">0</text><rect class="cxd" x="90" y="40" width="10" height="22"/><text x="95" y="56" text-anchor="middle" class="ts">1</text><text x="60" y="80" text-anchor="middle" class="tm ts">01</text><rect class="cxa" x="102" y="40" width="10" height="22"/><text x="107" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="112" y="40" width="10" height="22"/><text x="117" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="122" y="40" width="10" height="22"/><text x="127" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="132" y="40" width="10" height="22"/><text x="137" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="142" y="40" width="10" height="22"/><text x="147" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="152" y="40" width="10" height="22"/><text x="157" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="162" y="40" width="10" height="22"/><text x="167" y="56" text-anchor="middle" class="ts">1</text><rect class="cxd" x="172" y="40" width="10" height="22"/><text x="177" y="56" text-anchor="middle" class="ts">1</text><text x="142" y="80" text-anchor="middle" class="tm ts">23</text><rect class="cxa" x="184" y="40" width="10" height="22"/><text x="189" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="194" y="40" width="10" height="22"/><text x="199" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="204" y="40" width="10" height="22"/><text x="209" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="214" y="40" width="10" height="22"/><text x="219" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="224" y="40" width="10" height="22"/><text x="229" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="234" y="40" width="10" height="22"/><text x="239" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="244" y="40" width="10" height="22"/><text x="249" y="56" text-anchor="middle" class="ts">0</text><rect class="cxd" x="254" y="40" width="10" height="22"/><text x="259" y="56" text-anchor="middle" class="ts">1</text><text x="224" y="80" text-anchor="middle" class="tm ts">45</text><rect class="cxa" x="266" y="40" width="10" height="22"/><text x="271" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="276" y="40" width="10" height="22"/><text x="281" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="286" y="40" width="10" height="22"/><text x="291" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="296" y="40" width="10" height="22"/><text x="301" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="306" y="40" width="10" height="22"/><text x="311" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="316" y="40" width="10" height="22"/><text x="321" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="326" y="40" width="10" height="22"/><text x="331" y="56" text-anchor="middle" class="ts">1</text><rect class="cxd" x="336" y="40" width="10" height="22"/><text x="341" y="56" text-anchor="middle" class="ts">1</text><text x="306" y="80" text-anchor="middle" class="tm ts">67</text><rect class="cxa" x="348" y="40" width="10" height="22"/><text x="353" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="358" y="40" width="10" height="22"/><text x="363" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="368" y="40" width="10" height="22"/><text x="373" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="378" y="40" width="10" height="22"/><text x="383" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="388" y="40" width="10" height="22"/><text x="393" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="398" y="40" width="10" height="22"/><text x="403" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="408" y="40" width="10" height="22"/><text x="413" y="56" text-anchor="middle" class="ts">0</text><rect class="cxd" x="418" y="40" width="10" height="22"/><text x="423" y="56" text-anchor="middle" class="ts">1</text><text x="388" y="80" text-anchor="middle" class="tm ts">89</text><rect class="cxa" x="430" y="40" width="10" height="22"/><text x="435" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="440" y="40" width="10" height="22"/><text x="445" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="450" y="40" width="10" height="22"/><text x="455" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="460" y="40" width="10" height="22"/><text x="465" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="470" y="40" width="10" height="22"/><text x="475" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="480" y="40" width="10" height="22"/><text x="485" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="490" y="40" width="10" height="22"/><text x="495" y="56" text-anchor="middle" class="ts">1</text><rect class="cxd" x="500" y="40" width="10" height="22"/><text x="505" y="56" text-anchor="middle" class="ts">1</text><text x="470" y="80" text-anchor="middle" class="tm ts">AB</text><rect class="cxa" x="512" y="40" width="10" height="22"/><text x="517" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="522" y="40" width="10" height="22"/><text x="527" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="532" y="40" width="10" height="22"/><text x="537" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="542" y="40" width="10" height="22"/><text x="547" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="552" y="40" width="10" height="22"/><text x="557" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="562" y="40" width="10" height="22"/><text x="567" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="572" y="40" width="10" height="22"/><text x="577" y="56" text-anchor="middle" class="ts">0</text><rect class="cxd" x="582" y="40" width="10" height="22"/><text x="587" y="56" text-anchor="middle" class="ts">1</text><text x="552" y="80" text-anchor="middle" class="tm ts">CD</text><rect class="cxa" x="594" y="40" width="10" height="22"/><text x="599" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="604" y="40" width="10" height="22"/><text x="609" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="614" y="40" width="10" height="22"/><text x="619" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="624" y="40" width="10" height="22"/><text x="629" y="56" text-anchor="middle" class="ts">0</text><rect class="cxa" x="634" y="40" width="10" height="22"/><text x="639" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="644" y="40" width="10" height="22"/><text x="649" y="56" text-anchor="middle" class="ts">1</text><rect class="cxa" x="654" y="40" width="10" height="22"/><text x="659" y="56" text-anchor="middle" class="ts">1</text><rect class="cxd" x="664" y="40" width="10" height="22"/><text x="669" y="56" text-anchor="middle" class="ts">1</text><text x="634" y="80" text-anchor="middle" class="tm ts">EF</text>
<rect class="cxa" x="20" y="96" width="14" height="14"/><text x="40" y="108" class="ts">7 bits de chave por byte: 56 no total</text>
<rect class="cxd" x="300" y="96" width="14" height="14"/><text x="320" y="108" class="ts">bit de paridade: completa um número ímpar de 1 no byte</text>
</svg>
<figcaption>Figura 39.3 — Os 64 bits de uma chave DES. Oito deles só conferem a digitação; a cifra os ignora.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<text x="200" y="44" text-anchor="end">DES</text><rect x="210" y="30" width="95.2" height="18" fill="#7a1f1f"/><text x="311.2" y="44" class="ts">56 bits</text><text x="200" y="74" text-anchor="end">2 × DES (encontro no meio)</text><rect x="210" y="60" width="96.9" height="18" fill="#7a1f1f"/><text x="312.9" y="74" class="ts">57 bits</text><text x="200" y="104" text-anchor="end">3DES duplo, muitos pares</text><rect x="210" y="90" width="136.0" height="18" fill="#888"/><text x="352.0" y="104" class="ts">80 bits</text><text x="200" y="134" text-anchor="end">3DES triplo</text><rect x="210" y="120" width="190.4" height="18" fill="#2d4f73"/><text x="406.4" y="134" class="ts">112 bits</text><text x="200" y="164" text-anchor="end">AES-128</text><rect x="210" y="150" width="217.6" height="18" fill="#2f5f2f"/><text x="433.6" y="164" class="ts">128 bits</text><text x="200" y="194" text-anchor="end">AES-256</text><rect x="210" y="180" width="435.2" height="18" fill="#2f5f2f"/><text x="651.2" y="194" class="ts">256 bits</text>
<line x1="305.2" y1="20" x2="305.2" y2="210" stroke="#7a1f1f" stroke-dasharray="4 3"/>
<text x="310" y="222" class="ts td">56 bits: achada em 22 horas em 1999</text>
</svg>
<figcaption>Figura 39.4 — A força efetiva de cada cifra, em bits de busca. Cada bit a mais dobra o trabalho: o AES-256 custa 2²⁰⁰ vezes o trabalho do DES.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="20" class="tb">3DES: cifra, decifra, cifra</text>
<rect class="cxa" x="10" y="35" width="60" height="30"/><text x="40" y="55" text-anchor="middle">P</text>
<rect class="cxd" x="110" y="35" width="90" height="30"/><text x="155" y="55" text-anchor="middle">E, K1</text>
<rect class="cx" x="240" y="35" width="90" height="30"/><text x="285" y="55" text-anchor="middle">D, K2</text>
<rect class="cxd" x="370" y="35" width="90" height="30"/><text x="415" y="55" text-anchor="middle">E, K3</text>
<rect class="cxv" x="500" y="35" width="60" height="30"/><text x="530" y="55" text-anchor="middle">C</text>
<line class="ln" x1="70" y1="50" x2="108" y2="50" marker-end="url(#seta)"/><line class="ln" x1="200" y1="50" x2="238" y2="50" marker-end="url(#seta)"/><line class="ln" x1="330" y1="50" x2="368" y2="50" marker-end="url(#seta)"/><line class="ln" x1="460" y1="50" x2="498" y2="50" marker-end="url(#seta)"/>
<text x="580" y="46" class="ts">dupla: K3 = K1</text><text x="580" y="60" class="ts">simples: todas iguais</text>
<text x="10" y="110" class="tb">por que não 2 × DES: o encontro no meio</text>
<rect class="cxa" x="10" y="125" width="60" height="30"/><text x="40" y="145" text-anchor="middle">P</text>
<rect class="cx" x="110" y="125" width="150" height="30"/><text x="185" y="140" text-anchor="middle" class="ts">E(K1, P) para todas</text><text x="185" y="151" text-anchor="middle" class="ts">as 2⁵⁶ chaves: tabela</text>
<rect class="cxd" x="300" y="125" width="80" height="30"/><text x="340" y="145" text-anchor="middle" class="ts tb">iguais?</text>
<rect class="cx" x="420" y="125" width="150" height="30"/><text x="495" y="140" text-anchor="middle" class="ts">D(K2, C) para todas</text><text x="495" y="151" text-anchor="middle" class="ts">as 2⁵⁶ chaves</text>
<rect class="cxv" x="610" y="125" width="60" height="30"/><text x="640" y="145" text-anchor="middle">C</text>
<line class="ln" x1="70" y1="140" x2="108" y2="140" marker-end="url(#seta)"/><line class="ln" x1="260" y1="140" x2="298" y2="140" marker-end="url(#seta)"/>
<line class="ln" x1="418" y1="140" x2="382" y2="140" marker-end="url(#seta)"/><line class="ln" x1="608" y1="140" x2="572" y2="140" marker-end="url(#seta)"/>
<text x="340" y="190" text-anchor="middle" class="ts">2⁵⁶ + 2⁵⁶ = 2⁵⁷ operações, e não 2¹¹²: as duas chaves se acham separadas</text>
<text x="340" y="208" text-anchor="middle" class="ts">no 3DES, o encontro no meio ainda funciona, mas um dos lados tem duas cifras: cerca de 2¹¹²</text>
</svg>
<figcaption>Figura 39.5 — O 3DES, e por que não basta cifrar duas vezes.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 250" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="60" y1="200" x2="600" y2="200" marker-end="url(#seta)"/>
<line class="ln" x1="60" y1="200" x2="60" y2="20" marker-end="url(#seta)"/>
<g class="ts"><text x="60" y="216" text-anchor="middle">2²⁰</text><text x="164" y="216" text-anchor="middle">2²⁴</text><text x="268" y="216" text-anchor="middle">2²⁸</text><text x="372" y="216" text-anchor="middle">2³²</text><text x="476" y="216" text-anchor="middle">2³⁶</text><text x="580" y="216" text-anchor="middle">2⁴⁰</text>
<text x="52" y="204" text-anchor="end">0</text><text x="52" y="119" text-anchor="end">0,5</text><text x="52" y="34" text-anchor="end">1</text></g>
<line class="grade" x1="60" y1="115" x2="590" y2="115"/><line class="grade" x1="60" y1="30" x2="590" y2="30"/>
<polyline points="60.0,200.0 66.5,200.0 73.0,200.0 79.5,200.0 86.0,200.0 92.5,200.0 99.0,200.0 105.5,200.0 112.0,200.0 118.5,200.0 125.0,200.0 131.5,200.0 138.0,200.0 144.5,200.0 151.0,200.0 157.5,200.0 164.0,200.0 170.5,200.0 177.0,200.0 183.5,200.0 190.0,200.0 196.5,200.0 203.0,200.0 209.5,200.0 216.0,200.0 222.5,200.0 229.0,200.0 235.5,199.9 242.0,199.9 248.5,199.9 255.0,199.8 261.5,199.8 268.0,199.7 274.5,199.5 281.0,199.3 287.5,199.1 294.0,198.7 300.5,198.1 307.0,197.4 313.5,196.3 320.0,194.8 326.5,192.7 333.0,189.7 339.5,185.6 346.0,180.0 352.5,172.5 359.0,162.4 365.5,149.4 372.0,133.1 378.5,113.8 385.0,92.5 391.5,71.3 398.0,53.0 404.5,40.0 411.0,33.1 417.5,30.6 424.0,30.1 430.5,30.0 437.0,30.0 443.5,30.0 450.0,30.0 456.5,30.0 463.0,30.0 469.5,30.0 476.0,30.0 482.5,30.0 489.0,30.0 495.5,30.0 502.0,30.0 508.5,30.0 515.0,30.0 521.5,30.0 528.0,30.0 534.5,30.0 541.0,30.0 547.5,30.0 554.0,30.0 560.5,30.0 567.0,30.0 573.5,30.0 580.0,30.0" fill="none" stroke="#7a1f1f" stroke-width="2.2"/>
<line x1="60" y1="199" x2="590" y2="199" stroke="#2f5f2f" stroke-width="2.2"/>
<circle cx="372" cy="133.1" r="5" fill="#7a1f1f"/>
<text x="380" y="137.1" class="ts td">2³² blocos = 32 GB: 39%</text>
<text x="420" y="60" class="ts td">bloco de 64 bits (DES, 3DES)</text>
<text x="420" y="190" class="ts" fill="#2f5f2f">bloco de 128 bits (AES): fica em zero</text>
<text x="330" y="240" text-anchor="middle" class="ts">blocos cifrados com a mesma chave</text>
<text x="20" y="110" class="ts" transform="rotate(-90 20 110)" text-anchor="middle">chance de dois cifrados iguais</text>
</svg>
<figcaption>Figura 39.6 — O paradoxo do aniversário no bloco de 64 bits. Uma chave de PIN cifra um bloco por vez; uma conexão TLS, gigabytes.</figcaption>
</figure>

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

**O que uma chave 3DES faz em cada comando.** O tipo da chave trava os
comandos, e cada trava caiu quando a função correspondente entrou:

| Comando | Com chave 3DES | Quando muda |
|---|---|---|
| `K0`, `K2` | gera e confere | — |
| `K4`, `K6` sob uma KEK AES | exporta e importa | — |
| `K4`, `K6` com uma KEK 3DES | exporta e importa, em bloco versão B | feito na etapa 8.7, seção 39.9 |
| `P0` | traduz no formato 0; no formato 4, recusa (`11`) | feito na etapa 8.4, seção 34.2 |
| `C0`, `C2`, `M0`, `M2` | cifra dados em CBC e faz o retail MAC | feito na etapa 8.9a, seção 39.10 |

A trava não era só política. O coprocessador só faz AES-256: uma chave de 16
bytes entregue a ele seria lida além do fim. Por isso o 3DES tem caminho
próprio, em software, em cada comando. A checagem do algoritmo fica no
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
chave de proteção (a KBPK, seção 8). Este equipamento usa duas:

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


<figure class="fig">
<svg viewBox="0 0 680 190" xmlns="http://www.w3.org/2000/svg">
<text x="90" y="20" text-anchor="middle" class="tb">KEK</text>
<text x="560" y="20" text-anchor="middle" class="tb">chave transportada</text>
<rect class="cxv" x="20" y="35" width="140" height="34"/><text x="90" y="56" text-anchor="middle">AES-256</text>
<rect class="cx" x="20" y="85" width="140" height="34"/><text x="90" y="106" text-anchor="middle">3DES triplo</text>
<rect class="cxd" x="20" y="135" width="140" height="34"/><text x="90" y="156" text-anchor="middle">3DES duplo</text>
<rect class="cxv" x="490" y="35" width="140" height="34"/><text x="560" y="56" text-anchor="middle">AES-256</text>
<rect class="cx" x="490" y="85" width="140" height="34"/><text x="560" y="106" text-anchor="middle">3DES triplo</text>
<rect class="cxd" x="490" y="135" width="140" height="34"/><text x="560" y="156" text-anchor="middle">3DES duplo</text>
<line class="ln" x1="160" y1="52" x2="488" y2="52" marker-end="url(#seta)"/>
<line class="ln" x1="160" y1="52" x2="488" y2="100" marker-end="url(#seta)"/>
<line class="ln" x1="160" y1="52" x2="488" y2="150" marker-end="url(#seta)"/>
<line class="ln" x1="160" y1="102" x2="488" y2="104" marker-end="url(#seta)"/>
<line class="ln" x1="160" y1="102" x2="488" y2="154" marker-end="url(#seta)"/>
<line class="ln" x1="160" y1="152" x2="488" y2="158" marker-end="url(#seta)"/>
<text x="325" y="186" text-anchor="middle" class="ts">só setas para baixo ou na mesma linha: a chave nunca sai sob outra mais fraca (recusa 13 no K4, 10 no K6)</text>
</svg>
<figcaption>Figura 39.7 — A regra de força da KEK. Versão D sob a KEK AES; versão B sob a KEK 3DES.</figcaption>
</figure>

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

### 39.10 MAC de mensagem e dados com 3DES

Numa rede de pagamento, cada mensagem entre o terminal, o adquirente e o
emissor leva um **MAC**: um código que só quem tem a chave calcula, e que
denuncia qualquer alteração no caminho. Quando a chave é 3DES, o MAC quase
sempre é o **retail MAC**, o algoritmo 3 da ISO/IEC 9797-1. O nome vem da
ANSI X9.19, a norma de MAC do varejo financeiro americano, que o definiu
primeiro.

**O problema que ele resolve.** O MAC mais simples com uma cifra de bloco é o
CBC-MAC: cifrar a mensagem em CBC, com IV zero, e ficar com o último bloco.
Com DES simples, a chave tem 56 bits e cai por busca exaustiva (seção 39.4).
Com 3DES em todo bloco, a chave tem 112 bits, mas cada bloco custa três DES.
O retail MAC fica no meio: DES simples na cadeia, e o 3DES só no fim.

```
   chave dupla K ‖ K'          mensagem preenchida M1 M2 ... Mq

   H1 = DES_K( M1 )
   Hj = DES_K( H(j-1) ⊕ Mj )               j = 2 .. q
   MAC = DES_K( DES⁻¹_K'( Hq ) )           as duas chaves, só no último
```

O passo final é o 3DES de chave dupla `K ‖ K'` sobre o último bloco: o
primeiro DES desse 3DES é o último da cadeia. Uma mensagem de `q` blocos custa
`q + 2` DES, e não `3q`.


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<g>
<rect class="cxa" x="40" y="20" width="80" height="28"/><text x="80" y="39" text-anchor="middle" class="tm">M1</text>
<rect class="cxa" x="200" y="20" width="80" height="28"/><text x="240" y="39" text-anchor="middle" class="tm">M2</text>
<rect class="cxa" x="360" y="20" width="80" height="28"/><text x="400" y="39" text-anchor="middle" class="tm">…</text>
<rect class="cxa" x="520" y="20" width="80" height="28"/><text x="560" y="39" text-anchor="middle" class="tm">Mq</text>
</g>
<rect class="cx" x="40" y="90" width="80" height="30"/><text x="80" y="110" text-anchor="middle" class="ts">DES, K</text>
<circle class="cx" cx="240" cy="70" r="12"/><text x="240" y="75" text-anchor="middle" class="tb">⊕</text>
<rect class="cx" x="200" y="90" width="80" height="30"/><text x="240" y="110" text-anchor="middle" class="ts">DES, K</text>
<circle class="cx" cx="400" cy="70" r="12"/><text x="400" y="75" text-anchor="middle" class="tb">⊕</text>
<rect class="cx" x="360" y="90" width="80" height="30"/><text x="400" y="110" text-anchor="middle" class="ts">DES, K</text>
<circle class="cx" cx="560" cy="70" r="12"/><text x="560" y="75" text-anchor="middle" class="tb">⊕</text>
<rect class="cxd" x="500" y="90" width="120" height="30"/><text x="560" y="110" text-anchor="middle" class="ts">3DES, K ‖ K'</text>
<line class="ln" x1="80" y1="48" x2="80" y2="88" marker-end="url(#seta)"/>
<line class="ln" x1="240" y1="48" x2="240" y2="56" marker-end="url(#seta)"/>
<line class="ln" x1="400" y1="48" x2="400" y2="56" marker-end="url(#seta)"/>
<line class="ln" x1="560" y1="48" x2="560" y2="56" marker-end="url(#seta)"/>
<line class="ln" x1="240" y1="82" x2="240" y2="88" marker-end="url(#seta)"/>
<line class="ln" x1="400" y1="82" x2="400" y2="88" marker-end="url(#seta)"/>
<line class="ln" x1="560" y1="82" x2="560" y2="88" marker-end="url(#seta)"/>
<path class="ln" d="M120,105 H160 V70 H226" marker-end="url(#seta)"/>
<path class="ln" d="M280,105 H320 V70 H386" marker-end="url(#seta)"/>
<path class="ln" d="M440,105 H480 V70 H546" marker-end="url(#seta)"/>
<line class="ln" x1="560" y1="120" x2="560" y2="148" marker-end="url(#seta)"/>
<rect class="cxv" x="490" y="150" width="140" height="30"/><text x="560" y="170" text-anchor="middle" class="tb">MAC: 4 ou 8 bytes</text>
<text x="40" y="160" class="ts">a cadeia é um CBC-MAC com DES simples sob K;</text>
<text x="40" y="174" class="ts">só o último bloco vê as duas chaves</text>
<text x="40" y="198" class="ts">preenchimento 1: zeros · preenchimento 2: 80 e zeros</text>
</svg>
<figcaption>Figura 39.8 — O retail MAC (ISO/IEC 9797-1, algoritmo 3). Uma mensagem de q blocos custa q + 2 DES.</figcaption>
</figure>

**O preenchimento.** A mensagem é completada até um múltiplo de 8 bytes. A
ISO 9797-1 define três métodos, e este equipamento faz os dois mais usados:

| Método | Regra | Mensagem já múltipla de 8 |
|---|---|---|
| 1 | completar com zeros | nada é acrescentado |
| 2 | um byte `80`, e zeros | um bloco inteiro é acrescentado: `80 00 … 00` |

O método 1 é ambíguo: `41 42` e `41 42 00` dão o mesmo MAC. Ele só é seguro
quando o tamanho da mensagem é fixo, ou vem dentro dela, como num campo de
tamanho da mensagem ISO 8583. O método 2 não tem essa ambiguidade.

**O tamanho.** O MAC tem 8 bytes, e muitas redes usam só os 4 da esquerda.
Com 4 bytes, quem tenta forjar acerta uma vez em 2³², e o controle é
recusar e contar as tentativas, como no CVV (seção 36).

**Um exemplo.** É o da ISO/IEC 9797-1:2011, seção B.4, que o projeto confere
nos testes. A chave e a mensagem `"Now is the time for it"` (22 bytes), com
o preenchimento 1:

```
   K  = 0123456789ABCDEF           K' = FEDCBA9876543210

   M1 = 4E6F772069732074           H1 = 3FA40E8A984D4815
   M2 = 68652074696D6520           H2 = 0B2E73F88DC5856A
   M3 = 666F722069740000           H3 = E45B3AD2B7CC0856
                                   DES⁻¹_K'(H3) = 328AC78BA1CA0B3F
                                   MAC = DES_K(…) = 2E2B1428CC78254F
```

Com o preenchimento 2, só o último bloco muda (`M3 = 666F722069748000`), e o
MAC passa a `5A692CE64F404145`. Uma diferença de um byte no preenchimento
muda o MAC inteiro.

**A fraqueza conhecida.** A cadeia em DES simples cobra um preço. Preneel e
van Oorschot (*Electronics Letters* 32(17), 1996) mostraram que, com cerca de
2^32,5 pares conhecidos de mensagem e MAC, as duas chaves saem em cerca de
3 · 2^56 cifras DES, uma de cada vez: a força volta à do DES simples. Daí a
recomendação de trocar a chave de MAC muito antes de 2³² mensagens e, num
sistema novo, usar CMAC com AES. O DUKPT resolve de outro modo: uma chave por
transação (seção 37).

**Dados com 3DES.** A cifra de dados com chave 3DES é o CBC da seção 39.5,
com IV de 8 bytes e dados em múltiplos de 8. O pedido não leva enchimento:
quem completa a mensagem é o host, como no AES.

**Neste equipamento.** Os comandos são os mesmos do AES, e o algoritmo da
chave, no cabeçalho do key block, escolhe a conta:

| Comando | Chave AES | Chave 3DES |
|---|---|---|
| `C0`, `C2` | AES-CBC, IV de 32 caracteres, dados múltiplos de 16 | 3DES-CBC, IV de 16 caracteres, dados múltiplos de 8 |
| `M0` | CMAC-AES, MAC de 32 caracteres | retail MAC: key block ‖ preenchimento (`1`/`2`) ‖ tamanho (`4`/`8`) ‖ dados → MAC de 8 ou 16 caracteres |
| `M2` | verifica o CMAC | key block ‖ preenchimento ‖ tamanho ‖ MAC ‖ dados → `00` confere, `01` não confere |

```
    pedido      M0  <bloco 3DES, uso M3, modo C>  1  8  0022  4E6F77…6974
                                                  |  |  |
                                                  |  |  22 bytes de mensagem
                                                  |  MAC de 8 bytes
                                                  preenchimento 1
    resposta    M1  00  2E2B1428CC78254F
```

As regras do equipamento:

- **A chave de MAC 3DES é dupla.** O retail MAC usa o par `K`, `K'`. Uma
  chave tripla responde `11`, como no CVV.
- **O uso é o da família `M`**, como a chave de CMAC, e o modo separa gerar
  (`G`) de verificar (`V`); `C` faz os dois. Uma chave `D0` não faz MAC, e
  uma chave `M` não cifra dados: os dois respondem `11`.
- **Mensagem vazia** responde `15`, e preenchimento ou tamanho fora da
  tabela, `16`.
- **O `M2` devolve um bit**, e compara em tempo constante dentro do
  equipamento, como o CMAC. O MAC e o veredito são calculados duas vezes, e
  uma discordância responde `91`.
- **O autoteste do 3DES** (seção 39.8) passou a incluir dois valores
  publicados de retail MAC, um de cada preenchimento.
