# Parte VII — Criptografia de pagamento

Esta parte existe porque o modelo de referência deste projeto passou a ser
um **HSM de pagamento comercial**. Entender o que
esses equipamentos fazem o dia inteiro é o que separa "sei o que é uma
fronteira criptográfica" de "sei por que aquele comando existe".

O equipamento implementa uma parte do que está aqui: o PIN block formato 4
e a tradução de PIN (seções 33.4 e 34), e as chaves 3DES (seção 38). A seção 37 explica o que é
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
só deixa dois nibbles de enchimento para conferir. A seção 41.2 faz a conta.

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
| `P0` traduzir | `P1` | key block de origem · key block de destino · formato de origem(1) · formato de destino(1) · tamanho do PAN(2) · PAN · PIN block(32) | PIN block(32) |

As regras:

- **As duas chaves têm uso `P0`** no key block, o código da norma para chave
  de PIN. Uma chave de dados (`D0`) no lugar responde `11`. O contrário
  também vale: o `C2` recusa uma chave de PIN. Sem essa separação, decifrar
  um PIN block seria só "decifrar dados".
- **O modo conta.** A chave de origem precisa decifrar (`D` ou `B`), e a de
  destino precisa cifrar (`E` ou `B`). Uma chave de modo `E` serve a um
  equipamento que só envia PINs adiante, e nunca abre o que recebe.
- **O formato é conferido.** Se o bloco aberto não é um formato 4 bem
  formado, a resposta é `14` e nada sai. É o veredito de "deu certo" de que
  a seção fala. Com o formato 4 ele revela pouco: não separa um PIN de
  outro, e um bloco forjado ao acaso só passa uma vez em 17 milhões. Isso
  não é barreira contra quem pergunta em laço: o controle é o log.
- **O aleatório é novo.** O bloco de saída não herda os 8 bytes aleatórios
  do bloco de entrada. Dois pedidos iguais dão duas saídas diferentes.
- **O resultado é calculado duas vezes**, na abertura e no fechamento, como
  tudo o que sai ao host (seção 29).

O PIN em claro fica numa área do key store, entre abrir com uma chave e
fechar com a outra. Ele não passa pelo código que interpreta o comando, e é
apagado no fim do comando, qualquer que seja o resultado.

Hoje os dois campos de formato só aceitam `4`. Eles existem porque o uso
real do comando é traduzir entre formatos, e é nessa conversão que moram os
ataques da seção 15.3.

---

## 35. Verificação de PIN — PVV e IBM 3624

O emissor precisa decidir se o PIN digitado está certo. Guardar os PINs
numa base seria insano, então guarda-se um **valor derivado** de quatro
dígitos, e a verificação recalcula e compara.

Duas famílias dominam.

### 35.1 PVV (Visa)

Combinam-se dígitos do PAN, um índice de chave e o PIN; cifra-se o conjunto
com um par de chaves PVK; **decimaliza-se** o resultado; guardam-se quatro
dígitos. Para verificar, o emissor refaz a conta com o PIN apresentado e
compara.

Repare no que ele **não** faz: não guarda o PIN e não permite recuperá-lo.
Quatro dígitos de PVV não determinam o PIN — várias entradas colidem, e é
proposital.

### 35.2 IBM 3624 e o *offset*

Cifra-se um dado de validação derivado do PAN, decimaliza-se, e obtêm-se
alguns dígitos: o **PIN natural**. Como o cliente quer escolher o próprio
PIN, guarda-se o **offset** — a diferença dígito a dígito, módulo 10, entre
o PIN escolhido e o natural.

O offset **não é secreto**: ele pode ser impresso, transportado, guardado em
claro. Sem a chave, ele não diz nada sobre o PIN.

### 35.3 A decimalização, e por que ela é o ponto fraco

Cifrar produz **hexadecimal**. PIN é **decimal**. A ponte entre os dois é
uma tabela:

```
   hex:    0 1 2 3 4 5 6 7 8 9 A B C D E F
   tabela: 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
```

Essa tabela, que parece detalhe de formatação, é a origem do ataque mais
instrutivo da literatura de HSM — **Bond e Zieliński, 2003**. Algumas APIs
deixavam o *chamador* fornecê-la. Fornecendo tabelas degeneradas e
observando apenas "verificou / não verificou", recupera-se um PIN de quatro
dígitos em cerca de **quinze chamadas**, contra cinco mil de força bruta.

O ataque está detalhado na **seção 15.2**. Aqui só o alerta que ele deixa:

> Um parâmetro que parece configuração inofensiva pode ser a superfície de
> ataque inteira.

E é por isso que o checklist deste projeto pergunta, para todo comando
novo, *o que ele vaza se for chamado em laço com entradas escolhidas*.

---

## 36. DUKPT — uma chave por transação

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

### 36.1 X9.24-1 (TDES) e X9.24-3 (AES)

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

## 37. O que este projeto pode e o que não pode ensinar

A separação não é por dificuldade. É por **hardware** e por **procedência
de vetor de teste**.

| Assunto | Aqui? | O que decide |
|---|---|---|
| PIN block formato 4 | **feito** | é AES, e AES é o que existe no fabric |
| Chaves 3DES: gerar, conferir, exportar | **feito** | motor em software, com vetores oficiais (seção 38.8) |
| PIN block formato 0 e 3 | **planejado** | a cifra é o 3DES, que entra no equipamento |
| Tradução de PIN | **feita** (`P0`, só formato 4) | o valor está no formato do comando e no oráculo, não na cifra |
| Verificação de PIN e ataque de decimalização | **planejado, e é o melhor item** | é ataque de **API**, sobre o método real |
| DUKPT AES (X9.24-3) | **planejado** | é AES |
| CVV / CVC | **planejado** | inerentemente 3DES; não há variante AES em uso |
| PVV | **planejado** | idem |
| DUKPT TDES (X9.24-1) | **planejado** | idem |
| Criptogramas EMV, emissão de PIN | fora, por enquanto | são funções de emissor, maiores que as demais |

### 37.1 Um HSM precisa de 3DES?

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

### 37.2 Como o 3DES entra aqui

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

A seção 38 explica o DES e o 3DES.

### 37.3 O obstáculo maior são os vetores

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

### 37.4 Uma regra que não se negocia

⚠ **Nenhum número de cartão real, nunca.** Pela mesma razão que nenhuma
chave de produção. Gerar CVV ou PIN para um PAN que existe deixa de ser
exercício, e o fato de o dispositivo ser de brinquedo não muda isso.

---

## 38. DES e 3DES — a cifra que o mercado ainda usa

O AES tem seção própria na Parte I. O DES entra aqui, na Parte VII, porque é
em pagamentos que ele sobrevive. Quem opera um HSM de pagamento lida com
chaves 3DES todos os dias, e precisa saber o que elas são, o que os termos
"comprimento duplo" e "paridade" querem dizer, e por que a cifra está sendo
aposentada.

### 38.1 A rede de Feistel

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

### 38.2 O DES por dentro

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

### 38.3 A chave: 64 bits que são 56

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

### 38.4 Por que o DES caiu

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

### 38.5 O 3DES

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
está migrando (seção 37.1).

**O KCV de uma chave 3DES** é calculado com o próprio 3DES: cifram-se 8
bytes de zeros, e os primeiros 3 bytes do resultado são o KCV. A chave de
comprimento duplo `0123456789ABCDEF FEDCBA9876543210` tem KCV `08D7B4`.

### 38.6 O bloco de 64 bits

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

### 38.7 DES, 3DES e AES, lado a lado

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

### 38.8 O 3DES neste equipamento

O 3DES é um **motor separado, em software**, ao lado do AES do coprocessador.
Ele serve às funções de pagamento, e a LMK continua AES-256 (seção 37.2).

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

- **Paridade ímpar** em todo byte (seção 38.3).
- **Nenhuma chave fraca.** Se alguma das partes cair numa das 16 chaves
  fracas ou semifracas do DES, ou se duas partes saírem iguais, o
  equipamento sorteia de novo. A chance é desprezível; a regra está na
  SP 800-67, e um gerador que a ignora não passa numa avaliação.
- **KCV calculado com 3DES**, como na seção 38.5. O `K2` devolve o mesmo
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
| `K4`, `K6` com uma KEK 3DES | recusa (`13`) | com a troca de chaves 3DES |
| `P0` | recusa (`11`) | com o PIN block formato 0 |
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
