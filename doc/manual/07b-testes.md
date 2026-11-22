# Parte VIII — Como o equipamento é testado

Um equipamento criptográfico que calcula errado não avisa. Ele devolve
bytes com a mesma cara dos bytes certos. Por isso o teste, aqui, não é uma
etapa no fim: é a única forma de saber o que o equipamento faz.

Esta parte descreve cada tipo de teste do projeto, o que ele prova, o que
ele **não** prova, e a conta que sustenta a conclusão. As medidas de cada
rodada (tempos, datas, contagens por fase) estão nas notas de fase, em
`doc/faseN-notas.md`.

## 40. O que um teste pode provar

Três ideias organizam tudo o que vem depois.

**Um teste só vale o que vale a referência dele.** Comparar a saída do
equipamento com um valor esperado prova que os dois concordam. Se o valor
esperado saiu da mesma cabeça que escreveu o código, o teste prova só que a
pessoa é coerente consigo mesma. A referência tem de ser **independente**.
Este projeto usa quatro tipos, do mais forte ao mais fraco:

| Referência | Exemplo | O que garante |
|---|---|---|
| Vetor oficial | arquivos do CAVP, do NIST | o algoritmo é o da norma |
| Vetor de terceiros | o key block, o PIN block nos formatos 0 e 4, o offset e o PVV | uma implementação independente concorda |
| Segunda implementação | o Python do host contra o C do firmware | duas leituras da mesma norma concordam |
| Propriedade | ida e volta, um bit trocado tem de reprovar | o comportamento é coerente, sem dizer que é o da norma |

**Um teste que passa não prova ausência de erro.** Ele prova que os casos
testados funcionam. A pergunta útil é: qual erro escaparia? Se um defeito
afeta uma fração `f` das entradas, e o teste sorteia `n` entradas, a chance
de o defeito escapar é

```
    P(escapar) = (1 − f)^n
```

Com `n = 100`, um defeito que afeta 5% das entradas escapa com chance de
0,6%. Um defeito que afeta 1% das entradas escapa com chance de 37%. Sorteio
pega erro frequente. Erro raro, de borda, só é pego por um caso **escolhido**
para ele. Por isso os testes aqui têm as duas coisas: vetores escolhidos para
as bordas, e sorteio para o resto.

**Zero falhas em `n` tentativas é uma medida, e não uma garantia.** Se a
taxa real de falha fosse `p`, a chance de ver zero falhas em `n` tentativas
seria `(1 − p)^n`. Com 95% de confiança, a taxa real é menor que

```
    p < 3 / n            (a "regra de três")
```

Dez mil comandos sem erro dizem que a taxa de erro é menor que 3 em 10 000.
Não dizem que é zero.

### 40.1 A regra que protege os testes

A regra nº 5 do projeto diz: se um teste de resposta conhecida falha, o erro
está no código, e não no vetor. Ninguém ajusta o vetor, relaxa a comparação
ou pula o teste.

A regra só se sustenta com disciplina de procedência:

- Todo vetor externo tem a origem (URL) e o SHA-256 registrados em
  `vectors/MANIFEST.txt`. Um script confere os hashes.
- Nenhum vetor é escrito de memória. Os vetores embutidos no firmware são
  gerados por programa (`scripts/mkkat.py`) a partir dos arquivos oficiais.
- Onde não existe vetor oficial público, o projeto diz isso, e marca a fonte
  como secundária (seção 38.3).

### 40.2 Os quatro lugares onde se testa

| Lugar | O que roda | Velocidade | O que só ele vê |
|---|---|---|---|
| No PC | o C do firmware compilado com `gcc`, e o Python | segundos | a lógica, contra milhares de casos |
| Simulação do circuito | o hardware e o firmware reais, ciclo a ciclo | 12 s por milissegundo simulado | sinais internos, falhas provocadas, o tempo em ciclos |
| No boot | o autoteste do próprio equipamento | 28 ms | o equipamento **desta** placa, **agora** |
| Na placa | os comandos, pela serial | tempo real | o silício: temperatura, ruído, o gerador aleatório de verdade |

Cada lugar cobre o que os outros não alcançam. O teste no PC não prova que o
firmware fala certo com o coprocessador. A simulação não prova nada sobre o
ruído físico. A placa não deixa ver por dentro.

A ordem é fixa: PC, simulação, placa. Um erro de enchimento que aparece na
placa aparece como "resposta errada", sem pista. Na simulação, o mesmo erro
aparece com todos os sinais à vista.

## 41. Testes de resposta conhecida

Um **KAT** (*Known Answer Test*) dá uma entrada e cobra a saída exata.
Para uma função determinística, é o teste mais forte que existe: a saída de
um AES tem 128 bits, e um AES errado acerta um vetor por acaso com chance de
`2⁻¹²⁸`.

A força de um conjunto de KATs está na escolha dos vetores. Os conjuntos do
NIST são desenhados para que cada parte do algoritmo seja exercitada por
algum vetor.

### 41.1 AES-256

1620 vetores: 405 em cada combinação de modo (ECB, CBC) e direção. São
quatro famílias, e cada uma procura um tipo de erro:

| Família | Como é | O erro que ela pega |
|---|---|---|
| GFSbox | chave zero, textos escolhidos | a caixa S e a aritmética do corpo finito |
| KeySbox | texto zero, chaves escolhidas | a caixa S dentro da expansão de chave |
| VarKey | um bit da chave ligado por vez, 256 vetores | bit de chave ignorado ou trocado de posição |
| VarTxt | um bit do bloco ligado por vez, 128 vetores | bit do bloco ignorado ou trocado de posição |

As duas últimas são as que pegam erro **estrutural**. Uma implementação com
dois bytes da chave trocados de lugar passa em todo vetor com chave zero, e
falha no VarKey.

Os mesmos vetores rodam em dois níveis: no núcleo de AES sozinho, e de novo
através do mapa de registradores do coprocessador. O segundo nível pega um
erro que o primeiro não vê: um núcleo certo atrás de um barramento com a
ordem das palavras invertida dá resultados perfeitamente errados.

### 41.2 SHA-256, HMAC, CMAC e o gerador determinístico

- **SHA-256:** 65 mensagens, de 0 a 512 bits. O ponto delicado do SHA é o
  **enchimento**: a mensagem recebe um bit 1, zeros, e o tamanho em 64 bits.
  Uma mensagem de 448 a 511 bits não cabe com o enchimento num bloco, e
  transborda para o segundo. Os vetores cobrem os dois lados dessa borda.
- **HMAC-SHA-256:** os casos da RFC 4231, que incluem chave maior que o
  bloco. Nesse caso a chave é trocada pelo hash dela, e é o ramo que uma
  implementação apressada esquece.
- **CMAC-AES-256:** vetores do CAVP. Eles só trazem a tag **truncada**, e a
  comparação é sobre os bytes que o vetor tem. Os últimos 6 bytes da tag não
  são cobertos por vetor oficial, e o projeto registra essa lacuna.
- **CTR_DRBG:** o gerador determinístico é uma função: mesma semente, mesma
  saída. O vetor dá a entropia, o nonce e os bytes esperados depois de duas
  chamadas. Isso testa o algoritmo do gerador, e não a qualidade da
  entropia, que é assunto da seção 43.

### 41.3 DES e 3DES

O DES é feito de tabelas: duas permutações, uma expansão, oito caixas S e o
escalonamento de chave (seção 39.2). Um número errado numa tabela dá uma
cifra que funciona, se desfaz, e não é o DES. Os KATs da SP 800-20 foram
feitos para esse erro, tabela por tabela:

| Família | Vetores | O que exercita |
|---|---|---|
| Texto variável | 64 | cada bit do bloco: a permutação inicial e a expansão |
| Permutação inversa | 64 | a permutação final |
| Chave variável | 56 | cada bit útil da chave: a tabela PC-1 |
| Operação de permutação | 32 | a permutação P |
| Tabela de substituição | 19 | cada uma das 64 entradas das 8 caixas S |

Somados aos testes de várias mensagens, com chave dupla e tripla em ECB e
CBC, são 1000 vetores. A implementação em Python e a em C passam em todos.
O autoteste do equipamento leva 25 deles: os 19 de substituição, porque uma
caixa S errada é o defeito mais provável de uma tabela copiada, e seis
mensagens.

### 41.4 RSA

**Verificar.** O vetor dá `n`, `e`, a mensagem e a assinatura `S`. O teste
calcula `S^e mod n` e exige o bloco PKCS#1 v1.5 inteiro (seção 30). Um
segundo teste troca um bit de `S` e exige a **recusa**: uma verificação que
aceita tudo passa no primeiro teste e falha no segundo.

**Assinar.** O PKCS#1 v1.5 é determinístico, então a assinatura tem resposta
conhecida. O vetor do CAVP dá `n`, `e` e `d`, e o equipamento assina pelo
Teorema Chinês do Resto, que precisa de `p` e `q`. O programa que prepara o
vetor os recupera de `e·d − 1`, que é múltiplo de `(p − 1)(q − 1)`:

```
    escreve  e·d − 1 = 2^s · t,  com t ímpar
    sorteia  g,  calcula  x = g^t mod n
    eleva x ao quadrado até achar  x ≠ ±1  com  x² = 1 (mod n)
    então    mdc(x − 1, n)  é um dos primos
```

Funciona porque um número diferente de `±1` cujo quadrado é 1 só existe
módulo um número composto, e ele separa os fatores. O programa confere que
`p · q` é o `n` do vetor, e que a assinatura por CRT é o `S` do vetor.

**O multiplicador.** Antes de qualquer RSA, o produto de Montgomery é
testado sozinho contra inteiros do Python, com os casos de borda: 0, 1,
`n − 1`, e `R mod n`. São os valores em que a subtração final decide o
resultado.

### 41.5 ECDSA

**Verificar.** Os vetores do CAVP vêm com o veredito: válido, ou inválido
com a causa (mensagem, `r`, `s` ou chave pública alterados). O teste exige o
veredito certo em cada um.

**Assinar.** A assinatura usa um `k` sorteado, então não tem resposta
conhecida (seção 30). Há duas saídas, e o projeto usa as duas:

- No autoteste, uma entrada interna recebe o `k` **do vetor**. Com ele, `r`
  e `s` têm de ser os do vetor. Nenhum comando alcança essa entrada.
- Nos testes pela serial, a assinatura é conferida pela **verificação**, com
  uma implementação independente e só com a chave pública.

**Os casos que os vetores não cobrem.** A multiplicação de ponto falha para
os escalares `1`, `n − 1` e `n − 2`, se a implementação não os tratar: um
ponto intermediário vira o ponto no infinito. Um escalar sorteado cai num
deles com chance de `3 / 2²⁵⁶`. Nenhum vetor do CAVP os usa, e nenhum
sorteio os acharia. O teste os inclui de propósito, junto com os casos de
exceção da soma de pontos (pontos iguais, pontos opostos, escalar zero).

**Validação da chave pública.** Os vetores de validação trazem pontos fora
da curva e coordenadas fora da faixa. O equipamento tem de recusá-los antes
de qualquer conta.

### 41.6 Primalidade

O teste de Miller-Rabin (seção 30) tem resposta conhecida: o CAVP dá
números primos e números compostos escolhidos. O firmware tem de aceitar o
primo e recusar os compostos.

A conta do erro é a parte interessante. Cada rodada de Miller-Rabin deixa
passar um composto com chance de no máximo `1/4`. Com 5 rodadas, o pior caso
seria `4⁻⁵ = 2⁻¹⁰`, o que é muito. A norma (FIPS 186-5, tabela B.1) fixa 5
rodadas mesmo assim, porque o pior caso não é o caso que ocorre: o candidato
é **sorteado**, e para um número sorteado de 1024 bits a chance de ser um
composto que engana 5 rodadas é menor que `2⁻¹¹²` (Damgård, Landrock e
Pomerance, 1993). A garantia é sobre a média dos candidatos, e só vale
porque o candidato vem de um gerador aleatório aprovado.

## 42. Testes de formato e de protocolo

Um formato não é uma função matemática: é um acordo sobre a posição dos
bytes. Não existe "resposta certa" calculável, só a norma. Os testes de
formato usam as outras três referências da seção 40.

### 42.1 O key block

- **O vetor de terceiros** prova o caminho de **abrir**: derivar as
  subchaves, decifrar e conferir o MAC, contra um bloco que este projeto não
  fez.
- **Ida e volta** prova o caminho de **fechar**. Fechar usa enchimento
  aleatório, então dois blocos da mesma chave são diferentes, e não há
  resposta conhecida.
- **Um bit trocado em cada posição.** O teste troca um caractere em cada uma
  das posições do bloco, uma por vez, e exige a recusa em todas. É o teste
  mais valioso dos três. Uma implementação que esquece de pôr o cabeçalho
  dentro do MAC passa no vetor e na ida e volta, e só falha aqui.
- **As duas subchaves têm de ser diferentes.** Se a chave de cifra e a de
  autenticação coincidissem, todos os testes acima passariam, e um oráculo
  de MAC viraria um oráculo de cifra.

O MAC do bloco tem 128 bits. Quem não tem a chave acerta um MAC com chance
de `2⁻¹²⁸` por tentativa.

**O acordo entre as duas implementações.** O formato está escrito em C e em
Python. Um teste gera 100 chaves no equipamento, exporta, abre no Python, e
faz o caminho inverso. Se uma das duas leu a norma errado, as duas discordam
no primeiro bloco: a discordância num formato é sistemática, e não rara.

### 42.2 O PIN block

- Os três valores de terceiros cobrem o campo do PIN, o campo do PAN e um
  bloco cifrado completo.
- O C do firmware e o Python são comparados na forma dos campos, para todo
  tamanho de PIN e de PAN.
- A conferência do formato é testada com campos válidos e com cada nibble
  alterado para cada um dos outros 15 valores.
- **Formato 0.** Onze valores de terceiros cobrem o bloco em claro, isto é,
  o campo do PIN já combinado com o campo do PAN: seis blocos bem formados e
  cinco malformados. A cifra do formato 0 é um bloco de 3DES, que tem vetor
  oficial (seção 41.3). O C e o Python são comparados no campo do PAN, na
  conferência do campo e nas duas conversões entre a forma do formato 0 e a
  do formato 4.
- **O formato 0 não tem aleatório, e o teste usa isso.** O bloco traduzido é
  previsível: o testbench compara os 8 bytes que o firmware devolve com os
  que o Python calculou, um a um. No formato 4 isso não é possível, e o
  teste tem de abrir o bloco para conferir.

**Quanto vale a conferência do formato.** Um bloco aberto com a chave
errada, ou com o PAN errado, é um bloco de 16 bytes ao acaso. A chance de
ele passar na conferência é a soma, sobre os tamanhos de PIN de 4 a 12, de:

```
    1/16          o controle é 4
  · 1/16          o tamanho é este
  · (10/16)^n     os n dígitos são de 0 a 9
  · (1/16)^(14−n) o enchimento é A
```

A soma dá cerca de `2⁻²⁴`: um bloco ao acaso em 17 milhões passa. Quem
domina a conta é o PIN de 12 dígitos, que só tem dois nibbles de enchimento
para conferir. Um PIN de 4 dígitos tem dez. A conferência serve para pegar
chave e PAN trocados, e não é barreira contra quem pode perguntar milhões de
vezes: esse é o papel do log e do controle de acesso ao comando.

A conta do formato 0 é a mesma, com controle `0` e enchimento `F`, e dá o
mesmo `2⁻²⁴`. Os dois formatos têm `10⁴ + 10⁵ + … + 10¹²` campos válidos,
cerca de `1,1 × 10¹²`, em `2⁶⁴` possíveis.

**Medir um vazamento.** No formato 0, o veredito da conferência depende do
PIN quando quem pede informa um PAN alterado (seção 34.3). O teste de PC faz
o papel do atacante: troca um dígito do PAN por vez, anota só "passou" ou
"recusou", e agrupa os valores do dígito do PIN que dão as mesmas respostas.
Valores no mesmo grupo são indistinguíveis para o atacante. A medida é o
tamanho médio do grupo:

```
   candidatos que sobram  =  soma, sobre os grupos, de  (tamanho)² / 10
```

Com um grupo só, de 10, sobram 10: nada vazou. Com dez grupos de 1, sobra 1:
o dígito saiu inteiro. A medida deu 3,92, na média sobre os dez dígitos do
PAN. O teste também cobra o que **não** pode vazar: os dois primeiros
dígitos do PIN e o último bit de cada dígito. É um teste que mede um defeito
conhecido do formato, e não um defeito do equipamento. Ele existe para o
número do manual sair de um programa, e para acusar se uma mudança no código
alterar o que o veredito revela.

### 42.3 A verificação de PIN

O método do offset e o PVV estão em norma paga e em documentação de
bandeira. A referência é de terceiros: 24 valores de uma biblioteca aberta,
fixados por hash.

| Valores | Cobrem | Não cobrem |
|---|---|---|
| 10 de offset para PIN, 10 de PIN para offset | a cifra dos dados de validação, a decimalização, a soma e a subtração módulo 10 | PIN com mais de 4 dígitos, outra tabela, chave tripla |
| 4 de PVV | a montagem do bloco de entrada, com dois índices e três contas, e a primeira passada da extração | a segunda passada |

O que os valores não cobrem é coberto pela comparação entre o C do firmware
e o Python, com casos escolhidos.

**Soma e subtração módulo 10.** Há 100 pares de dígitos (PIN, natural). O
teste percorre os 100, confere o offset de cada um, e confere que os outros
9 offsets são recusados: 100 aceitações e 900 recusas. Não sobra par sem
teste.

**A extração do PVV.** A segunda passada só entra quando o bloco cifrado tem
menos de 4 dígitos decimais. Um dígito hexadecimal é decimal com chance
10/16, e a chance de um bloco de 16 ter menos de 4 é

```
   P = soma, k de 0 a 3, de  C(16,k) · (10/16)^k · (6/16)^(16−k) = 1/2 214
```

Um teste de 5 000 sorteios veria o caso duas vezes, em média, e a chance de
não ver nenhuma seria `(1 − 1/2 214)^5 000 = 10%`. Por isso o teste não
depende do sorteio: ele **constrói** 300 blocos para cada quantidade de
decimais, de 0 a 16, com as posições sorteadas. São 5 100 blocos, e 1 200
deles exercitam a segunda passada.

**Tempo constante.** O PIN natural e o resultado da cifra do PVV são
segredo. O código de decimalização lê as 16 entradas da tabela em toda
volta e escolhe por máscara; a extração do PVV faz sempre as mesmas 128
voltas. O teste confere o **resultado** dessas funções, e não o tempo: a
propriedade está no código, por construção, e não tem medida aqui.

**A tabela autorizada.** O testbench pede a tabela ao console, com os
botões, para a chave do offset, e compara o MAC com o que o Python calcula
com a LMK e o KCV. São duas implementações da derivação e do MAC. Depois ele
espera o erro `17` em três casos:

| Caso | O que prova |
|---|---|
| um dígito da tabela trocado | o MAC cobre a tabela |
| um bit do MAC trocado | a conferência compara o MAC inteiro |
| o MAC da mesma tabela, feito para outra chave | o MAC cobre o KCV, e o equipamento usa o KCV da chave que abriu |

Um MAC de 64 bits ao acaso é aceito com chance de 2⁻⁶⁴ por tentativa. Na
placa, o `pinv-confere` repete o terceiro caso a cada volta, com uma chave
`V1` nova, e confere que a mesma tabela funciona com a chave certa.

**O veredito duplo** não tem teste que o dispare: provocar a discordância
pede uma falha de hardware no meio da conta. A seção 45.2 explica como a
dupla execução é testada nos comandos da fase 6.

**O que o teste não refaz.** A conta do ataque de decimalização (15 pedidos
em média) é do relatório de Bond e Zieliński, citado na seção 35.3. O
equipamento é testado pela defesa: tabela sem MAC não entra.

### 42.4 O CVV

O método está em documentação de bandeira, sem vetor oficial público. A
referência é de terceiros: 7 valores de **três** bibliotecas abertas e
independentes, cada arquivo fixado por commit e por hash.

| Fonte | Valores | Cobrem |
|---|---|---|
| `psec` | 2 | PAN de 16 dígitos, chave com `A ≠ B`, códigos de serviço da tarja |
| jPOS | 2 | PAN de 12 dígitos, CVV2 (`000`), chave com `A = B` e com `A ≠ B` |
| `jmeter-iso8583` | 3 | o mesmo cartão nos três códigos: `101`, `000` e `999` |

As três fontes concordam com um mesmo algoritmo. Três implementações
escritas por pessoas diferentes que dão o mesmo número são mais fortes que
uma só: um erro de leitura do método teria de se repetir nas três.

No jPOS, a chave está cifrada sob a LMK de teste da biblioteca, e o valor em
claro vem num comentário. O KCV da declaração vai junto, e o teste confere o
KCV contra a chave. Se a leitura do comentário estivesse errada, o KCV não
bateria.

**Os valores de terceiros vão até o firmware.** O testbench embrulha a
chave da fonte num key block, pede o `W0`, e exige o código que a fonte
publicou. Não é só o Python que é conferido contra a fonte: é o equipamento.

**O que nenhum dos 7 cobre.** O caso em que faltam decimais e as letras
completam o código. A chance é

```
   P = soma, k de 0 a 2, de  C(16,k) · (10/16)^k · (6/16)^(16−k) = 1/18 113
```

Um teste de 5 000 sorteios veria o caso 0,28 vez, em média, e a chance de
não ver nenhuma seria `(1 − 1/18 113)^5 000 = 76%`. Por isso o teste de PC
**constrói** 300 blocos para cada quantidade de decimais, de 0 a 16. São
5 100 blocos, e 900 deles exercitam a segunda passada. O C do firmware e o
Python têm de concordar em todos.

**A montagem da entrada** é conferida entre o C e o Python para todo tamanho
de PAN, de 12 a 19, com 200 casos de cada.

**O retail MAC.** A conta do CVV é a da ISO/IEC 9797-1, algoritmo 3 (seção
36.1). A igualdade foi conferida por programa, em 2 000 chaves ao acaso,
quando o manual foi escrito. Ela não é um teste do equipamento: é o que
liga o CVV ao MAC de 3DES da etapa 8.9.

**O que o testbench prova no firmware real:**

| Caso | Espera |
|---|---|
| os 4 valores de terceiros, com as chaves das fontes | o código publicado |
| PAN inventado de 19 e de 12 dígitos | o código do Python |
| `W2` com o código certo, nos três códigos de serviço | `00` |
| `W2` com o primeiro ou o último dígito trocado | `01` |
| chave só de verificar no `W0`, só de gerar no `W2` | `11` |
| chave tripla, chave de outro uso (`V2`) | `11` |
| PAN de 11 dígitos, letra na validade | `16` |
| key block adulterado | `10` |

**O que o teste não prova.** A busca de 1 000 valores não é refeita: a conta
é simples (500 pedidos em média), e o controle é de fora do equipamento.
O veredito duplo, como na seção 42.3, não tem teste que o dispare.

### 42.5 O PKCS#8

A codificação da chave privada é conferida contra uma biblioteca
independente, nos dois sentidos, e byte a byte: o que o firmware monta tem
de ser idêntico ao que a biblioteca monta para a mesma chave. Isso é mais
forte que "a biblioteca consegue abrir", porque uma biblioteca tolerante
abre codificações que não são canônicas.

O leitor é testado pela recusa: um byte alterado em cada posição da
estrutura, o arquivo truncado em vários pontos, bytes sobrando no fim,
outra curva, outro tamanho de chave.

Um byte alterado dentro do **valor** de um inteiro não é recusado, e não
tem como ser: o resultado é outra chave, bem formada. Quem protege o valor é
o MAC do key block, que cobre o PKCS#8 inteiro.

### 42.6 O enquadramento da serial

Cada mensagem do console leva um CRC-32. Um CRC de 32 bits detecta toda
rajada de erros de até 32 bits, e deixa passar um erro aleatório com chance
de `2⁻³²`. Ele protege contra **ruído**, e não contra **ataque**: quem
altera a mensagem recalcula o CRC. O teste de ataque por falha (seção 45.3)
mostrou exatamente isso: respostas erradas com CRC válido.

Os testes do protocolo cobrem o que acontece fora do caminho feliz: CRC
errado, opcode desconhecido, mensagem maior que o limite, mensagem que para
no meio. Depois de cada um, um `PING` tem de responder: o equipamento se
recupera, e não trava.

## 43. Testes do gerador aleatório

Não existe KAT para aleatoriedade. Um gerador que devolve sempre a mesma
sequência "aleatória" passaria. O teste aqui é estatístico, e a SP 800-90B
define dois testes **contínuos**, que olham toda amostra da fonte.

Os dois partem de uma hipótese sobre a fonte: cada amostra tem pelo menos
`H` bits de entropia. O valor mais provável de uma amostra aparece então com
probabilidade de no máximo `p = 2^(−H)`. O projeto adota `H = 0,5`, e por
isso `p = 0,707`. Os dois testes usam a mesma taxa de alarme falso,
`α = 2⁻²⁰`.

### 43.1 Teste de repetição (RCT)

Pega uma fonte **travada**: o mesmo valor repetido. A chance de ver o mesmo
valor `C` vezes seguidas, numa fonte sã, é no máximo `p^(C−1)`. O limite `C`
é o menor que torna isso menor que `α`:

```
    C = 1 + ⌈ −log₂(α) / H ⌉ = 1 + ⌈ 20 / 0,5 ⌉ = 41
```

Uma fonte sã repete 41 vezes com chance de `0,707⁴⁰ = 2⁻²⁰`. O teste do
circuito cobra a **borda exata**: 40 repetições passam, e a 41ª reprova. Um
teste que dispara uma amostra antes desliga um equipamento são, e um que
dispara uma depois deixa passar entropia degradada.

### 43.2 Teste de proporção (APT)

Pega uma fonte **viciada**, que não trava mas favorece um valor. Numa janela
de `W = 1024` amostras, o teste conta quantas vezes a primeira amostra da
janela reaparece. Numa fonte sã, essa contagem segue uma distribuição
binomial com 1023 tentativas e probabilidade `p`, e a média é

```
    1 + 1023 · 0,707 = 724
```

O limite é o valor que a contagem só ultrapassa com probabilidade `α`: é a
cauda da binomial, calculada por programa, e dá **793**. Uma fonte que solta
o mesmo valor em 85% das amostras passa no teste de repetição, porque nunca
repete 41 vezes seguidas, e reprova aqui.

| H (bits por amostra) | Limite do RCT | Limite do APT |
|---|---|---|
| 0,25 | 81 | 915 |
| **0,5** | **41** | **793** |
| 0,75 | 28 | 684 |
| 1,0 | 21 | 589 |

⚠ **`H = 0,5` é uma hipótese, e não uma medida.** Os limites saem dela. Uma
validação de verdade estima `H` a partir de um milhão de amostras reais da
fonte, com os estimadores da norma.

### 43.3 Onde cada teste roda

A fonte produz uma amostra por ciclo de 100 MHz. O processador veria uma em
mil. Por isso os testes contínuos estão no **circuito**, que vê todas. O
circuito também congela 1024 amostras seguidas, e o **firmware** refaz os
dois testes sobre esse retrato, no boot. São duas implementações
independentes da mesma norma: se discordam, uma delas leu a norma errado.

Um teste do sistema inteiro trava a fonte na simulação e segue a corrente
até o fim: o circuito acusa, o POST reprova, o equipamento vai para
`TAMPERED` e recusa comando.

### 43.4 O que a estatística de saída não prova

O projeto tem um programa que mede a saída do gerador: frequência de bits,
de bytes, correlação. Ele está marcado como **sanidade**, e não como
validação. A razão é que a saída passa por um gerador determinístico baseado
em AES. Uma semente fixa, sem entropia nenhuma, produz uma saída que passa
em qualquer teste estatístico. Testar a saída testa o AES. Quem diz algo
sobre a entropia são os testes sobre as amostras **brutas** da fonte.

## 44. Testes de propriedade de segurança

Aqui a pergunta não é "calculou certo?", e sim "a regra vale?". Não há
vetor. O teste constrói a situação em que a regra seria violada, e exige a
recusa.

### 44.1 Zeroização: provar que apagou

"Chamei a função de apagar" não é "apagou". O compilador pode eliminar um
laço que zera memória que ninguém lê depois. A prova tem duas camadas, e a
segunda não confia na primeira:

1. O firmware varre a região de chaves byte a byte e acumula com OU. O
   resultado tem de ser zero.
2. O teste refaz a cerimônia com os mesmos componentes e exige o mesmo KCV,
   que é um vetor do CAVP. Um único bit sobrevivente da chave anterior daria
   outra chave, e outro KCV.

O **KCV** são os 3 primeiros bytes da cifra de um bloco de zeros. Duas
chaves diferentes têm o mesmo KCV com chance de `2⁻²⁴`. Ele é fraco como
prova de igualdade num caso isolado, e forte o bastante para acusar uma
chave errada.

### 44.2 Separação de chaves

Cada restrição do cabeçalho do key block tem um teste que tenta violá-la:

| Regra | O teste tenta | E espera |
|---|---|---|
| Uso | cifrar dados com uma KEK ou com uma chave de PIN | recusa |
| Modo | decifrar com uma chave só de cifrar | recusa |
| Grupo | autenticar com uma chave de cifra | recusa |
| Exportabilidade | exportar uma chave marcada como não exportável | recusa |
| Tipo | assinar com um key block de chave AES | recusa |
| Algoritmo | cifrar com AES usando uma chave 3DES | recusa |
| Papel | exportar sob uma chave de proteção que não é KEK | recusa |
| Método | calcular PVV com a chave do offset, e o contrário | recusa |
| Emissão | gerar offset ou PVV com uma chave só de verificar | recusa |

O teste confere também o **código** da recusa. Uma recusa pelo motivo
errado indica que a checagem que barrou não foi a que deveria.

### 44.3 Dual control

O teste cobra o gesto, e não só o nível dos botões:

- sem botão, o comando é recusado;
- com os dois apertados, é aceito;
- com os dois **ainda** apertados, o comando seguinte é recusado: cada
  autorização exige um aperto novo;
- um trem de ressaltos elétricos no botão não conta como aperto.

### 44.4 Estado e persistência

- Antes da cerimônia, todo comando que usa chave responde "estado não
  permite".
- Desligar e religar devolve o equipamento ao estado em que estava, com as
  mesmas chaves, conferidas pelo KCV e por uma cifra de referência.
- Com uma cópia do registro corrompida, o equipamento sobe pela outra.
- O modelo da memória flash conta as escritas abaixo do limite de 4 MB,
  onde mora o bitstream. A contagem tem de ser zero.

### 44.5 Silêncio

O equipamento não fala sem ser perguntado. Um teste observa a linha de
transmissão durante o boot inteiro e exige que ela não se mexa. A janela de
observação é pouco maior que o tempo do autoteste, de propósito: se o boot
ficar mais lento, o teste reprova e alguém tem de olhar.

## 45. Testes de canal lateral e de falha

### 45.1 Tempo constante

O multiplicador modular tem de levar o mesmo número de ciclos para
quaisquer operandos (seção 30). O teste conta os ciclos de cada produto e
exige que sejam iguais para o mesmo tamanho, inclusive nos casos em que a
subtração final acontece e nos que não acontece.

O teste tem um controle: o mesmo testbench roda com o circuito
**sabotado** de três formas (sem a subtração, sem o limb alto na comparação,
sem o vai-um do fim de linha) e tem de reprovar nas três. Um teste que nunca
reprovou não provou que consegue reprovar.

Isso mede ciclos, e não corrente. O consumo de energia ao longo do tempo
também vaza, e este projeto não o mede.

### 45.2 Dupla execução

Todo resultado que sai ao host é calculado duas vezes, e só sai se as duas
contas concordarem. Uma falha provocada num cálculo não se repete igual no
outro.

Uma falha não existe em simulação de circuito digital, então o teste a
imita: ele força o resultado do núcleo de AES a partir da metade do segundo
cálculo. O equipamento tem de reter a resposta, marcar o erro grave e seguir
com as chaves intactas.

A condição para a defesa valer é que as duas contas sejam **independentes**.
Com a chave carregada uma vez só para as duas, uma falha na expansão da
chave erra as duas do mesmo jeito, e elas concordam. Isso foi medido na
placa, e a chave passou a ser carregada antes de cada conta.

### 45.3 A campanha de falha na placa

Um injetor encurta um ciclo de clock num instante escolhido. O resultado de
cada tentativa cai numa classe: resposta certa, sem resposta, recusa, erro
detectado, ou **resposta errada entregue**. Só a última é uma quebra.

Com a chave carregada a cada execução, foram 13 506 tentativas e nenhuma
resposta errada entregue. Pela regra de três da seção 40, a taxa de quebra
é menor que `3 / 13 506 = 2,2 × 10⁻⁴` por tentativa, com 95% de confiança,
para **este** injetor, **nestes** instantes. Outro tipo de falha (tensão,
laser, campo eletromagnético) é outra medida.

### 45.4 Resposta a violação

Os sensores de temperatura e de tensão têm limites, e o teste cobra a
borda dos dois lados: um valor logo dentro da faixa não dispara, e um logo
fora dispara o bit certo, e só ele. O alarme fica retido mesmo depois de o
valor voltar à faixa, e mesmo depois de um reset.

O teste do sistema sobe a temperatura na simulação, sem comando e sem
botão, e exige a corrente inteira: o equipamento apaga as chaves sozinho,
vai para `TAMPERED`, recusa comando, e a causa fica no log.

## 46. O autoteste do próprio equipamento

Os testes das seções 41 a 45 rodam no laboratório. O autoteste roda no
equipamento, a cada vez que ele liga, e responde a outra pergunta: **este**
exemplar, **agora**, ainda calcula certo? Uma célula de memória que falhou
ontem não aparece em teste de laboratório nenhum.

| Teste | Quando | Tipo |
|---|---|---|
| AES-256, SHA-256, HMAC, CMAC, gerador determinístico | boot | resposta conhecida |
| Fonte de entropia | boot | os dois testes da seção 43, sobre 1024 amostras |
| Key store | boot | função crítica: as regras da seção 44.2, e a zeroização |
| Key block | boot | função crítica: abrir o vetor, recusar o adulterado |
| RSA, verificação | boot | resposta conhecida, e a recusa da adulterada |
| RSA, assinatura | primeiro uso | resposta conhecida |
| ECDSA | primeiro uso | resposta conhecida com `k` fixo, e verificação |
| DES e 3DES | primeiro uso | resposta conhecida, 25 vetores |
| Par assimétrico recém-gerado | a cada geração | assina e verifica antes de entregar |
| Toda assinatura | a cada assinatura | verificada com a chave pública antes de sair |

**Por que alguns rodam no primeiro uso.** A FIPS 140-3 permite que o teste
de um algoritmo rode antes do primeiro uso dele, e não no boot. O critério
aqui foi o custo: cada propriedade conferida no boot cobra tempo de todo
boot, para sempre. Os três testes de primeiro uso são os mais caros.

**O que acontece se reprovar.** O equipamento apaga as chaves e vai para
`TAMPERED`, de onde não sai por comando. Ele continua respondendo só ao
comando de autoteste, para o operador ver qual teste reprovou.

**A máscara.** O resultado é um bit por teste. Um teste novo que não coubesse
na máscara sumiria na conversão, e o equipamento reportaria sucesso sobre um
teste que reprovou. O código tem uma checagem que impede a compilação nesse
caso.

**O que o autoteste não cobre.** A integridade do próprio firmware. O
equipamento informa o hash da memória de código (apêndice E.1), mas não o
compara, no boot, com uma referência autenticada.

## 47. Testes na placa

A placa é o único lugar onde o silício entra no teste. Ela roda em tempo
real, e isso muda o que se pode perguntar: geração de chave RSA de ponta a
ponta, centenas de voltas, o gerador aleatório de verdade.

### 47.1 Os testes de conferência

Cada um segue o mesmo desenho: o equipamento faz uma operação, e uma
implementação independente no PC a refaz ou a desfaz.

| Teste | O equipamento | O PC |
|---|---|---|
| Chaves simétricas | gera, cifra, decifra, autentica, exporta, importa | abre os blocos com a LMK e refaz AES e CMAC |
| Tradução de PIN | traduz um PIN block entre duas chaves e entre os formatos 0 e 4 | faz o papel do terminal e o do destino; no formato 0, prevê o bloco de saída |
| Verificação de PIN | gera e verifica offset e PVV, a partir de um PIN block | faz o papel do terminal e o do emissor; calcula o MAC da tabela com a LMK |
| CVV | gera e verifica CVV, CVV2 e iCVV de um cartão | faz o papel do emissor e refaz a conta com a chave aberta |
| Chaves 3DES | gera e devolve o KCV | abre o bloco e confere tamanho, paridade e KCV |
| RSA e ECDSA | gera pares e assina | verifica só com a chave pública |
| PKCS#8 | gera, e assina com chave vinda de fora | usa a chave do equipamento numa biblioteca, e o contrário |

O PC precisa da LMK para abrir os blocos. Isso só existe porque o
equipamento é de estudo: num sistema real, quem testa não tem a chave
mestra, e a conferência independente é feita por um segundo HSM.

**O `r` não se repete.** No teste de ECDSA, cada assinatura tem o `r`
comparado com os das anteriores. Dois `r` iguais significariam o mesmo `k`,
e a chave privada exposta (seção 30). Com `k` de 256 bits, uma repetição
honesta em algumas centenas de assinaturas tem chance desprezível: se
aparecer, o gerador está quebrado.

### 47.2 O que os números da placa dizem

- **"100 de 100 voltas"** diz, pela conta da seção 40, que um defeito que
  afete 5% das entradas teria aparecido com 99,4% de certeza. Não diz nada
  sobre um defeito de borda, que é coberto pelos vetores escolhidos.
- **"10 000 comandos sem erro"** diz que a taxa de erro do enlace é menor
  que 3 em 10 000, com 95% de confiança.
- **Tempos** são medidos na placa, porque a simulação mede ciclos e a placa
  mede o sistema inteiro, serial incluída.

### 47.3 A regressão

Um script roda todos os testes de conferência em sequência e dá um
veredito. O primeiro passo dele é perguntar ao equipamento o hash do
firmware gravado e comparar com o do arquivo compilado no PC. Se não
conferem, o resto testaria outro firmware, e o script para.

Ele não substitui a simulação. Não provoca falhas, não vê sinais internos e
não aperta botões.

## 48. O que não é testado

Uma lista honesta do que fica fora vale tanto quanto a lista do que está
dentro.

- **Consumo de energia e emissão eletromagnética.** O tempo em ciclos é
  constante; o resto dos canais laterais não é medido.
- **A entropia real da fonte.** O valor `H = 0,5` é hipótese.
- **Falhas que não sejam de clock.** Tensão, laser e campo não foram
  tentados.
- **A integridade do firmware no boot.**
- **Vetores oficiais para os formatos de pagamento.** As normas são pagas, e
  as fontes são secundárias.
- **Os últimos 6 bytes da tag de CMAC**, que os vetores oficiais não trazem.
- **A geração de chave RSA de ponta a ponta na simulação.** Ela leva
  segundos de tempo real, e horas de simulação por segundo. É provada por
  partes na simulação, e inteira na placa.
- **O invólucro.** A placa é aberta, e não há detecção de abertura.

Um teste que falta e está escrito aqui é uma decisão. Um teste que falta e
ninguém sabe que falta é um defeito esperando.
