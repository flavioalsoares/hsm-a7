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


<figure class="fig">
<svg viewBox="0 0 680 240" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="70" y1="190" x2="640" y2="190" marker-end="url(#seta)"/>
<line class="ln" x1="70" y1="190" x2="70" y2="20" marker-end="url(#seta)"/>
<g class="ts"><text x="70" y="206" text-anchor="middle">0</text><text x="180" y="206" text-anchor="middle">100</text><text x="290" y="206" text-anchor="middle">200</text><text x="400" y="206" text-anchor="middle">300</text><text x="510" y="206" text-anchor="middle">400</text><text x="620" y="206" text-anchor="middle">500</text>
<text x="62" y="194" text-anchor="end">0</text><text x="62" y="114" text-anchor="end">0,5</text><text x="62" y="34" text-anchor="end">1</text></g>
<line class="grade" x1="70" y1="110" x2="630" y2="110"/><line class="grade" x1="70" y1="30" x2="630" y2="30"/>
<polyline points="70.0,30.0 75.5,30.8 81.0,31.6 86.5,32.4 92.0,33.2 97.5,34.0 103.0,34.7 108.5,35.5 114.0,36.3 119.5,37.0 125.0,37.8 130.5,38.6 136.0,39.3 141.5,40.1 147.0,40.8 152.5,41.6 158.0,42.3 163.5,43.0 169.0,43.8 174.5,44.5 180.0,45.2 185.5,46.0 191.0,46.7 196.5,47.4 202.0,48.1 207.5,48.8 213.0,49.5 218.5,50.2 224.0,50.9 229.5,51.6 235.0,52.3 240.5,53.0 246.0,53.7 251.5,54.3 257.0,55.0 262.5,55.7 268.0,56.4 273.5,57.0 279.0,57.7 284.5,58.4 290.0,59.0 295.5,59.7 301.0,60.3 306.5,61.0 312.0,61.6 317.5,62.3 323.0,62.9 328.5,63.5 334.0,64.2 339.5,64.8 345.0,65.4 350.5,66.0 356.0,66.6 361.5,67.3 367.0,67.9 372.5,68.5 378.0,69.1 383.5,69.7 389.0,70.3 394.5,70.9 400.0,71.5 405.5,72.1 411.0,72.7 416.5,73.3 422.0,73.8 427.5,74.4 433.0,75.0 438.5,75.6 444.0,76.1 449.5,76.7 455.0,77.3 460.5,77.8 466.0,78.4 471.5,78.9 477.0,79.5 482.5,80.1 488.0,80.6 493.5,81.1 499.0,81.7 504.5,82.2 510.0,82.8 515.5,83.3 521.0,83.8 526.5,84.4 532.0,84.9 537.5,85.4 543.0,85.9 548.5,86.5 554.0,87.0 559.5,87.5 565.0,88.0 570.5,88.5 576.0,89.0 581.5,89.5 587.0,90.0 592.5,90.5 598.0,91.0 603.5,91.5 609.0,92.0 614.5,92.5 620.0,93.0" fill="none" stroke="#888" stroke-width="2"/><polyline points="70.0,30.0 75.5,37.8 81.0,45.3 86.5,52.4 92.0,59.1 97.5,65.5 103.0,71.6 108.5,77.4 114.0,83.0 119.5,88.2 125.0,93.2 130.5,97.9 136.0,102.5 141.5,106.7 147.0,110.8 152.5,114.7 158.0,118.4 163.5,121.9 169.0,125.2 174.5,128.4 180.0,131.4 185.5,134.3 191.0,137.0 196.5,139.6 202.0,142.1 207.5,144.4 213.0,146.7 218.5,148.8 224.0,150.8 229.5,152.7 235.0,154.6 240.5,156.3 246.0,158.0 251.5,159.5 257.0,161.0 262.5,162.4 268.0,163.8 273.5,165.1 279.0,166.3 284.5,167.5 290.0,168.6 295.5,169.6 301.0,170.6 306.5,171.6 312.0,172.5 317.5,173.3 323.0,174.1 328.5,174.9 334.0,175.7 339.5,176.4 345.0,177.0 350.5,177.7 356.0,178.3 361.5,178.8 367.0,179.4 372.5,179.9 378.0,180.4 383.5,180.9 389.0,181.3 394.5,181.7 400.0,182.2 405.5,182.5 411.0,182.9 416.5,183.3 422.0,183.6 427.5,183.9 433.0,184.2 438.5,184.5 444.0,184.8 449.5,185.0 455.0,185.3 460.5,185.5 466.0,185.7 471.5,185.9 477.0,186.1 482.5,186.3 488.0,186.5 493.5,186.7 499.0,186.8 504.5,187.0 510.0,187.1 515.5,187.3 521.0,187.4 526.5,187.5 532.0,187.7 537.5,187.8 543.0,187.9 548.5,188.0 554.0,188.1 559.5,188.2 565.0,188.3 570.5,188.3 576.0,188.4 581.5,188.5 587.0,188.6 592.5,188.6 598.0,188.7 603.5,188.8 609.0,188.8 614.5,188.9 620.0,188.9" fill="none" stroke="#2d4f73" stroke-width="2"/><polyline points="70.0,30.0 75.5,66.2 81.0,94.2 86.5,115.9 92.0,132.6 97.5,145.6 103.0,155.7 108.5,163.4 114.0,169.4 119.5,174.1 125.0,177.7 130.5,180.5 136.0,182.6 141.5,184.3 147.0,185.6 152.5,186.6 158.0,187.4 163.5,188.0 169.0,188.4 174.5,188.8 180.0,189.1 185.5,189.3 191.0,189.4 196.5,189.6 202.0,189.7 207.5,189.7 213.0,189.8 218.5,189.8 224.0,189.9 229.5,189.9 235.0,189.9 240.5,189.9 246.0,190.0 251.5,190.0 257.0,190.0 262.5,190.0 268.0,190.0 273.5,190.0 279.0,190.0 284.5,190.0 290.0,190.0 295.5,190.0 301.0,190.0 306.5,190.0 312.0,190.0 317.5,190.0 323.0,190.0 328.5,190.0 334.0,190.0 339.5,190.0 345.0,190.0 350.5,190.0 356.0,190.0 361.5,190.0 367.0,190.0 372.5,190.0 378.0,190.0 383.5,190.0 389.0,190.0 394.5,190.0 400.0,190.0 405.5,190.0 411.0,190.0 416.5,190.0 422.0,190.0 427.5,190.0 433.0,190.0 438.5,190.0 444.0,190.0 449.5,190.0 455.0,190.0 460.5,190.0 466.0,190.0 471.5,190.0 477.0,190.0 482.5,190.0 488.0,190.0 493.5,190.0 499.0,190.0 504.5,190.0 510.0,190.0 515.5,190.0 521.0,190.0 526.5,190.0 532.0,190.0 537.5,190.0 543.0,190.0 548.5,190.0 554.0,190.0 559.5,190.0 565.0,190.0 570.5,190.0 576.0,190.0 581.5,190.0 587.0,190.0 592.5,190.0 598.0,190.0 603.5,190.0 609.0,190.0 614.5,190.0 620.0,190.0" fill="none" stroke="#7a1f1f" stroke-width="2"/>
<line x1="180" y1="190" x2="180" y2="30" stroke="#555" stroke-dasharray="3 3"/>
<text x="186" y="127.4" class="ts" fill="#2d4f73">37%</text>
<text x="186" y="183.0" class="ts td">0,6%</text>
<text x="560" y="80.0" class="ts" fill="#888">f = 0,1%</text>
<text x="420" y="174.2" class="ts" fill="#2d4f73">f = 1%</text>
<text x="100" y="185.4" class="ts td">f = 5%</text>
<text x="355" y="230" text-anchor="middle" class="ts">n, entradas sorteadas</text>
<text x="20" y="105" class="ts" transform="rotate(-90 20 105)" text-anchor="middle">chance de o defeito escapar</text>
</svg>
<figcaption>Figura 40.1 — (1 − f)ⁿ: a chance de um defeito que afeta a fração f das entradas escapar de n sorteios. Erro raro pede caso escolhido.</figcaption>
</figure>

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


<figure class="fig">
<svg viewBox="0 0 680 190" xmlns="http://www.w3.org/2000/svg">
<rect class="cxv" x="10" y="40" width="150" height="70"/><text x="85" y="62" text-anchor="middle" class="tb">no PC</text><text x="85" y="80" text-anchor="middle" class="ts">C com gcc, e Python</text><text x="85" y="94" text-anchor="middle" class="ts">segundos</text>
<rect class="cxa" x="180" y="40" width="150" height="70"/><text x="255" y="62" text-anchor="middle" class="tb">simulação</text><text x="255" y="80" text-anchor="middle" class="ts">circuito e firmware reais</text><text x="255" y="94" text-anchor="middle" class="ts">horas</text>
<rect class="cx" x="350" y="40" width="150" height="70"/><text x="425" y="62" text-anchor="middle" class="tb">na placa</text><text x="425" y="80" text-anchor="middle" class="ts">o silício, pela serial</text><text x="425" y="94" text-anchor="middle" class="ts">minutos</text>
<rect class="cxd" x="520" y="40" width="150" height="70"/><text x="595" y="62" text-anchor="middle" class="tb">no boot</text><text x="595" y="80" text-anchor="middle" class="ts">o autoteste</text><text x="595" y="94" text-anchor="middle" class="ts">28 ms, sempre</text>
<line class="ln" x1="160" y1="75" x2="178" y2="75" marker-end="url(#seta)"/>
<line class="ln" x1="330" y1="75" x2="348" y2="75" marker-end="url(#seta)"/>
<line class="ln" x1="500" y1="75" x2="518" y2="75" marker-end="url(#seta)"/>
<text x="85" y="130" text-anchor="middle" class="ts">milhares de casos</text><text x="85" y="144" text-anchor="middle" class="ts">e as bordas</text>
<text x="255" y="130" text-anchor="middle" class="ts">sinais internos,</text><text x="255" y="144" text-anchor="middle" class="ts">falhas provocadas</text>
<text x="425" y="130" text-anchor="middle" class="ts">ruído, temperatura,</text><text x="425" y="144" text-anchor="middle" class="ts">o gerador de verdade</text>
<text x="595" y="130" text-anchor="middle" class="ts">esta placa,</text><text x="595" y="144" text-anchor="middle" class="ts">agora</text>
<text x="340" y="178" text-anchor="middle" class="ts">o que só aquele lugar vê; um erro achado mais à esquerda custa menos para achar a causa</text>
</svg>
<figcaption>Figura 40.2 — Os quatro lugares onde se testa. Cada um cobre o que os outros não alcançam.</figcaption>
</figure>

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
- **CMAC-TDES** (etapa 8.7): vetores do mesmo arquivo do CAVP, 96 com chave
  dupla e 96 com tripla, mensagens de 0, 7, 8, 15, 16 e 32 bytes, que passam
  pelos três ramos do CMAC (vazia, último bloco incompleto, último bloco
  cheio). O C do firmware, compilado no PC, e a biblioteca `cryptography`
  dão todas as tags. Uma lacuna, registrada: os vetores de chave **dupla**
  só trazem tag truncada (5 e 7 bytes), e nenhum vetor oficial confere o
  último byte da tag com chave dupla. Quem confere são os key blocks versão
  B da seção 42.7, cujo MAC de 8 bytes vem de uma KBPK dupla.
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


<figure class="fig">
<svg viewBox="0 0 680 170" xmlns="http://www.w3.org/2000/svg">
<text x="20" y="20" class="ts">as 112 posições de um key block AES; troca-se um caractere por vez</text>
<rect class="cxa" x="20" y="30" width="20" height="22"/><text x="30" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="42" y="30" width="20" height="22"/><text x="52" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="64" y="30" width="20" height="22"/><text x="74" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="86" y="30" width="20" height="22"/><text x="96" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="108" y="30" width="20" height="22"/><text x="118" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="130" y="30" width="20" height="22"/><text x="140" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="152" y="30" width="20" height="22"/><text x="162" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="174" y="30" width="20" height="22"/><text x="184" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="196" y="30" width="20" height="22"/><text x="206" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="218" y="30" width="20" height="22"/><text x="228" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="240" y="30" width="20" height="22"/><text x="250" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="262" y="30" width="20" height="22"/><text x="272" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="284" y="30" width="20" height="22"/><text x="294" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="306" y="30" width="20" height="22"/><text x="316" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="328" y="30" width="20" height="22"/><text x="338" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cxa" x="350" y="30" width="20" height="22"/><text x="360" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="372" y="30" width="20" height="22"/><text x="382" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="394" y="30" width="20" height="22"/><text x="404" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="416" y="30" width="20" height="22"/><text x="426" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="438" y="30" width="20" height="22"/><text x="448" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="460" y="30" width="20" height="22"/><text x="470" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="482" y="30" width="20" height="22"/><text x="492" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="504" y="30" width="20" height="22"/><text x="514" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="526" y="30" width="20" height="22"/><text x="536" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="548" y="30" width="20" height="22"/><text x="558" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="570" y="30" width="20" height="22"/><text x="580" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="592" y="30" width="20" height="22"/><text x="602" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="614" y="30" width="20" height="22"/><text x="624" y="46" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="20" y="56" width="20" height="22"/><text x="30" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="42" y="56" width="20" height="22"/><text x="52" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="64" y="56" width="20" height="22"/><text x="74" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="86" y="56" width="20" height="22"/><text x="96" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="108" y="56" width="20" height="22"/><text x="118" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="130" y="56" width="20" height="22"/><text x="140" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="152" y="56" width="20" height="22"/><text x="162" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="174" y="56" width="20" height="22"/><text x="184" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="196" y="56" width="20" height="22"/><text x="206" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="218" y="56" width="20" height="22"/><text x="228" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="240" y="56" width="20" height="22"/><text x="250" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="262" y="56" width="20" height="22"/><text x="272" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="284" y="56" width="20" height="22"/><text x="294" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="306" y="56" width="20" height="22"/><text x="316" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="328" y="56" width="20" height="22"/><text x="338" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="350" y="56" width="20" height="22"/><text x="360" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="372" y="56" width="20" height="22"/><text x="382" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="394" y="56" width="20" height="22"/><text x="404" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="416" y="56" width="20" height="22"/><text x="426" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="438" y="56" width="20" height="22"/><text x="448" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="460" y="56" width="20" height="22"/><text x="470" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="482" y="56" width="20" height="22"/><text x="492" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="504" y="56" width="20" height="22"/><text x="514" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="526" y="56" width="20" height="22"/><text x="536" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="548" y="56" width="20" height="22"/><text x="558" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="570" y="56" width="20" height="22"/><text x="580" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="592" y="56" width="20" height="22"/><text x="602" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="614" y="56" width="20" height="22"/><text x="624" y="72" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="20" y="82" width="20" height="22"/><text x="30" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="42" y="82" width="20" height="22"/><text x="52" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="64" y="82" width="20" height="22"/><text x="74" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="86" y="82" width="20" height="22"/><text x="96" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="108" y="82" width="20" height="22"/><text x="118" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="130" y="82" width="20" height="22"/><text x="140" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="152" y="82" width="20" height="22"/><text x="162" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="174" y="82" width="20" height="22"/><text x="184" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="196" y="82" width="20" height="22"/><text x="206" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="218" y="82" width="20" height="22"/><text x="228" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="240" y="82" width="20" height="22"/><text x="250" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="262" y="82" width="20" height="22"/><text x="272" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="284" y="82" width="20" height="22"/><text x="294" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="306" y="82" width="20" height="22"/><text x="316" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="328" y="82" width="20" height="22"/><text x="338" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="350" y="82" width="20" height="22"/><text x="360" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="372" y="82" width="20" height="22"/><text x="382" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="394" y="82" width="20" height="22"/><text x="404" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="416" y="82" width="20" height="22"/><text x="426" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="438" y="82" width="20" height="22"/><text x="448" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="460" y="82" width="20" height="22"/><text x="470" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="482" y="82" width="20" height="22"/><text x="492" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="504" y="82" width="20" height="22"/><text x="514" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cx" x="526" y="82" width="20" height="22"/><text x="536" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="548" y="82" width="20" height="22"/><text x="558" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="570" y="82" width="20" height="22"/><text x="580" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="592" y="82" width="20" height="22"/><text x="602" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="614" y="82" width="20" height="22"/><text x="624" y="98" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="20" y="108" width="20" height="22"/><text x="30" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="42" y="108" width="20" height="22"/><text x="52" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="64" y="108" width="20" height="22"/><text x="74" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="86" y="108" width="20" height="22"/><text x="96" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="108" y="108" width="20" height="22"/><text x="118" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="130" y="108" width="20" height="22"/><text x="140" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="152" y="108" width="20" height="22"/><text x="162" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="174" y="108" width="20" height="22"/><text x="184" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="196" y="108" width="20" height="22"/><text x="206" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="218" y="108" width="20" height="22"/><text x="228" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="240" y="108" width="20" height="22"/><text x="250" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="262" y="108" width="20" height="22"/><text x="272" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="284" y="108" width="20" height="22"/><text x="294" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="306" y="108" width="20" height="22"/><text x="316" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="328" y="108" width="20" height="22"/><text x="338" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="350" y="108" width="20" height="22"/><text x="360" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="372" y="108" width="20" height="22"/><text x="382" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="394" y="108" width="20" height="22"/><text x="404" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="416" y="108" width="20" height="22"/><text x="426" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="438" y="108" width="20" height="22"/><text x="448" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="460" y="108" width="20" height="22"/><text x="470" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="482" y="108" width="20" height="22"/><text x="492" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="504" y="108" width="20" height="22"/><text x="514" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="526" y="108" width="20" height="22"/><text x="536" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="548" y="108" width="20" height="22"/><text x="558" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="570" y="108" width="20" height="22"/><text x="580" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="592" y="108" width="20" height="22"/><text x="602" y="124" text-anchor="middle" class="ts td">✗</text><rect class="cxv" x="614" y="108" width="20" height="22"/><text x="624" y="124" text-anchor="middle" class="ts td">✗</text>
<rect class="cxa" x="20" y="142" width="14" height="14"/><text x="40" y="154" class="ts">cabeçalho (16)</text>
<rect class="cx" x="150" y="142" width="14" height="14"/><text x="170" y="154" class="ts">corpo cifrado (64)</text>
<rect class="cxv" x="300" y="142" width="14" height="14"/><text x="320" y="154" class="ts">MAC (32)</text>
<text x="420" y="154" class="ts td">✗ = o equipamento tem de recusar</text>
</svg>
<figcaption>Figura 42.1 — O teste de um caractere trocado. Uma implementação que deixa o cabeçalho fora do MAC passa nos outros testes e falha nas 16 primeiras casas.</figcaption>
</figure>

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

### 42.7 O key block versão B (KEK 3DES)

A versão B é o formato da seção 42.1 com 3DES no lugar do AES (seção
39.9). Os testes repetem os da versão D, com números próprios.

**Os valores de terceiros.** A biblioteca `psec` publica seis blocos versão
B no mesmo arquivo do vetor da versão D, fixado por hash. O equipamento
aceita três e recusa três, de propósito:

| Bloco | KBPK | Chave | Resultado |
|---|---|---|---|
| 0 | dupla | 8 bytes (DES simples) | recusado: DES simples não existe aqui |
| 1 | dupla | dupla, uso `M3` | aceito, chave publicada |
| 2 | tripla | dupla | aceito, chave publicada |
| 3 | dupla | dupla, uso `P0` | aceito, chave publicada |
| 4 | dupla | dupla, com blocos opcionais | recusado: blocos opcionais |
| 5 | dupla | dupla, com blocos opcionais | recusado: idem |

O Python e o C compilado no PC (`host/test_tr31b.py`) dão o mesmo resultado
nos seis. O `tb_kek3` leva os blocos 1, 2 e 3 ao firmware real: a KBPK do
bloco 3 entra por componentes no console, e as outras duas, embrulhadas sob
a LMK. O firmware tem de devolver a chave publicada, conferida pelo KCV, e
recusar os blocos 0 e 4. O bloco 3 também está no autoteste de primeiro uso
do 3DES.

**O que os valores de terceiros não cobrem.** Fechar (o enchimento é
aleatório) e a KBPK tripla com chave tripla. Para esses, o teste de PC fecha
24 blocos no C e no Python com o **mesmo enchimento**, nas combinações de
KBPK dupla e tripla, chave dupla e tripla e seis pares de uso e modo, e
exige os blocos iguais caractere a caractere. Cada lado abre o bloco do
outro. Com o enchimento fixado, fechar vira uma função, e duas
implementações independentes que concordam em 24 casos concordam sobre a
leitura da norma.

**Um bit trocado em cada posição.** Num bloco de 96 caracteres (KBPK e chave
triplas), o teste troca um bit de cada caractere, um de cada vez, e o C
recusa as 96 versões. Um bloco versão D apresentado como B, e um bloco sob
outra KBPK, também são recusados.

**A força do MAC.** O MAC da versão B tem 64 bits. Quem não tem a chave
acerta um MAC com chance de `2⁻⁶⁴` por tentativa: com um milhão de
tentativas por segundo, a chance de acertar em um ano é de cerca de
3,15 × 10¹³ / 1,84 × 10¹⁹, ou 1 em 585 mil. É menos que os `2⁻¹²⁸` da versão
D, e é a razão de a regra de força (seção 39.9) não deixar uma chave AES
viajar sob uma KEK 3DES.

**A regra de força, no firmware.** O `tb_kek3` pede ao `K4` uma chave AES e
uma 3DES tripla sob a KEK dupla, e exige `13` nas duas. Uma tripla sob uma
KEK tripla sai, em bloco B. O `tdes-confere` (seção 47.1) faz o mesmo na
placa, nos dois sentidos, com blocos fechados pelo Python.

**A KEK que volta da flash.** O `tb_kek3` religa o equipamento depois de
formar a KEK, e exige no mesmo handle o mesmo KCV. O registro da flash
guarda cada chave numa entrada de 144 caracteres, e o bloco de uma chave
3DES tem 112: o teste prova que o resto da entrada não atrapalha a carga.

**O que estes testes não provam.** Que a versão B deste equipamento
conversa com o equipamento de um parceiro real: a referência é uma
biblioteca aberta, e não a norma, que é paga. E as versões A e C, que o
equipamento não faz.

### 42.8 O DUKPT TDES

O DUKPT da seção 37.2 é uma conta determinística: a BDK e o KSN dão sempre
a mesma chave. Por isso há valor esperado para cada passo, e os testes
conferem cada passo, e não só o resultado.

**Os valores de terceiros.** O anexo A.4 da X9.24-1:2009 traz a IPEK e 34
transações: o KSN, a chave da transação e o PIN block cifrado. A norma é
paga. Os valores vêm do arquivo de testes do projeto `openemv/dukpt`, que os
transcreve, fixado por commit e por hash. É uma fonte só, por decisão do
usuário.

As 34 transações cobrem:

- a sequência inicial (A.4.2), contadores de 1 a 21: um passo a cada bit 1,
  com até 4 bits 1;
- a sequência de rolagem (A.4.3), contadores de `0FF800` (9 bits 1) a
  `0FFC00` (10 bits 1, o caminho mais longo que a norma permite), e o
  `100000`, que é o bit mais alto do contador sozinho.

**Duas implementações, dois motores.** O `host/test_dukpt.py` confere o
Python (`host/dukpt.py`) e o C do firmware (`fw/src/dukpt.c`, compilado no
PC) contra os 34 valores. O DES do Python é o da biblioteca `cryptography`,
e o do C é o `des.c`: os dois lados não dividem o motor. Depois, os dois
calculam a IPEK e a chave de PIN de 300 BDKs e KSNs ao acaso, com
contadores de 1 a 10 bits 1, e as 300 contas têm de ser iguais.

**O que os valores de terceiros não cobrem:** BDK diferente da do anexo, e o
KSN inválido. Os 300 casos ao acaso cobrem a primeira lacuna. Para a
segunda, o teste exige a recusa dos dois lados com o contador zero, com 11
bits 1 e com 21 bits 1, e a aceitação com 10 bits 1.

**A conta dos contadores válidos.** São válidos os contadores com 1 a 10
bits 1 entre 21 posições: `C(21,1) + … + C(21,10) = 1 048 575`. Como
`C(21,k) = C(21,21−k)`, a soma de 0 a 10 é exatamente a metade de `2²¹`, e
tirando o zero sobram `2²⁰ − 1`. O teste não precisa varrer o milhão: a
regra é a contagem de bits, e as bordas são 10 (aceito) e 11 (recusado).

**No firmware real.** O `tb_dukpt` leva a BDK do anexo ao equipamento,
embrulhada sob a LMK, e pede:

1. o `P2` da transação de contador `0FF800` (9 bits 1): o firmware refaz a chave de PIN, abre o PIN
   block publicado e o fecha sob uma chave de zona. A saída é formato 0,
   sem aleatório, e o testbench a compara inteira com a conta do Python;
2. o `I0` da IPEK do anexo, sob uma KEK 3DES: o cabecalho do bloco tem de
   ser `B0080B1TX00N0000`, e o KCV, o da IPEK publicada (`AF8C07`);
3. quatro recusas: KSN de contador zero (`16`), BDK sem modo `X` (`11`), PIN
   block com um bit trocado (`14`), chave de zona no lugar da KEK (`13`).

O autoteste do 3DES também confere a IPEK e a transação `0FF800` a cada
primeiro uso, antes de qualquer BDK ser usada.

**O bit trocado do PIN block.** Com um bit trocado, o bloco abre num valor
ao acaso, e um valor ao acaso passa como formato 0 cerca de uma vez em
`2²⁴`. O gerador dos vetores escolhe um bit que o Python confirma que não
passa, para a recusa ser certa e não provável. Na placa, o `dukpt-confere`
faz o mesmo a cada volta.

**O que estes testes não provam.** Que a conta é a da norma, e não a do
`openemv/dukpt`: se a transcrição estiver errada, os três lados concordam
no erro. Que o equipamento conversa com um terminal real. Os MACs e a
cifra de dados com chave DUKPT estão na seção 42.11.

### 42.9 O DUKPT AES

O DUKPT AES da seção 37.3 também é uma conta determinística, e os testes
seguem o molde da seção 42.8.

**Os valores de terceiros.** O suplemento de vetores da X9.24-3 traz, para
uma BDK AES-128 e uma AES-256, a chave inicial (IK) e 15 transações. Vêm do
mesmo projeto `openemv/dukpt`, que os transcreve, fixados por commit e por
hash. As transações cobrem:

- os contadores de 1 a 8, com a chave de PIN AES-128 (e a AES-256, na BDK
  AES-256) e, na BDK AES-128, o PIN block formato 4 cifrado;
- as bordas de `1FFFE` a `20001`, onde o contador muda de 16 para 17 bits
  significativos;
- os quatro últimos contadores, de `FFFE2000` a `FFFF0000`. O último tem 16
  bits 1: o caminho mais longo que a norma permite, 16 derivações.

**O motor AES-128.** O motor em C (`fw/src/aes128.c`) é conferido contra os
568 vetores ECB de 128 bits do CAVP, nas duas direções. As caixas S foram
calculadas da definição por um script, e não copiadas de memória.

**Duas implementações.** O `host/test_dukpt.py` confere o Python e o C do
firmware contra os valores de terceiros: a IK, as 30 chaves de transação,
as 24 chaves de PIN e os 8 PIN blocks. O AES do Python é o da biblioteca
`cryptography`; o do C é o `aes128.c` com chave de 16 bytes. Com chave de
32 bytes o C usa o coprocessador, e no PC o teste o troca pela OpenSSL.
Depois, os dois calculam a chave de PIN de 400 casos ao acaso, nas quatro
combinações de BDK (16 ou 32 bytes) e chave de trabalho (16 ou 32), com
contadores de 1 a 16 bits 1.

**Os KSNs inválidos.** O teste exige a recusa dos dois lados com o contador
zero e com 17 bits 1, a aceitação com 16 bits 1, e a recusa de uma chave de
trabalho de 24 bytes.

**No firmware real.** O `tb_dukpt_aes` leva as duas BDKs publicadas ao
equipamento, embrulhadas sob a LMK, e pede:

1. o `P2` com a BDK AES-128 e a transação de contador 7: o PIN block
   publicado abre pelo motor em C e sai sob uma chave de zona 3DES. A saída é
   formato 0, sem aleatório, e o testbench a compara inteira com a conta do
   Python;
2. o `P2` com a BDK AES-256 e a chave de trabalho AES-256: a derivação e a
   abertura passam pelo coprocessador. O PIN block de origem é conta do
   Python sob a chave de PIN AES-256 publicada (o suplemento não traz um), e
   a saída tem de ser a mesma do passo 1;
3. o `I0` da IK da BDK AES-128 sob uma KEK AES-256: o cabeçalho do bloco
   tem de ser `D0112B1AX00N0000`, e o KCV, o da IK publicada;
4. quatro recusas: a IK sob uma KEK 3DES (`13`), o KSN de contador zero
   (`16`), o PIN block de origem formato 0 com BDK AES (`11`), e uma chave
   AES-128 de dados no `K2` (`10`).

O autoteste do AES-128 e do DUKPT AES (um bit próprio, `0x1000`) roda no
primeiro uso de uma chave AES-128 ou de uma BDK AES. Ele confere o motor nas
duas direções, a chave de PIN AES-128 da transação 7 com o PIN block
publicado refeito sob ela, e a chave de PIN AES-256 da mesma transação.

**O que estes testes não provam.** Os mesmos limites da seção 42.8: que a
conta é a da norma, e não a da transcrição; que o equipamento conversa com
um terminal real. O MAC e os dados com DUKPT estão na seção 42.11.

### 42.10 O retail MAC e os dados com 3DES

O retail MAC da seção 39.10 não tem vetor oficial público: a ISO/IEC 9797-1
e a X9.19 são pagas. Desde a etapa 8.9, um valor de terceiros só entra com
**duas fontes independentes**.

**Os valores de terceiros.** Seis, de duas fontes, fixadas por commit e por
hash:

- o teste da função do `psec`: a mesma mensagem com os preenchimentos 1 e 2,
  e o MAC de 8 e de 4 bytes;
- o exemplo do crate `retail-mac` do RustCrypto, que transcreve a seção B.4
  da ISO/IEC 9797-1:2011: duas mensagens, de 24 e de 22 bytes.

As duas fontes pedem uma leitura, e o extrator a escreve. O `psec` recebe
cada chave em 16 bytes com as metades iguais, o que faz do 3DES um DES
simples: a chave `K ‖ K'` sai das duas metades. O crate preenche com zeros, o
método 1. Um terceiro valor do `psec`, o exemplo da documentação da função,
fica fora: usa chaves de metades diferentes, e isso não é o algoritmo da
norma.

**Duas implementações.** O `host/test_retail_mac.py` confere o Python
(`host/mac_tdes.py`, com o DES da biblioteca `cryptography`) e o C
(`fw/src/mac_tdes.c`, com o `des.c` do firmware) contra os seis valores.
Depois, os dois calculam o MAC de 2 000 mensagens ao acaso, de 1 a 160 bytes,
nos dois preenchimentos, e de todo tamanho de 1 a 40 bytes, onde moram as
bordas de bloco. Uma em vinte chaves tem `K = K'`, o caso em que o MAC vira um
CBC-MAC de DES simples. Mensagem vazia e preenchimento 0 ou 3 têm de ser
recusados nos dois.

**O 3DES-CBC** tem vetor oficial, os MMT do NIST (seção 41.3), e o teste o
confere no Python nas duas direções.

**No firmware real.** O `tb_mac3` leva ao equipamento as chaves publicadas,
embrulhadas sob a LMK, e pede:

1. o `M0` com a chave e a mensagem da B.4: o MAC publicado. O primeiro uso
   de chave 3DES roda o autoteste do 3DES, que inclui o retail MAC;
2. o `M2` com o mesmo MAC: confere;
3. o `M2` com a chave do `psec`, em modo `V`, e o MAC de 4 bytes do
   preenchimento 2: confere; com um caractere trocado, não confere (`01`);
4. o `C0` e o `C2` com o vetor CBC de chave tripla do NIST, de 64 bytes: a
   saída publicada, nos dois sentidos;
5. sete recusas: `M0` com chave de modo `V`, com chave tripla e com chave
   `D0` (`11`); mensagem vazia (`15`); preenchimento 3 (`16`); `C2` com
   chave de modo `E` (`11`); `C0` com 12 bytes (`15`).

**O que estes testes não provam.** Que a conta é a da norma, e não a das
duas fontes: as duas podem ter lido a norma do mesmo jeito errado. Duas
fontes independentes tornam isso menos provável, e não impossível.

### 42.11 O MAC e os dados com DUKPT

Os valores de terceiros vêm de **duas fontes**, fixadas por commit e por
hash: o `openemv/dukpt` (as mesmas transações da seção 42.8) e o
`moov-io/dukpt`, uma biblioteca em Go. A mensagem das duas é a mesma,
`4012345678909D987`.

| | `openemv/dukpt` | `moov-io/dukpt` |
|---|---|---|
| TDES, MAC de pedido e de resposta | 34 transações, 4 bytes | 5 transações, 8 bytes |
| TDES, dados de pedido | 34 | 5 |
| TDES, dados de resposta | — | 5 |
| AES, chaves de MAC (2000) e de dados (3000) | 8 por BDK, AES-128 e AES-256 | — |
| AES, CMAC e dados de pedido | — | 8 |
| AES, CMAC e dados de resposta (2001, 3001) | — | 8 |

Onde as duas se cruzam, elas concordam: o MAC de 4 bytes do `openemv` é o
começo do MAC de 8 bytes do `moov-io`, e o CMAC do `moov-io` sai das chaves
publicadas pelo `openemv`. As três linhas de resposta têm uma fonte só, e
entraram por decisão do usuário (seção 38.3).

**Duas implementações.** O `host/test_dukpt.py` confere o Python e o C do
firmware contra os 63 valores. Depois compara os dois em 200 BDKs TDES ao
acaso (as quatro chaves de uso) e em 200 casos AES ao acaso, com BDK e chave
de trabalho de 16 e de 32 bytes: a chave de uso, o CMAC e o AES-CBC nos dois
sentidos. O CMAC e o CBC do C rodam no motor AES-128 ou, com 32 bytes, no
coprocessador, que no PC é trocado pela OpenSSL.

**No firmware real.** O `tb_dukpt_mac` leva a BDK do anexo A.4 e a BDK
AES-128 do suplemento ao equipamento, e pede, na primeira transação de
cada uma, os quatro comandos com os valores publicados: o `M4` confere o MAC
de pedido, o `M6` devolve o de resposta, o `C4` decifra o pedido e o `C6`
cifra a resposta. Um CMAC com um caractere trocado tem de dar `01`. E quatro
recusas: contador zero (`16`), chave de trabalho `3` (`16`), chave de zona no
lugar da BDK (`11`) e dados que não são múltiplos de 8 (`15`).

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


<figure class="fig">
<svg viewBox="0 0 680 240" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="40" y1="190" x2="660" y2="190"/>
<polyline points="42.4,190.0 44.8,190.0 47.2,190.0 49.6,190.0 52.0,190.0 54.4,190.0 56.8,190.0 59.2,190.0 61.6,190.0 64.0,190.0 66.4,190.0 68.8,190.0 71.2,190.0 73.6,190.0 76.0,190.0 78.4,189.9 80.8,189.9 83.2,189.9 85.6,189.9 88.0,189.8 90.4,189.8 92.8,189.7 95.2,189.7 97.6,189.6 100.0,189.5 102.4,189.3 104.8,189.2 107.2,189.0 109.6,188.7 112.0,188.4 114.4,188.1 116.8,187.7 119.2,187.2 121.6,186.6 124.0,185.9 126.4,185.1 128.8,184.2 131.2,183.1 133.6,181.9 136.0,180.5 138.4,178.9 140.8,177.1 143.2,175.0 145.6,172.7 148.0,170.2 150.4,167.4 152.8,164.2 155.2,160.8 157.6,157.1 160.0,153.1 162.4,148.7 164.8,144.1 167.2,139.2 169.6,134.0 172.0,128.5 174.4,122.8 176.8,117.0 179.2,110.9 181.6,104.8 184.0,98.6 186.4,92.4 188.8,86.3 191.2,80.3 193.6,74.5 196.0,68.9 198.4,63.7 200.8,58.8 203.2,54.4 205.6,50.5 208.0,47.1 210.4,44.3 212.8,42.2 215.2,40.8 217.6,40.0 220.0,39.9 222.4,40.6 224.8,41.9 227.2,44.0 229.6,46.7 232.0,50.0 234.4,53.8 236.8,58.3 239.2,63.1 241.6,68.4 244.0,74.0 246.4,79.9 248.8,86.0 251.2,92.2 253.6,98.5 256.0,104.8 258.4,111.1 260.8,117.2 263.2,123.2 265.6,129.0 268.0,134.6 270.4,139.9 272.8,144.9 275.2,149.7 277.6,154.1 280.0,158.2 282.4,161.9 284.8,165.3 287.2,168.5 289.6,171.3 292.0,173.8 294.4,176.1 296.8,178.1 299.2,179.9 301.6,181.4 304.0,182.8 306.4,183.9 308.8,184.9 311.2,185.8 313.6,186.5 316.0,187.1 318.4,187.7 320.8,188.1 323.2,188.5 325.6,188.8 328.0,189.0 330.4,189.2 332.8,189.4 335.2,189.5 337.6,189.6 340.0,189.7 342.4,189.8 344.8,189.8 347.2,189.9 349.6,189.9 352.0,189.9 354.4,189.9 356.8,190.0 359.2,190.0 361.6,190.0 364.0,190.0 366.4,190.0 368.8,190.0 371.2,190.0 373.6,190.0 376.0,190.0 378.4,190.0 380.8,190.0 383.2,190.0 385.6,190.0 388.0,190.0 390.4,190.0 392.8,190.0 395.2,190.0 397.6,190.0 400.0,190.0 402.4,190.0 404.8,190.0 407.2,190.0 409.6,190.0 412.0,190.0 414.4,190.0 416.8,190.0 419.2,190.0 421.6,190.0 424.0,190.0 426.4,190.0 428.8,190.0 431.2,190.0 433.6,190.0 436.0,190.0 438.4,190.0 440.8,190.0 443.2,190.0 445.6,190.0 448.0,190.0 450.4,190.0 452.8,190.0 455.2,190.0 457.6,190.0 460.0,190.0 462.4,190.0 464.8,190.0 467.2,190.0 469.6,190.0 472.0,190.0 474.4,190.0 476.8,190.0 479.2,190.0 481.6,190.0 484.0,190.0 486.4,190.0 488.8,190.0 491.2,190.0 493.6,190.0 496.0,190.0 498.4,190.0 500.8,190.0 503.2,190.0 505.6,190.0 508.0,190.0 510.4,190.0 512.8,190.0 515.2,190.0 517.6,190.0 520.0,190.0 522.4,190.0 524.8,190.0 527.2,190.0 529.6,190.0 532.0,190.0 534.4,190.0 536.8,190.0 539.2,190.0 541.6,190.0 544.0,190.0 546.4,190.0 548.8,190.0 551.2,190.0 553.6,190.0 556.0,190.0 558.4,190.0 560.8,190.0 563.2,190.0 565.6,190.0 568.0,190.0 570.4,190.0 572.8,190.0 575.2,190.0 577.6,190.0 580.0,190.0 582.4,190.0 584.8,190.0 587.2,190.0 589.6,190.0 592.0,190.0 594.4,190.0 596.8,190.0 599.2,190.0 601.6,190.0 604.0,190.0 606.4,190.0 608.8,190.0 611.2,190.0 613.6,190.0 616.0,190.0 618.4,190.0 620.8,190.0 623.2,190.0 625.6,190.0 628.0,190.0 630.4,190.0 632.8,190.0 635.2,190.0 637.6,190.0 640.0,190.0" fill="none" stroke="#2f5f2f" stroke-width="2"/>
<polyline points="42.4,190.0 44.8,190.0 47.2,190.0 49.6,190.0 52.0,190.0 54.4,190.0 56.8,190.0 59.2,190.0 61.6,190.0 64.0,190.0 66.4,190.0 68.8,190.0 71.2,190.0 73.6,190.0 76.0,190.0 78.4,190.0 80.8,190.0 83.2,190.0 85.6,190.0 88.0,190.0 90.4,190.0 92.8,190.0 95.2,190.0 97.6,190.0 100.0,190.0 102.4,190.0 104.8,190.0 107.2,190.0 109.6,190.0 112.0,190.0 114.4,190.0 116.8,190.0 119.2,190.0 121.6,190.0 124.0,190.0 126.4,190.0 128.8,190.0 131.2,190.0 133.6,190.0 136.0,190.0 138.4,190.0 140.8,190.0 143.2,190.0 145.6,190.0 148.0,190.0 150.4,190.0 152.8,190.0 155.2,190.0 157.6,190.0 160.0,190.0 162.4,190.0 164.8,190.0 167.2,190.0 169.6,190.0 172.0,190.0 174.4,190.0 176.8,190.0 179.2,190.0 181.6,190.0 184.0,190.0 186.4,190.0 188.8,190.0 191.2,190.0 193.6,190.0 196.0,190.0 198.4,190.0 200.8,190.0 203.2,190.0 205.6,190.0 208.0,190.0 210.4,190.0 212.8,190.0 215.2,190.0 217.6,190.0 220.0,190.0 222.4,190.0 224.8,190.0 227.2,190.0 229.6,190.0 232.0,190.0 234.4,190.0 236.8,190.0 239.2,190.0 241.6,190.0 244.0,190.0 246.4,190.0 248.8,190.0 251.2,190.0 253.6,190.0 256.0,190.0 258.4,190.0 260.8,190.0 263.2,190.0 265.6,190.0 268.0,190.0 270.4,190.0 272.8,190.0 275.2,190.0 277.6,190.0 280.0,190.0 282.4,190.0 284.8,190.0 287.2,190.0 289.6,190.0 292.0,190.0 294.4,190.0 296.8,190.0 299.2,190.0 301.6,190.0 304.0,190.0 306.4,190.0 308.8,190.0 311.2,190.0 313.6,190.0 316.0,190.0 318.4,190.0 320.8,190.0 323.2,190.0 325.6,190.0 328.0,190.0 330.4,190.0 332.8,190.0 335.2,190.0 337.6,190.0 340.0,190.0 342.4,190.0 344.8,190.0 347.2,190.0 349.6,190.0 352.0,190.0 354.4,190.0 356.8,190.0 359.2,190.0 361.6,190.0 364.0,190.0 366.4,190.0 368.8,190.0 371.2,190.0 373.6,190.0 376.0,190.0 378.4,190.0 380.8,190.0 383.2,190.0 385.6,190.0 388.0,190.0 390.4,190.0 392.8,190.0 395.2,190.0 397.6,190.0 400.0,190.0 402.4,190.0 404.8,190.0 407.2,190.0 409.6,190.0 412.0,190.0 414.4,190.0 416.8,190.0 419.2,190.0 421.6,190.0 424.0,190.0 426.4,190.0 428.8,190.0 431.2,190.0 433.6,190.0 436.0,190.0 438.4,190.0 440.8,190.0 443.2,190.0 445.6,190.0 448.0,190.0 450.4,190.0 452.8,190.0 455.2,189.9 457.6,189.9 460.0,189.9 462.4,189.9 464.8,189.8 467.2,189.7 469.6,189.6 472.0,189.5 474.4,189.4 476.8,189.2 479.2,188.9 481.6,188.6 484.0,188.2 486.4,187.7 488.8,187.0 491.2,186.2 493.6,185.3 496.0,184.1 498.4,182.6 500.8,180.9 503.2,178.9 505.6,176.5 508.0,173.6 510.4,170.4 512.8,166.6 515.2,162.3 517.6,157.4 520.0,151.9 522.4,145.8 524.8,139.1 527.2,131.8 529.6,123.9 532.0,115.4 534.4,106.5 536.8,97.1 539.2,87.4 541.6,77.5 544.0,67.6 546.4,57.7 548.8,48.1 551.2,38.8 553.6,30.2 556.0,22.3 558.4,15.3 560.8,9.4 563.2,4.7 565.6,1.3 568.0,-0.8 570.4,-1.3 572.8,-0.5 575.2,1.9 577.6,5.6 580.0,10.7 582.4,17.0 584.8,24.3 587.2,32.6 589.6,41.7 592.0,51.4 594.4,61.5 596.8,71.8 599.2,82.1 601.6,92.4 604.0,102.4 606.4,112.0 608.8,121.2 611.2,129.8 613.6,137.7 616.0,145.0 618.4,151.6 620.8,157.5 623.2,162.8 625.6,167.4 628.0,171.4 630.4,174.8 632.8,177.7 635.2,180.1 637.6,182.1 640.0,183.8" fill="none" stroke="#7a1f1f" stroke-width="2"/>
<line x1="383.2" y1="30" x2="383.2" y2="190" stroke="#1a1a1a" stroke-dasharray="5 3"/>
<text x="389.2" y="40" class="ts tb">limite 793</text>
<text x="217.6" y="24" text-anchor="middle" class="ts" fill="#2f5f2f">fonte sã, H = 0,5: média 724</text>
<text x="544.0" y="60" text-anchor="middle" class="ts td">fonte viciada, 85%:</text><text x="544.0" y="74" text-anchor="middle" class="ts td">média 871</text>
<g class="ts"><text x="40.0" y="206" text-anchor="middle">650</text><text x="160.0" y="206" text-anchor="middle">700</text><text x="280.0" y="206" text-anchor="middle">750</text><text x="400.0" y="206" text-anchor="middle">800</text><text x="520.0" y="206" text-anchor="middle">850</text><text x="640.0" y="206" text-anchor="middle">900</text></g>
<text x="350" y="230" text-anchor="middle" class="ts">quantas vezes a primeira amostra reaparece numa janela de 1024</text>
<text x="389.2" y="170" class="ts">à direita: alarme falso 2⁻²⁰</text>
</svg>
<figcaption>Figura 43.1 — O teste de proporção. A fonte sã quase nunca passa de 793; a viciada quase sempre passa.</figcaption>
</figure>

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
| DES e 3DES | primeiro uso | resposta conhecida, 25 vetores; o CMAC-TDES e um key block versão B (etapa 8.7); a IPEK e uma transação do DUKPT (etapa 8.8a), com o MAC de pedido dela (etapa 8.9b); dois retail MACs publicados, um de cada preenchimento (etapa 8.9a) |
| AES-128 e DUKPT AES | primeiro uso | resposta conhecida: o motor nas duas direções, e as chaves de PIN AES-128 e AES-256 de uma transação, com o PIN block refeito (etapa 8.8b), e as chaves de MAC e de dados dela (etapa 8.9b) |
| Par assimétrico recém-gerado | a cada geração | assina e verifica antes de entregar |
| Toda assinatura | a cada assinatura | verificada com a chave pública antes de sair |

**Por que alguns rodam no primeiro uso.** A FIPS 140-3 permite que o teste
de um algoritmo rode antes do primeiro uso dele, e não no boot. O critério
aqui foi o custo: cada propriedade conferida no boot cobra tempo de todo
boot, para sempre. Os três testes de primeiro uso são os mais caros.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="20" y1="120" x2="660" y2="120" marker-end="url(#seta)"/>
<text x="650" y="140" text-anchor="end" class="ts">tempo</text>
<rect class="cxd" x="30" y="90" width="120" height="30"/><text x="90" y="110" text-anchor="middle" class="ts">POST, 28 ms</text>
<text x="90" y="80" text-anchor="middle" class="ts">a cada boot</text>
<rect class="cxv" x="150" y="90" width="510" height="30"/><text x="405" y="110" text-anchor="middle" class="ts">atende comandos</text>
<line class="ln" x1="260" y1="40" x2="260" y2="88" marker-end="url(#seta)"/><rect class="cx" x="200" y="16" width="120" height="24"/><text x="260" y="33" text-anchor="middle" class="ts">1º comando 3DES</text>
<line class="ln" x1="420" y1="40" x2="420" y2="88" marker-end="url(#seta)"/><rect class="cx" x="360" y="16" width="120" height="24"/><text x="420" y="33" text-anchor="middle" class="ts">1ª assinatura RSA</text>
<line class="ln" x1="570" y1="40" x2="570" y2="88" marker-end="url(#seta)"/><rect class="cx" x="510" y="16" width="120" height="24"/><text x="570" y="33" text-anchor="middle" class="ts">1º uso de ECDSA</text>
<text x="260" y="58" text-anchor="middle" class="ts">KAT do 3DES</text>
<text x="420" y="58" text-anchor="middle" class="ts">KAT da assinatura</text>
<text x="570" y="58" text-anchor="middle" class="ts">KAT do ECDSA</text>
<text x="340" y="166" text-anchor="middle" class="ts">cada KAT de primeiro uso roda uma vez por boot, antes do primeiro comando que usa o algoritmo</text>
<text x="340" y="184" text-anchor="middle" class="ts td">reprovou: apaga as chaves, TAMPERED, e o comando responde 91</text>
</svg>
<figcaption>Figura 46.1 — O autoteste no tempo. O que custa pouco roda no boot; o que custa muito, antes do primeiro uso.</figcaption>
</figure>

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
| Chaves 3DES | gera e devolve o KCV; com uma KEK 3DES, exporta e importa em bloco versão B; cifra e decifra dados e faz o retail MAC | abre o bloco e confere tamanho, paridade e KCV; abre e fecha os blocos B com a KEK, e confere as recusas da regra de força; refaz o 3DES-CBC e o retail MAC com a chave aberta |
| DUKPT TDES e AES | traduz o PIN de um terminal DUKPT para uma chave de zona; gera a IPEK ou a IK sob uma KEK; confere o MAC e decifra o pedido, e faz o MAC e cifra a resposta | faz o papel do terminal (cifra o PIN sob a chave da transação) e o do destino; abre a chave inicial com a KEK e a refaz da BDK; leva as BDKs publicadas (anexo A.4 da X9.24-1, suplemento da X9.24-3) e exige o PIN e a chave inicial publicados, e os MACs e dados das duas fontes |
| RSA e ECDSA | gera pares e assina | verifica só com a chave pública |
| PKCS#8 | gera, e assina com chave vinda de fora | usa a chave do equipamento numa biblioteca, e o contrário |

O PC precisa da LMK para abrir os blocos. Isso só existe porque o
equipamento é de estudo: num sistema real, quem testa não tem a chave
mestra, e a conferência independente é feita por um segundo HSM.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="fr" x="20" y="30" width="230" height="130"/>
<text x="135" y="50" text-anchor="middle" class="tb">a placa</text>
<rect class="cxd" x="40" y="65" width="190" height="34"/><text x="135" y="86" text-anchor="middle" class="ts">gera, cifra, assina, traduz…</text>
<rect class="cx" x="40" y="110" width="190" height="34"/><text x="135" y="131" text-anchor="middle" class="ts">C, coprocessador, silício</text>
<rect class="cxa" x="430" y="30" width="230" height="130"/>
<text x="545" y="50" text-anchor="middle" class="tb">o PC</text>
<rect class="cx" x="450" y="65" width="190" height="34"/><text x="545" y="80" text-anchor="middle" class="ts">abre o bloco com a LMK</text><text x="545" y="93" text-anchor="middle" class="ts">(só num equipamento de estudo)</text>
<rect class="cx" x="450" y="110" width="190" height="34"/><text x="545" y="125" text-anchor="middle" class="ts">refaz ou desfaz a conta</text><text x="545" y="138" text-anchor="middle" class="ts">com outra implementação</text>
<line class="ln" x1="250" y1="80" x2="428" y2="80" marker-end="url(#seta)"/>
<text x="340" y="72" text-anchor="middle" class="ts">key block, criptograma, PIN block</text>
<line class="ln" x1="428" y1="130" x2="250" y2="130" marker-end="url(#seta)"/>
<text x="340" y="148" text-anchor="middle" class="ts">o caminho inverso: bloco do Python</text>
<text x="340" y="188" text-anchor="middle" class="ts">cem voltas por teste; uma discordância de formato aparece na primeira volta</text>
</svg>
<figcaption>Figura 47.1 — O teste de conferência. O equipamento faz; uma implementação independente refaz ou desfaz.</figcaption>
</figure>

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
