# Parte III — Como HSMs são atacados

Esta parte é o contrapeso da anterior. Cada mecanismo descrito até aqui
existe porque alguém, em algum momento, quebrou um dispositivo que não o
tinha.

Os ataques abaixo são **públicos e históricos**, documentados em literatura
acadêmica e usados há décadas no ensino de segurança. Estão aqui pelo motivo
de sempre: não se projeta defesa sem entender o ataque.

## 15. Ataques de API — o mais importante

A observação central, e a que mais custa a ser internalizada:

> Contra um HSM bem construído, você não ataca a criptografia. Você ataca a
> **API** — procura uma sequência de comandos, todos legítimos, que
> combinados revelem algo que nenhum comando isolado revelaria.

O módulo funciona perfeitamente. Cada chamada é válida. Nenhum algoritmo é
quebrado. E ainda assim a chave sai.

Este é o tipo de ataque que mais aparece contra HSMs reais, e o menos
intuitivo para quem vem de criptografia teórica — porque a falha não está na
matemática, está na **composição** de operações.

### 15.1 Confusão de tipo de chave

Nos formatos antigos da IBM CCA, o tipo de uma chave era codificado
fazendo-se XOR de um *vetor de controle* com a chave mestra antes de cifrar a
chave de trabalho. O tipo, portanto, não era autenticado — era apenas um
valor combinado.

Mike Bond (*Attacks on Cryptoprocessor Transaction Sets*, 2001) mostrou
famílias de ataques que consistiam em manipular
esses vetores para **converter uma chave de um tipo em outro**. Uma chave
destinada a derivar PINs podia ser reapresentada ao módulo como chave de
dados; a partir daí, bastava pedir ao HSM que cifrasse com ela para obter o
que deveria ser secreto.

**A defesa é o TR-31**, e agora a seção 8 faz sentido: o cabeçalho declara o
tipo *e é coberto pelo MAC*. Alterar o tipo invalida o bloco inteiro. Toda a
feiura do formato existe por causa desta classe de ataque.


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<text x="165" y="18" text-anchor="middle" class="tb">vetor de controle (formato antigo)</text>
<rect class="cxd" x="20" y="32" width="90" height="30"/><text x="65" y="52" text-anchor="middle">chave mestra</text>
<circle class="cx" cx="150" cy="47" r="14"/><text x="150" y="52" text-anchor="middle" class="tb">⊕</text>
<rect class="cxa" x="190" y="32" width="120" height="30"/><text x="250" y="47" text-anchor="middle" class="ts">vetor "chave de PIN"</text><text x="250" y="58" text-anchor="middle" class="ts">valor público</text>
<line class="ln" x1="110" y1="47" x2="134" y2="47" marker-end="url(#seta)"/>
<line class="ln" x1="190" y1="47" x2="166" y2="47" marker-end="url(#seta)"/>
<line class="ln" x1="150" y1="61" x2="150" y2="92" marker-end="url(#seta)"/>
<rect class="cx" x="80" y="94" width="140" height="34"/><text x="150" y="116" text-anchor="middle" class="ts">chave de cifra efetiva</text>
<text x="165" y="150" text-anchor="middle" class="ts">o atacante troca o vetor e compensa a diferença;</text>
<text x="165" y="164" text-anchor="middle" class="ts">nada autentica o tipo</text>
<rect class="cxd" x="40" y="180" width="250" height="34"/><text x="165" y="202" text-anchor="middle" class="ts td">a chave de PIN vira "chave de dados"</text>
<line class="lnt" x1="340" y1="10" x2="340" y2="220"/>
<text x="510" y="18" text-anchor="middle" class="tb">key block (X9.143)</text>
<rect class="cxa" x="380" y="40" width="70" height="30"/><text x="415" y="60" text-anchor="middle" class="tm">P0…</text>
<rect class="cx" x="450" y="40" width="130" height="30"/><text x="515" y="60" text-anchor="middle" class="ts">corpo cifrado</text>
<rect class="cxv" x="580" y="40" width="80" height="30"/><text x="620" y="60" text-anchor="middle" class="ts">MAC</text>
<text x="415" y="90" text-anchor="middle" class="ts">P0 → D0</text>
<line class="lnd" x1="415" y1="96" x2="415" y2="124" marker-end="url(#seta-d)"/>
<rect class="cxa" x="380" y="126" width="70" height="30"/><text x="415" y="146" text-anchor="middle" class="tm td">D0…</text>
<rect class="cx" x="450" y="126" width="130" height="30"/><text x="515" y="146" text-anchor="middle" class="ts">corpo cifrado</text>
<rect class="cxd" x="580" y="126" width="80" height="30"/><text x="620" y="146" text-anchor="middle" class="ts td">não confere</text>
<rect class="cxv" x="400" y="180" width="240" height="34"/><text x="520" y="202" text-anchor="middle" class="ts">o bloco inteiro é recusado</text>
</svg>
<figcaption>Figura 15.1 — Confusão de tipo de chave. No formato antigo o tipo só entrava na conta; no key block, ele é autenticado.</figcaption>
</figure>

### 15.2 Ataque da tabela de decimalização

O exemplo mais didático que existe, porque a matemática é trivial e o efeito
é devastador.

O método de verificação de PIN IBM 3624 funciona assim: cifra-se o número da
conta com a chave de derivação, obtêm-se dígitos hexadecimais, e uma **tabela
de decimalização** os mapeia para decimais:

```
    hex:    0 1 2 3 4 5 6 7 8 9 A B C D E F
    tabela: 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5      (padrão)
```

O problema: algumas APIs permitiam que **o chamador fornecesse a tabela**.

Bond e Zieliński (2003) observaram que, ao fornecer uma tabela degenerada —
por exemplo, toda de zeros exceto uma posição — o atacante aprende, a cada
consulta, se um determinado dígito aparece no PIN. Poucas consultas revelam
o conjunto de dígitos; poucas mais revelam a ordem.

O resultado, para um PIN de quatro dígitos: **15 chamadas em média** na
variante adaptativa, e 24 no pior caso, contra as cinco mil de uma busca
exaustiva. E cada chamada é perfeitamente legítima.


<figure class="fig">
<svg viewBox="0 0 680 260" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="20" class="tb">a tabela legítima e uma tabela de sonda (para o dígito 7)</text>
<g class="tm">
<text x="10" y="44">hex</text>
<text x="10" y="66">legítima</text>
<text x="10" y="88">sonda</text>
</g>
<g class="tm">
<text x="90" y="44">0 1 2 3 4 5 6 7 8 9 A B C D E F</text>
<text x="90" y="66">0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5</text>
<text x="90" y="88">0 0 0 0 0 0 0 <tspan class="td">1</tspan> 0 0 0 0 0 0 0 0</text>
</g>
<text x="400" y="60" class="ts">Com a sonda, o PIN natural vira 0000,</text>
<text x="400" y="74" class="ts">ou tem um 1 onde havia um 7.</text>
<text x="400" y="88" class="ts">"Este PIN confere?" responde: há 7 no PIN?</text>
<line class="ln" x1="200" y1="225" x2="650" y2="225"/>
<text x="10" y="120" class="tb">chamadas para achar um PIN de 4 dígitos (escala log)</text>
<g class="ts"><text x="200" y="240" text-anchor="middle">1</text><text x="310" y="240" text-anchor="middle">10</text><text x="420" y="240" text-anchor="middle">100</text><text x="530" y="240" text-anchor="middle">1 000</text><text x="640" y="240" text-anchor="middle">10 000</text></g>
<line class="grade" x1="310" y1="130" x2="310" y2="225"/><line class="grade" x1="420" y1="130" x2="420" y2="225"/><line class="grade" x1="530" y1="130" x2="530" y2="225"/><line class="grade" x1="640" y1="130" x2="640" y2="225"/>
<text x="190" y="148" text-anchor="end">busca exaustiva, média</text><rect x="200" y="136" width="406.9" height="16" fill="#888"/><text x="612" y="149" class="ts">5 000</text>
<text x="190" y="172" text-anchor="end">adaptativo, pior caso</text><rect x="200" y="160" width="151.8" height="16" fill="#7a1f1f"/><text x="358" y="173" class="ts">24</text>
<text x="190" y="196" text-anchor="end">variante do offset, média</text><rect x="200" y="184" width="133.9" height="16" fill="#7a1f1f"/><text x="340" y="197" class="ts">16,5</text>
<text x="190" y="220" text-anchor="end">adaptativo, média</text><rect x="200" y="208" width="129.4" height="14" fill="#7a1f1f"/><text x="336" y="220" class="ts">15</text>
</svg>
<figcaption>Figura 15.2 — O ataque da tabela de decimalização. Uma tabela escolhida pelo chamador transforma "confere?" em "este dígito está no PIN?".</figcaption>
</figure>

Uma terceira variante usa a tabela legítima com uma entrada alterada, e
compensa no offset: 16,5 chamadas em média, com um único PIN block
capturado. Por causa dela, conferir a forma da tabela não basta. A defesa
completa é aceitar só tabela **autorizada**, protegida por criptografia. A
seção 35 mostra as contas e o que este equipamento faz.

**A lição de projeto:** todo parâmetro controlado pelo chamador é uma
entrada de ataque, inclusive os que parecem configuração inofensiva. É a
razão do item mais importante do checklist deste projeto:

> *O que este comando pode fazer vazar se for chamado em laço com entradas
> escolhidas?*

Note que a pergunta não é "este comando vaza a chave?". É "**dez mil
chamadas** deste comando vazam a chave?".

### 15.3 Ataques a PIN blocks

Um PIN não trafega sozinho: ele vai dentro de um *PIN block*, que combina o
PIN com o número da conta. O formato mais comum, ISO-0 (ANSI X9.8), faz XOR
entre o PIN preenchido e parte do número da conta.

HSMs de pagamento precisam **traduzir** PIN blocks — de uma chave para outra,
de um formato para outro — porque a rede de pagamentos tem domínios de chave
distintos entre adquirente, bandeira e emissor.

Clulow (2003) e outros mostraram que a combinação de tradução de formato com
controle sobre o número da conta fornecido permite extrair informação sobre o
PIN, um pedaço de cada vez. O módulo nunca revela o PIN; ele revela se uma
operação teve sucesso, e isso basta.


<figure class="fig">
<svg viewBox="0 0 680 180" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="50" width="140" height="70"/>
<text x="80" y="72" text-anchor="middle" class="tb">atacante</text>
<text x="80" y="90" text-anchor="middle" class="ts">um PIN block capturado</text>
<text x="80" y="104" text-anchor="middle" class="ts">e um PAN alterado</text>
<line class="ln" x1="150" y1="75" x2="258" y2="75" marker-end="url(#seta)"/>
<text x="204" y="68" text-anchor="middle" class="ts">traduza</text>
<rect class="fr" x="260" y="30" width="170" height="110"/>
<rect class="cxd" x="275" y="50" width="140" height="70"/>
<text x="345" y="72" text-anchor="middle" class="tb">HSM</text>
<text x="345" y="90" text-anchor="middle" class="ts">abre com o PAN dado</text>
<text x="345" y="104" text-anchor="middle" class="ts">confere a forma</text>
<line class="ln" x1="430" y1="60" x2="498" y2="45" marker-end="url(#seta)"/>
<line class="lnd" x1="430" y1="105" x2="498" y2="120" marker-end="url(#seta-d)"/>
<rect class="cxv" x="500" y="25" width="170" height="36"/><text x="585" y="47" text-anchor="middle" class="ts">00: a forma é válida</text>
<rect class="cxd" x="500" y="104" width="170" height="36"/><text x="585" y="126" text-anchor="middle" class="ts">14: a forma é inválida</text>
<text x="340" y="168" text-anchor="middle" class="ts">um bit por pedido; com PANs escolhidos, os bits contam o tamanho do PIN e partes de cada dígito</text>
</svg>
<figcaption>Figura 15.3 — A tradução de PIN como oráculo. O módulo nunca mostra o PIN; o código de erro basta.</figcaption>
</figure>

**A lição:** funções de conversão são pontos de vazamento. Sempre que um
módulo traduz entre representações, ele pode virar oráculo — e o mesmo
padrão aparece fora de pagamentos, no *padding oracle*, em que um servidor
que distingue "preenchimento inválido" de "MAC inválido" entrega decifração
completa a quem perguntar o suficiente.

É por isso que, neste projeto, o arquivo de códigos de status carrega esta
regra:

```c
/* Um status nunca pode revelar mais do que o host tem direito de saber.
   "Chave errada" e "slot vazio" devem ser o mesmo codigo sempre que a
   distincao ajudar um atacante a enumerar o key store. */
```

### 15.4 O padrão comum

Repare no que os três têm em comum:

1. Todas as chamadas são **legítimas** — nenhuma validação foi burlada.
2. O vazamento vem da **composição**, não de um comando isolado.
3. O canal é estreito (um bit de sucesso/falha), e mesmo assim suficiente.
4. A defesa está no **projeto da API**, não em criptografia mais forte.

E é por isso que "todo opcode novo precisa de entrada na tabela, verificação
de estado e teste, nessa ordem" é regra de projeto e não burocracia. A hora
barata de perceber que um comando vaza é antes de escrevê-lo.

## 16. Canais laterais

Aqui o atacante não fala com a API. Ele **observa o dispositivo trabalhando**
e infere o segredo a partir de algo que não era para ser saída.

### 16.1 Tempo

Kocher (1996) mostrou que o tempo de execução de exponenciação modular
depende dos bits do expoente. Medindo tempos de resposta, recupera-se a chave
privada.

A versão moderna mais comum não envolve matemática de chave pública: é
**comparação de MAC que retorna cedo**.

```c
    /* ERRADO: vaza o comprimento do prefixo correto */
    if (memcmp(mac_calculado, mac_recebido, 16) != 0) return ERRO;
```

`memcmp` retorna assim que encontra diferença. Um atacante mede o tempo,
descobre quantos bytes iniciais acertou, e reconstrói o MAC byte a byte —
2\*16\*256 tentativas em vez de 2^128.


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="60" y1="190" x2="650" y2="190" marker-end="url(#seta)"/>
<line class="ln" x1="60" y1="190" x2="60" y2="15" marker-end="url(#seta)"/>
<text x="355" y="222" text-anchor="middle" class="ts">bytes iniciais certos no MAC enviado</text>
<text x="25" y="105" class="ts" transform="rotate(-90 25 105)" text-anchor="middle">tempo da resposta</text>
<g class="ts"><text x="60" y="205" text-anchor="middle">0</text><text x="200" y="205" text-anchor="middle">4</text><text x="340" y="205" text-anchor="middle">8</text><text x="480" y="205" text-anchor="middle">12</text><text x="620" y="205" text-anchor="middle">16</text></g>
<path d="M60,170 H95 V160 H130 V150 H165 V140 H200 V130 H235 V120 H270 V110 H305 V100 H340 V90 H375 V80 H410 V70 H445 V60 H480 V50 H515 V40 H550 V30 H585 V20 H620" fill="none" stroke="#7a1f1f" stroke-width="2"/>
<text x="250" y="96" class="ts td">memcmp: cada byte certo atrasa a resposta</text>
<line x1="60" y1="60" x2="620" y2="60" stroke="#2f5f2f" stroke-width="2" stroke-dasharray="6 3"/>
<text x="470" y="78" class="ts" fill="#2f5f2f">tempo constante: o mesmo tempo sempre</text>
</svg>
<figcaption>Figura 16.1 — O canal de tempo da comparação. Com o retorno antecipado, o tempo conta quantos bytes o atacante acertou; ele acha o MAC um byte de cada vez.</figcaption>
</figure>

A defesa é **comparação em tempo constante**: acumular diferenças em vez de
retornar cedo.

```c
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= a[i] ^ b[i];
    return diff == 0;
```

### 16.2 Cache

Uma variação que merece destaque porque explica uma decisão deste projeto.
Implementações de AES por tabela têm tempo de acesso dependente do dado: se a
entrada da tabela está em cache, é rápida; se não, lenta. E o índice da
tabela depende da chave.

Bernstein (2005) e Osvik–Shamir–Tromer (2006) demonstraram recuperação de
chave AES a partir apenas de temporização de cache, inclusive remotamente.

É por isso que neste projeto **as caches do processador estão desligadas**.
Elas seriam inúteis (a memória interna já responde em um ciclo) e nocivas
(introduzem tempo dependente do dado). Duas razões independentes, ambas
suficientes.

### 16.3 Consumo de energia

Kocher, Jaffe e Jun (1999) introduziram a análise de potência:

**SPA** (*Simple Power Analysis*) — observar um único traço de consumo e ler
a estrutura da operação. Numa exponenciação ingênua, quadrado e
multiplicação têm assinaturas diferentes, e o traço *desenha* o expoente.


<figure class="fig">
<svg viewBox="0 0 680 160" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="20" y1="110" x2="660" y2="110"/>
<text x="20" y="20" class="ts">consumo</text>
<path d="M20,110 H40 V70 H100 V110 H110 V50 H190 V110 H200 V70 H260 V110 H270 V70 H330 V110 H340 V50 H420 V110 H430 V70 H490 V110 H500 V50 H580 V110 H660" fill="none" stroke="#2d4f73" stroke-width="2"/>
<g class="ts" text-anchor="middle">
<text x="70" y="64">Q</text><text x="150" y="44">M</text><text x="230" y="64">Q</text><text x="300" y="64">Q</text><text x="380" y="44">M</text><text x="460" y="64">Q</text><text x="540" y="44">M</text>
</g>
<g class="tb" text-anchor="middle">
<text x="110" y="135">1</text><text x="230" y="135">0</text><text x="340" y="135">1</text><text x="500" y="135">1</text>
</g>
<text x="340" y="155" text-anchor="middle" class="ts">Q = quadrado, M = multiplicação: "Q M" é um bit 1; "Q" sozinho é um bit 0. O traço lê o expoente 1011.</text>
</svg>
<figcaption>Figura 16.2 — Análise simples de potência. Uma exponenciação que só multiplica nos bits 1 desenha o expoente secreto no traço de consumo.</figcaption>
</figure>

**DPA** (*Differential Power Analysis*) — coletar milhares de traços com
entradas variadas e correlacionar estatisticamente com uma hipótese sobre
alguns bits da chave. A hipótese certa produz correlação; as erradas, ruído.
Funciona mesmo quando o sinal é muito menor que o ruído, porque a estatística
acumula.

DPA é devastadora contra implementações desprotegidas e é a razão de existir
uma indústria inteira de contramedidas: **mascaramento** (dividir valores
intermediários em partilhas aleatórias), **blinding** (randomizar a entrada
de forma reversível), **embaralhamento** da ordem de operações, lógica de
trilha dupla, e geradores de ruído.

### 16.4 Emissão eletromagnética

Mesmo princípio da análise de potência, mas captado por sonda próxima em vez
de resistor em série. Vantagem para o atacante: é **local** — dá para
posicionar a sonda sobre um bloco específico do chip e isolar o sinal que
interessa, o que é especialmente eficaz contra circuitos grandes.

### 16.5 Onde este projeto está

Sem defesa de canal lateral **físico**, e vale ser explícito: o AES no
fabric não é mascarado, não há gerador de ruído, e nada no projeto tenta
igualar consumo de corrente.

O que existe são as defesas que custam pouco e valem sempre:

- **caches desligadas**, para que o padrão de acesso à memória não vire
  sinal;
- **uma única comparação de segredo em todo o firmware, e ela é de tempo
  constante.** Não é zelo espalhado — é o contrário: ter duas comparações,
  uma segura e uma comum, é exatamente como se escolhe a errada no caminho
  raro. Vale para MAC, KCV e vetores de teste igualmente, inclusive onde não
  há segredo nenhum a proteger;
- **um único código de erro para toda recusa de importação de key block**,
  pelo mesmo motivo pelo qual o oráculo de padding existe: o atacante não
  precisa da chave, precisa que a vítima diga em qual etapa parou.

As duas últimas são canal lateral **lógico** — vazamento por tempo e por
mensagem de erro. São as que dá para fechar em firmware, e estão fechadas.
O que fica aberto é o físico, e a Fase 6 do plano ataca o próprio
dispositivo — é lá que o assunto vira prático.

## 17. Injeção de falha

Se observar não basta, **estrague o cálculo e observe o erro**. É uma das
famílias de ataque mais eficientes contra hardware criptográfico.

### 17.1 O ataque Bellcore

O exemplo mais elegante da área. Boneh, DeMillo e Lipton (1997) mostraram
que **um único erro** numa assinatura RSA feita com o Teorema Chinês do Resto
revela a fatoração da chave.

O RSA-CRT calcula duas metades, uma módulo `p` e outra módulo `q`, e as
combina. Se uma das metades sair errada por causa de uma falha induzida, a
assinatura resultante `s` satisfaz uma congruência e não a outra. Então:

```
    gcd(s^e - m  mod N,  N)  =  p
```

Uma assinatura defeituosa, um cálculo de máximo divisor comum, e a chave
privada de 2048 bits está fatorada.


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="20" y="80" width="90" height="40"/><text x="65" y="104" text-anchor="middle">m</text>
<line class="ln" x1="110" y1="92" x2="178" y2="50" marker-end="url(#seta)"/>
<line class="ln" x1="110" y1="108" x2="178" y2="150" marker-end="url(#seta)"/>
<rect class="cxv" x="180" y="30" width="150" height="40"/><text x="255" y="48" text-anchor="middle" class="ts">s_p = m^d mod p</text><text x="255" y="62" text-anchor="middle" class="ts">certo</text>
<rect class="cxd" x="180" y="130" width="150" height="40"/><text x="255" y="148" text-anchor="middle" class="ts">s_q = m^d mod q</text><text x="255" y="162" text-anchor="middle" class="ts td">⚡ falha: errado</text>
<line class="ln" x1="330" y1="50" x2="398" y2="92" marker-end="url(#seta)"/>
<line class="ln" x1="330" y1="150" x2="398" y2="108" marker-end="url(#seta)"/>
<rect class="cx" x="400" y="80" width="90" height="40"/><text x="445" y="98" text-anchor="middle" class="ts">CRT</text><text x="445" y="112" text-anchor="middle" class="ts">s errado</text>
<line class="ln" x1="490" y1="100" x2="518" y2="100" marker-end="url(#seta)"/>
<rect class="cxd" x="520" y="70" width="150" height="60"/>
<text x="595" y="92" text-anchor="middle" class="ts">s^e ≡ m (mod p), e</text>
<text x="595" y="106" text-anchor="middle" class="ts">s^e ≢ m (mod q):</text>
<text x="595" y="122" text-anchor="middle" class="tb td">gcd(s^e − m, N) = p</text>
<text x="340" y="198" text-anchor="middle" class="ts">a contramedida: conferir s^e = m com a chave pública antes de deixar a assinatura sair</text>
</svg>
<figcaption>Figura 17.1 — O ataque Bellcore. Uma metade errada no RSA-CRT deixa a assinatura certa módulo p e errada módulo q; o máximo divisor comum entrega p.</figcaption>
</figure>

Isso é imensamente relevante para a Fase 7 deste projeto, que implementa
RSA-2048 por Montgomery nos DSPs. **A contramedida padrão é verificar a
assinatura antes de emiti-la** — gastar uma exponenciação pública (barata,
expoente pequeno) para garantir que a privada saiu certa.

### 17.2 Análise diferencial de falhas em cifras de bloco

Para AES, Piret e Quisquater (2003) mostraram que uma falha injetada nas
últimas rodadas restringe drasticamente o espaço de chaves: poucos pares
correto/defeituoso bastam para recuperar a chave de rodada, e dela a chave
mestra.

### 17.3 Como se injeta a falha

| Método | Custo | O que faz |
|---|---|---|
| **Glitch de clock** | muito baixo | Pulso curto demais faz a CPU pular ou corromper uma instrução |
| **Glitch de tensão** | baixo | Queda breve na alimentação, mesmo efeito |
| **Pulso eletromagnético** | médio | Sem contato, localizado |
| **Laser** | alto | Precisão de célula individual, exige decapsulação |
| **Temperatura** | baixo | Fora de faixa, memórias e lógica ficam instáveis |

O glitch de clock é o mais didático e o mais barato. Se o pulso cair no
instante certo, a CPU pula uma instrução — e se a instrução pulada for o
`if` que compara o PIN, ou o que verifica a exportabilidade da chave, você
contornou a verificação sem tocar em criptografia alguma.

**Por que um clock rápido produz erro.** Entre dois flip-flops existe lógica, e
o sinal leva tempo para atravessá-la. Para o segundo flip-flop capturar o valor
certo, vale:

```
T_clock  >=  t_saida + t_logica + t_setup
```

Se o período encolhe abaixo disso, a borda chega antes do resultado. O flip-flop
guarda o valor antigo, ou uma mistura de bits novos e antigos. Nada quebra e
nada avisa: o circuito segue funcionando, com um valor errado dentro.


<figure class="fig">
<svg viewBox="0 0 680 220" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="28" class="ts">clock normal</text>
<path d="M110,40 V15 H230 V40 H350 V15 H470 V40 H590 V15" fill="none" stroke="#1a1a1a" stroke-width="1.5"/>
<text x="10" y="68" class="ts">dado chega</text>
<rect class="cxv" x="110" y="55" width="200" height="18"/><text x="210" y="68" text-anchor="middle" class="ts">saída + lógica + setup</text>
<line x1="350" y1="10" x2="350" y2="85" stroke="#2f5f2f" stroke-dasharray="4 3"/>
<text x="356" y="84" class="ts" fill="#2f5f2f">captura o valor certo</text>
<text x="10" y="128" class="ts">clock com glitch</text>
<path d="M110,140 V115 H230 V140 H270 V115 H300 V140 H420 V115" fill="none" stroke="#7a1f1f" stroke-width="1.5"/>
<text x="10" y="168" class="ts">dado chega</text>
<rect class="cxv" x="110" y="155" width="200" height="18"/><text x="210" y="168" text-anchor="middle" class="ts">o mesmo atraso</text>
<line x1="270" y1="110" x2="270" y2="185" stroke="#7a1f1f" stroke-dasharray="4 3"/>
<text x="276" y="196" class="ts td">a borda chega antes do dado: valor antigo, ou misturado</text>
</svg>
<figcaption>Figura 17.2 — Por que um período curto produz erro. O circuito não para; ele captura o valor errado e continua.</figcaption>
</figure>

Quatro consequências explicam o comportamento de um ataque real:

- **Só os caminhos longos falham.** Um período um pouco curto atinge os poucos
  caminhos mais lentos e poupa o resto. Por isso a falha é seletiva.
- **O que falha depende do que está ativo.** Um caminho só erra se seu valor
  estiver mudando naquele ciclo, e por isso o instante do pulso escolhe o alvo.
- **A ferramenta de timing não diz onde falha.** Ela calcula o pior caso de
  processo, tensão e temperatura. Um chip típico, frio e bem alimentado aguenta
  bem mais do que a frequência garantida.
- **Existe uma janela útil.** Pouco abaixo do limite nada acontece, e muito
  abaixo a CPU busca instruções erradas e trava. Só no meio a CPU continua
  viva com um resultado errado, que é o que o atacante quer.


<figure class="fig">
<svg viewBox="0 0 680 120" xmlns="http://www.w3.org/2000/svg">
<rect class="cxv" x="20"  y="30" width="250" height="40"/><text x="145" y="54" text-anchor="middle" class="ts">nada acontece</text>
<rect class="cxd" x="270" y="30" width="160" height="40"/><text x="350" y="48" text-anchor="middle" class="tb td">janela útil</text><text x="350" y="62" text-anchor="middle" class="ts">resultado errado, CPU viva</text>
<rect class="cxc" x="430" y="30" width="230" height="40"/><text x="545" y="54" text-anchor="middle" class="ts">a CPU trava</text>
<line class="ln" x1="20" y1="90" x2="660" y2="90" marker-end="url(#seta)"/>
<text x="340" y="110" text-anchor="middle" class="ts">pulso de clock mais curto →</text>
<line x1="150" y1="20" x2="150" y2="80" stroke="#555" stroke-dasharray="3 3"/>
<text x="154" y="24" class="ts">margem real do chip</text>
</svg>
<figcaption>Figura 17.3 — A janela útil do glitch. O atacante procura o intervalo estreito em que o circuito erra sem parar.</figcaption>
</figure>

**Injeção de falha não é canal lateral.** Canal lateral observa um dispositivo
que funciona certo. Injeção de falha perturba o dispositivo para que ele
funcione errado.

### 17.4 Contramedidas

- **Dupla execução e comparação** — calcular duas vezes e confrontar. Dobra
  o custo e derrota falhas isoladas. Não derrota duas falhas iguais: se o pulso
  atingir as duas execuções do mesmo jeito, elas concordam no erro.
- **Verificação do resultado** — refazer a conta pelo caminho inverso, como
  decifrar o que acabou de cifrar. No RSA, checar a assinatura antes de emitir.
  É mais forte que repetir, porque o caminho inverso não erra do mesmo jeito.
- **Sensores** — detectores de frequência fora de faixa, de tensão, de
  temperatura, de luz. Ao disparar: zeroize.
- **Redundância na codificação** — representar estados críticos com valores
  distantes em distância de Hamming, para que um bit trocado não converta
  "recusado" em "aceito".

**Dupla execução só vê o que difere entre as execuções.** Essa é a regra que
decide se a contramedida funciona. Compare os dois arranjos:

```
errado:   carrega chave -> cifra -> cifra -> compara
certo:    carrega chave -> cifra -> carrega chave -> cifra -> compara
```

No primeiro, a carga da chave é um **ponto comum**: acontece uma vez, e as duas
execuções herdam o resultado dela. Uma falha ali produz uma chave expandida
errada, as duas execuções calculam certo sobre essa chave errada, e o comparador
vê dois resultados iguais. O nome disso é **falha de modo comum**, e é o mesmo
problema de dois motores de avião alimentados pelo mesmo tanque.


<figure class="fig">
<svg viewBox="0 0 680 220" xmlns="http://www.w3.org/2000/svg">
<text x="165" y="18" text-anchor="middle" class="tb">carga única: a falha passa</text>
<rect class="cxd" x="105" y="30" width="120" height="34"/><text x="165" y="46" text-anchor="middle" class="ts">carrega a chave</text><text x="165" y="58" text-anchor="middle" class="ts td">⚡ aqui</text>
<line class="lnd" x1="140" y1="64" x2="90" y2="96" marker-end="url(#seta-d)"/>
<line class="lnd" x1="190" y1="64" x2="240" y2="96" marker-end="url(#seta-d)"/>
<rect class="cx" x="40" y="98" width="100" height="30"/><text x="90" y="118" text-anchor="middle" class="ts">cifra 1</text>
<rect class="cx" x="190" y="98" width="100" height="30"/><text x="240" y="118" text-anchor="middle" class="ts">cifra 2</text>
<line class="ln" x1="90" y1="128" x2="150" y2="160" marker-end="url(#seta)"/>
<line class="ln" x1="240" y1="128" x2="180" y2="160" marker-end="url(#seta)"/>
<rect class="cxd" x="95" y="162" width="140" height="40"/><text x="165" y="180" text-anchor="middle" class="ts">iguais, e errados:</text><text x="165" y="194" text-anchor="middle" class="ts td">o resultado sai</text>
<line class="lnt" x1="340" y1="10" x2="340" y2="210"/>
<text x="510" y="18" text-anchor="middle" class="tb">carga em cada execução: a falha aparece</text>
<rect class="cxd" x="380" y="30" width="110" height="34"/><text x="435" y="46" text-anchor="middle" class="ts">carrega a chave</text><text x="435" y="58" text-anchor="middle" class="ts td">⚡ aqui</text>
<rect class="cx" x="530" y="30" width="110" height="34"/><text x="585" y="52" text-anchor="middle" class="ts">carrega a chave</text>
<rect class="cx" x="380" y="98" width="110" height="30"/><text x="435" y="118" text-anchor="middle" class="ts">cifra 1</text>
<rect class="cx" x="530" y="98" width="110" height="30"/><text x="585" y="118" text-anchor="middle" class="ts">cifra 2</text>
<line class="lnd" x1="435" y1="64" x2="435" y2="96" marker-end="url(#seta-d)"/>
<line class="ln" x1="585" y1="64" x2="585" y2="96" marker-end="url(#seta)"/>
<line class="ln" x1="435" y1="128" x2="495" y2="160" marker-end="url(#seta)"/>
<line class="ln" x1="585" y1="128" x2="525" y2="160" marker-end="url(#seta)"/>
<rect class="cxv" x="440" y="162" width="140" height="40"/><text x="510" y="180" text-anchor="middle" class="ts">diferentes:</text><text x="510" y="194" text-anchor="middle" class="ts">recusa, erro grave</text>
</svg>
<figcaption>Figura 17.4 — Falha de modo comum. A dupla execução só vê o que difere entre as execuções; o que elas compartilham fica sem proteção.</figcaption>
</figure>

Por isso a pergunta útil não é "calculei duas vezes?", e sim "o que as duas
execuções compartilham?". Tudo o que for compartilhado fica sem proteção:

| Ponto comum | Como cobrir |
|---|---|
| Carga e expansão da chave | Repetir a carga dentro de cada execução |
| Entrada já lida da memória | Verificar antes, por CRC ou MAC do pedido |
| Saída depois da comparação | Comparar o mais tarde possível, e proteger o transporte |
| A própria comparação | Comparar de forma redundante, com valores distantes |

O que não dá é fechar tudo. A última linha mostra por quê: o comparador é mais
código, e pode ser atacado também. Contramedida de falha aumenta o custo do
ataque, sem eliminá-lo. Repetir exige também que as execuções fiquem separadas
no tempo além da largura do pulso, ou um pulso só atinge as duas.

Isso também mostra por que contramedida se valida atacando. Em simulação, a
falha é posta onde quem escreveu o teste imaginou, e por isso o teste passa. O
ataque real cai onde a física deixa, inclusive nos pontos comuns.

O último ponto da lista é subestimado. Se `AUTORIZADO = 1` e `NEGADO = 0`, um único
bit trocado inverte a decisão. Se `AUTORIZADO = 0x5A` e `NEGADO = 0xA5`, é
preciso trocar muitos bits coordenadamente.

### 17.5 Onde este projeto está

O gerador de clock deste projeto trata a perda de lock do MMCM como violação:
reafirma o reset, retém o evento, apaga as chaves e vai para `TAMPERED`. Mas o
detector só vê o lock. Um pulso que encurta o clock sem derrubar o `LOCKED`
passa por ele.

A Fase 6 faz esse ataque contra o próprio dispositivo. A reconfiguração dinâmica
do MMCM, que o plano previa, exige reset e para o clock. O injetor usa então um
segundo clock, mais rápido, e um multiplexador de clock global. Fica num
bitstream separado, nunca no de produção, e faz o papel do equipamento externo
de quem ataca: escuta a linha serial, conta bytes, espera um atraso e dá o pulso.

Isso é um modelo, com uma diferença importante. Um pulso aplicado de fora, no
pino do oscilador, passaria pelo MMCM, que o filtraria. Quem atacasse esta placa
de verdade usaria mais provavelmente a tensão. O injetor interno reproduz o
efeito, a violação de timing, e não o caminho físico.

A medição contou a história da seção 17.4 na prática. Sem contramedida, o
dispositivo devolveu resultados errados com CRC válido. Com dupla execução e a
chave carregada uma vez só, continuou devolvendo, e nenhuma discordância apareceu:
era a falha de modo comum. Com a chave carregada a cada execução, os resultados
errados sumiram das medições e as recusas apareceram exatamente nos momentos das
duas cargas. A falha não deixou de acontecer. Passou a ser vista.

Quando as execuções discordam, o comando é recusado, nada sai, e o equipamento
marca **erro grave**. As chaves não são apagadas. Numa violação detectada por
sensor, apagar é a resposta certa. Aqui o aparelho só sabe que uma conta deu errado
uma vez, e recomissionar nem sempre é viável ou barato. Por isso a decisão fica com
quem opera: o flag fica visível até o próximo boot, e o log guarda o comando.

## 18. Ataques físicos e antitamper

O degrau mais alto da escada: o atacante tem o aparelho na bancada.

### 18.1 A escada da resistência

| Nível | Nome | O que significa |
|---|---|---|
| 1 | **Tamper-evident** | A violação deixa marca visível: lacre, resina que estilhaça, tinta que mancha |
| 2 | **Tamper-resistant** | A violação é difícil: resina dura, blindagem, parafusos especiais |
| 3 | **Tamper-responsive** | O dispositivo **detecta e reage**: malha ativa que zeroiza ao ser rompida |
| 4 | **Environmental failure protection** | Detecta condições anormais — temperatura, tensão — e zeroiza antes de falhar |


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="cxc" x="20"  y="140" width="150" height="45"/><text x="95"  y="160" text-anchor="middle" class="tb">evidente</text><text x="95"  y="176" text-anchor="middle" class="ts">deixa marca</text>
<rect class="cx"  x="180" y="105" width="150" height="80"/><text x="255" y="125" text-anchor="middle" class="tb">resistente</text><text x="255" y="141" text-anchor="middle" class="ts">ganha tempo</text>
<rect class="cxd" x="340" y="65" width="150" height="120"/><text x="415" y="85" text-anchor="middle" class="tb td">responsivo</text><text x="415" y="101" text-anchor="middle" class="ts">detecta e apaga</text><text x="415" y="115" text-anchor="middle" class="ts">malha ativa, bateria</text>
<rect class="cxd" x="500" y="25" width="160" height="160"/><text x="580" y="45" text-anchor="middle" class="tb td">ambiental</text><text x="580" y="61" text-anchor="middle" class="ts">tensão, temperatura,</text><text x="580" y="75" text-anchor="middle" class="ts">clock: apaga antes</text><text x="580" y="89" text-anchor="middle" class="ts">de falhar</text>
<line class="lnd" x1="335" y1="25" x2="335" y2="190"/>
<text x="330" y="20" text-anchor="end" class="ts">resistência: o atacante espera</text>
<text x="340" y="20" class="ts td">resposta: o alvo some</text>
</svg>
<figcaption>Figura 18.1 — A escada da resistência física. O salto conceitual é do degrau 2 para o 3: resistir só atrasa; responder destrói a chave.</figcaption>
</figure>

O salto conceitual está entre 2 e 3. Resistência apenas ganha tempo;
**resposta** destrói o alvo. Um HSM de alto nível tem uma malha de trilhas
finíssimas envolvendo a eletrônica, monitorada continuamente. Furar,
esmerilhar ou dissolver a resina rompe a malha, e a chave desaparece antes
que se chegue nela.

### 18.2 Por que a bateria importa

A malha precisa estar viva mesmo com o equipamento desligado — senão o
ataque é trivial: corte a energia, abra com calma. Por isso HSMs de alto
nível têm bateria interna que mantém detectores e memória de chaves.

E daí decorre um comportamento que parece defeito e é projeto: **um HSM cuja
bateria descarregou acorda zeroizado e inútil.** É a falha segura correta.

Este projeto reproduz isso por acidente de hardware, e o acidente é
instrutivo: no core board QMTECH usado, o pino `VCCBATT` está ligado ao rail
de 1,8 V, sem bateria. Uma chave de bitstream em BBRAM se perde a cada
desligamento e teria de ser recarregada por JTAG (seção 18.5).

Aqui isso é desejável — nada persiste no hardware, tudo é recuperável — e é
exatamente o comportamento de um HSM comercial com bateria descarregada.

### 18.3 Ataques invasivos

- **Decapsulação** — remover o encapsulamento com ácido ou plasma, expondo o
  die.
- **Microssondagem** — colocar sondas em trilhas internas e ler barramentos
  diretamente.
- **FIB** (*Focused Ion Beam*) — cortar e refazer ligações no próprio die;
  permite, por exemplo, desconectar um sensor.
- **Imageamento** — ler ROM ou fusíveis opticamente, ou por microscopia
  eletrônica.
- **Cold boot** — resfriar a memória para retardar a perda de conteúdo e lê-la
  em outro equipamento. Relevante para DRAM, e mais um motivo para chaves
  não morarem em memória externa.

### 18.4 O que este projeto não tem

Absolutamente nada disso. Não há resina, malha, sensor, bateria ou blindagem.
O FPGA está numa placa de desenvolvimento com conectores de expansão
expostos.

Vale registrar sem rodeios: **o modelo de ameaça deste projeto vai até o
adversário que fala com a API.** Contra qualquer coisa acima disso, ele não
oferece defesa — e não pretende.

O valor está em entender por que os degraus existem. Um leitor que termine
esta parte sabendo *o que* uma malha ativa faz, *por que* ela precisa de
bateria e *por que* um HSM sem bateria acorda inútil aprendeu algo que
nenhum diagrama de blocos ensina.

### 18.5 Proteger o bitstream, e por que a produção não usa

O bitstream é o arquivo que configura o FPGA, e aqui ele carrega também o
firmware. Quem tira a flash da placa lê tudo isso: o circuito, o código e os
vetores de teste. Cifrar o bitstream fecha essa leitura.

O mecanismo tem duas partes:

- **Uma chave dentro do FPGA.** Ela nunca sai dali. O bitstream chega cifrado, um
  bloco de hardware dedicado decifra e confere a autenticidade, e só então o FPGA
  se configura. Quem lê a flash só vê bytes sem sentido.
- **Um lugar para guardar essa chave.** Existem dois, e a diferença entre eles é o
  centro da questão:

| | BBRAM | eFUSE |
|---|---|---|
| O que é | memória mantida por uma bateria | fusíveis queimados uma única vez |
| Sem energia | a chave some | a chave fica para sempre |
| Erro | apaga e grava de novo | placa perdida |
| Neste projeto | permitida | proibida pela regra nº 1 |

A chave entra na BBRAM só pelo JTAG. Num produto real, isso acontece uma vez, na
fábrica, e a bateria mantém a chave daí em diante. O equipamento liga sozinho: lê
a flash, decifra e funciona. O JTAG não faz parte do uso.


<figure class="fig">
<svg viewBox="0 0 680 170" xmlns="http://www.w3.org/2000/svg">
<rect class="cx" x="20" y="50" width="130" height="60"/>
<text x="85" y="72" text-anchor="middle" class="tb">flash</text>
<text x="85" y="88" text-anchor="middle" class="ts">bitstream cifrado</text>
<text x="85" y="102" text-anchor="middle" class="ts">(AES-256)</text>
<line class="ln" x1="150" y1="80" x2="238" y2="80" marker-end="url(#seta)"/>
<rect class="fr" x="240" y="15" width="420" height="140"/>
<text x="650" y="32" text-anchor="end" class="ts td">FPGA</text>
<rect class="cx" x="260" y="50" width="160" height="60"/>
<text x="340" y="72" text-anchor="middle" class="tb">decifrador dedicado</text>
<text x="340" y="88" text-anchor="middle" class="ts">decifra e confere</text>
<text x="340" y="102" text-anchor="middle" class="ts">a autenticidade</text>
<rect class="cxd" x="270" y="118" width="140" height="28"/>
<text x="340" y="137" text-anchor="middle" class="ts">chave na BBRAM (bateria)</text>
<line class="ln" x1="340" y1="118" x2="340" y2="112" marker-end="url(#seta)"/>
<line class="ln" x1="420" y1="80" x2="478" y2="80" marker-end="url(#seta)"/>
<rect class="cxv" x="480" y="50" width="160" height="60"/>
<text x="560" y="76" text-anchor="middle" class="tb">configura</text>
<text x="560" y="92" text-anchor="middle" class="ts">só se autêntico</text>
</svg>
<figcaption>Figura 18.2 — O boot com bitstream cifrado. Quem lê a flash vê bytes sem sentido; sem a chave na BBRAM, o FPGA recusa a configuração.</figcaption>
</figure>

**O que a placa mostrou.** O mecanismo foi provado com o experimento de RO-PUF. A
placa só aceitou o bitstream com a chave certa na BBRAM. Com outra chave, ou com a
BBRAM vazia, ela recusou a configuração.

**Por que a produção segue sem cifra.** Este é um dispositivo didático, e a decisão
do autor foi manter o bitstream de produção sem cifra, por dois motivos:

1. **Sem bateria, cifrar transformaria cada desligamento em manutenção.** Nesta
   placa a chave some ao desligar (seção 18.2). Com a flash cifrada, o equipamento
   não subiria sozinho, e cada religamento exigiria gravar a chave de novo pelo JTAG.
   Sem cifra, ele liga e funciona sem cabo nenhum.
2. **Cifrar não protegeria o que importa aqui.** A cifra cobre o bitstream, e a LMK
   está em outra região da mesma flash (Fase 4). Quem lê a flash continuaria lendo a
   chave mestra. O código deste projeto, por sua vez, é aberto.

A lição vale para qualquer equipamento: **um controle só protege o que está dentro
do seu alcance, e todo controle cobra um custo de operação.** Antes de ligar um,
pergunte o que ele cobre e quem vai pagar por ele todos os dias.
