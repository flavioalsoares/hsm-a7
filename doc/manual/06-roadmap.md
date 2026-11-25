# Parte VI — As funções, fase a fase

Esta parte descreve o que cada fase acrescentou ao equipamento, e o conceito
por trás de cada função. As medidas, os testes e o histórico da construção
ficam nas notas de fase, em `doc/fase1-notas.md` a `doc/fase7-notas.md`.

## 25. Fase 2 — engines e self-test

**Objetivo:** primitivas corretas e verificáveis. Correção antes de
desempenho.

| Bloco | Fonte | Estado |
|---|---|---|
| AES-256 | secworks/aes | **no CFS, verificado** |
| SHA-256 | secworks/sha256 | **no CFS, verificado** |
| `DNA_PORT` | primitiva Xilinx | **no CFS, verificado** |
| TRNG | neoTRNG (do NEORV32) | **no CFS, com health tests em RTL** |
| CTR_DRBG | firmware | **implementado, no POST** |

### Vetores oficiais

Os vetores KAT foram baixados das fontes oficiais — NIST CAVP para AES e
SHA, RFC 4231 para HMAC, SP 800-90A para o DRBG — com URL e hash SHA-256 de
cada arquivo registrados num manifesto. Nada foi escrito de memória.

Isso não é formalidade. A regra inviolável do projeto diz que, se um KAT
falha, o bug está no código e não no vetor — e essa regra só tem força se a
procedência do vetor for verificável por um terceiro. Um script rebaixa,
confere hash e reextrai; sobre um repositório limpo, o resultado é byte a
byte idêntico.

O AESAVS traz quatro tipos de vetor e todos foram usados, porque cada um
pega uma classe diferente de defeito: `VarKey` varre cada bit da chave
isoladamente e acha indexação errada na expansão; `VarTxt` varre cada bit do
bloco e acha ordem de byte e permutação trocadas. Um core que passa apenas
no `GFSbox` pode estar inteiro errado.

Uma divisão de responsabilidade ficou registrada e vai importar no firmware:
o core de AES faz ECB, e o encadeamento de CBC é de quem chama; o core de
SHA recebe blocos de 512 bits já preenchidos, e o *padding* também é de quem
chama. Testar o core com essas coisas embutidas misturaria falhas de
naturezas diferentes.

### O coprocessador: o CFS

Os cores entraram pelo **CFS** (*Custom Functions Subsystem*) do NEORV32 —
um slot de periférico projetado para receber coprocessadores. O arquivo do
upstream é um template feito para ser jogado fora; a substituição é feita
trocando qual arquivo o build compila, sem patch e sem tocar no submódulo.

O CFS, e não um barramento externo, por um motivo de arquitetura: o
coprocessador precisa estar **dentro da fronteira criptográfica** (seção 5),
não pendurado num barramento que sai do die. Coerente com `XBUS_EN => false`,
que é a mesma decisão vista do outro lado.

Três escolhas do mapa de registradores merecem nota, porque cada uma é um
conceito da Parte II virando linha de RTL:

- **O único fio do CFS que chega ao toplevel está amarrado em zero.** Não
  existe caminho físico do bloco que guarda a chave até um pino. A fronteira
  deixa de ser promessa de firmware e vira topologia.
- **Chave e blocos de entrada são escrita-somente**; ler devolve zero. Não
  protege contra a CPU, que acabou de escrever a chave — evita criar um
  caminho de leitura que um bug use por acidente.
- **Não há AES-128.** O tamanho de chave é fixo no hardware. Um modo mais
  fraco alcançável por escrita em registrador seria um *downgrade* de graça,
  e a seção 15 mostra o que APIs fazem com modos mais fracos disponíveis.

E há um `WIPE` que não é decorativo: ele sobrescreve a **chave expandida**
dentro do core, não só o registrador visível. O teste correspondente é o que
separa zeroização de teatro de zeroização — depois do wipe, cifrar sem
carregar chave nenhuma tem de produzir o resultado sob a chave zero.


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<rect class="cx" x="10" y="60" width="110" height="80"/><text x="65" y="94" text-anchor="middle" class="tb">CPU</text><text x="65" y="110" text-anchor="middle" class="ts">firmware</text>
<rect class="fr" x="150" y="15" width="400" height="180"/>
<text x="540" y="32" text-anchor="end" class="ts td">CFS, dentro do FPGA</text>
<rect class="cxd" x="170" y="45" width="150" height="34"/><text x="245" y="60" text-anchor="middle" class="ts">registrador de chave</text><text x="245" y="73" text-anchor="middle" class="ts td">só escrita: lê zero</text>
<rect class="cx" x="170" y="90" width="150" height="34"/><text x="245" y="105" text-anchor="middle" class="ts">bloco de entrada</text><text x="245" y="118" text-anchor="middle" class="ts">só escrita</text>
<rect class="cx" x="170" y="135" width="150" height="34"/><text x="245" y="150" text-anchor="middle" class="ts">bloco de saída, status</text><text x="245" y="163" text-anchor="middle" class="ts">leitura</text>
<line class="ln" x1="120" y1="62" x2="168" y2="62" marker-end="url(#seta)"/>
<line class="ln" x1="120" y1="107" x2="168" y2="107" marker-end="url(#seta)"/>
<line class="ln" x1="168" y1="152" x2="120" y2="152" marker-end="url(#seta)"/>
<rect class="cxd" x="360" y="45" width="170" height="80"/><text x="445" y="68" text-anchor="middle" class="tb">core AES-256</text><text x="445" y="86" text-anchor="middle" class="ts">chave expandida</text><text x="445" y="100" text-anchor="middle" class="ts">só AES-256: sem modo</text><text x="445" y="114" text-anchor="middle" class="ts">mais fraco por registrador</text>
<line class="ln" x1="320" y1="62" x2="358" y2="62" marker-end="url(#seta)"/>
<line class="ln" x1="320" y1="107" x2="358" y2="107" marker-end="url(#seta)"/>
<line class="ln" x1="445" y1="125" x2="322" y2="152" marker-end="url(#seta)"/>
<rect class="cx" x="360" y="140" width="170" height="40"/><text x="445" y="158" text-anchor="middle" class="tb">WIPE</text><text x="445" y="172" text-anchor="middle" class="ts">sobrescreve a chave expandida</text>
<line class="ln" x1="550" y1="105" x2="610" y2="105"/>
<text x="616" y="98" class="ts">único fio para</text><text x="616" y="111" class="ts">o toplevel:</text><text x="616" y="124" class="ts td">amarrado em 0</text>
</svg>
<figcaption>Figura 25.1 — O coprocessador por dentro da fronteira. A chave entra e não volta; o WIPE apaga o que o core derivou dela.</figcaption>
</figure>

### Health tests: o hardware vê, o firmware decide

Os testes RCT e APT (seção 10) se dividem entre hardware e firmware. A
SP 800-90B exige que os testes *contínuos* vejam **toda** amostra, e a fonte
produz uma por ciclo de 100 MHz. A CPU veria uma em mil. Por isso:

- **hardware** faz os testes contínuos, amostra a amostra, e congela um
  retrato de 1024 amostras brutas consecutivas;
- **firmware** faz os testes de partida sobre esse retrato e é dono da
  política — reprovou, o dispositivo vai para `TAMPERED`.

Os dois testes acabam implementados **duas vezes, de forma independente**, e
uma discordância entre eles denuncia erro de interpretação da norma.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="cx" x="10" y="70" width="110" height="50"/><text x="65" y="92" text-anchor="middle" class="tb">fonte</text><text x="65" y="108" text-anchor="middle" class="ts">1 amostra/ciclo</text>
<line class="ln" x1="120" y1="95" x2="168" y2="95" marker-end="url(#seta)"/>
<rect class="cxa" x="170" y="20" width="200" height="70"/><text x="270" y="42" text-anchor="middle" class="tb">hardware</text><text x="270" y="58" text-anchor="middle" class="ts">RCT e APT contínuos,</text><text x="270" y="72" text-anchor="middle" class="ts">sobre toda amostra</text>
<rect class="cxa" x="170" y="110" width="200" height="60"/><text x="270" y="132" text-anchor="middle" class="tb">retrato</text><text x="270" y="148" text-anchor="middle" class="ts">1024 amostras brutas seguidas</text>
<line class="ln" x1="140" y1="95" x2="140" y2="140"/><line class="ln" x1="140" y1="140" x2="168" y2="140" marker-end="url(#seta)"/>
<rect class="cx" x="420" y="110" width="240" height="60"/><text x="540" y="132" text-anchor="middle" class="tb">firmware</text><text x="540" y="148" text-anchor="middle" class="ts">testes de partida sobre o retrato</text><text x="540" y="162" text-anchor="middle" class="ts">e a política: reprovou → TAMPERED</text>
<line class="ln" x1="370" y1="140" x2="418" y2="140" marker-end="url(#seta)"/>
<line class="lnd" x1="370" y1="55" x2="520" y2="108" marker-end="url(#seta-d)"/>
<text x="470" y="68" class="ts td">falha contínua: bit de status</text>
<text x="340" y="194" text-anchor="middle" class="ts">a CPU veria uma amostra em mil; por isso o teste contínuo é do hardware</text>
</svg>
<figcaption>Figura 25.2 — Os testes de saúde divididos. O hardware vê tudo; o firmware decide.</figcaption>
</figure>

**Cuidado térmico:** meia dúzia de anéis
osciladores, não centenas. Array grande gera calor e ruído de alimentação
localizados sem ganho de entropia.

O **POST** (seção 11) roda antes de aceitar qualquer comando. Ele cobre
AES-256, SHA-256, HMAC-SHA-256, CTR_DRBG, os testes de partida da fonte,
CMAC-AES-256, o key store, o key block X9.143 e a verificação RSA-2048 —
todos contra vetores oficiais ou de procedência registrada.

Dois autotestes ficam fora do boot, porque são lentos: o da assinatura RSA e
o do ECDSA. Cada um roda **antes do primeiro uso** do algoritmo depois do
boot. A FIPS 140-3 chama isso de autoteste condicional de algoritmo, e o
permite. O que ela não permite é usar o algoritmo antes de testá-lo.

Falha leva a `TAMPERED`, e o dispositivo passa a atender **só** ao
`SELFTEST`, que é o único jeito de o operador saber *o que* reprovou em vez
de olhar um LED vermelho.

Cada propriedade que o dispositivo garante sobre si mesmo cobra
milissegundos de todo boot, para sempre. O POST deste equipamento leva
cerca de 28 ms.

## 26. Fase 3 — hierarquia de chaves

O coração do projeto, e onde os conceitos das Partes II e III viram código.

- **Key store** com os campos do cabeçalho TR-31 modelados desde o início —
  o MAC cobre o cabeçalho inteiro, então os campos não podem mudar depois.
- **Cerimônia de LMK** com três componentes XOR, KCV a cada passo, e dual
  control exigindo os dois botões.
- **Máquina de estados** com o display de 7 segmentos soletrando
  `Uni` / `Aut` / `OPE` / `tPr`, mais o ponto decimal confirmando o dual
  control.
- **Key blocks ANSI X9.143 (TR-31 versão D)**: KBEK e KBAK derivadas por
  CMAC, corpo em AES-CBC, autenticação por CMAC sobre cabeçalho e corpo —
  escritos **duas vezes**, em C e em Python.
- **Zeroize** com prova — e a prova não vem de dump.
- **Comandos de chave**: gerar dentro da fronteira, exportar embrulhado,
  reimportar, consultar metadados, apagar um slot, cifrar e gerar MAC com a
  chave referida por handle, e formar chave de trabalho por componentes.
  Só o último exige dual control, e a razão está mais abaixo.

### A cerimônia, e o que o dual control prova

A LMK entra em **três componentes** que se acumulam por XOR: cada custodiante
carrega o seu e nenhum vê os demais, e nenhum componente isolado revela nada
sobre a chave. A cada passo volta o KCV **do componente** — não do acumulado
— para que quem digitou errado descubra na hora, e não no fim, quando já não
dá para saber qual dos três estava trocado.

Os dois botões físicos autorizam, e há um detalhe que só aparece quando se
tenta atacar o próprio mecanismo: **não basta que os dois estejam
pressionados**. Entre uma autorização e a seguinte, os dois têm de ser vistos
**soltos**. Sem essa exigência, fita adesiva sobre os dois botões carregaria
a LMK inteira sozinha, e o dual control seria teatro — e, pior, um botão
travado em "pressionado" passaria a autorizar tudo em vez de nada.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="38" class="ts">botão A</text><text x="10" y="78" class="ts">botão B</text><text x="664" y="46" class="ts" text-anchor="end">apertado ↓</text>
<path d="M80,30 H130 V50 H260 V30 H340 V50 H660" fill="none" stroke="#1a1a1a" stroke-width="1.5"/>
<path d="M80,70 H140 V90 H250 V70 H350 V90 H660" fill="none" stroke="#1a1a1a" stroke-width="1.5"/>
<text x="10" y="128" class="ts">comando</text>
<rect class="cxv" x="170" y="112" width="70" height="26"/><text x="205" y="130" text-anchor="middle" class="ts">1º: ok</text>
<rect class="cxv" x="380" y="112" width="70" height="26"/><text x="415" y="130" text-anchor="middle" class="ts">2º: ok</text>
<rect class="cxd" x="560" y="112" width="90" height="26"/><text x="605" y="130" text-anchor="middle" class="ts">3º: recusa</text>
<text x="300" y="25" text-anchor="middle" class="ts">soltos: rearma</text>
<text x="560" y="25" text-anchor="middle" class="ts td">continuam apertados (fita adesiva)</text>
<text x="340" y="170" text-anchor="middle" class="ts">cada autorização consome o aperto; a próxima exige ver os dois soltos de novo</text>
<text x="340" y="188" text-anchor="middle" class="ts">fita adesiva sobre os dois botões autoriza uma vez, e nunca mais</text>
</svg>
<figcaption>Figura 26.1 — O rearme do dual control. Botão travado em "apertado" não autoriza tudo; não autoriza nada depois da primeira vez.</figcaption>
</figure>

A escada de estados é de **uma via só**. Carregou os três componentes, o
dispositivo vai a `AUTHORIZED` e o comando de carregar deixa de existir —
não há caminho para trocar a chave mestra por cima da existente. Ativou, vai
a `OPERATIONAL` e o comando de ativar some. Descer exige apagar.

### O painel

Durante a cerimônia, o operador precisa saber se o dispositivo vê os dois
botões. O display de 7 segmentos responde. Ele soletra o estado, e o
**ponto decimal acende enquanto o dual control está satisfeito**. O operador aperta e vê o dispositivo concordar,
antes de gastar o comando. É a diferença entre uma autorização que se
descobre pelo erro e uma que se confirma pelo gesto.

Duas notas de projeto:

- O display **não lê a máquina de estados**; ele recebe dois bits pelo GPIO.
  Um caminho de hardware até a estrutura de estado seria caminho de hardware
  até o que está ao lado dela na memória.
- O `default` do decodificador é `tPr`, não `Uni` nem apagado. Estado
  corrompido tem de aparecer como comprometido — falhar para o lado seguro
  vale também para o painel.

### O key block, e a pergunta que ele responde

Uma chave que nunca sai não serve para nada além de si mesma. O key block é
a resposta para "como deixar uma chave sair **sem que ela vaze**" — que é um
problema diferente de guardá-la, e mais difícil.

O formato é uma string de texto:

```
cabeçalho(16 caracteres) || corpo cifrado em hex || MAC em hex

D 0144 D0 A B 00 E 00 00
| |    |  | | |  | |  +-- reservado
| |    |  | | |  | +----- blocos opcionais
| |    |  | | |  +------- exportabilidade
| |    |  | | +---------- versão da chave
| |    |  | +------------ modo de uso
| |    |  +-------------- algoritmo
| |    +----------------- uso: dados, KEK, MAC, BDK…
| +---------------------- comprimento total
+------------------------ versão do formato
```

Três decisões dele valem mais que o código inteiro.

**Duas chaves derivadas, não uma.** A LMK não cifra o corpo nem autentica o
bloco: dela saem duas filhas por CMAC, uma para cada trabalho, distinguidas
por um campo de *propósito* na entrada da derivação. É a separação de chaves
da seção 15 aplicada onde ela é mais fácil de esquecer — se as duas fossem a
mesma, um oráculo de MAC seria um oráculo de cifragem de graça.

**O cabeçalho vai dentro do MAC.** São dezesseis bytes de texto legível, à
vista de qualquer um — e autenticados. Sem isso, alguém que não consegue
decifrar o corpo simplesmente **edita o caractere** da exportabilidade de `N`
para `E` e devolve o bloco. O criptograma não mudou; a política mudou. É o
ponto que resume a Parte II inteira: chave protegida sob metadado
desprotegido não está protegida.

**O MAC é o vetor de inicialização.** Não há IV para transmitir, e o MAC é
calculado sobre o texto **claro** — o que permite recusar um bloco adulterado
*antes* de acreditar em qualquer campo do que se decifrou.

E o enchimento aleatório no fim do corpo não é sobra: sem ele, o tamanho do
bloco denunciaria o tamanho da chave, e "esta é uma chave de 128 bits" já é
informação para quem escolhe onde gastar esforço.

### Por que o mesmo formato foi escrito duas vezes

Uma implementação em C, dentro do dispositivo; outra em Python, no host,
sobre uma biblioteca diferente. Não é redundância — é o **método de
verificação**.

Um formato binário se aprende errado em silêncio: a implementação lê a
norma, se convence, e testa contra si mesma. Duas implementações escritas
para discordar não têm essa saída, e a menor divergência aparece como MAC
inválido, que é barulhento e imediato. Se as duas compartilhassem o AES,
concordariam sobre um erro no AES sem nunca discordar — daí a exigência de
bibliotecas diferentes.

E aqui aparece um limite que vale enunciar, porque ele explica de onde vem a
confiança em cada camada. **Não existe vetor oficial para este formato.** O
programa de validação do NIST valida *algoritmo*; X9.143 é *formato*, e a
norma que traz o exemplo é paga. O que se usa é um valor conhecido de
terceiros, e o resto da confiança vem de propriedades: ida e volta, e um bit
trocado em **cada posição do bloco** tendo de invalidar tudo.

Esse último é o teste que vale mais que os outros. Uma implementação que
esqueceu de incluir o cabeçalho no MAC passa no vetor e passa na ida e volta.
Falha só ali.

### Apagar, e provar que apagou

"Chamei a função de apagar" não é a mesma coisa que "apagou", e a diferença
é invisível de fora. Um `wipe` que o compilador eliminou por ser escrita
morta, um campo novo que ninguém acrescentou ao laço, um índice fora do
intervalo: os três falham em **silêncio** e deixam chave viva num
dispositivo que se anuncia limpo.

O problema é que a verificação óbvia — o firmware varrer a própria memória
— é **auto-atestação**: é o mesmo código dizendo que o mesmo código
funcionou. Ela vale (e roda a cada boot), mas não fecha a pergunta.

O que fecha é usar **criptografia para provar memória**. A chave mestra se
acumula por XOR dos três componentes. Se a zeroização deixasse um único bit
para trás, a cerimônia seguinte acumularia sobre o resíduo — e o KCV
resultante não seria o dos componentes. Então o teste é: cerimônia, KCV
esperado; apagar; **mesma cerimônia, e o KCV tem de voltar a bater**. E o
valor esperado não é "o que o dispositivo devolveu da outra vez": é um
vetor oficial do NIST.

Nenhum firmware passa nesse teste sem que a memória estivesse mesmo zerada.


<figure class="fig">
<svg viewBox="0 0 680 190" xmlns="http://www.w3.org/2000/svg">
<rect class="cx" x="10" y="30" width="140" height="44"/><text x="80" y="50" text-anchor="middle" class="tb">cerimônia</text><text x="80" y="65" text-anchor="middle" class="ts">componentes fixos</text>
<line class="ln" x1="150" y1="52" x2="188" y2="52" marker-end="url(#seta)"/>
<rect class="cxv" x="190" y="30" width="120" height="44"/><text x="250" y="50" text-anchor="middle" class="ts">KCV = vetor</text><text x="250" y="65" text-anchor="middle" class="ts">do NIST</text>
<line class="ln" x1="310" y1="52" x2="348" y2="52" marker-end="url(#seta)"/>
<rect class="cxd" x="350" y="30" width="110" height="44"/><text x="405" y="57" text-anchor="middle" class="tb">ZEROIZE</text>
<line class="ln" x1="460" y1="52" x2="498" y2="52" marker-end="url(#seta)"/>
<rect class="cx" x="500" y="30" width="170" height="44"/><text x="585" y="50" text-anchor="middle" class="tb">a mesma cerimônia</text><text x="585" y="65" text-anchor="middle" class="ts">os mesmos componentes</text>
<line class="ln" x1="585" y1="74" x2="500" y2="112" marker-end="url(#seta)"/>
<line class="ln" x1="585" y1="74" x2="620" y2="112" marker-end="url(#seta)"/>
<rect class="cxv" x="380" y="114" width="170" height="44"/><text x="465" y="133" text-anchor="middle" class="ts">memória zerada:</text><text x="465" y="148" text-anchor="middle" class="ts">KCV = o mesmo vetor</text>
<rect class="cxd" x="560" y="114" width="115" height="44"/><text x="617" y="133" text-anchor="middle" class="ts">um bit sobrou:</text><text x="617" y="148" text-anchor="middle" class="ts td">KCV diferente</text>
<text x="200" y="135" text-anchor="middle" class="ts">o XOR acumula sobre o resíduo:</text>
<text x="200" y="150" text-anchor="middle" class="ts">LMK' = resíduo ⊕ A ⊕ B ⊕ C</text>
</svg>
<figcaption>Figura 26.2 — Provar o apagamento com criptografia. O valor esperado é um vetor oficial, e não o que o equipamento disse antes.</figcaption>
</figure>

Duas notas de projeto, e a segunda é a mais instrutiva:

- **A sobrescrita é em duas passadas**, um padrão e depois zeros. Para
  memória estática a segunda é a que conta — dizer o contrário seria
  repetir folclore de disco magnético. A primeira existe porque uma
  zeroização **interrompida** tem de deixar padrão, não meia chave.

- **O comando exige dois operadores; o gatilho automático não exige
  ninguém.** Apagar é destrutivo, então uma pessoa não basta. Mas quando é
  o próprio dispositivo que se descobre comprometido, exigir autorização
  seria absurdo: bastaria não haver ninguém na sala para a chave sobreviver
  ao comprometimento. A assimetria não é inconsistência — é o
  reconhecimento de que as duas situações têm ameaças opostas.

E há um detalhe que a máquina de estados resolve de graça: apagar em
`TAMPERED` funciona, e **não tira** o dispositivo de `TAMPERED`. A chave vai
embora, que era o pedido; o veredito fica, porque um HSM que se cura de
tamper não detectou tamper nenhum.

### Os comandos de chave, e por que quase nenhum pede dois dedos

Depois da cerimônia vem o trabalho: gerar uma chave, exportá-la embrulhada,
reimportá-la, consultar o que ela é, usá-la. **Nenhum desses comandos exige
dual control** — o que contraria a intuição o suficiente para valer o
parágrafo.

**Dual control é para cerimônia, não para operação.** Carregar a chave
mestra, ativar o dispositivo e apagar tudo são eventos raros, com gente na
frente do equipamento. Gerar e exportar chave é o que um HSM faz o dia
inteiro. Exigir dois dedos ali não aumentaria segurança nenhuma — garantiria
apenas que ninguém usa o equipamento. E um controle que impede o uso legítimo
é desligado no primeiro dia ruim, junto com os que serviam para alguma coisa.

O que protege esses comandos é estrutural, não humano:

- a chave **nunca sai em claro** — sai embrulhada num key block, e quem
  recebe não sabe abrir;
- o key block é **autenticado sobre cabeçalho mais corpo**, então a política
  viaja junto com a chave e não pode ser reescrita a caminho;
- `exportabilidade` decide quem pode sair, e existe **um único caminho** no
  código para os bytes deixarem um slot — é ele que consulta o campo.

A última linha é a diferença entre uma regra e uma promessa. Se houvesse
duas formas de obter os bytes, a verificação viraria convenção — e convenção
é o que se esquece no caminho raro.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="fr" x="10" y="10" width="420" height="180"/>
<text x="420" y="26" text-anchor="end" class="ts td">keystore.c</text>
<rect class="cxd" x="30" y="70" width="110" height="60"/><text x="85" y="96" text-anchor="middle" class="tb">slots</text><text x="85" y="112" text-anchor="middle" class="ts">bytes da chave</text>
<rect class="cx" x="200" y="30" width="210" height="36"/><text x="305" y="46" text-anchor="middle" class="ts">usa_aes(): carrega no coprocessador</text><text x="305" y="59" text-anchor="middle" class="ts">e não devolve nada</text>
<rect class="cx" x="200" y="82" width="210" height="36"/><text x="305" y="98" text-anchor="middle" class="ts">cmac(), pin_abre(), cvv()…</text><text x="305" y="111" text-anchor="middle" class="ts">a conta fica aqui dentro</text>
<rect class="cxv" x="200" y="134" width="210" height="44"/><text x="305" y="152" text-anchor="middle" class="tb">exporta()</text><text x="305" y="168" text-anchor="middle" class="ts">o único caminho: confere a exportabilidade</text>
<line class="ln" x1="140" y1="85" x2="198" y2="48" marker-end="url(#seta)"/>
<line class="ln" x1="140" y1="100" x2="198" y2="100" marker-end="url(#seta)"/>
<line class="ln" x1="140" y1="115" x2="198" y2="152" marker-end="url(#seta)"/>
<line class="ln" x1="410" y1="156" x2="478" y2="156" marker-end="url(#seta)"/>
<rect class="cxa" x="480" y="134" width="190" height="44"/><text x="575" y="152" text-anchor="middle" class="ts">tr31: embrulha</text><text x="575" y="168" text-anchor="middle" class="ts">sai como key block</text>
<line class="ln" x1="410" y1="100" x2="478" y2="100" marker-end="url(#seta)"/>
<rect class="cxa" x="480" y="82" width="190" height="36"/><text x="575" y="104" text-anchor="middle" class="ts">sai: criptograma, MAC, veredito</text>
</svg>
<figcaption>Figura 26.3 — A API assimétrica do key store. Usar a chave tem muitas portas; ver os bytes dela tem uma, e ela confere a exportabilidade.</figcaption>
</figure>

A exceção é **formar uma chave de trabalho por componentes**. É a cerimônia
de LMK um nível abaixo: cada custodiante carrega a sua parte, e por isso ela
exige os dois botões, como a cerimônia.

**O contraste que fecha a Parte II.** Um comando que recebe a chave *no
pedido* faz material de chave atravessar a fronteira na entrada. Aqui o host
escolhe os **metadados** e nunca vê o material. Nenhum comando deste
equipamento aceita chave em claro.

E uma decisão que só parece detalhe: **toda recusa de importação devolve o
mesmo código**. Bloco malformado, hexadecimal inválido, MAC errado e
comprimento impossível são indistinguíveis de fora. É o comando mais exposto
do dispositivo — um atacante manda blocos forjados em laço e cada resposta é
informação. Dizer em qual etapa a validação parou é o oráculo de padding da
seção 15, com outra roupa: o atacante não precisa da chave, precisa que a
vítima seja prestativa.

### Console e host na mesma porta

Num HSM de verdade o componente entra por teclado local ou cartão do
custodiante, **nunca pela mesma porta por onde o host fala**. Aqui o console
e o host são protocolos diferentes na mesma UART (seção 28), e o componente
passa pela máquina do host. O dual control impede *carregar*; não impede
*observar*. É a maior distância entre este projeto e o modelo — e está
escrita, não escondida.

## 27. Fase 4 — armazenamento não-volátil

Um HSM comercial desliga e volta *online* com a chave mestra, as chaves de
trabalho e o estado. Este equipamento faz o mesmo: a cerimônia só é
necessária na primeira vez e depois de um `ZEROIZE`.

### A memória segura, e por que ela é fraca de propósito

Num HSM comercial, a LMK sobrevive ao desligamento numa **memória mantida
por bateria, dentro de um invólucro com detecção de violação** (§18.2). Abrir
a caixa corta a bateria, e a chave some.

Esta placa não tem nada equivalente. O eFUSE é proibido pela regra nº 1, a
BBRAM está sem bateria, o DNA do chip é público e não há invólucro.
Embrulhar a LMK antes de gravá-la só mudaria o problema de lugar: a chave que
a embrulha teria de ficar guardada em algum lugar, e esse lugar seria a mesma
flash.

Então, por ser um projeto **educacional** e diante dessa **limitação de
hardware**, a decisão do autor foi:

> A região da flash SPI a partir de 4 MB é **tratada como memória segura**.
> A LMK é guardada nela em claro; as chaves de trabalho, embrulhadas sob a
> LMK como key blocks X9.143.

O comportamento operacional fica igual ao de um equipamento comercial. A
proteção física não fica: quem tiver um gravador SPI lê a LMK. A diferença
está escrita em `doc/fase4-notas.md`, em vez de disfarçada por um esquema que
pareceria proteger e não protegeria.

### O que existe

- **Hardware.** O SPI do NEORV32 fala com a mesma flash que guarda o
  bitstream. O clock passa pela primitiva `STARTUPE2`, a única forma de a
  lógica do usuário alcançar o pino de clock de configuração.
- **A guarda do bitstream.** O driver recusa apagar ou gravar abaixo de
  4 MB, num lugar só, por onde toda escrita passa.
- **O registro persistente**, com a LMK, o estado e os slots, em **duas
  cópias**. Cada gravação vai para a mais velha, e uma queda de energia no
  meio deixa a outra intacta. No boot vale a mais nova cujo CRC confere.


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<rect class="cxc" x="60" y="20" width="200" height="90"/><text x="160" y="58" text-anchor="middle" class="tb">bitstream</text><text x="160" y="76" text-anchor="middle" class="ts">intocável: a escrita é recusada</text>
<rect class="cxd" x="60" y="110" width="200" height="26"/><text x="160" y="127" text-anchor="middle" class="ts">registro A</text>
<rect class="cxd" x="60" y="136" width="200" height="26"/><text x="160" y="153" text-anchor="middle" class="ts">registro B</text>
<rect class="cx" x="60" y="162" width="200" height="40"/><text x="160" y="180" text-anchor="middle" class="ts">log de auditoria</text><text x="160" y="194" text-anchor="middle" class="ts">64 KB, 4096 registros, anel</text>
<g class="tm" text-anchor="end"><text x="52" y="24">000000</text><text x="52" y="114">400000</text><text x="52" y="140">401000</text><text x="52" y="166">410000</text></g>
<line class="lnd" x1="40" y1="110" x2="280" y2="110"/><text x="290" y="114" class="ts td">guarda de 4 MB, num lugar só (flash.c)</text>
<text x="290" y="140" class="ts">LMK em claro, estado, slots embrulhados</text>
<text x="290" y="154" class="ts">duas cópias: grava na mais velha; vale a mais nova com CRC certo</text>
<path class="lnt" d="M268,123 C285,130 285,140 268,149" marker-end="url(#seta-t)"/>
<text x="290" y="186" class="ts">registro gravado antes de executar; resultado depois, por cima do FF</text>
</svg>
<figcaption>Figura 27.1 — O mapa da flash. A região a partir de 4 MB faz o papel da memória com bateria de um HSM comercial.</figcaption>
</figure>
- **Chave anunciada é chave guardada.** Se a flash falhar, `GEN_KEY` e
  parentes desfazem o slot e devolvem `STORE_FAIL`.
- **O log de auditoria.** Cada comando é
  registrado **antes** de executar, com o resultado "pendente"; depois só o
  byte de resultado é programado por cima. Um registro que ficou pendente é
  um comando que começou e não terminou. E se o log não puder ser gravado, o
  comando não executa. A exceção é o `ZEROIZE`.

### Anti-rollback: fora, de propósito

Um HSM real tem um **contador anti-rollback**. O problema é real: quem
restaurar uma imagem antiga da flash ressuscita uma chave apagada. Mas a
defesa exige um contador monotônico **fora** da flash, que a placa não tem, e
um contador dentro dela seria restaurado junto com o resto. A limitação está
documentada, não mitigada. É um dos pontos onde HSMs reais gastam esforço
desproporcional, e aqui fica como lição, não como código.

## 28. Fase 5 — API de host

A porta host usa um **command set ASCII** no estilo dos HSM de
pagamento — código de comando de dois caracteres, código de resposta igual
ao comando mais um, erros numéricos, campos posicionais — e não de um
subconjunto de PKCS#11 como biblioteca compartilhada.

Não é troca de sintaxe. PKCS#11 é uma API de *biblioteca*: objetos, sessões,
atributos, estado do lado do cliente. Um command set de HSM de pagamento é
um protocolo de *serviço*, sem sessão e sem estado — **cada comando chega
sozinho e precisa se bastar**. Isso muda o que o dispositivo tem de
verificar, e muda para pior: não há contexto acumulado em que confiar.

É aqui que se entende por que a API é o que é: **é você que precisa impedi-la
de vazar material de chave**. Depois de ter lido a seção 15, escrever a API
com a pergunta "o que isto vaza em laço?" na cabeça é uma experiência
diferente.

### Três decisões de arquitetura

**Quem interpreta o ASCII é o dispositivo.** No computador fica só uma ponte
que liga um socket TCP à UART e repassa os bytes sem entendê-los. A outra
opção — um programa no PC traduzindo o ASCII para o protocolo binário — seria
mais rápida de escrever e ensinaria a coisa errada: a defesa da API ficaria
fora da fronteira criptográfica, que é justamente o lugar onde ela não
protege nada.

**Console e host passam a ter papéis separados.** O protocolo binário das
fases anteriores vira o *console*: cerimônia, estado, diagnóstico, log. O
ASCII é o *host*, e não tem nenhum comando de cerimônia — quem opera não
administra. Os dois dividem a mesma UART (o primeiro byte de cada mensagem
diz qual é qual), então a separação é de papéis, não física; a distância em
relação a um equipamento comercial, que tem portas separadas, continua
registrada.


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="20" width="150" height="50"/><text x="85" y="40" text-anchor="middle" class="tb">aplicação</text><text x="85" y="56" text-anchor="middle" class="ts">hsmhost.py, por TCP</text>
<rect class="cx" x="190" y="20" width="110" height="50"/><text x="245" y="40" text-anchor="middle" class="tb">ponte</text><text x="245" y="56" text-anchor="middle" class="ts">repassa bytes</text>
<line class="ln" x1="160" y1="45" x2="188" y2="45" marker-end="url(#seta)"/>
<rect class="cxd" x="10" y="120" width="150" height="50"/><text x="85" y="140" text-anchor="middle" class="tb">operador</text><text x="85" y="156" text-anchor="middle" class="ts">hsmtool.py (console)</text>
<line class="ln" x1="300" y1="45" x2="340" y2="90" marker-end="url(#seta)"/>
<line class="ln" x1="160" y1="145" x2="340" y2="102" marker-end="url(#seta)"/>
<rect class="cx" x="342" y="78" width="70" height="36"/><text x="377" y="100" text-anchor="middle" class="ts">UART</text>
<line class="ln" x1="412" y1="96" x2="448" y2="96" marker-end="url(#seta)"/>
<rect class="fr" x="440" y="10" width="230" height="190"/>
<rect class="cx" x="455" y="75" width="90" height="44"/><text x="500" y="93" text-anchor="middle" class="ts">1º byte do</text><text x="500" y="107" text-anchor="middle" class="ts">corpo</text>
<rect class="cxa" x="565" y="25" width="95" height="60"/><text x="612" y="44" text-anchor="middle" class="ts tb">'0' a '~'</text><text x="612" y="60" text-anchor="middle" class="ts">ASCII: host</text><text x="612" y="73" text-anchor="middle" class="ts">sem cerimônia</text>
<rect class="cxd" x="565" y="115" width="95" height="60"/><text x="612" y="134" text-anchor="middle" class="ts tb">outro valor</text><text x="612" y="150" text-anchor="middle" class="ts">binário: console</text><text x="612" y="163" text-anchor="middle" class="ts">cerimônia, log</text>
<line class="ln" x1="545" y1="90" x2="563" y2="60" marker-end="url(#seta)"/>
<line class="ln" x1="545" y1="105" x2="563" y2="140" marker-end="url(#seta)"/>
<text x="220" y="196" text-anchor="middle" class="ts">a separação é de papéis, e não física: o componente passa pela máquina do host</text>
</svg>
<figcaption>Figura 28.1 — Console e host na mesma porta. O primeiro byte decide o protocolo; nenhum opcode binário cai entre 0x30 e 0x7E.</figcaption>
</figure>

**A chave de trabalho viaja no comando.** Esta é a mudança de modelo mental
da fase. Até aqui o dispositivo guardava as chaves em 16 slots e o host as
citava por número. Um HSM de pagamento não funciona assim: ele não guarda as
chaves de trabalho de ninguém. O sistema do cliente as mantém no banco de
dados dele, cada uma como um key block embrulhado sob a LMK, e manda o bloco
junto com cada pedido. O dispositivo abre o bloco por dentro, usa a chave e a
esquece **antes de responder**.

É por isso que um equipamento com memória para poucas chaves atende milhões
delas, e é por isso que a LMK é a única chave que ele precisa guardar. A
frase "sem estado" do parágrafo anterior quer dizer exatamente isto: o estado
existe, mas mora do lado do cliente, embrulhado.


<figure class="fig">
<svg viewBox="0 0 680 220" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="20" width="150" height="180"/>
<text x="85" y="40" text-anchor="middle" class="tb">banco de dados</text><text x="85" y="55" text-anchor="middle" class="ts">do cliente</text>
<rect class="cx" x="25" y="70" width="120" height="20"/><text x="85" y="84" text-anchor="middle" class="ts tm">bloco 1</text>
<rect class="cx" x="25" y="95" width="120" height="20"/><text x="85" y="109" text-anchor="middle" class="ts tm">bloco 2</text>
<rect class="cx" x="25" y="120" width="120" height="20"/><text x="85" y="134" text-anchor="middle" class="ts tm">…</text>
<rect class="cx" x="25" y="145" width="120" height="20"/><text x="85" y="159" text-anchor="middle" class="ts tm">bloco 1 000 000</text>
<line class="ln" x1="160" y1="80" x2="298" y2="80" marker-end="url(#seta)"/><text x="230" y="72" text-anchor="middle" class="ts">1. C0 · bloco · IV · dados</text>
<rect class="fr" x="300" y="20" width="370" height="180"/>
<rect class="cxd" x="320" y="60" width="120" height="44"/><text x="380" y="78" text-anchor="middle" class="ts">2. abre sob a LMK</text><text x="380" y="92" text-anchor="middle" class="ts">no slot efêmero</text>
<rect class="cx" x="470" y="60" width="90" height="44"/><text x="515" y="86" text-anchor="middle" class="ts">3. cifra</text>
<rect class="cxv" x="580" y="60" width="80" height="44"/><text x="620" y="78" text-anchor="middle" class="ts">4. apaga</text><text x="620" y="92" text-anchor="middle" class="ts">o slot</text>
<line class="ln" x1="440" y1="82" x2="468" y2="82" marker-end="url(#seta)"/>
<line class="ln" x1="560" y1="82" x2="578" y2="82" marker-end="url(#seta)"/>
<line class="ln" x1="298" y1="160" x2="160" y2="160" marker-end="url(#seta)"/><text x="230" y="152" text-anchor="middle" class="ts">5. C1 · criptograma</text>
<text x="485" y="150" text-anchor="middle" class="ts">o equipamento guarda só a LMK;</text>
<text x="485" y="164" text-anchor="middle" class="ts">o estado mora no cliente, embrulhado</text>
</svg>
<figcaption>Figura 28.2 — A chave viaja no comando. O HSM abre o bloco, usa a chave e a esquece antes de responder.</figcaption>
</figure>

### Os comandos

Nove comandos simétricos, com códigos deste projeto (da categoria vem só a forma geral):
diagnóstico, gerar chave, conferir um key block, exportar e importar sob uma
chave de troca, cifrar e decifrar em AES-CBC, gerar e verificar CMAC. A chave de cada comando é aberta num slot
**efêmero** do key store — o mesmo código de sempre faz a checagem de modo de
uso — e apagada ao fim do comando, em qualquer desfecho. Os comandos de RSA
estão na seção 30. O apêndice B tem o formato.

### Trocar chave com outra instituição

Uma chave guardada sob a LMK só abre dentro deste dispositivo. Para mandá-la
a outra instituição, as duas combinam antes uma **KEK** — uma chave cujo
único serviço é proteger outras chaves em trânsito — formada por componentes
em cerimônia, com um custodiante de cada lado. Cada instituição guarda a KEK
sob a sua própria LMK.

Exportar é re-embrulhar: o dispositivo abre o bloco da chave (sob a LMK), abre
o da KEK (também sob a LMK) e devolve a chave sob a KEK. Do outro lado,
importar é o caminho inverso. A chave nunca existe em claro fora de um
dispositivo, e nenhuma LMK sai de casa.

É aqui que o campo de exportabilidade passa a significar alguma coisa de
verdade: antes, "exportar" queria dizer sempre "sob a LMK", e o campo era
quase um sim-ou-não. Agora a pergunta é "esta chave pode ir **para lá**?" —
e uma chave marcada `N` recebe a resposta não, enquanto continua podendo ser
usada aqui à vontade. E o modo de uso da KEK também conta: uma KEK que só
embrulha serve para mandar chaves e não para recebê-las.

Na prática, o uso tem cinco passos:

1. **Formar a KEK com os mesmos componentes nos dois dispositivos.** Cada
   custodiante leva o seu componente aos dois lados. O mesmo valor entra
   nos dois dispositivos, e ninguém conhece a KEK inteira.
2. **Conferir pelo KCV.** As duas instituições comparam o KCV da KEK, por
   telefone ou em papel. KCVs iguais provam que as KEKs são iguais, sem
   que a chave viaje.
3. **Guardar a KEK fora do dispositivo.** Cada host fica com a KEK como key
   block sob a sua LMK, como qualquer outra chave, e o slot é apagado.
4. **Exportar.** O lado que manda apresenta o bloco da KEK e o da chave e
   recebe a chave sob a KEK, com o KCV. É isso que vai pela rede.
5. **Importar.** O lado que recebe apresenta o seu bloco da KEK e o que
   chegou, e recebe a chave sob a sua própria LMK. O KCV tem de bater com
   o informado.

O cabeçalho atravessa intacto: uso, modo e exportabilidade continuam os que
a chave tinha na origem. O roteiro com os comandos está em
`doc/fase5-notas.md`.


<figure class="fig">
<svg viewBox="0 0 680 250" xmlns="http://www.w3.org/2000/svg">
<text x="140" y="18" text-anchor="middle" class="tb">banco A</text>
<text x="540" y="18" text-anchor="middle" class="tb">banco B</text>
<rect class="fr" x="40" y="28" width="200" height="120"/>
<rect class="fr" x="440" y="28" width="200" height="120"/>
<rect class="cxd" x="60" y="44" width="70" height="30"/><text x="95" y="64" text-anchor="middle" class="ts">LMK A</text>
<rect class="cxd" x="550" y="44" width="70" height="30"/><text x="585" y="64" text-anchor="middle" class="ts">LMK B</text>
<rect class="cx" x="150" y="44" width="75" height="30"/><text x="187" y="64" text-anchor="middle" class="ts">KEK</text>
<rect class="cx" x="455" y="44" width="75" height="30"/><text x="492" y="64" text-anchor="middle" class="ts">KEK</text>
<rect class="cxa" x="290" y="40" width="100" height="40"/><text x="340" y="57" text-anchor="middle" class="ts">custodiantes</text><text x="340" y="71" text-anchor="middle" class="ts">componentes</text>
<line class="ln" x1="290" y1="60" x2="227" y2="60" marker-end="url(#seta)"/>
<line class="ln" x1="390" y1="60" x2="453" y2="60" marker-end="url(#seta)"/>
<text x="340" y="98" text-anchor="middle" class="ts">KCV igual dos dois lados:</text>
<text x="340" y="111" text-anchor="middle" class="ts">conferido por telefone ou papel</text>
<rect class="cx" x="60" y="100" width="165" height="34"/><text x="142" y="115" text-anchor="middle" class="ts">K4: chave sob LMK A</text><text x="142" y="128" text-anchor="middle" class="ts">→ chave sob KEK</text>
<rect class="cx" x="455" y="100" width="165" height="34"/><text x="537" y="115" text-anchor="middle" class="ts">K6: chave sob KEK</text><text x="537" y="128" text-anchor="middle" class="ts">→ chave sob LMK B</text>
<line class="lnd" x1="142" y1="134" x2="142" y2="190"/>
<line class="lnd" x1="142" y1="190" x2="537" y2="190" marker-end="url(#seta-d)"/>
<line class="lnd" x1="537" y1="190" x2="537" y2="136" marker-end="url(#seta-d)"/>
<rect class="cxa" x="250" y="176" width="180" height="28"/><text x="340" y="194" text-anchor="middle" class="ts">rede: key block sob a KEK</text>
<text x="340" y="228" text-anchor="middle" class="ts">nenhuma LMK sai de casa; a chave nunca existe em claro fora de um HSM</text>
<text x="340" y="244" text-anchor="middle" class="ts">o cabeçalho (uso, modo, exportabilidade) atravessa intacto</text>
</svg>
<figcaption>Figura 28.3 — Trocar uma chave com outra instituição. A KEK nasce por componentes nos dois lados; só o key block sob ela atravessa a rede.</figcaption>
</figure>

## 29. Fase 6 — tamper e ataques

Duas metades.

**Defesa:** XADC monitorando temperatura e tensão, disparando zeroize fora de
faixa. É o mecanismo de proteção contra falhas ambientais do FIPS nível 4
(seção 19), em versão mínima. Implementada, junto com a perda de lock do MMCM.
Ver `doc/fase6-notas.md`, que diz também o que ela não protege.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect x="60" y="20" width="580" height="35" fill="#f6e6e4"/><text x="70" y="42" class="ts td">acima do limite do datasheet: alarme</text>
<rect x="60" y="55" width="580" height="80" fill="#e5f0e3"/><text x="70" y="75" class="ts" fill="#2f5f2f">faixa de operação</text>
<rect x="60" y="135" width="580" height="35" fill="#f6e6e4"/><text x="70" y="157" class="ts td">abaixo do limite: alarme</text>
<line class="ln" x1="60" y1="170" x2="650" y2="170" marker-end="url(#seta)"/>
<text x="355" y="192" text-anchor="middle" class="ts">tempo</text>
<text x="40" y="95" class="ts" transform="rotate(-90 40 95)" text-anchor="middle">tensão ou temperatura</text>
<path d="M60,95 C120,90 160,100 220,94 S320,92 380,98 S440,105 470,110 S500,140 520,150" fill="none" stroke="#2d4f73" stroke-width="2"/>
<circle cx="508" cy="135" r="5" fill="#7a1f1f"/>
<line class="lnd" x1="508" y1="135" x2="560" y2="110" marker-end="url(#seta-d)"/>
<text x="565" y="100" class="ts td">o hardware retém;</text><text x="565" y="113" class="ts td">o firmware apaga e</text><text x="565" y="126" class="ts td">vai para TAMPERED</text>
</svg>
<figcaption>Figura 29.1 — O monitor ambiental. Tensão ou temperatura fora da faixa vira violação antes de virar falha explorável.</figcaption>
</figure>

**Ataque:** atacar o próprio HSM. Glitch de clock num bitstream separado,
observar o resultado sair errado, e então implementar contramedidas — dupla
execução, verificação de resultado (seção 17.4). O alvo é o AES e o MAC. Tudo
o que sai ao host é calculado duas vezes, e discordância vira erro grave.

Também: bitstream encriptado com chave em BBRAM, como confidencialidade de
firmware. O mecanismo existe, e a produção segue sem cifra, por decisão
explicada na seção 18.5. E o experimento de RO-PUF, documentado à parte, que mede na própria
placa **por que** um PUF de FPGA é ruim e por que o corretor de erros é
obrigatório.

## 30. Fase 7 — assimétrico

RSA-2048 e ECDSA sobre a curva P-256. O aprendizado de arquitetura de HSM está
nas fases 3 a 5. Mas há um gancho direto com a seção 17.1 — implementar RSA-CRT sem verificar a assinatura antes de
emitir é reproduzir o ataque Bellcore no próprio equipamento.

O equipamento tem o RSA-2048 completo: um multiplicador modular no fabric, a
exponenciação no firmware, a geração de chave, a assinatura por CRT em tempo
constante, a verificação, o KAT no POST e três comandos na porta host — `R0`,
`R2` e `R4`. Tem também o ECDSA P-256, sobre o mesmo multiplicador, com os
comandos `E0`, `E2` e `E4`.
As medidas e o estado de cada peça estão em `doc/fase7-notas.md`.

### Por que um HSM precisa de criptografia assimétrica

As funções das seções 25 a 29 são **simétricas**: quem cifra e quem
decifra têm a mesma chave. Isso funciona dentro de uma instituição, e entre
duas só depois de elas já terem uma chave em comum — foi o que a KEK da seção 28
resolveu, por componentes levados em mãos.

A criptografia assimétrica separa a chave em duas metades. A **privada** fica
dentro da fronteira e nunca sai; a **pública** pode ser publicada. O que uma
faz, só a outra confere. Disso saem dois serviços que a simétrica não presta:

- **assinatura:** só o dono da privada produz, qualquer um confere. Prova
  origem sem segredo compartilhado;
- **troca de chave:** duas partes que nunca se encontraram combinam uma chave
  simétrica por um canal aberto.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<text x="165" y="18" text-anchor="middle" class="tb">simétrica</text>
<rect class="cxa" x="20" y="40" width="90" height="40"/><text x="65" y="64" text-anchor="middle">A</text>
<rect class="cxa" x="220" y="40" width="90" height="40"/><text x="265" y="64" text-anchor="middle">B</text>
<rect class="cxd" x="40" y="95" width="50" height="24"/><text x="65" y="112" text-anchor="middle" class="ts">K</text>
<rect class="cxd" x="240" y="95" width="50" height="24"/><text x="265" y="112" text-anchor="middle" class="ts">K</text>
<line class="ln" x1="110" y1="60" x2="218" y2="60" marker-end="url(#seta)"/><text x="165" y="52" text-anchor="middle" class="ts">cifra ou MAC</text>
<text x="165" y="150" text-anchor="middle" class="ts">os dois têm a mesma chave:</text>
<text x="165" y="164" text-anchor="middle" class="ts">antes, ela precisou chegar aos dois</text>
<line class="lnt" x1="340" y1="10" x2="340" y2="190"/>
<text x="510" y="18" text-anchor="middle" class="tb">assimétrica</text>
<rect class="cxa" x="370" y="40" width="90" height="40"/><text x="415" y="64" text-anchor="middle">A</text>
<rect class="cxa" x="570" y="40" width="90" height="40"/><text x="615" y="64" text-anchor="middle">qualquer um</text>
<rect class="cxd" x="375" y="95" width="80" height="24"/><text x="415" y="112" text-anchor="middle" class="ts">privada</text>
<rect class="cxv" x="575" y="95" width="80" height="24"/><text x="615" y="112" text-anchor="middle" class="ts">pública</text>
<line class="ln" x1="460" y1="60" x2="568" y2="60" marker-end="url(#seta)"/><text x="515" y="52" text-anchor="middle" class="ts">assinatura</text>
<text x="510" y="150" text-anchor="middle" class="ts">só A assina; todos conferem</text>
<text x="510" y="164" text-anchor="middle" class="ts">a privada nunca sai da fronteira</text>
</svg>
<figcaption>Figura 30.1 — Simétrica e assimétrica. A assimétrica dispensa a chave em comum, e com isso dispensa os custodiantes viajando com envelopes.</figcaption>
</figure>

Num HSM de pagamento, os dois aparecem na carga remota de chaves: o terminal e
o centro de processamento trocam a chave de transporte por certificados e
assinaturas, sem custodiantes viajando com envelopes.

### RSA em uma página

Escolhem-se dois primos grandes, `p` e `q`, e calcula-se `n = p·q`. O expoente
público `e` é um número pequeno e ímpar; o privado `d` é o inverso de `e`
módulo `(p−1)(q−1)`. Chave pública: `(n, e)`. Chave privada: `d` — ou,
equivalentemente, `p` e `q`, porque com eles se calcula `d`.

```
    assinar:    s = m^d mod n          (só quem tem d)
    verificar:  s^e mod n == m ?       (qualquer um com n e e)
```

Com números de brinquedo: `p = 61`, `q = 53`, `n = 3233`, `e = 17`, `d = 2753`.
A assinatura de `m = 65` é `65^2753 mod 3233 = 588`, e quem verifica calcula
`588^17 mod 3233 = 65`. Confere.

A segurança vem de que, conhecendo só `n`, achar `p` e `q` é fatorar — e para
`n` de 2048 bits (617 dígitos decimais) não se conhece método viável. Toda a
operação, porém, é **uma única conta**: elevar um número de 2048 bits a outro e
reduzir módulo um terceiro. O resto desta seção é sobre como fazer essa conta
num FPGA pequeno, e fazê-la sem vazar `d`.

### Exponenciação: elevar sem calcular a potência

`m^d` com `d` de 2048 bits não se calcula multiplicando `m` por ele mesmo `d`
vezes — seriam `2^2048` multiplicações. Lê-se o expoente bit a bit, do mais
alto para o mais baixo:

```
    acc = 1
    para cada bit de d:
        acc = acc · acc mod n          (eleva ao quadrado: sempre)
        se o bit é 1:
            acc = acc · m mod n        (multiplica: só nos bits 1)
```

É o *square-and-multiply*. Para um expoente de 2048 bits são 2048 quadrados e,
em média, 1024 multiplicações — cerca de 3000 produtos modulares de 2048 bits.
Para verificar, com `e` pequeno, bastam algumas dezenas. É por isso que
verificar é barato e assinar é caro.

⚠ **O `se o bit é 1` é o ataque de temporização da seção 16.1.** Um bit 1
custa um produto a mais, e quem mede o tempo lê o expoente. Com `e`, que é
público, o desvio é inofensivo e o firmware o usa. Com `d`, a exponenciação
tem de fazer **o mesmo trabalho para todo bit** — é o que a escada de
Montgomery, que vem com a assinatura, garante.

### O problema da divisão, e a solução de Montgomery

Cada produto modular é uma multiplicação seguida de `mod n`, e `mod n` é o
resto de uma **divisão** de um número de 4096 bits por um de 2048. Divisão é a
operação mais cara que existe em hardware: não se faz em paralelo, e cada
dígito do quociente depende do anterior.

Montgomery (1985) trocou a divisão por `n` por uma divisão por **potência de
dois**, que em binário é só descartar bits. A ideia é trabalhar com os números
numa representação deslocada: em vez de `a`, guarda-se `a·R mod n`, com
`R = 2^2048`. O produto de Montgomery de duas representações calcula

```
    MontProd(x, y) = x · y · R⁻¹ mod n
```

e, se `x = a·R` e `y = b·R`, o resultado é `a·b·R` — a representação de `a·b`.
O fator `R` extra se cancela a cada produto, e o resultado já está pronto para o
próximo.

O truque está em como se divide por `R` sem errar. O produto `T = x·y` não é
múltiplo de `R`, mas pode-se somar a ele um múltiplo de `n` que torna os bits
baixos zero — e somar múltiplo de `n` não muda o valor módulo `n`. O múltiplo
certo é `m = T · n' mod R`, com `n' = −n⁻¹ mod R`, calculado uma vez por chave:

```
    T = x · y
    m = (T mod R) · n'  mod R        (só os bits baixos interessam)
    u = (T + m · n) / R              (divisão exata: descarta bits)
    se u ≥ n:  u = u − n             (a "subtração final")
```

Com números pequenos: `n = 97`, `R = 128`, `a = 20`, `b = 30`. As
representações são `20·128 mod 97 = 38` e `30·128 mod 97 = 57`;
`T = 38·57 = 2166`; `n' = 95`; `m = 2166·95 mod 128 = 74`;
`u = (2166 + 74·97) / 128 = 9344 / 128 = 73`. E de fato
`20·30·128 mod 97 = 73`: a representação de `a·b`, sem nenhuma divisão por 97.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="20" width="110" height="34"/><text x="65" y="41" text-anchor="middle" class="ts">a = 20 → 38</text>
<rect class="cxa" x="10" y="64" width="110" height="34"/><text x="65" y="85" text-anchor="middle" class="ts">b = 30 → 57</text>
<text x="65" y="116" text-anchor="middle" class="ts">x · R mod n</text>
<line class="ln" x1="120" y1="37" x2="158" y2="55" marker-end="url(#seta)"/>
<line class="ln" x1="120" y1="81" x2="158" y2="63" marker-end="url(#seta)"/>
<rect class="cx" x="160" y="40" width="110" height="40"/><text x="215" y="57" text-anchor="middle" class="ts">T = 38 · 57</text><text x="215" y="71" text-anchor="middle" class="ts tb">= 2166</text>
<line class="ln" x1="270" y1="60" x2="298" y2="60" marker-end="url(#seta)"/>
<rect class="cx" x="300" y="40" width="130" height="40"/><text x="365" y="57" text-anchor="middle" class="ts">m = T·n' mod 128</text><text x="365" y="71" text-anchor="middle" class="ts tb">= 74</text>
<line class="ln" x1="430" y1="60" x2="458" y2="60" marker-end="url(#seta)"/>
<rect class="cx" x="460" y="40" width="200" height="40"/><text x="560" y="57" text-anchor="middle" class="ts">T + m·n = 9344 = 73 · 128</text><text x="560" y="71" text-anchor="middle" class="ts">os 7 bits baixos são zero</text>
<line class="ln" x1="560" y1="80" x2="560" y2="118" marker-end="url(#seta)"/>
<rect class="cxv" x="470" y="120" width="180" height="40"/><text x="560" y="137" text-anchor="middle" class="ts">÷ 128: descarta 7 bits</text><text x="560" y="151" text-anchor="middle" class="tb">u = 73 = 600 · R mod 97</text>
<text x="230" y="140" text-anchor="middle" class="ts">a divisão por n = 97 nunca acontece:</text>
<text x="230" y="154" text-anchor="middle" class="ts">só a por R = 128, que é deslocar bits</text>
<text x="230" y="180" text-anchor="middle" class="ts">n' = −97⁻¹ mod 128 = 95, calculado uma vez por módulo</text>
</svg>
<figcaption>Figura 30.3 — Um produto de Montgomery com números pequenos. Somar um múltiplo certo de n zera os bits baixos, e a divisão vira deslocamento.</figcaption>
</figure>

Entrar na representação custa um produto por `R² mod n`, e sair, um produto
por `1`. Numa exponenciação de milhares de produtos, as duas conversões são
irrelevantes.

### Limbs, DSPs e o FIOS

Um número de 2048 bits não cabe em multiplicador nenhum. Ele é cortado em
**limbs** — 128 pedaços de 16 bits — e o produto vira uma multiplicação de
escola primária, limb contra limb, como se faz à mão com algarismos. Cada
multiplicação de 16 × 16 bits cabe num **DSP48E1**, o bloco multiplicador
dedicado do Artix-7.

A forma ingênua calcula `x·y` inteiro (4096 bits) e só depois reduz. O FIOS
(*Finely Integrated Operand Scanning*, Koç, Acar e Kaliski, 1996) intercala as
duas coisas: a cada limb de `x`, multiplica por `y`, soma o múltiplo de `n` que
zera o limb mais baixo e descarta esse limb. O acumulador nunca passa de
2048 bits mais um pouco, e a redução não custa uma segunda passada. Dois
multiplicadores trabalham juntos — um para `x·y`, outro para `m·n` —, e um
produto de 2048 bits leva cerca de `128²` ciclos: 18 433, ou 184 µs a
100 MHz.

O core usa **4** dos 90 DSP48E1. Paralelizar mais encurtaria o produto, mas o gargalo de um HSM didático não é a vazão de
assinaturas — e cada DSP a mais é área e rota no fabric apertado do XC7A35T.


<figure class="fig">
<svg viewBox="0 0 680 220" xmlns="http://www.w3.org/2000/svg">
<text x="164" y="22" text-anchor="middle" class="ts">limbs de y (16 bits cada)</text>
<text x="40" y="110" class="ts" transform="rotate(-90 40 110)" text-anchor="middle">limbs de x</text>
<rect x="60" y="30" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="86" y="30" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="112" y="30" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="138" y="30" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="164" y="30" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="190" y="30" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="216" y="30" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="242" y="30" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="60" y="50" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="86" y="50" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="112" y="50" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="138" y="50" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="164" y="50" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="190" y="50" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="216" y="50" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="242" y="50" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="60" y="70" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="86" y="70" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="112" y="70" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="138" y="70" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="164" y="70" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="190" y="70" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="216" y="70" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="242" y="70" width="24" height="18" fill="#e6edf5" stroke="#bbb"/><rect x="60" y="90" width="24" height="18" fill="#f6e6e4" stroke="#bbb"/><rect x="86" y="90" width="24" height="18" fill="#f6e6e4" stroke="#bbb"/><rect x="112" y="90" width="24" height="18" fill="#f6e6e4" stroke="#bbb"/><rect x="138" y="90" width="24" height="18" fill="#f6e6e4" stroke="#bbb"/><rect x="164" y="90" width="24" height="18" fill="#f6e6e4" stroke="#bbb"/><rect x="190" y="90" width="24" height="18" fill="#f6e6e4" stroke="#bbb"/><rect x="216" y="90" width="24" height="18" fill="#f6e6e4" stroke="#bbb"/><rect x="242" y="90" width="24" height="18" fill="#f6e6e4" stroke="#bbb"/><rect x="60" y="110" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="86" y="110" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="112" y="110" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="138" y="110" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="164" y="110" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="190" y="110" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="216" y="110" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="242" y="110" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="60" y="130" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="86" y="130" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="112" y="130" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="138" y="130" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="164" y="130" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="190" y="130" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="216" y="130" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="242" y="130" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="60" y="150" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="86" y="150" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="112" y="150" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="138" y="150" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="164" y="150" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="190" y="150" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="216" y="150" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="242" y="150" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="60" y="170" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="86" y="170" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="112" y="170" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="138" y="170" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="164" y="170" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="190" y="170" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="216" y="170" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/><rect x="242" y="170" width="24" height="18" fill="#f6f6f4" stroke="#bbb"/>
<text x="280" y="44" class="ts">linhas já feitas: o limb baixo foi zerado e descartado</text>
<text x="280" y="104" class="ts td">linha atual: x_i · y, mais m_i · n</text>
<text x="280" y="118" class="ts td">(dois DSP48E1: um para cada produto)</text>
<text x="280" y="160" class="ts">linhas por fazer</text>
<rect class="cxv" x="420" y="140" width="240" height="56"/>
<text x="540" y="160" text-anchor="middle" class="ts">o acumulador nunca passa de</text>
<text x="540" y="174" text-anchor="middle" class="ts">2048 bits e um pouco: a redução</text>
<text x="540" y="188" text-anchor="middle" class="ts">vem junto, sem segunda passada</text>
<text x="164" y="210" text-anchor="middle" class="ts">128 × 128 limbs: cerca de 18 433 ciclos, 184 µs</text>
</svg>
<figcaption>Figura 30.4 — O FIOS, limb por limb. A cada linha da multiplicação de escola, o múltiplo de n entra e o limb mais baixo sai.</figcaption>
</figure>

### Hardware faz o produto, firmware faz a política

O coprocessador faz **uma** coisa: `dst = a · b · R⁻¹ mod n`, sobre oito
registradores internos de 2048 bits numa Block RAM. Tudo o mais é firmware:
calcular `n'` e `R² mod n`, percorrer o expoente, montar e conferir o
enchimento. É a mesma divisão do TRNG na seção 25: o que custa ciclo fica no
hardware, e o que é decisão fica em C, onde se lê e se testa.

Três propriedades do core são de segurança, não de desempenho:

- **Tempo constante.** O algoritmo de livro faz a subtração final só quando
  `u ≥ n` — e esse desvio vaza informação sobre os operandos, o que já bastou
  para recuperar chaves RSA (Walter e Thompson, 2001; Schindler, 2000). Aqui
  a subtração **sempre** acontece, e um multiplexador escolhe entre `u` e
  `u − n` na hora de gravar. Todo produto do mesmo tamanho leva o mesmo número
  de ciclos, e o testbench cobra isso.
- **Módulo só de escrita.** Na verificação, `n` é público. Na assinatura com
  CRT, o módulo de cada metade é `p` ou `q` — a chave privada. O registrador do
  módulo não tem caminho de leitura pelo barramento.
- **Zeroização.** O `WIPE` global do coprocessador apaga as três memórias do
  core, interrompendo qualquer produto em curso.

O tamanho do produto é configurável, de 16 a 2048 bits, para que o mesmo core
sirva às metades de 1024 bits do CRT.

### PKCS#1 v1.5: o que se assina não é o hash

RSA puro é perigosamente maleável: se `s₁` assina `m₁` e `s₂` assina `m₂`,
então `s₁·s₂` assina `m₁·m₂`. E um hash de 256 bits, elevado a `e`, é um
número pequeno demais perto de `n`. Por isso o que se assina é o hash
**embrulhado** num bloco do tamanho de `n` (RFC 8017, seção 9.2):

```
    EM = 00 01 FF FF ... FF 00 || DigestInfo(SHA-256) || hash
```

O `DigestInfo` diz qual hash foi usado — sem ele, uma assinatura sobre um hash
fraco poderia passar por assinatura sobre um forte.


<figure class="fig">
<svg viewBox="0 0 680 120" xmlns="http://www.w3.org/2000/svg">
<rect class="cxc" x="20" y="30" width="20" height="36"/><text x="30" y="53" text-anchor="middle" class="tm">00</text>
<rect class="cxc" x="40" y="30" width="20" height="36"/><text x="50" y="53" text-anchor="middle" class="tm">01</text>
<rect class="cx" x="60" y="30" width="360" height="36"/><text x="240" y="53" text-anchor="middle" class="tm">FF FF FF … FF</text>
<rect class="cxc" x="420" y="30" width="20" height="36"/><text x="430" y="53" text-anchor="middle" class="tm">00</text>
<rect class="cxa" x="440" y="30" width="100" height="36"/><text x="490" y="53" text-anchor="middle" class="ts">DigestInfo</text>
<rect class="cxd" x="540" y="30" width="120" height="36"/><text x="600" y="53" text-anchor="middle" class="ts">hash SHA-256</text>
<g class="ts" text-anchor="middle"><text x="40" y="84">2</text><text x="240" y="84">202 bytes</text><text x="430" y="84">1</text><text x="490" y="84">19 bytes</text><text x="600" y="84">32 bytes</text></g>
<text x="340" y="110" text-anchor="middle" class="ts">256 bytes, o tamanho de n; a verificação monta este bloco e compara byte a byte</text>
<text x="340" y="18" text-anchor="middle" class="ts">EM, o que de fato é elevado a d</text>
</svg>
<figcaption>Figura 30.5 — O bloco PKCS#1 v1.5 de uma assinatura RSA-2048 com SHA-256.</figcaption>
</figure>

⚠ **A verificação reconstrói o `EM` inteiro e compara, em vez de interpretá-lo.**
Bleichenbacher (2006) mostrou que verificadores que *liam* o bloco — achavam o
`00`, pulavam os `FF`, extraíam o hash — aceitavam lixo depois do hash. O
defeito apareceu em bibliotecas de uso geral e está registrado como
CVE-2006-4339. Com
`e = 3`, isso deixava forjar assinaturas com uma raiz cúbica, sem chave
nenhuma. Quem monta o bloco esperado e compara byte a byte não tem parser para
enganar. A comparação acumula diferenças, como a de MAC da seção 16.1.

### O `R4`, o primeiro comando sem chave nenhuma

`R4` recebe `n`, `e`, o hash e a assinatura, e devolve **um bit**: `00`
confere, `01` não confere. Só dados públicos entram, e nada do dispositivo
sai. Fica em `OPERATIONAL` e entra no log, como os demais.

Parece estranho um HSM verificar algo que qualquer computador verifica. A
razão é a mesma da fronteira inteira: quando a decisão de aceitar uma chave
importada depende de uma assinatura conferir — que é o que acontece na carga
remota —, a verificação tem de ser feita **dentro** da fronteira, ou um host
comprometido diria "conferiu" sobre qualquer coisa.

Como todo resultado que sai ao host, a verificação roda duas vezes, e
discordância responde `91` (seção 29). Um pedido `R4` tem mais de 1100
caracteres. O limite de mensagem é de 3072 bytes: o maior pedido é o `R2`,
que leva o key block da chave RSA.

### O preço no boot

O POST tem o KAT de RSA: verificar uma assinatura oficial do CAVP e
**recusar** a mesma assinatura com um bit trocado. O vetor tem `e = 0x260445`,
de 22 bits, e cada verificação custa cerca de 9 ms. É a regra da seção 11:
cada propriedade que o dispositivo garante sobre si mesmo cobra milissegundos
de todo boot, para sempre.

### Assinar: o Teorema Chinês do Resto

Assinar é `s = m^d mod n`, com `d` de 2048 bits: cerca de 3000 produtos de
2048 bits. Quem tem a chave privada, porém, conhece `p` e `q` — e pode fazer a
conta **duas vezes pela metade**:

```
    sp = m^dp mod p        dp = d mod (p−1)
    sq = m^dq mod q        dq = d mod (q−1)
    h  = qinv · (sp − sq) mod p      qinv = q⁻¹ mod p
    s  = sq + h · q
```

O Teorema Chinês do Resto garante que só existe um número menor que `n` com
esses dois restos, e a última linha (a recombinação de Garner) o reconstrói.
Cada metade tem expoente e módulo de 1024 bits, e um produto de 1024 bits custa
um quarto do de 2048. Duas exponenciações de meio tamanho custam cerca de
**um quarto** de uma inteira.

Com os números de brinquedo da seção anterior (`p = 61`, `q = 53`,
`d = 2753`, `m = 65`): `dp = 53`, `dq = 49`, `qinv = 38`; `sp = 39`,
`sq = 5`, `h = 11` e `s = 5 + 11·53 = 588` — a mesma assinatura de antes.


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="80" width="80" height="40"/><text x="50" y="104" text-anchor="middle">m = 65</text>
<line class="ln" x1="90" y1="92" x2="148" y2="50" marker-end="url(#seta)"/>
<line class="ln" x1="90" y1="108" x2="148" y2="150" marker-end="url(#seta)"/>
<rect class="cxd" x="150" y="30" width="170" height="40"/><text x="235" y="47" text-anchor="middle" class="ts">sp = 65⁵³ mod 61</text><text x="235" y="61" text-anchor="middle" class="tb">= 39</text>
<rect class="cxd" x="150" y="130" width="170" height="40"/><text x="235" y="147" text-anchor="middle" class="ts">sq = 65⁴⁹ mod 53</text><text x="235" y="161" text-anchor="middle" class="tb">= 5</text>
<text x="235" y="96" text-anchor="middle" class="ts">duas metades de 1024 bits:</text><text x="235" y="110" text-anchor="middle" class="ts">um quarto do custo</text>
<line class="ln" x1="320" y1="50" x2="378" y2="92" marker-end="url(#seta)"/>
<line class="ln" x1="320" y1="150" x2="378" y2="108" marker-end="url(#seta)"/>
<rect class="cx" x="380" y="75" width="130" height="50"/><text x="445" y="94" text-anchor="middle" class="ts">h = 38·(39 − 5) mod 61</text><text x="445" y="108" text-anchor="middle" class="ts">= 11; s = 5 + 11·53</text><text x="445" y="121" text-anchor="middle" class="tb">= 588</text>
<line class="ln" x1="510" y1="100" x2="538" y2="100" marker-end="url(#seta)"/>
<rect class="cxv" x="540" y="70" width="130" height="60"/><text x="605" y="90" text-anchor="middle" class="ts">confere</text><text x="605" y="104" text-anchor="middle" class="ts">588¹⁷ mod 3233</text><text x="605" y="118" text-anchor="middle" class="tb">= 65 ✓</text>
<text x="605" y="152" text-anchor="middle" class="ts td">não conferiu: nada sai,</text><text x="605" y="166" text-anchor="middle" class="ts td">91, erro grave</text>
</svg>
<figcaption>Figura 30.6 — A assinatura pelo Teorema Chinês do Resto, com os números de brinquedo. A conferência no fim fecha o ataque Bellcore.</figcaption>
</figure>

Por isso a chave privada deste dispositivo **não guarda `d`**: guarda
`p, q, dp, dq, qinv` e o `e`. E por isso o ataque Bellcore (seção 17.1) é
assunto desta fase: se uma das metades sair errada, `s` fica certo módulo um
primo e errado módulo o outro, e `mdc(s^e − m, n)` entrega a fatoração. A
contramedida: **toda assinatura é verificada com `e` antes
de sair**. Se não conferir, nada sai, o comando responde `91` e o erro grave
fica marcado até o próximo boot, como a dupla execução da Fase 6.

### A escada de Montgomery

O *square-and-multiply* da seção anterior faz um produto a mais em cada bit 1,
e com `dp` e `dq` isso é o ataque de temporização. A **escada de Montgomery**
(o nome é do mesmo Montgomery, mas é outra ideia) mantém dois valores, `X` e
`Y`, sempre com `Y = X · m`, e faz **exatamente um produto e um quadrado por
bit**:

```
    bit 0:   Y = X · Y     X = X²
    bit 1:   X = X · Y     Y = Y²
```

O bit decide só **quais registradores** entram em cada operação — e o
coprocessador leva o mesmo número de ciclos qualquer que seja o registrador.
No firmware, a escolha é feita por máscara, sem `if`. O expoente é percorrido
inteiro, zeros à esquerda inclusive, então o tempo depende só do tamanho dele.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="30" class="tb">square-and-multiply</text>
<text x="10" y="55" class="ts">o tempo varia</text>
<rect x="90" y="40" width="28" height="22" fill="#2d4f73"/><text x="104" y="55" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="120" y="40" width="28" height="22" fill="#7a1f1f"/><text x="134" y="55" text-anchor="middle" class="ts" fill="#fff">M</text><rect x="156" y="40" width="28" height="22" fill="#2d4f73"/><text x="170" y="55" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="192" y="40" width="28" height="22" fill="#2d4f73"/><text x="206" y="55" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="222" y="40" width="28" height="22" fill="#7a1f1f"/><text x="236" y="55" text-anchor="middle" class="ts" fill="#fff">M</text><rect x="258" y="40" width="28" height="22" fill="#2d4f73"/><text x="272" y="55" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="288" y="40" width="28" height="22" fill="#7a1f1f"/><text x="302" y="55" text-anchor="middle" class="ts" fill="#fff">M</text><rect x="324" y="40" width="28" height="22" fill="#2d4f73"/><text x="338" y="55" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="360" y="40" width="28" height="22" fill="#2d4f73"/><text x="374" y="55" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="396" y="40" width="28" height="22" fill="#2d4f73"/><text x="410" y="55" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="426" y="40" width="28" height="22" fill="#7a1f1f"/><text x="440" y="55" text-anchor="middle" class="ts" fill="#fff">M</text>
<text x="10" y="110" class="tb">escada de Montgomery</text>
<text x="10" y="135" class="ts">o mesmo trabalho</text>
<rect x="90" y="120" width="28" height="22" fill="#2d4f73"/><text x="104" y="135" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="120" y="120" width="28" height="22" fill="#2f5f2f"/><text x="134" y="135" text-anchor="middle" class="ts" fill="#fff">P</text><text x="119" y="160" text-anchor="middle" class="tb">1</text><rect x="156" y="120" width="28" height="22" fill="#2d4f73"/><text x="170" y="135" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="186" y="120" width="28" height="22" fill="#2f5f2f"/><text x="200" y="135" text-anchor="middle" class="ts" fill="#fff">P</text><text x="185" y="160" text-anchor="middle" class="tb">0</text><rect x="222" y="120" width="28" height="22" fill="#2d4f73"/><text x="236" y="135" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="252" y="120" width="28" height="22" fill="#2f5f2f"/><text x="266" y="135" text-anchor="middle" class="ts" fill="#fff">P</text><text x="251" y="160" text-anchor="middle" class="tb">1</text><rect x="288" y="120" width="28" height="22" fill="#2d4f73"/><text x="302" y="135" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="318" y="120" width="28" height="22" fill="#2f5f2f"/><text x="332" y="135" text-anchor="middle" class="ts" fill="#fff">P</text><text x="317" y="160" text-anchor="middle" class="tb">1</text><rect x="354" y="120" width="28" height="22" fill="#2d4f73"/><text x="368" y="135" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="384" y="120" width="28" height="22" fill="#2f5f2f"/><text x="398" y="135" text-anchor="middle" class="ts" fill="#fff">P</text><text x="383" y="160" text-anchor="middle" class="tb">0</text><rect x="420" y="120" width="28" height="22" fill="#2d4f73"/><text x="434" y="135" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="450" y="120" width="28" height="22" fill="#2f5f2f"/><text x="464" y="135" text-anchor="middle" class="ts" fill="#fff">P</text><text x="449" y="160" text-anchor="middle" class="tb">0</text><rect x="486" y="120" width="28" height="22" fill="#2d4f73"/><text x="500" y="135" text-anchor="middle" class="ts" fill="#fff">Q</text><rect x="516" y="120" width="28" height="22" fill="#2f5f2f"/><text x="530" y="135" text-anchor="middle" class="ts" fill="#fff">P</text><text x="515" y="160" text-anchor="middle" class="tb">1</text>
<text x="10" y="160" class="ts">bits do expoente</text>
<text x="340" y="190" text-anchor="middle" class="ts">Q = quadrado, M = multiplicação, P = produto: na escada, cada bit custa um quadrado e um produto, sempre</text>
</svg>
<figcaption>Figura 30.2 — O mesmo expoente, 1011001, pelos dois métodos. O primeiro desenha os bits no tempo; o segundo, não.</figcaption>
</figure>

### Tudo no coprocessador, inclusive o que não é modular

As contas da assinatura que não são exponenciação também vão para o hardware:

- **reduzir `m` módulo `p`**: `m` tem 2048 bits e `p`, 1024. Partindo
  `m = hi·R + lo`, a representação de Montgomery de `m mod p` é
  `Mont(hi, R³) + Mont(lo, R²)` — dois produtos e uma soma, sem divisão;
- **`h · q` e `n = p · q`**, que são produtos comuns de inteiros, usam o
  módulo `M = 2²⁰⁴⁸ − 1`. Como `R = 2²⁰⁴⁸` é congruente a 1 módulo `M`, o
  produto de Montgomery `a·b·R⁻¹ mod M` é o próprio `a·b` — e, sendo
  `a·b < M`, é o inteiro. O mesmo core que faz a exponenciação faz a
  multiplicação comum.

Em C sobram somas, subtrações, comparações e o enchimento PKCS#1.

### Gerar a chave: procurar primos

Gerar um par RSA é achar dois primos de 1024 bits ao acaso. Não há fórmula
para isso: sorteia-se um número e testa-se. Perto de `2¹⁰²⁴`, um número ímpar
ao acaso é primo com probabilidade de cerca de 1 em 355, então a busca leva
centenas de sorteios.

O dispositivo segue a FIPS 186-5, Apêndice A.1.3 (*primos prováveis*):

1. sorteia 1024 bits do DRBG, liga os dois bits altos (o que garante
   `p ≥ √2 · 2¹⁰²³`, e portanto `n` com 2048 bits exatos) e o bit baixo;
2. descarta o candidato se ele for divisível por algum ímpar até 1023 — conta
   barata, em C, que elimina mais de 80% dos candidatos antes de qualquer
   exponenciação;
3. exige `mdc(p − 1, e) = 1`, senão `e` não teria inverso;
4. aplica o **teste de Miller-Rabin** com 5 bases sorteadas;
5. para `q`, exige ainda `|p − q| > 2⁹²⁴`: primos próximos demais tornam `n`
   fatorável pelo método de Fermat.

O **Miller-Rabin** parte do pequeno teorema de Fermat: se `w` é primo, então
`b^(w−1) ≡ 1 (mod w)`. Escrevendo `w − 1 = 2^a · m`, calcula-se `b^m` e
eleva-se ao quadrado até `a` vezes. Num primo, a sequência termina em 1, e o
valor antes do primeiro 1 é sempre `w − 1`. Um composto quase sempre quebra
essa regra. Exemplo clássico: `561 = 3·11·17` engana o teste de Fermat com
qualquer base, mas não o de Miller-Rabin. Com `b = 2` e
`560 = 2⁴ · 35`, a sequência é `263, 166, 67, 1` — chega a 1 sem passar por
560, e 561 é declarado composto.

Cada rodada deixa passar um composto com probabilidade de no máximo 1/4 (na
prática, muito menos). A Tabela B.1 da FIPS 186-5 fixa **5 rodadas** para
primos de 1024 bits, para um erro de 2⁻¹¹², que é a força de segurança do
RSA-2048. Cada rodada é uma exponenciação de 1024 bits na escada — no
coprocessador.

Achados `p` e `q`, o resto vem deles:

- `dp = e⁻¹ mod (p − 1)`, calculado sem dividir número grande por número
  grande: com `k = −(p − 1)⁻¹ mod e`, o número `1 + k(p − 1)` é múltiplo de
  `e`, e o quociente é `dp`. Como `e = 65537` é pequeno, tudo isso é conta de
  32 bits;
- `qinv = q^(p−2) mod p`, pelo pequeno teorema de Fermat — uma exponenciação,
  na escada, porque `p` é segredo;
- `n = p · q`, no coprocessador.

Antes de sair, o par novo passa por um **teste de consistência**: o
dispositivo assina com ele e verifica a assinatura. É exigência da FIPS 140-3
para geração de chave assimétrica, e pega na hora um primo errado ou um
`qinv` mal calculado.


<figure class="fig">
<svg viewBox="0 0 680 220" xmlns="http://www.w3.org/2000/svg">
<polygon points="40,20 640,20 520,80 160,80" fill="#e6edf5" stroke="#2d4f73"/>
<text x="340" y="44" text-anchor="middle" class="tb">cerca de 355 candidatos ímpares</text>
<text x="340" y="62" text-anchor="middle" class="ts">de 1024 bits, do DRBG, para achar um primo</text>
<polygon points="160,84 520,84 440,140 240,140" fill="#f6f6f4" stroke="#1a1a1a"/>
<text x="340" y="106" text-anchor="middle" class="tb">divisão pelos ímpares até 1023</text>
<text x="340" y="124" text-anchor="middle" class="ts">em C; elimina 84%: sobram cerca de 57</text>
<polygon points="240,144 440,144 400,196 280,196" fill="#f6e6e4" stroke="#7a1f1f"/>
<text x="340" y="164" text-anchor="middle" class="tb">Miller-Rabin</text>
<text x="340" y="180" text-anchor="middle" class="ts">5 rodadas, no coprocessador</text>
<rect class="cxv" x="300" y="200" width="80" height="18"/><text x="340" y="213" text-anchor="middle" class="ts tb">1 primo</text>
<text x="560" y="110" class="ts">mdc(p − 1, e) = 1</text>
<text x="560" y="124" class="ts">e, para q, |p − q| > 2⁹²⁴</text>
<text x="20" y="170" class="ts">um composto quase sempre</text>
<text x="20" y="184" class="ts">cai na 1ª rodada</text>
</svg>
<figcaption>Figura 30.7 — O funil da busca de primos. A conta barata em C descarta a maior parte antes da exponenciação cara.</figcaption>
</figure>

### A chave privada no key block

A chave sai como **key block X9.143 sob a LMK** e fica com o host, como as
chaves AES da porta host (seção 28). O cabeçalho usa os códigos da norma:
uso `S0` (par assimétrico de assinatura), algoritmo `R` (RSA), modo `S`
(só assinar). As duas implementações do formato — em C e em Python — recusam
qualquer outra combinação para `R`.

**O conteúdo do bloco é a chave em PKCS#8**, a codificação pública de chave
privada (RFC 5958). É o formato que o `openssl` e as bibliotecas de
criptografia leem e escrevem. Quem abre o bloco, com a chave de proteção,
tem nas mãos uma chave que qualquer ferramenta entende.

O PKCS#8 é escrito em **DER**, a codificação binária do ASN.1. Cada elemento
tem três partes: uma **etiqueta** que diz o tipo, o **comprimento**, e o
**valor**. Os elementos se aninham:

```
    30 82 04 BE                    SEQUENCE, 1214 bytes     (o PKCS#8)
       02 01 00                       INTEGER 0             versão
       30 0D                          SEQUENCE              o algoritmo:
          06 09 2A 86 48 86 F7 0D 01 01 01    OID           rsaEncryption
          05 00                               NULL
       04 82 04 A8                    OCTET STRING, 1192 bytes
          30 82 04 A4                    SEQUENCE           a chave RSA
             02 01 00                       versão: dois primos
             02 82 01 01 00 ...             n      (257 bytes: 00 e o módulo)
             02 03 01 00 01                 e      65537
             02 82 01 01 00 ...             d
             02 81 81 00 ...                p
             02 81 81 00 ...                q
             02 81 81 00 ...                dp
             02 81 80 ...                   dq
             02 81 80 ...                   qinv
```

Três detalhes do DER aparecem no exemplo:

- **O comprimento tem forma curta e forma longa.** Até 127, é um byte. Acima
  disso, o primeiro byte diz quantos bytes de comprimento vêm depois: `81`
  anuncia um, `82` anuncia dois.
- **Um inteiro positivo com o bit alto ligado ganha um `00` na frente**,
  para não ser lido como negativo. Por isso `n` ocupa 257 bytes, e não 256.
  Como isso depende do valor, o tamanho total varia de chave para chave, em
  alguns bytes.
- **Só existe uma forma certa de escrever cada valor.** É a diferença entre
  o DER e o BER, a variante permissiva. Um leitor de DER recusa comprimento
  em forma longa sem necessidade, zeros sobrando e lixo depois do fim.

O leitor do equipamento é estrito, e de propósito: aceita exatamente essa
estrutura, com módulo de 2048 bits e primos de 1024, e recusa todo o resto.
Um leitor que "tolera" variações é a origem de uma família de ataques
(seção sobre o PKCS#1 v1.5, acima).

O PKCS#8 leva `n` e `d`, que o equipamento não usa: ele assina pelo Teorema
Chinês do Resto, com `p`, `q`, `dp`, `dq` e `qinv`. Ao **gerar** uma chave,
ele calcula `d` para o bloco ficar completo. Ao **receber** uma chave, ele
lê os cinco números de que precisa e recalcula `n` como `p · q`.

⚠ **A norma do key block é paga, e este projeto não confirmou que é o PKCS#8
que ela manda usar para chave assimétrica.** O PKCS#8 foi escolhido por ser
público e por dar interoperabilidade com as ferramentas comuns. Não é
alegação de conformidade com a X9.143 nesse ponto.

O bloco tem até 2512 caracteres, e a chave aberta vive numa área própria do
key store **só durante o comando** — nunca num slot, nunca na flash. O
despachante a apaga no fim de todo comando, como faz com o slot efêmero.

### Os comandos

| Pedido | Resposta | Entrada | Saída |
|---|---|---|---|
| `R0` gerar par | `R1` | exportabilidade(1) | key block · n(512) · e(8) |
| `R2` assinar | `R3` | key block · digest(64) | assinatura(512) |
| `R4` verificar | `R5` | n(512) · e(8) · digest(64) · assinatura(512) | — |

`R2` com um key block AES responde `11`: é a confusão de tipo de chave (seção
15.1), recusada como nas chaves simétricas. Um bloco adulterado responde `10`,
o mesmo código de qualquer outro bloco inválido.

### Curvas elípticas: outro problema difícil

O RSA apoia-se na fatoração. As curvas elípticas apoiam-se em outro problema,
e ele permite chaves muito menores: uma chave de 256 bits numa curva tem a
força de um RSA de 3072 bits.

Uma curva elíptica, para este uso, é o conjunto dos pares `(x, y)` que
satisfazem uma equação como

```
    y² = x³ + a·x + b        (contas módulo um primo p)
```

mais um ponto especial, o **ponto no infinito**, que faz o papel do zero.
Os números `x` e `y` não são reais: são inteiros de `0` a `p − 1`, e toda
conta termina com `mod p`. O desenho da curva como uma linha suave serve
para entender a regra. O que o equipamento calcula é uma nuvem de pontos
isolados.

O nome engana. Uma curva elíptica não é uma elipse: o nome vem das integrais
que medem o comprimento de arco da elipse, onde essas equações apareceram
primeiro.

### Somar pontos

Os pontos da curva podem ser **somados**, e a soma de dois pontos da curva é
outro ponto da curva. A regra é geométrica:

1. Trace a reta que passa por `P` e por `Q`.
2. A reta corta a curva em um terceiro ponto.
3. Espelhe esse ponto no eixo `x`. O resultado é `P + Q`.


<figure class="fig">
<svg viewBox="0 0 680 260" xmlns="http://www.w3.org/2000/svg">
<line class="grade" x1="90" y1="130" x2="440" y2="130"/>
<line class="grade" x1="250" y1="15" x2="250" y2="245"/>
<path d="M417.4,221.7 L414.9,219.3 L412.4,216.9 L410.0,214.6 L407.5,212.3 L405.0,210.0 L402.5,207.8 L400.0,205.5 L397.5,203.3 L395.1,201.2 L392.6,199.0 L390.1,196.9 L387.6,194.7 L385.1,192.7 L382.7,190.6 L380.2,188.6 L377.7,186.6 L375.2,184.6 L372.7,182.7 L370.2,180.8 L367.8,178.9 L365.3,177.1 L362.8,175.3 L360.3,173.6 L357.8,171.9 L355.4,170.2 L352.9,168.6 L350.4,167.1 L347.9,165.6 L345.4,164.2 L342.9,162.8 L340.5,161.6 L338.0,160.4 L335.5,159.2 L333.0,158.2 L330.5,157.3 L328.0,156.5 L325.6,155.8 L323.1,155.2 L320.6,154.7 L318.1,154.4 L315.6,154.1 L313.2,154.0 L310.7,154.0 L308.2,154.1 L305.7,154.4 L303.2,154.7 L300.7,155.1 L298.3,155.6 L295.8,156.2 L293.3,156.8 L290.8,157.5 L288.3,158.2 L285.9,159.0 L283.4,159.8 L280.9,160.6 L278.4,161.5 L275.9,162.4 L273.4,163.3 L271.0,164.1 L268.5,165.0 L266.0,165.9 L263.5,166.8 L261.0,167.7 L258.6,168.6 L256.1,169.5 L253.6,170.3 L251.1,171.2 L248.6,172.0 L246.1,172.8 L243.7,173.6 L241.2,174.4 L238.7,175.2 L236.2,175.9 L233.7,176.6 L231.3,177.3 L228.8,177.9 L226.3,178.5 L223.8,179.1 L221.3,179.7 L218.8,180.2 L216.4,180.7 L213.9,181.2 L211.4,181.6 L208.9,182.0 L206.4,182.4 L204.0,182.7 L201.5,183.0 L199.0,183.2 L196.5,183.4 L194.0,183.5 L191.5,183.6 L189.1,183.7 L186.6,183.7 L184.1,183.6 L181.6,183.5 L179.1,183.3 L176.6,183.1 L174.2,182.8 L171.7,182.4 L169.2,182.0 L166.7,181.5 L164.2,180.9 L161.8,180.3 L159.3,179.5 L156.8,178.7 L154.3,177.7 L151.8,176.7 L149.3,175.5 L146.9,174.2 L144.4,172.7 L141.9,171.1 L139.4,169.3 L136.9,167.2 L134.5,164.9 L132.0,162.3 L129.5,159.3 L127.0,155.7 L124.5,151.2 L122.0,145.2 L119.6,130.0 L119.6,130.0 L122.0,114.8 L124.5,108.8 L127.0,104.3 L129.5,100.7 L132.0,97.7 L134.5,95.1 L136.9,92.8 L139.4,90.7 L141.9,88.9 L144.4,87.3 L146.9,85.8 L149.3,84.5 L151.8,83.3 L154.3,82.3 L156.8,81.3 L159.3,80.5 L161.8,79.7 L164.2,79.1 L166.7,78.5 L169.2,78.0 L171.7,77.6 L174.2,77.2 L176.6,76.9 L179.1,76.7 L181.6,76.5 L184.1,76.4 L186.6,76.3 L189.1,76.3 L191.5,76.4 L194.0,76.5 L196.5,76.6 L199.0,76.8 L201.5,77.0 L204.0,77.3 L206.4,77.6 L208.9,78.0 L211.4,78.4 L213.9,78.8 L216.4,79.3 L218.8,79.8 L221.3,80.3 L223.8,80.9 L226.3,81.5 L228.8,82.1 L231.3,82.7 L233.7,83.4 L236.2,84.1 L238.7,84.8 L241.2,85.6 L243.7,86.4 L246.1,87.2 L248.6,88.0 L251.1,88.8 L253.6,89.7 L256.1,90.5 L258.6,91.4 L261.0,92.3 L263.5,93.2 L266.0,94.1 L268.5,95.0 L271.0,95.9 L273.4,96.7 L275.9,97.6 L278.4,98.5 L280.9,99.4 L283.4,100.2 L285.9,101.0 L288.3,101.8 L290.8,102.5 L293.3,103.2 L295.8,103.8 L298.3,104.4 L300.7,104.9 L303.2,105.3 L305.7,105.6 L308.2,105.9 L310.7,106.0 L313.2,106.0 L315.6,105.9 L318.1,105.6 L320.6,105.3 L323.1,104.8 L325.6,104.2 L328.0,103.5 L330.5,102.7 L333.0,101.8 L335.5,100.8 L338.0,99.6 L340.5,98.4 L342.9,97.2 L345.4,95.8 L347.9,94.4 L350.4,92.9 L352.9,91.4 L355.4,89.8 L357.8,88.1 L360.3,86.4 L362.8,84.7 L365.3,82.9 L367.8,81.1 L370.2,79.2 L372.7,77.3 L375.2,75.4 L377.7,73.4 L380.2,71.4 L382.7,69.4 L385.1,67.3 L387.6,65.3 L390.1,63.1 L392.6,61.0 L395.1,58.8 L397.5,56.7 L400.0,54.5 L402.5,52.2 L405.0,50.0 L407.5,47.7 L410.0,45.4 L412.4,43.1 L414.9,40.7 L417.4,38.3" fill="none" stroke="#2d4f73" stroke-width="2"/>
<line x1="101.2" y1="64.7" x2="411.2" y2="106.3" stroke="#555" stroke-width="1.2"/>
<line x1="226.5" y1="81.5" x2="226.5" y2="178.5" stroke="#7a1f1f" stroke-dasharray="4 3"/>
<circle cx="188.0" cy="76.3" r="5" fill="#1a1a1a"/><text x="180.0" y="68.3" text-anchor="end" class="tb">P</text>
<circle cx="343.0" cy="97.1" r="5" fill="#1a1a1a"/><text x="351.0" y="113.1" class="tb">Q</text>
<circle cx="226.5" cy="81.5" r="5" fill="#555"/><text x="230.5" y="71.5" class="ts">3º ponto</text>
<circle cx="226.5" cy="178.5" r="6" fill="#7a1f1f"/><text x="236.5" y="182.5" class="tb td">P + Q</text>
<text x="470" y="60" class="ts">1. a reta por P e Q</text>
<text x="470" y="76" class="ts">2. corta a curva num 3º ponto</text>
<text x="470" y="92" class="ts">3. o espelho no eixo x é P + Q</text>
<text x="470" y="170" class="ts">sobre os reais, para ver a regra;</text>
<text x="470" y="184" class="ts">no equipamento, as mesmas fórmulas</text>
<text x="470" y="198" class="ts">rodam módulo p</text>
</svg>
<figcaption>Figura 30.9 — A soma de pontos, desenhada sobre os números reais, na curva y² = x³ − 3x + 3.</figcaption>
</figure>

Para somar um ponto a ele mesmo (**dobrar**), a reta é a tangente à curva
naquele ponto. Escrita em fórmulas, a regra só usa somas, produtos e **uma
divisão** módulo `p`:

```
    somar P + Q:      λ = (yQ − yP) / (xQ − xP)
    dobrar P:         λ = (3·xP² + a) / (2·yP)

    x = λ² − xP − xQ                (na dobra, xQ = xP)
    y = λ·(xP − x) − yP
```

O `λ` é a inclinação da reta. Dividir módulo `p` é multiplicar pelo inverso:
`1/14 mod 17 = 11`, porque `14 · 11 = 154 = 9·17 + 1`.

Dois casos ficam fora das fórmulas:

- O **oposto** de `P = (x, y)` é `−P = (x, −y)`. A reta por `P` e `−P` é
  vertical e não corta a curva de novo. Por definição, `P + (−P)` é o ponto
  no infinito.
- O ponto no infinito é o zero: `P + 0 = P`.

Com essas regras, os pontos formam um **grupo**: a soma é associativa, tem
zero e todo ponto tem oposto. A ordem das parcelas não importa.

### Uma curva de brinquedo

A curva `y² = x³ − 3x + 3` módulo `17` tem 22 pontos, mais o ponto no
infinito: 23 elementos. Parta de `G = (1, 1)` e some `G` repetidas vezes:

```
     1G = ( 1,  1)     7G = ( 4, 15)    13G = ( 8,  7)    19G = ( 3,  2)
     2G = (15, 16)     8G = (13, 11)    14G = ( 7,  6)    20G = ( 9, 12)
     3G = ( 9,  5)     9G = ( 7, 11)    15G = (13,  6)    21G = (15,  1)
     4G = ( 3, 15)    10G = ( 8, 10)    16G = ( 4,  2)    22G = ( 1, 16)
     5G = (11, 14)    11G = (10,  2)    17G = (14,  6)    23G = infinito
     6G = (14, 11)    12G = (10, 15)    18G = (11,  3)
```

Uma soma, passo a passo: `3G = 2G + G`, com `2G = (15, 16)` e `G = (1, 1)`.

```
    λ = (1 − 16) / (1 − 15) = 15 / 14 = 15 · 11 mod 17 = 12
    x = 12² − 15 − 1 = 128 mod 17 = 9
    y = 12 · (15 − 9) − 16 = 56 mod 17 = 5            3G = (9, 5)
```

E uma dobra: `4G = 2 · (2G)`.

```
    λ = (3 · 15² − 3) / (2 · 16) = 9 / 15 = 9 · 8 mod 17 = 4
    x = 4² − 15 − 15 = −14 mod 17 = 3
    y = 4 · (15 − 3) − 16 = 32 mod 17 = 15            4G = (3, 15)
```

Três coisas aparecem na tabela:

- **A sequência fecha.** `23G` é o ponto no infinito, e `24G` volta a `G`. O
  número 23 é a **ordem** de `G`. Os múltiplos de `G` só dependem do
  multiplicador módulo 23. É por isso que as contas de ECDSA com escalares
  são feitas módulo a ordem, e não módulo `p`.
- **A tabela é simétrica.** `22G = (1, 16)` é o oposto de `G = (1, 1)`,
  porque `16 = −1 mod 17`. Em geral, `(23 − k)·G = −(k·G)`.
- **Não há padrão.** `5G` não fica perto de `4G`. Dado o ponto `(8, 7)`, a
  única forma de achar o `13` é procurar.


<figure class="fig">
<svg viewBox="0 0 680 280" xmlns="http://www.w3.org/2000/svg">
<line class="grade" x1="60" y1="250" x2="60" y2="42"/><line class="grade" x1="60" y1="250" x2="540" y2="250"/><line class="grade" x1="90" y1="250" x2="90" y2="42"/><line class="grade" x1="60" y1="237" x2="540" y2="237"/><line class="grade" x1="120" y1="250" x2="120" y2="42"/><line class="grade" x1="60" y1="224" x2="540" y2="224"/><line class="grade" x1="150" y1="250" x2="150" y2="42"/><line class="grade" x1="60" y1="211" x2="540" y2="211"/><line class="grade" x1="180" y1="250" x2="180" y2="42"/><line class="grade" x1="60" y1="198" x2="540" y2="198"/><line class="grade" x1="210" y1="250" x2="210" y2="42"/><line class="grade" x1="60" y1="185" x2="540" y2="185"/><line class="grade" x1="240" y1="250" x2="240" y2="42"/><line class="grade" x1="60" y1="172" x2="540" y2="172"/><line class="grade" x1="270" y1="250" x2="270" y2="42"/><line class="grade" x1="60" y1="159" x2="540" y2="159"/><line class="grade" x1="300" y1="250" x2="300" y2="42"/><line class="grade" x1="60" y1="146" x2="540" y2="146"/><line class="grade" x1="330" y1="250" x2="330" y2="42"/><line class="grade" x1="60" y1="133" x2="540" y2="133"/><line class="grade" x1="360" y1="250" x2="360" y2="42"/><line class="grade" x1="60" y1="120" x2="540" y2="120"/><line class="grade" x1="390" y1="250" x2="390" y2="42"/><line class="grade" x1="60" y1="107" x2="540" y2="107"/><line class="grade" x1="420" y1="250" x2="420" y2="42"/><line class="grade" x1="60" y1="94" x2="540" y2="94"/><line class="grade" x1="450" y1="250" x2="450" y2="42"/><line class="grade" x1="60" y1="81" x2="540" y2="81"/><line class="grade" x1="480" y1="250" x2="480" y2="42"/><line class="grade" x1="60" y1="68" x2="540" y2="68"/><line class="grade" x1="510" y1="250" x2="510" y2="42"/><line class="grade" x1="60" y1="55" x2="540" y2="55"/><line class="grade" x1="540" y1="250" x2="540" y2="42"/><line class="grade" x1="60" y1="42" x2="540" y2="42"/><text x="60" y="266" text-anchor="middle" class="ts">0</text><text x="52" y="254" text-anchor="end" class="ts">0</text><text x="180" y="266" text-anchor="middle" class="ts">4</text><text x="52" y="202" text-anchor="end" class="ts">4</text><text x="300" y="266" text-anchor="middle" class="ts">8</text><text x="52" y="150" text-anchor="end" class="ts">8</text><text x="420" y="266" text-anchor="middle" class="ts">12</text><text x="52" y="98" text-anchor="end" class="ts">12</text><text x="540" y="266" text-anchor="middle" class="ts">16</text><text x="52" y="46" text-anchor="end" class="ts">16</text><circle cx="90" cy="237" r="4.5" fill="#2d4f73"/><circle cx="90" cy="42" r="4.5" fill="#2d4f73"/><circle cx="150" cy="224" r="4.5" fill="#2d4f73"/><circle cx="150" cy="55" r="4.5" fill="#2d4f73"/><circle cx="180" cy="224" r="4.5" fill="#2d4f73"/><circle cx="180" cy="55" r="4.5" fill="#2d4f73"/><circle cx="270" cy="172" r="4.5" fill="#2d4f73"/><circle cx="270" cy="107" r="4.5" fill="#2d4f73"/><circle cx="300" cy="159" r="4.5" fill="#2d4f73"/><circle cx="300" cy="120" r="4.5" fill="#2d4f73"/><circle cx="330" cy="185" r="4.5" fill="#2d4f73"/><circle cx="330" cy="94" r="4.5" fill="#2d4f73"/><circle cx="360" cy="224" r="4.5" fill="#2d4f73"/><circle cx="360" cy="55" r="4.5" fill="#2d4f73"/><circle cx="390" cy="211" r="4.5" fill="#2d4f73"/><circle cx="390" cy="68" r="4.5" fill="#2d4f73"/><circle cx="450" cy="172" r="4.5" fill="#2d4f73"/><circle cx="450" cy="107" r="4.5" fill="#2d4f73"/><circle cx="480" cy="172" r="4.5" fill="#2d4f73"/><circle cx="480" cy="107" r="4.5" fill="#2d4f73"/><circle cx="510" cy="237" r="4.5" fill="#2d4f73"/><circle cx="510" cy="42" r="4.5" fill="#2d4f73"/><circle cx="90" cy="237" r="6" fill="#7a1f1f"/><text x="99" y="231" class="ts td">G</text><circle cx="510" cy="42" r="6" fill="#7a1f1f"/><text x="519" y="36" class="ts td">2G</text><circle cx="330" cy="185" r="6" fill="#7a1f1f"/><text x="339" y="179" class="ts td">3G</text><circle cx="150" cy="55" r="6" fill="#7a1f1f"/><text x="159" y="49" class="ts td">4G</text><circle cx="90" cy="42" r="6" fill="#7a1f1f"/><text x="99" y="36" class="ts td">22G = −G</text><line x1="90" y1="237" x2="510" y2="42" stroke="#7a1f1f" stroke-width="1" stroke-dasharray="4 3" marker-end="url(#seta-d)"/><line x1="510" y1="42" x2="330" y2="185" stroke="#7a1f1f" stroke-width="1" stroke-dasharray="4 3" marker-end="url(#seta-d)"/><line x1="330" y1="185" x2="150" y2="55" stroke="#7a1f1f" stroke-width="1" stroke-dasharray="4 3" marker-end="url(#seta-d)"/><line x1="60" y1="139.5" x2="540" y2="139.5" stroke="#888" stroke-dasharray="2 4"/>
<text x="556" y="143.5" class="ts">eixo de simetria:</text>
<text x="556" y="157.5" class="ts">(x, y) e (x, 17 − y)</text>
<text x="556" y="60" class="ts">22 pontos e o infinito:</text>
<text x="556" y="74" class="ts">G tem ordem 23</text>
<text x="556" y="200" class="ts">G → 2G → 3G → 4G:</text>
<text x="556" y="214" class="ts">pulos sem padrão</text>
</svg>
<figcaption>Figura 30.8 — A curva y² = x³ − 3x + 3 módulo 17. Não é uma linha: é uma nuvem de pontos, e os múltiplos de G saltam por ela sem padrão visível.</figcaption>
</figure>

### O problema difícil: o logaritmo discreto

Calcular `k · P` é fácil. Lê-se `k` bit a bit, dobra-se sempre e soma-se
conforme o bit, como na exponenciação. É a **multiplicação de ponto**, a
operação cara da curva. Para um `k` de 256 bits são 256 dobras e cerca de
128 somas.

O inverso é o problema difícil: dados `P` e `Q = k · P`, achar `k`. É o
**logaritmo discreto** na curva. Na curva de brinquedo, 22 tentativas
resolvem. Numa curva com cerca de `2²⁵⁶` pontos, o melhor método conhecido
(o rô de Pollard) custa cerca de `2¹²⁸` operações. É a raiz quadrada do
número de pontos, e não há atalho conhecido.

A correspondência com o RSA é direta. Só muda a notação:

| No RSA | Na curva |
|---|---|
| multiplicar dois números módulo `n` | somar dois pontos |
| elevar ao quadrado | dobrar |
| `m^d mod n` (exponenciação) | `k · P` (multiplicação de ponto) |
| *square-and-multiply* | dobrar e somar |
| achar o expoente: logaritmo discreto | achar o escalar: logaritmo discreto |

### Por que a chave da curva é menor

A diferença está no melhor ataque conhecido contra cada problema.

Contra a fatoração existe o **crivo do corpo de números**, um método
subexponencial. Ele explora a estrutura dos inteiros: números pequenos,
fatores pequenos, relações entre eles. Cada bit a mais no módulo dá pouco
trabalho a mais ao atacante. Para compensar, o módulo tem de crescer muito.

Os pontos de uma curva bem escolhida não têm essa estrutura. Não existe
"ponto pequeno" nem "ponto primo". Só sobram os ataques genéricos, que
servem para qualquer grupo e custam a raiz quadrada da ordem. Cada dois bits
a mais na chave dobram o trabalho do atacante.

A SP 800-57 do NIST dá a equivalência:

| Força de segurança | Simétrica | RSA (módulo) | Curva (ordem) |
|---|---|---|---|
| 112 bits | 3DES de três chaves | 2048 | 224 |
| 128 bits | AES-128 | 3072 | 256 |
| 192 bits | AES-192 | 7680 | 384 |
| 256 bits | AES-256 | 15360 | 512 |

A P-256 é mais forte que o RSA-2048 deste equipamento, com uma chave oito
vezes menor. E a distância cresce: dobrar a força da curva custa dobrar a
chave, e dobrar a força do RSA custa multiplicar o módulo por cinco.


<figure class="fig">
<svg viewBox="0 0 680 250" xmlns="http://www.w3.org/2000/svg">
<text x="70" y="18" text-anchor="end" class="ts">força (bits)</text>
<text x="380" y="18" text-anchor="middle" class="ts">tamanho da chave, em bits (SP 800-57)</text>
<text x="70" y="50" text-anchor="end" class="tb">112</text><rect x="80" y="30" width="66.6" height="18" fill="#7a1f1f"/><text x="152.6" y="44" class="ts">RSA 2048</text><rect x="80" y="51" width="7.3" height="18" fill="#2d4f73"/><text x="93.3" y="65" class="ts">curva 224</text><text x="70" y="102" text-anchor="end" class="tb">128</text><rect x="80" y="82" width="99.8" height="18" fill="#7a1f1f"/><text x="185.8" y="96" class="ts">RSA 3072</text><rect x="80" y="103" width="8.3" height="18" fill="#2d4f73"/><text x="94.3" y="117" class="ts">curva 256</text><text x="70" y="154" text-anchor="end" class="tb">192</text><rect x="80" y="134" width="249.6" height="18" fill="#7a1f1f"/><text x="335.6" y="148" class="ts">RSA 7680</text><rect x="80" y="155" width="12.5" height="18" fill="#2d4f73"/><text x="98.5" y="169" class="ts">curva 384</text><text x="70" y="206" text-anchor="end" class="tb">256</text><rect x="80" y="186" width="499.2" height="18" fill="#7a1f1f"/><text x="585.2" y="200" class="ts">RSA 15360</text><rect x="80" y="207" width="16.6" height="18" fill="#2d4f73"/><text x="102.6" y="221" class="ts">curva 512</text>
<line class="ln" x1="80" y1="25" x2="80" y2="240"/>
</svg>
<figcaption>Figura 30.10 — O tamanho de chave para a mesma força. A curva cresce em linha reta; o RSA, muito mais depressa.</figcaption>
</figure>

⚠ **Nenhum dos dois resiste a um computador quântico grande.** O algoritmo
de Shor resolve a fatoração e o logaritmo discreto. A chave menor da curva
não é defesa contra isso.

### A curva P-256

Uma curva é definida por um conjunto de números públicos, os **parâmetros
de domínio**. Todos os usuários da curva usam os mesmos. A **P-256** é uma
das curvas do NIST (FIPS 186, SP 800-186). Outras normas dão a ela os nomes
`secp256r1` e `prime256v1`. Os parâmetros:

- **O primo `p`**, de 256 bits, que define o corpo das coordenadas:
  `p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1`. A forma não é acaso. Um primo feito de
  poucas potências de dois permite reduzir módulo `p` só com somas e
  subtrações de palavras de 32 bits, o que acelera o software. Este
  equipamento não usa esse atalho: o produto de Montgomery do coprocessador
  serve para qualquer módulo ímpar, e já estava pronto.
- **Os coeficientes `a` e `b`.** `a = −3`, um valor que economiza produtos
  na fórmula da dobra. `b` é um número de 256 bits que saiu de um hash
  (SHA-1) de uma semente publicada. A ideia é mostrar que ninguém escolheu
  `b` para criar uma curva fraca. A norma não explica de onde veio a
  semente, e essa é a crítica conhecida às curvas do NIST. Não se conhece
  fraqueza na P-256.
- **O ponto base `G`**, de onde saem todas as chaves públicas.
- **A ordem `n`** de `G`: o menor número com `n · G` igual ao ponto no
  infinito. É o `23` da curva de brinquedo. Na P-256, `n` é um primo de
  256 bits, um pouco menor que `p`.
- **O cofator `h = 1`.** O número de pontos da curva é `h · n`. Com `h = 1`,
  todo ponto da curva, menos o infinito, é múltiplo de `G` e tem ordem `n`.
  Curvas com cofator maior têm pontos de ordem pequena, e quem os aceita
  sem conferir vaza bits da chave. Na P-256, conferir que o ponto está na
  curva basta.

O número de pontos fica sempre perto de `p`: o teorema de Hasse garante a
distância máxima de `2·√p`. Por isso `n` e `p` têm o mesmo tamanho, e por
isso são dois números diferentes, com dois papéis diferentes:

- **módulo `p`** fazem-se as contas com **coordenadas** (somar e dobrar
  pontos);
- **módulo `n`** fazem-se as contas com **escalares** (a chave privada, o
  `k`, o `s` da assinatura).

Trocar um pelo outro é o erro clássico de quem implementa. O firmware
carrega um ou outro no coprocessador conforme a conta.

A chave:

```
    chave privada:  d, um número de 1 a n − 1, sorteado
    chave pública:  Q = d · G, um ponto da curva
```

Gerar a chave custa **uma** multiplicação de ponto. Não há busca de primos:
qualquer número de `1` a `n − 1` é uma chave privada válida. O `d` sai do
DRBG por rejeição: sorteiam-se 256 bits, e um valor fora da faixa é
descartado e sorteado de novo. Reduzir o valor com `mod n` seria mais
simples, mas favoreceria os números baixos.

### ECDSA: a assinatura

O ECDSA (*Elliptic Curve Digital Signature Algorithm*, FIPS 186-5) é a
versão em curva do DSA. Para assinar um hash `e`, com a chave privada `d`:

```
    sorteia k, de 1 a n − 1              (o número secreto DESTA assinatura)
    R = k · G
    r = (coordenada x de R) mod n
    s = k⁻¹ · (e + r · d) mod n
    a assinatura é o par (r, s)
```

Para verificar, com a chave pública `Q`:

```
    u1 = e · s⁻¹ mod n
    u2 = r · s⁻¹ mod n
    R' = u1 · G + u2 · Q
    confere se (coordenada x de R') mod n == r
```

Funciona porque `Q = d · G`, e então
`u1 · G + u2 · Q = (e + r · d) · s⁻¹ · G = k · G`. Quem verifica refaz o
ponto `R` sem conhecer `k` nem `d`.


<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<text x="165" y="18" text-anchor="middle" class="tb">assinar (tem d)</text>
<rect class="cxd" x="20" y="30" width="80" height="30"/><text x="60" y="50" text-anchor="middle" class="ts">k do DRBG</text>
<line class="ln" x1="100" y1="45" x2="138" y2="45" marker-end="url(#seta)"/>
<rect class="cx" x="140" y="30" width="90" height="30"/><text x="185" y="50" text-anchor="middle" class="ts">R = k · G</text>
<line class="ln" x1="230" y1="45" x2="258" y2="45" marker-end="url(#seta)"/>
<rect class="cx" x="260" y="30" width="70" height="30"/><text x="295" y="50" text-anchor="middle" class="ts">r = x(R)</text>
<rect class="cxd" x="60" y="80" width="240" height="30"/><text x="180" y="100" text-anchor="middle" class="ts">s = k⁻¹ · (e + r · d) mod n</text>
<rect class="cxv" x="100" y="130" width="160" height="30"/><text x="180" y="150" text-anchor="middle" class="tb">(r, s)</text>
<line class="ln" x1="180" y1="110" x2="180" y2="128" marker-end="url(#seta)"/>
<line class="lnt" x1="340" y1="10" x2="340" y2="200"/>
<text x="510" y="18" text-anchor="middle" class="tb">verificar (tem Q)</text>
<rect class="cx" x="370" y="30" width="290" height="30"/><text x="515" y="50" text-anchor="middle" class="ts">u1 = e · s⁻¹,  u2 = r · s⁻¹  (mod n)</text>
<rect class="cx" x="370" y="80" width="290" height="30"/><text x="515" y="100" text-anchor="middle" class="ts">R' = u1 · G + u2 · Q   (= k · G)</text>
<rect class="cxv" x="420" y="130" width="190" height="30"/><text x="515" y="150" text-anchor="middle" class="ts">x(R') mod n = r ?</text>
<line class="ln" x1="515" y1="60" x2="515" y2="78" marker-end="url(#seta)"/>
<line class="ln" x1="515" y1="110" x2="515" y2="128" marker-end="url(#seta)"/>
<text x="340" y="190" text-anchor="middle" class="ts">curva de brinquedo: d = 7, e = 5, k = 10 → (r, s) = (8, 13); u1 = 11, u2 = 13; 11G + 13Q = (8, 10): confere</text>
</svg>
<figcaption>Figura 30.11 — O ECDSA dos dois lados. Quem verifica refaz o ponto R sem conhecer k nem d.</figcaption>
</figure>

O papel de cada peça:

- **`r`** compromete o assinante com o ponto `R`, sem revelar `k`. Tirar
  `k` de `R` é o logaritmo discreto.
- **`s`** amarra o hash, o `r` e a chave privada numa equação só. Sem `d`,
  ninguém acha um `s` que feche a conta.
- **`k⁻¹`** é um inverso módulo `n`. Como `n` é primo, o pequeno teorema de
  Fermat dá o inverso com uma exponenciação: `k⁻¹ = k^(n−2) mod n`. Ela
  roda na mesma escada do RSA, porque `k` é segredo.
- **O hash** tem 256 bits, o mesmo tamanho de `n`, e entra inteiro. Com um
  hash mais longo que `n`, a norma manda usar só os bits da esquerda.

Com a curva de brinquedo (`n = 23`): chave privada `d = 7`, chave pública
`Q = 7G = (4, 15)`, hash `e = 5` e `k = 10`.

```
    assinar:    R  = 10G = (8, 10)           r = 8
                k⁻¹ = 7                      (10 · 7 = 70 = 3·23 + 1)
                s  = 7 · (5 + 8·7) mod 23 = 13
                assinatura: (8, 13)

    verificar:  s⁻¹ = 16                     (13 · 16 = 208 = 9·23 + 1)
                u1 = 5 · 16 mod 23 = 11      u2 = 8 · 16 mod 23 = 13
                11G = (10, 2)                13Q = (1, 16)
                R' = (10, 2) + (1, 16) = (8, 10)
                x de R' = 8 = r              confere
```

⚠ **O `k` é tão secreto quanto a chave, e não pode se repetir.** Duas
assinaturas com o mesmo `k` têm o mesmo `r`, e delas sai `d` com uma
subtração e uma divisão:

```
    k = (e1 − e2) / (s1 − s2)        d = (s1 · k − e1) / r
```

Na curva de brinquedo: assine o hash `12` com o mesmo `k = 10`. A
assinatura é `(8, 16)`, com o mesmo `r = 8`. Quem vê as duas calcula
`k = (5 − 12) / (13 − 16) = 10` e `d = (13 · 10 − 5) / 8 = 7`, tudo
módulo 23. A chave privada saiu de duas assinaturas e quatro contas.

Foi assim que a chave de assinatura de um console de videogame foi
recuperada em 2010: o `k` era constante. E não precisa repetir: conhecer
alguns bits de `k` em várias assinaturas já basta (ataques de reticulado).
Por isso o `k` deste equipamento sai do DRBG a cada assinatura, por
rejeição, e a multiplicação `k · G` tem tempo constante.

Existe uma variante que calcula `k` a partir da chave e do hash, sem
sorteio (ECDSA determinístico, RFC 6979). A FIPS 186-5 aceita as duas. Este
equipamento usa o sorteio: ele tem um gerador aprovado dentro da fronteira.

⚠ **A assinatura não é determinística.** Assinar o mesmo hash duas vezes dá
duas assinaturas diferentes, as duas válidas. Um teste não pode comparar a
assinatura com um valor esperado, como no RSA. Ele a confere pela
verificação. O autoteste do equipamento usa um `k` fixo do vetor oficial,
por uma entrada que nenhum comando alcança.

⚠ **Para cada assinatura válida existe outra.** Se `(r, s)` confere,
`(r, n − s)` também confere, sobre o mesmo hash. Quem usa a assinatura como
identificador único de uma mensagem tem de saber disso. O equipamento aceita
as duas formas, como a norma manda.

### RSA e ECDSA, lado a lado

| | RSA-2048 | ECDSA P-256 |
|---|---|---|
| Problema difícil | fatorar `n = p · q` | logaritmo discreto na curva |
| Força de segurança | 112 bits | 128 bits |
| Chave privada | dois primos de 1024 bits | um número de 256 bits |
| Chave pública | `n` e `e`: 256 bytes e mais um pouco | um ponto: 64 bytes |
| Assinatura | 256 bytes | 64 bytes |
| Gerar a chave | procurar dois primos: lento, tempo variável | uma multiplicação de ponto |
| Assinar | caro (duas exponenciações de 1024 bits) | uma multiplicação de ponto |
| Verificar | barato (`e` pequeno) | duas multiplicações de ponto: mais caro que assinar |
| Sorteio na assinatura | nenhum (PKCS#1 v1.5) | um `k` novo por assinatura |
| Mesma mensagem, duas vezes | mesma assinatura | assinaturas diferentes |
| Parâmetros | cada chave tem o seu módulo | todos usam a mesma curva |
| Erro que entrega a chave | falha numa metade do CRT (Bellcore) | `k` repetido, previsível ou vazado |
| Enchimento | obrigatório, e fonte de ataques | não existe |

Duas linhas merecem atenção num HSM:

- **A qualidade do sorteio.** No RSA, o gerador aleatório só importa quando
  a chave nasce. No ECDSA, ele importa em **toda** assinatura. Um gerador
  que falha depois de a chave existir não compromete a chave RSA, e
  compromete a chave ECDSA na primeira assinatura. Os testes contínuos da
  fonte de entropia (seção 25) pesam mais aqui.
- **O custo de verificar.** Um terminal que só verifica assinaturas trabalha
  menos com RSA. Um equipamento que assina muito trabalha menos com ECDSA.

O que os dois têm em comum, neste equipamento: a operação privada roda em
tempo constante, a assinatura é verificada antes de sair, e a chave privada
só existe fora da fronteira como key block sob a LMK.

### A multiplicação de ponto, sem vazar o escalar

O método de dobrar e somar tem o defeito do *square-and-multiply*: um bit 1
custa uma soma a mais. Com `k` ou `d` no escalar, o tempo entrega o segredo.

O equipamento usa a **escada de Montgomery** também aqui. Ela mantém dois
pontos, `R0` e `R1`, sempre com `R1 = R0 + P`, e a cada bit faz uma soma e
uma dobra, quaisquer que sejam os bits. O bit decide só qual dos dois pontos
recebe cada resultado.

Há um custo escondido na soma de pontos: a **divisão** módulo `p`. Dividir é
calcular um inverso, que custa centenas de produtos. A saída é a de sempre:
trocar a representação. Em vez de `(x, y)`, guarda-se `(X, Y, Z)`, com
`x = X/Z²` e `y = Y/Z³`. Nessa forma, somar e dobrar não dividem, e um único
inverso no fim devolve `(x, y)`. A escada deste equipamento usa uma variante
em que os dois pontos têm sempre o mesmo `Z`, e ele nem precisa ser guardado.

Cada bit do escalar custa 14 produtos modulares de 256 bits, e uma
multiplicação de ponto, cerca de 4 000. Todos vão para o mesmo coprocessador
do RSA, com o tamanho ajustado para 256 bits. As somas e subtrações ficam em
C, escritas sem desvio pelo valor.

⚠ **As fórmulas têm casos de exceção, e quem ataca os procura.** A soma de
dois pontos iguais é uma dobra, com outra fórmula. A soma de um ponto com o
seu oposto é o ponto no infinito, que `(x, y)` não representa. Na
assinatura, esses casos têm chance desprezível. Na verificação, quem monta a
assinatura escolhe `u1` e `u2`, e consegue produzi-los. O firmware trata
cada um deles de forma explícita.

⚠ **A chave pública que chega é conferida.** O `E4` recebe `Q` do host, e um
`Q` fora da curva leva as contas para outra curva, mais fraca. Antes de
qualquer conta, o firmware confere que as coordenadas são menores que `p` e
que o ponto satisfaz a equação.

### A chave de curva elíptica no key block, e os comandos

A chave privada sai como key block X9.143 sob a LMK, como a do RSA. O
cabeçalho usa uso `S0`, algoritmo `E` (curva elíptica) e modo `S`. O conteúdo
é a chave em **PKCS#8**, como a do RSA, com 138 bytes:

```
    30 81 87                       SEQUENCE                 (o PKCS#8)
       02 01 00                       versão
       30 13                          o algoritmo:
          06 07 2A 86 48 CE 3D 02 01        OID   chave de curva elíptica
          06 08 2A 86 48 CE 3D 03 01 07     OID   a curva P-256
       04 6D                          OCTET STRING
          30 6B                          a chave (RFC 5915)
             02 01 01                       versão
             04 20 ...                      d, 32 bytes
             A1 44 03 42 00 04 ...          a chave pública: 04, Qx, Qy
```

A curva vai no bloco pelo identificador dela, e o equipamento recusa
qualquer outra. A chave pública é opcional no formato. Quando ela vem, o
equipamento a usa para verificar a própria assinatura antes de entregá-la.
Quando não vem, ele a recalcula como `Q = d · G`. O bloco tem 336
caracteres.

| Pedido | Resposta | Entrada | Saída |
|---|---|---|---|
| `E0` gerar par | `E1` | exportabilidade(1) | key block · Qx(64) · Qy(64) |
| `E2` assinar | `E3` | key block · digest(64) | r(64) · s(64) |
| `E4` verificar | `E5` | Qx(64) · Qy(64) · digest(64) · r(64) · s(64) | — |

As regras são as do RSA. A assinatura é verificada antes de sair. O `E4`
verifica duas vezes e devolve um bit. Um key block RSA no `E2`, ou um de
ECDSA no `R2`, responde `11`: é confusão de tipo de chave.

### O que o equipamento não faz

- **Acordo de chave (ECDH).** Sobre a curva, o equipamento só assina e
  verifica.
- **Cifrar com RSA.** A chave RSA só assina.

## 31. Fase 8 — criptografia de pagamento

O modelo de referência do projeto é a categoria dos HSMs de pagamento. Esta
fase é a última porque depende de
tudo o que vem antes: sem hierarquia de chaves (Fase 3) e sem API de serviço
(Fase 5), não há onde encaixar um comando de tradução de PIN.

O equipamento tem as funções da Parte VII: tradução e verificação de PIN, CVV,
DUKPT, troca de chaves 3DES, e cifra e MAC de dados com 3DES.

O conteúdo dela é a **Parte VII** deste manual. O critério da fase é um só:
**aproximar o equipamento do mercado de meios de pagamento**. O objetivo não
é fazer o melhor projeto possível, é aprender como o mercado trabalha.

- **O 3DES entra**, como motor legado em software, ao lado do AES do
  coprocessador (seções 38.2 e 39). É o que a rede de pagamento usa.
- **Os vetores decidem como cada item entra.** O 3DES tem vetor oficial. As
  funções de pagamento não têm vetor oficial público, e entram com valores
  de implementações abertas, fixados por hash e marcados como fonte
  secundária (seção 38.3).

O item que mais ensina é o **ataque de tabela de decimalização** (seção
35.3): ele é um ataque sobre a **API**, e não sobre a cifra.

## 32. Ordem de trabalho, e a regra que a sustenta

Uma regra vale para todas as fases:

> **Nada vai para a placa sem passar antes no testbench.**

Depurar criptografia por UART, no hardware, sem visibilidade interna, é a
forma mais lenta possível de descobrir que faltou um byte no preenchimento.
Um erro de enquadramento em simulação custa segundos; o mesmo erro na bancada
custa uma tarde e várias hipóteses erradas.
