# Parte VI — O caminho adiante

## 27. Fase 2 — engines e self-test *(concluída)*

**Objetivo:** primitivas corretas e verificáveis. Correção antes de
desempenho.

| Bloco | Fonte | Estado |
|---|---|---|
| AES-256 | secworks/aes | **no CFS, verificado** |
| SHA-256 | secworks/sha256 | **no CFS, verificado** |
| `DNA_PORT` | primitiva Xilinx | **no CFS, verificado** |
| TRNG | neoTRNG (do NEORV32) | **no CFS, com health tests em RTL** |
| CTR_DRBG | firmware | **implementado, no POST** |

### O que já está feito

Os vetores KAT foram baixados das fontes oficiais — NIST CAVP para AES e
SHA, RFC 4231 para HMAC, SP 800-90A para o DRBG — com URL e hash SHA-256 de
cada arquivo registrados num manifesto. Nada foi escrito de memória.

Isso não é formalidade. A regra inviolável do projeto diz que, se um KAT
falha, o bug está no código e não no vetor — e essa regra só tem força se a
procedência do vetor for verificável por um terceiro. Um script rebaixa,
confere hash e reextrai; sobre um repositório limpo, o resultado é byte a
byte idêntico.

Os dois cores passam:

```
AES-256   405 vetores × 4 (ECB/CBC, cifra/decifra) = 1620
SHA-256   65 mensagens, 74 blocos
```

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

> **O teste encontrou um defeito no próprio teste.** O testbench de SHA
> reprovou com um sintoma característico: digests corretos, porém deslocados
> de um — a mensagem 1 devolvia o resultado da 0. Esperar apenas o sinal de
> "pronto" logo após o comando termina de imediato, porque o núcleo ainda
> não o baixou, e lê-se o resultado anterior. O testbench de AES passava com
> o mesmo handshake fraco, por sorte de temporização; recebeu a mesma
> correção. Teste que passa por sorte é dívida, não aprovação.

### O coprocessador: o CFS

Os cores entraram pelo **CFS** (*Custom Functions Subsystem*) do NEORV32 —
um slot de periférico projetado para receber coprocessadores. O arquivo do
upstream é um template feito para ser jogado fora; a substituição é feita
trocando qual arquivo o build compila, sem patch e sem tocar no submódulo.

É também por onde o `GET_DNA` finalmente se resolveu, fechando a última
sobra da Fase 1.

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

> **Um testbench a mais, para uma pergunta diferente.** Os KAT de core provam
> que o AES está certo. Não provam que o *caminho* entre a CPU e o AES está
> certo — um core correto atrás de um mapa de registradores com a ordem das
> palavras invertida produz resultados perfeitamente errados. Por isso os
> mesmos vetores do NIST são replicados uma segunda vez, agora **através do
> barramento**. Foi assim que a Fase 1 já tinha aprendido a separar
> "o módulo funciona" de "o sistema funciona".

### O preço em silício, e o que ele ensinou

Colocar criptografia no fabric custou caro e o custo apareceu onde não se
esperava.

| | Fase 1 | Com o CFS |
|---|---|---|
| Slice LUTs | 2240 (10,8%) | **7035 (33,8%)** |
| Flip-flops | 1633 (3,9%) | 6235 (15,0%) |
| Block RAM | 3,5 | 3,5 |
| DSP48E1 | 0 | 0 |

Área não foi problema — sobra um terço do chip. **Temporização foi.** O
projeto vinha com +0,637 ns de folga e, com os cores dentro, foi para
**−2,388 ns**: 58 caminhos falhando, o dispositivo não podia ser gravado.

O diagnóstico veio antes de qualquer conserto, e foi ele que economizou o
trabalho: dos 58 caminhos, **49 estavam no SHA-256 e 9 no AES**, e o pior do
AES era −0,087 ns — ruído. Um único bloco respondia por tudo. E dentro dele,
um único caminho: **oito somas de 32 bits encadeadas num ciclo só**, porque
a expansão da mensagem e a rodada de compressão dividem o mesmo ciclo.

A correção foi registrar as duas entradas combinacionais da rodada, com um
detalhe bonito: deslizar a janela da expansão uma rodada mais cedo faz os
quatro *taps* andarem junto, e a mesma fórmula que produzia `W[t]` passa a
produzir `W[t+1]`. Sem estágio de pipeline novo, sem ciclo a mais — ainda
são 64 rodadas por bloco.

```
+0,637 ns   Fase 1, sem criptografia
−2,388 ns   com o CFS                         não fecha
−1,215 ns   com esforço máximo de ferramenta  não fecha
+0,487 ns   com os dois patches de retimagem  fecha
```

> **A lição não é retimagem — é o que precisa existir antes de você poder
> tocar numa implementação criptográfica.**
>
> Modificar um core de hash é a espécie de coisa que se faz errado em
> silêncio: o resultado continua parecendo um hash. O que tornou isto
> aceitável foi a rede de vetores oficiais montada antes — 65 mensagens do
> SHAVS, rodadas no core e através do barramento. Foi possível **provar**
> que a modificação não mudou o resultado, sem tocar num vetor e sem
> relaxar um assert.
>
> É a mesma razão de o FIPS 140-3 exigir *self-test* (seção 11) e de o
> projeto ter a regra "se um KAT falha, o bug está no código". Sem isso,
> mexer ali seria irresponsável — e é exatamente por não ter essa rede que
> "não invente sua própria criptografia" é um bom conselho.

A modificação entrou como **patch versionado e revisável**, não como fork
nem reescrita: `third_party/` continua byte a byte igual ao upstream, e o
diff do que mudou está no repositório, legível, ao lado da justificativa.

### Como a fase terminou, e a surpresa dela

O plano dizia que RCT e APT (seção 10) ficariam em **firmware**. Não dá, e
descobrir por quê foi a lição da fase: a SP 800-90B exige que os testes
*contínuos* vejam **toda** amostra, e a fonte produz uma por ciclo de
100 MHz. A CPU veria uma em mil.

A divisão que sobrou é melhor do que a planejada:

- **hardware** faz os testes contínuos, amostra a amostra, e congela um
  retrato de 1024 amostras brutas consecutivas;
- **firmware** faz os testes de partida sobre esse retrato e é dono da
  política — reprovou, o dispositivo vai para `TAMPERED`.

Os dois testes acabam implementados **duas vezes, de forma independente**, e
uma discordância entre eles denuncia erro de interpretação da norma. Não foi
custo: foi a verificação saindo de graça.

**Cuidado térmico registrado no plano, e respeitado:** meia dúzia de anéis
osciladores, não centenas. Array grande gera calor e ruído de alimentação
localizados sem ganho de entropia.

O **POST** (seção 11) roda antes de aceitar qualquer comando. Ao fim da Fase
2 ele cobria AES-256, SHA-256, HMAC-SHA-256, CMAC-AES-256, CTR_DRBG, os
testes de partida da fonte e o key store — todos contra vetores oficiais —
a um custo de **5,94 ms** de boot.

Falha leva a `TAMPERED`, e o dispositivo passa a atender **só** ao
`SELFTEST`, que é o único jeito de o operador saber *o que* reprovou em vez
de olhar um LED vermelho.

> **O POST cresceu depois, e o número acima é o da Fase 2.** A Fase 3
> acrescentou o key block X9.143 e a prova de zeroização; são oito testes, e
> o boot passou a custar cerca de **9 ms**. A série está em
> `doc/fase3-notas.md`, e vale menos pelo número do que pela forma: cada
> propriedade que o dispositivo passa a garantir sobre si mesmo cobra
> milissegundos de todo boot, para sempre.

Da fase sobrou apenas `dieharder -a`, que não está instalado na máquina de
trabalho — e que é sanidade estatística, não validação de gerador.

## 28. Fase 3 — hierarquia de chaves *(em andamento)*

O coração do projeto, e onde os conceitos das Partes II e III viram código.

- ✅ **Key store** com os campos do cabeçalho TR-31 modelados desde o início —
  refatorar isso depois é doloroso porque o MAC cobre o cabeçalho inteiro.
- ✅ **Cerimônia de LMK** com três componentes XOR, KCV a cada passo, e dual
  control exigindo os dois botões.
- ✅ **Máquina de estados** com o display de 7 segmentos soletrando
  `Uni` / `Aut` / `OPE` / `tPr`, mais o ponto decimal confirmando o dual
  control.
- ✅ **Key blocks ANSI X9.143 (TR-31 versão D)**: KBEK e KBAK derivadas por
  CMAC, corpo em AES-CBC, autenticação por CMAC sobre cabeçalho e corpo —
  escritos **duas vezes**, em C e em Python.
- ✅ **Zeroize** com prova — e a prova não vem de dump.
- ✅ **Comandos de chave**: gerar dentro da fronteira, exportar embrulhado,
  reimportar, consultar metadados. **Nenhum deles exige dual control**, e a
  razão está mais abaixo.
- **Apagar um slot isolado** — a função existe no firmware, o comando não.
  Só apareceu quando se tentou *usar* o dispositivo em laço, e não quando se
  planejou a fase.
- **Usar chave por handle** — os comandos de AES e HMAC da Fase 2 recebem a
  chave no pedido e, com chave mestra carregada, param de responder
  sozinhos. As versões por handle ainda não existem.
- **Log de auditoria** gravado antes da execução, em flash, com contador
  monotônico.

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

A escada de estados é de **uma via só**. Carregou os três componentes, o
dispositivo vai a `AUTHORIZED` e o comando de carregar deixa de existir —
não há caminho para trocar a chave mestra por cima da existente. Ativou, vai
a `OPERATIONAL` e o comando de ativar some. Descer exige apagar.

O efeito colateral mais instrutivo é o que **desaparece**: em `OPERATIONAL`
os comandos da Fase 2 que recebem chave em claro no payload param de
responder. Nenhuma linha de código os desliga — a máscara de estados deles
diz `UNINITIALIZED`, e o dispositivo simplesmente não está mais lá.

### O painel, e uma pergunta de bancada que virou projeto

A cerimônia nasceu completa e **inoperável**: a ferramenta mandava "segure
SW2 e SW5", e o operador não tinha como saber quais eram. Rótulo minúsculo,
no meio de um procedimento, num par que o próprio projeto ainda não tinha
confirmado.

O conserto óbvio — descrever os botões por posição em vez de por rótulo —
resolveu metade. A outra metade veio de perguntar quem *deveria* responder
isso, e a resposta é o dispositivo. O display de 7 segmentos estava ocioso
desde a Fase 1, com a pinagem verificada e nada para exibir.

Agora ele soletra o estado, e o **ponto decimal acende enquanto o dual
control está satisfeito**. O operador aperta e vê o dispositivo concordar,
antes de gastar o comando. É a diferença entre uma autorização que se
descobre pelo erro e uma que se confirma pelo gesto.

Duas notas de projeto:

- O display **não lê a máquina de estados**; ele recebe dois bits pelo GPIO.
  Um caminho de hardware até a estrutura de estado seria caminho de hardware
  até o que está ao lado dela na memória.
- O `default` do decodificador é `tPr`, não `Uni` nem apagado. Estado
  corrompido tem de aparecer como comprometido — falhar para o lado seguro
  vale também para o painel.

E há uma medida que faltava e ninguém tinha notado que faltava. A
verificação de 2026-08-09 desenhou `222` nos três dígitos ao mesmo tempo, o
que confirma polaridade e mapeamento de segmento — e **não distingue ordem**:
três dígitos iguais são iguais em qualquer ordem. O experimento *parecia* ter
coberto o display inteiro. Fechou desenhando `123`, com a varredura vindo do
host, três comandos em laço.

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

### Os comandos de chave, e por que nenhum pede dois dedos

Depois da cerimônia vem o trabalho: gerar uma chave, exportá-la embrulhada,
reimportá-la, consultar o que ela é. Quatro comandos, e **nenhum deles exige
dual control** — o que contraria a intuição o suficiente para valer o
parágrafo.

**Dual control é para cerimônia, não para operação.** Carregar a chave
mestra, ativar o dispositivo e apagar tudo são eventos raros, com gente na
frente do equipamento. Gerar e exportar chave é o que um HSM faz o dia
inteiro. Exigir dois dedos ali não aumentaria segurança nenhuma — garantiria
apenas que ninguém usa o equipamento. E um controle que impede o uso legítimo
é desligado no primeiro dia ruim, junto com os que serviam para alguma coisa.

O que protege esses quatro é estrutural, não humano:

- a chave **nunca sai em claro** — sai embrulhada num key block, e quem
  recebe não sabe abrir;
- o key block é **autenticado sobre cabeçalho mais corpo**, então a política
  viaja junto com a chave e não pode ser reescrita a caminho;
- `exportabilidade` decide quem pode sair, e existe **um único caminho** no
  código para os bytes deixarem um slot — é ele que consulta o campo.

A última linha é a diferença entre uma regra e uma promessa. Se houvesse
duas formas de obter os bytes, a verificação viraria convenção — e convenção
é o que se esquece no caminho raro.

**O contraste que fecha a Parte II.** Na Fase 2, o comando de cifrar recebia
a chave *no pedido*, vinda do host. Na Fase 3 o host escolhe os **metadados**
e nunca vê o material. Os dois não podem coexistir num dispositivo com chave
de verdade — e não coexistem, sem uma linha de código desligando nada: a
máscara de estados dos comandos antigos diz `UNINITIALIZED`, e no instante
em que existe uma chave mestra eles somem.

E uma decisão que só parece detalhe: **toda recusa de importação devolve o
mesmo código**. Bloco malformado, hexadecimal inválido, MAC errado e
comprimento impossível são indistinguíveis de fora. É o comando mais exposto
do dispositivo — um atacante manda blocos forjados em laço e cada resposta é
informação. Dizer em qual etapa a validação parou é o oráculo de padding da
seção 15, com outra roupa: o atacante não precisa da chave, precisa que a
vítima seja prestativa.

### Uma lição de ferramenta, que valeu mais que o comando

As duas sabotagens deliberadas do mecanismo de apagar — quebrar o código de
propósito para ver se o teste reprova — **passaram**. Não porque o teste
fosse fraco: porque o script de simulação não recompilava o firmware. Ele
conferia que a imagem existia e seguia adiante, então o testbench validava
o binário anterior.

Um teste que nunca vê o código em teste é pior que teste nenhum, e essa
classe de falha não aparece em revisão de código — só aparece quando se
tenta, de propósito, fazer o teste falhar.

É a razão de a disciplina de sabotagem existir. Ela não confirma que o
código está certo; ela confirma que o **teste está ligado**.

E a honestidade que fecha a seção: num HSM de verdade o componente entra por
teclado local ou cartão do custodiante, **nunca pela mesma porta por onde o
host fala**. Aqui a porta é uma só, e o componente atravessa o link em claro.
É a maior distância entre este projeto e o modelo — e está escrita, não
escondida.

O critério de aceitação que mais importa:

> Captura da UART durante toda a suíte não contém nenhum byte de chave em
> claro — `grep` automatizado contra as chaves conhecidas do teste.

É a fronteira criptográfica deixando de ser afirmação e virando medida
(seção 5).

Outros critérios: gerar chave, exportar em TR-31, reimportar e usar em AES
com resultado idêntico; parser Python e firmware C concordando em 100 blocos
aleatórios; alterar um bit do cabeçalho ou do corpo invalidando o MAC; e
chave marcada como não exportável não saindo **por caminho nenhum**.

## 29. Fase 4 — armazenamento não-volátil *(em andamento)*

Até a Fase 3, desligar a placa apagava tudo: a LMK, as chaves e o estado.
Cada sessão de bancada começava digitando três componentes de 64 caracteres.
Um HSM comercial não se comporta assim. Ele desliga e volta *online* com a
chave mestra e as chaves de trabalho, e é esse comportamento que a Fase 4
reproduz.

### A decisão que a fase tomou, e por que ela é fraca de propósito

Num HSM comercial, a LMK sobrevive ao desligamento numa **memória mantida
por bateria, dentro de um invólucro com detecção de violação** (§18.2). Abrir
a caixa corta a bateria, e a chave some.

Esta placa não tem nada equivalente. O eFUSE é proibido pela regra nº 1, a
BBRAM está sem bateria, o DNA do chip é público e não há invólucro.
Embrulhar a LMK antes de gravá-la só mudaria o problema de lugar: a chave que
a embrulha teria de ficar guardada em algum lugar, e esse lugar seria a mesma
flash.

Então, por ser um projeto **educacional** e diante dessa **limitação de
hardware**, a decisão (do autor, em 2026-10-15) foi:

> A região da flash SPI a partir de 4 MB é **tratada como memória segura**.
> A LMK é guardada nela em claro; as chaves de trabalho, embrulhadas sob a
> LMK como key blocks X9.143.

O comportamento operacional fica igual ao de um equipamento comercial. A
proteção física não fica: quem tiver um gravador SPI lê a LMK. A diferença
está escrita em `doc/fase4-notas.md`, em vez de disfarçada por um esquema que
pareceria proteger e não protegeria.

### O que entrou

- **Hardware.** O SPI do NEORV32 fala com a mesma flash que guarda o
  bitstream. O clock passa pela primitiva `STARTUPE2`, a única forma de a
  lógica do usuário alcançar o pino de clock de configuração. As memórias do
  processador dobraram (32 KB de código, 16 KB de dados). Custo: +83 LUTs,
  +6 Block RAMs, e a folga de timing ficou praticamente igual (+0,258 ns).
- **A guarda do bitstream.** O driver recusa apagar ou gravar abaixo de
  4 MB, num lugar só, por onde toda escrita passa.
- **O registro persistente**, com a LMK, o estado e os slots, em **duas
  cópias**. Cada gravação vai para a mais velha, e uma queda de energia no
  meio deixa a outra intacta. No boot vale a mais nova cujo CRC confere.
- **Chave anunciada é chave guardada.** Se a flash falhar, `GEN_KEY` e
  parentes desfazem o slot e devolvem `STORE_FAIL`.
- **O log de auditoria**, finalmente (§5 do plano). Cada comando é
  registrado **antes** de executar, com o resultado "pendente"; depois só o
  byte de resultado é programado por cima. Um registro que ficou pendente é
  um comando que começou e não terminou. E se o log não puder ser gravado, o
  comando não executa. A exceção é o `ZEROIZE`.

### O que ficou de fora, de propósito

O plano previa um **contador anti-rollback**. O problema é real: quem
restaurar uma imagem antiga da flash ressuscita uma chave apagada. Mas a
defesa exige um contador monotônico **fora** da flash, que a placa não tem, e
um contador dentro dela seria restaurado junto com o resto. A limitação está
documentada, não mitigada. É um dos pontos onde HSMs reais gastam esforço
desproporcional, e aqui fica como lição, não como código.

## 30. Fase 5 — API de host *(em andamento)*

**Decidida em favor de um command set ASCII** no estilo dos HSM de
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

### As três decisões com que a fase começou

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

### O que já entrou

Nove comandos, com códigos deste projeto (da categoria vem só a forma geral):
diagnóstico, gerar chave, conferir um key block, exportar e importar sob uma
chave de troca, cifrar e decifrar em AES-CBC, gerar e verificar CMAC. A chave de cada comando é aberta num slot
**efêmero** do key store — o mesmo código de sempre faz a checagem de modo de
uso — e apagada ao fim do comando, em qualquer desfecho. O apêndice B tem o
formato.

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

## 31. Fase 6 — tamper e ataques

Duas metades.

**Defesa:** XADC monitorando temperatura e tensão, disparando zeroize fora de
faixa. É o mecanismo de proteção contra falhas ambientais do FIPS nível 4
(seção 19), em versão mínima. Implementada, junto com a perda de lock do MMCM.
Ver `doc/fase6-notas.md`, que diz também o que ela não protege.

**Ataque:** atacar o próprio HSM. Glitch de clock num bitstream separado,
observar o resultado sair errado, e então implementar contramedidas — dupla
execução, verificação de resultado (seção 17.4). Enquanto a Fase 7 não existe, o
alvo é o AES e o MAC, e não a assinatura.

Também: bitstream encriptado com chave em BBRAM, como confidencialidade de
firmware. O mecanismo foi provado na placa, e a produção segue sem cifra, por
decisão explicada na seção 18.5. E o experimento de RO-PUF, documentado à parte, que mede na própria
placa **por que** um PUF de FPGA é ruim e por que o corretor de erros é
obrigatório.

Esta é a fase mais divertida e a mais instrutiva: construir, quebrar,
reforçar.

## 32. Fase 7 — assimétrico *(em andamento)*

RSA-2048 primeiro, P-256 depois. Deixado por último de propósito: o
aprendizado de arquitetura de HSM está nas fases 3 a 5. E há um gancho direto
com a seção 17.1 — implementar RSA-CRT sem verificar a assinatura antes de
emitir é reproduzir o ataque Bellcore no próprio equipamento.

Até aqui a fase entregou a **verificação** de assinatura RSA-2048: um
multiplicador modular no fabric, a exponenciação no firmware, o KAT no POST e o
comando `R4` na porta host. A assinatura, que usa a chave privada, vem depois.
As medidas e o estado de cada peça estão em `doc/fase7-notas.md`.

### Por que um HSM precisa de criptografia assimétrica

Tudo o que o dispositivo fazia até a fase 6 é **simétrico**: quem cifra e quem
decifra têm a mesma chave. Isso funciona dentro de uma instituição, e entre
duas só depois de elas já terem uma chave em comum — foi o que a KEK da seção 30
resolveu, por componentes levados em mãos.

A criptografia assimétrica separa a chave em duas metades. A **privada** fica
dentro da fronteira e nunca sai; a **pública** pode ser publicada. O que uma
faz, só a outra confere. Disso saem dois serviços que a simétrica não presta:

- **assinatura:** só o dono da privada produz, qualquer um confere. Prova
  origem sem segredo compartilhado;
- **troca de chave:** duas partes que nunca se encontraram combinam uma chave
  simétrica por um canal aberto.

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
produto de 2048 bits leva cerca de `128²` ciclos: 18 433, medidos, ou 184 µs a
100 MHz.

O plano original falava em usar "os 90 DSP48E1". O core usa **4**. Paralelizar
mais encurtaria o produto, mas o gargalo de um HSM didático não é a vazão de
assinaturas — e cada DSP a mais é área e rota no fabric apertado do XC7A35T.

### Hardware faz o produto, firmware faz a política

O coprocessador faz **uma** coisa: `dst = a · b · R⁻¹ mod n`, sobre oito
registradores internos de 2048 bits numa Block RAM. Tudo o mais é firmware:
calcular `n'` e `R² mod n`, percorrer o expoente, montar e conferir o
enchimento. É a mesma divisão do TRNG na seção 27: o que custa ciclo fica no
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

⚠ **A verificação reconstrói o `EM` inteiro e compara, em vez de interpretá-lo.**
Bleichenbacher (2006) mostrou que verificadores que *liam* o bloco — achavam o
`00`, pulavam os `FF`, extraíam o hash — aceitavam lixo depois do hash. Com
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

Uma consequência prática: um pedido `R4` tem mais de 1100 caracteres, e o
limite de mensagem subiu de 512 para 2048 bytes. Um key block com uma chave
RSA privada, quando vier, é ainda maior.

### O preço no boot

O POST ganhou o KAT de RSA: verificar uma assinatura oficial do CAVP e
**recusar** a mesma assinatura com um bit trocado. O vetor tem `e = 0x260445`,
de 22 bits, e cada verificação custa cerca de 9 ms. O boot passou de 10,19 ms
para **28,27 ms** — a seção 11 avisou que cada propriedade que o dispositivo
garante sobre si mesmo cobra milissegundos de todo boot, para sempre.

### O que falta

A metade privada:

- **chave RSA privada como key block sob a LMK**, mantida pelo host como as
  chaves AES da porta host;
- **geração de chave** dentro da fronteira, com primos testados por
  Miller-Rabin;
- **assinatura com CRT** e escada de Montgomery, em tempo constante;
- **verificação antes de emitir**, que é a contramedida do Bellcore (seção
  17.1), somada à dupla execução da fase 6;
- e só então P-256.

## 33. Fase 8 — criptografia de pagamento

Acrescentada ao plano em 2026-08-08, quando o modelo de referência do projeto
passou a ser a categoria dos HSMs de pagamento. É a última porque depende de
tudo o que vem antes: sem hierarquia de chaves (Fase 3) e sem API de serviço
(Fase 5), não há onde encaixar um comando de tradução de PIN.

O conteúdo dela é a **Parte VII** deste manual. O que decide se um item é
implementável aqui não é a dificuldade — é o **hardware** e a **procedência
dos vetores**:

- o que é AES cabe (PIN block formato 4, DUKPT AES);
- o que é inerentemente 3DES não cabe, porque o coprocessador é AES-256 sem
  caminho de downgrade, e isso é decisão de arquitetura e não tarefa pendente;
- o que não tem vetor público não entra, ou entra marcado como não
  verificado — a regra nº 5 exige procedência, e "implementei e parece certo"
  é exatamente o que ela proíbe.

O melhor item da lista é o **ataque de tabela de decimalização** (seção
37.3), e por um motivo que vale registrar: ele não precisa de 3DES nem de
vetor de bandeira nenhuma. O ataque é sobre a **API**, não sobre a cifra, e
reproduz inteiro num esquema nosso com AES.

## 34. Ordem de trabalho, e a regra que a sustenta

Uma regra vale para todas as fases:

> **Nada vai para a placa sem passar antes no testbench.**

Depurar criptografia por UART, no hardware, sem visibilidade interna, é a
forma mais lenta possível de descobrir que faltou um byte no preenchimento.
Um erro de enquadramento em simulação custa segundos; o mesmo erro na bancada
custa uma tarde e várias hipóteses erradas.

A Fase 1 já demonstrou o retorno: dois defeitos reais foram pegos em
simulação, e o único que escapou até o hardware foi o único que a simulação
estruturalmente não podia ver.
