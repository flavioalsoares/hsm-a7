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

## 29. Fase 4 — armazenamento não-volátil

Blobs embrulhados na flash SPI, MAC de integridade, contador anti-rollback,
recuperação de estado no boot.

O problema novo aqui é o **rollback**: um atacante que restaure um estado
antigo da flash pode reviver uma chave revogada ou desfazer um incremento de
contador. Por isso o contador monotônico precisa de proteção específica, e é
um dos pontos onde HSMs reais gastam esforço desproporcional.

Detalhe de arquitetura já mapeado: a flash é a **mesma** que guarda o
bitstream. Log e blobs precisam morar num offset acima da imagem de
configuração, e o acesso a partir da lógica do usuário exige a primitiva
`STARTUPE2` para dirigir o clock de configuração.

## 30. Fase 5 — API de host

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

## 31. Fase 6 — tamper e ataques

Duas metades.

**Defesa:** XADC monitorando temperatura e tensão, disparando zeroize fora de
faixa. É o mecanismo de proteção contra falhas ambientais do FIPS nível 4
(seção 19), em versão mínima.

**Ataque:** atacar o próprio HSM. Glitch de clock pela porta de
reconfiguração dinâmica do MMCM, observar a assinatura sair errada, e então
implementar contramedidas — dupla execução, verificação de resultado (seção
17.4).

Também: bitstream encriptado com chave em BBRAM, como confidencialidade de
firmware. E o experimento de RO-PUF, documentado à parte, que mede na própria
placa **por que** um PUF de FPGA é ruim e por que o corretor de erros é
obrigatório.

Esta é a fase mais divertida e a mais instrutiva: construir, quebrar,
reforçar.

## 32. Fase 7 — assimétrico

RSA-2048 por Montgomery nos 90 DSP48E1; P-256 depois.

Deixado por último de propósito: o aprendizado de arquitetura de HSM está nas
fases 3 a 5. E há um gancho direto com a seção 17.1 — implementar RSA-CRT
sem verificar a assinatura antes de emitir é reproduzir o ataque Bellcore no
próprio equipamento.

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
