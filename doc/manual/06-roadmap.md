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

## 29. Fase 6 — tamper e ataques

Duas metades.

**Defesa:** XADC monitorando temperatura e tensão, disparando zeroize fora de
faixa. É o mecanismo de proteção contra falhas ambientais do FIPS nível 4
(seção 19), em versão mínima. Implementada, junto com a perda de lock do MMCM.
Ver `doc/fase6-notas.md`, que diz também o que ela não protege.

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
produto de 2048 bits leva cerca de `128²` ciclos: 18 433, ou 184 µs a
100 MHz.

O core usa **4** dos 90 DSP48E1. Paralelizar mais encurtaria o produto, mas o gargalo de um HSM didático não é a vazão de
assinaturas — e cada DSP a mais é área e rota no fabric apertado do XC7A35T.

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

Como todo resultado que sai ao host, a verificação roda duas vezes, e
discordância responde `91` (seção 29). Um pedido `R4` tem mais de 1100
caracteres, e o limite de mensagem é de 2048 bytes.

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

### A chave privada no key block

A chave sai como **key block X9.143 sob a LMK** e fica com o host, como as
chaves AES da porta host (seção 28). O cabeçalho usa os códigos da norma:
uso `S0` (par assimétrico de assinatura), algoritmo `R` (RSA), modo `S`
(só assinar). As duas implementações do formato — em C e em Python — recusam
qualquer outra combinação para `R`.

⚠ **O conteúdo do bloco é um layout deste projeto**, e não da norma: `e`, `p`,
`q`, `dp`, `dq` e `qinv` em campos fixos, 644 bytes. A X9.143 define os
códigos de chave assimétrica, mas a forma de codificar a chave dentro do
bloco não estava acessível — a norma é paga. Se um dia estiver, só esse campo
muda. O módulo `n` não vai no bloco: o dispositivo o recalcula como `p · q`.

O bloco tem 1360 caracteres, e a chave aberta vive numa área própria do key
store **só durante o comando** — nunca num slot, nunca na flash. O
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
é um layout deste projeto: `d`, `Qx` e `Qy`, 32 bytes cada. A chave pública
vai junto, para o dispositivo verificar a própria assinatura antes de
entregá-la.

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
35.3), e por um motivo que vale registrar: ele não precisa de 3DES nem de
vetor de bandeira nenhuma. O ataque é sobre a **API**, não sobre a cifra, e
reproduz inteiro num esquema nosso com AES.

## 32. Ordem de trabalho, e a regra que a sustenta

Uma regra vale para todas as fases:

> **Nada vai para a placa sem passar antes no testbench.**

Depurar criptografia por UART, no hardware, sem visibilidade interna, é a
forma mais lenta possível de descobrir que faltou um byte no preenchimento.
Um erro de enquadramento em simulação custa segundos; o mesmo erro na bancada
custa uma tarde e várias hipóteses erradas.
