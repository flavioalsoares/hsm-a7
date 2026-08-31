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

Mike Bond (2001) mostrou famílias de ataques que consistiam em manipular
esses vetores para **converter uma chave de um tipo em outro**. Uma chave
destinada a derivar PINs podia ser reapresentada ao módulo como chave de
dados; a partir daí, bastava pedir ao HSM que cifrasse com ela para obter o
que deveria ser secreto.

**A defesa é o TR-31**, e agora a seção 8 faz sentido: o cabeçalho declara o
tipo *e é coberto pelo MAC*. Alterar o tipo invalida o bloco inteiro. Toda a
feiura do formato existe por causa desta classe de ataque.

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

O resultado: recuperação de um PIN de quatro dígitos em cerca de **quinze
chamadas de API**, contra as cinco mil de uma busca exaustiva. E cada chamada
é perfeitamente legítima.

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

### 17.4 Contramedidas

- **Dupla execução e comparação** — calcular duas vezes e confrontar. Dobra
  o custo e derrota falhas isoladas.
- **Verificação do resultado** — no RSA, checar a assinatura antes de emitir.
- **Sensores** — detectores de frequência fora de faixa, de tensão, de
  temperatura, de luz. Ao disparar: zeroize.
- **Redundância na codificação** — representar estados críticos com valores
  distantes em distância de Hamming, para que um bit trocado não converta
  "recusado" em "aceito".

O último ponto é subestimado. Se `AUTORIZADO = 1` e `NEGADO = 0`, um único
bit trocado inverte a decisão. Se `AUTORIZADO = 0x5A` e `NEGADO = 0xA5`, é
preciso trocar muitos bits coordenadamente.

### 17.5 Onde este projeto está

O gerador de clock deste projeto tem a versão mínima e honesta de um sensor:

```verilog
    wire rst_src_n = locked_w & rst_n_sync[1];
```

Perda de lock do MMCM **reafirma o reset** em vez de ser ignorada. Não
sabemos *por que* o lock caiu, mas sabemos que não dá para confiar no que
vier depois. Um HSM real iria além: zeroizaria, iria para `TAMPERED`, e
registraria o evento.

A Fase 6 do plano faz exatamente este ataque contra o próprio dispositivo —
glitch de clock pela porta de reconfiguração dinâmica do MMCM — e depois
implementa as contramedidas. É o roteiro clássico de aprender segurança de
hardware: construir, quebrar, reforçar.

## 18. Ataques físicos e antitamper

O degrau mais alto da escada: o atacante tem o aparelho na bancada.

### 18.1 A escada da resistência

| Nível | Nome | O que significa |
|---|---|---|
| 1 | **Tamper-evident** | A violação deixa marca visível: lacre, resina que estilhaça, tinta que mancha |
| 2 | **Tamper-resistant** | A violação é difícil: resina dura, blindagem, parafusos especiais |
| 3 | **Tamper-responsive** | O dispositivo **detecta e reage**: malha ativa que zeroiza ao ser rompida |
| 4 | **Environmental failure protection** | Detecta condições anormais — temperatura, tensão — e zeroiza antes de falhar |

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
de 1,8 V, sem bateria. A chave de bitstream em BBRAM se perde a cada
desligamento e precisa ser recarregada por JTAG.

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
