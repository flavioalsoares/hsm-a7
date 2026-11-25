# Parte I — O que é um HSM

## 1. O problema que um HSM resolve

Software comum guarda chaves na memória do processo. Quem tem acesso à
máquina — o usuário `root`, um dump de memória, um bug de leitura fora de
limites, um backup mal apagado — tem a chave. E há uma consequência mais
sutil: **não existe forma de distinguir "usar a chave" de "copiar a chave"**.
Se o programa consegue assinar, o programa consegue exportar o segredo que
assina. Quem controla o programa herda essa capacidade.

Um HSM (*Hardware Security Module*) existe para tornar essas duas coisas
diferentes. Ele oferece uma **interface de operações**, não de acesso:

```
    o host manda:  "assine este bloco com a chave 7"
    o host nunca manda:  "me devolva a chave 7"
```

A chave nasce dentro do dispositivo, vive dentro e morre dentro. Ela pode
sair — mas só embrulhada (*wrapped*) por outra chave que também nunca saiu.

Essa separação parece pequena e reorganiza tudo. A pergunta de segurança
deixa de ser *"quem consegue ler a memória?"* e passa a ser:

> **O que a API permite deduzir sobre a chave, se for chamada um milhão de
> vezes com entradas escolhidas pelo atacante?**

Praticamente toda a arquitetura descrita neste documento decorre dessa
pergunta. É também por isso que os ataques mais interessantes contra HSMs
não quebram criptografia: eles conversam com a API.

### Um exemplo concreto

Imagine um banco que precisa verificar PINs de cartão. O PIN correto é
derivado do número da conta com uma chave secreta. Sem HSM:

- a chave de derivação está na memória do servidor de autorização;
- qualquer comprometimento desse servidor entrega a chave;
- com a chave, o atacante calcula o PIN de **qualquer** conta, offline, sem
  deixar rastro e sem limite de tentativas.

Com HSM:

- a chave está dentro do módulo e nunca esteve em outro lugar;
- o servidor manda "este PIN confere para esta conta?" e recebe sim ou não;
- comprometer o servidor dá ao atacante a capacidade de **perguntar**, não a
  chave. Perguntas são contadas, limitadas e registradas.

O atacante não é impedido — ele é **reduzido a um canal estreito, medido e
auditável**. Essa redução é o produto que um HSM vende.


<figure class="fig">
<svg viewBox="0 0 680 270" xmlns="http://www.w3.org/2000/svg">
<text x="160" y="18" class="tb" text-anchor="middle">Sem HSM</text>
<rect class="cx" x="40" y="40" width="240" height="120"/>
<text x="160" y="60" text-anchor="middle" class="tb">servidor de autorização</text>
<rect class="cxd" x="70" y="80" width="180" height="34"/>
<text x="160" y="102" text-anchor="middle">chave de PIN na memória</text>
<text x="160" y="140" text-anchor="middle" class="ts">o programa usa a chave e pode copiá-la</text>
<rect class="cxd" x="25" y="200" width="270" height="40"/>
<text x="160" y="218" text-anchor="middle" class="tb td">invasor com root</text>
<text x="160" y="232" text-anchor="middle" class="ts">leva a chave; calcula o PIN de qualquer conta</text>
<line class="lnd" x1="160" y1="200" x2="160" y2="118" marker-end="url(#seta-d)"/>
<line class="lnt" x1="340" y1="10" x2="340" y2="260"/>
<text x="510" y="18" class="tb" text-anchor="middle">Com HSM</text>
<rect class="cx" x="370" y="40" width="130" height="70"/>
<text x="435" y="62" text-anchor="middle" class="tb">servidor</text>
<text x="435" y="80" text-anchor="middle" class="ts">sem chave</text>
<rect class="fr" x="540" y="30" width="125" height="95"/>
<rect class="cxd" x="555" y="55" width="95" height="40"/>
<text x="602" y="73" text-anchor="middle">chave</text>
<text x="602" y="87" text-anchor="middle" class="ts">nunca sai</text>
<text x="602" y="118" text-anchor="middle" class="ts td">HSM</text>
<line class="ln" x1="500" y1="60" x2="553" y2="60" marker-end="url(#seta)"/>
<text x="520" y="52" class="ts" text-anchor="middle">confere?</text>
<line class="ln" x1="553" y1="88" x2="500" y2="88" marker-end="url(#seta)"/>
<text x="520" y="102" class="ts" text-anchor="middle">sim / não</text>
<rect class="cxa" x="360" y="200" width="240" height="40"/>
<text x="480" y="218" text-anchor="middle" class="tb">invasor com root</text>
<text x="480" y="232" text-anchor="middle" class="ts">só pergunta: contado, limitado, registrado</text>
<line class="ln" x1="450" y1="200" x2="435" y2="112" marker-end="url(#seta)"/>
</svg>
<figcaption>Figura 1.1 — O mesmo ataque, sem e com HSM. Com HSM, o invasor ganha o direito de perguntar, e não a chave.</figcaption>
</figure>

## 2. Modelo de ameaça

"Seguro" não significa nada sem dizer contra quem. HSMs são projetados
contra uma escada de adversários, e cada degrau custa mais caro de defender.

| Adversário | Capacidade | Defesa correspondente |
|---|---|---|
| **Aplicação comprometida** | Chama a API à vontade | Máquina de estados, atributos de chave, limites de uso |
| **Administrador do host** | Root na máquina, vê todo o tráfego do canal | Chaves nunca no host; autorização física no próprio módulo |
| **Insider com acesso físico** | Toca no equipamento, opera o painel | Dual control, split knowledge, log de auditoria |
| **Atacante com o aparelho na mão** | Bancada, osciloscópio, fonte de alimentação | Antitamper, sensores, canal lateral, injeção de falha |
| **Laboratório especializado** | Decapsulação, microssonda, FIB | Malha ativa, camadas de blindagem, zeroização por detecção |


<figure class="fig">
<svg viewBox="0 0 680 270" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="30" y1="225" x2="660" y2="225" marker-end="url(#seta)"/>
<line class="ln" x1="30" y1="225" x2="30" y2="15" marker-end="url(#seta)"/>
<text x="345" y="264" text-anchor="middle" class="ts">capacidade do adversário</text>
<text x="18" y="120" class="ts" transform="rotate(-90 18 120)" text-anchor="middle">custo da defesa</text>
<rect class="cxa" x="40"  y="190" width="118" height="35"/><text x="99" y="212" text-anchor="middle" class="ts">aplicação</text>
<rect class="cxa" x="163" y="160" width="118" height="65"/><text x="222" y="182" text-anchor="middle" class="ts">admin. do host</text>
<rect class="cx"  x="286" y="125" width="118" height="100"/><text x="345" y="147" text-anchor="middle" class="ts">insider</text>
<rect class="cxd" x="409" y="85"  width="118" height="140"/><text x="468" y="107" text-anchor="middle" class="ts">aparelho na mão</text>
<rect class="cxd" x="532" y="35"  width="118" height="190"/><text x="591" y="57" text-anchor="middle" class="ts">laboratório</text>
<text x="99"  y="240" text-anchor="middle" class="ts">API</text>
<text x="222" y="240" text-anchor="middle" class="ts">root</text>
<text x="345" y="240" text-anchor="middle" class="ts">acesso físico</text>
<text x="468" y="240" text-anchor="middle" class="ts">bancada</text>
<text x="591" y="240" text-anchor="middle" class="ts">FIB, microssonda</text>
</svg>
<figcaption>Figura 2.1 — A escada de adversários. Cada degrau custa mais caro de defender; o objetivo é tornar o ataque mais caro que o valor protegido.</figcaption>
</figure>

Duas observações que orientam o resto do documento.

**O host é hostil por premissa.** Não é que se desconfie do host — é que a
arquitetura não pode *depender* de ele estar íntegro. É por isso que
autorização de operações sensíveis é feita com **botões no próprio
equipamento**, e não com um comando "eu autorizo" que chega pelo cabo. Um
comando pelo cabo tem exatamente a confiabilidade do host que o enviou.

**A escada é econômica, não absoluta.** Nenhum HSM é inviolável. O objetivo
é tornar o ataque mais caro que o valor protegido, e detectável quando
tentado. Um módulo que resiste seis meses a um laboratório nacional e falha
contra ele no sétimo mês pode estar perfeitamente adequado, se as chaves
tiverem rotação trimestral.

## 3. As três propriedades

Tudo que um HSM faz se organiza em três propriedades. Elas são
interdependentes: qualquer uma sozinha é inútil.

### Confinamento

Existe uma fronteira física, e material de chave em claro não a atravessa.
Dentro: chaves, estado do gerador aleatório, segredos derivados. Fora:
criptogramas, chaves embrulhadas, valores de verificação, identificadores,
log.

Confinamento sem mediação é um cofre com a porta aberta.

### Mediação

Toda operação passa por verificação de política **antes** de executar: o
dispositivo está no estado certo? Há autorização suficiente? Esta chave tem
permissão para esta operação? O pedido é bem formado?

Mediação sem confinamento é uma sugestão — se a chave pode ser lida por
fora, a verificação é decorativa.

### Evidência

O que aconteceu fica registrado de forma que sobreviva à falha e não possa
ser reescrito para omitir a tentativa.

Sem evidência, você nunca descobre se as outras duas falharam. E é a
propriedade mais frequentemente subestimada: um log que registra apenas
sucessos mostra um dispositivo saudável exatamente enquanto ele está sendo
mapeado por um atacante, cujo trabalho produz muitos erros e poucos acertos.


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="70" width="90" height="50"/>
<text x="55" y="92" text-anchor="middle" class="tb">host</text>
<text x="55" y="108" text-anchor="middle" class="ts">hostil</text>
<line class="ln" x1="100" y1="95" x2="168" y2="95" marker-end="url(#seta)"/>
<text x="134" y="88" text-anchor="middle" class="ts">pedido</text>
<rect class="fr" x="160" y="20" width="510" height="160"/>
<text x="660" y="38" text-anchor="end" class="ts td">fronteira: confinamento</text>
<rect class="cx" x="180" y="50" width="200" height="90"/>
<text x="280" y="68" text-anchor="middle" class="tb">mediação</text>
<text x="190" y="88" class="ts">1. estado certo?</text>
<text x="190" y="102" class="ts">2. autorização suficiente?</text>
<text x="190" y="116" class="ts">3. a chave permite isto?</text>
<text x="190" y="130" class="ts">4. o pedido é bem formado?</text>
<line class="ln" x1="380" y1="95" x2="450" y2="95" marker-end="url(#seta)"/>
<text x="415" y="88" text-anchor="middle" class="ts">passou</text>
<rect class="cxd" x="452" y="60" width="200" height="70"/>
<text x="552" y="88" text-anchor="middle" class="tb">chaves e operações</text>
<text x="552" y="106" text-anchor="middle" class="ts">o que é segredo fica aqui</text>
<rect class="cxv" x="230" y="190" width="300" height="34"/>
<text x="380" y="212" text-anchor="middle"><tspan class="tb">evidência:</tspan> o log registra o pedido, antes</text>
<line class="lnt" x1="280" y1="140" x2="280" y2="190" marker-end="url(#seta-t)"/>
<line class="lnt" x1="134" y1="100" x2="240" y2="190" marker-end="url(#seta-t)"/>
</svg>
<figcaption>Figura 3.1 — As três propriedades no caminho de um pedido. O log vê também os pedidos recusados.</figcaption>
</figure>

## 4. Onde HSMs são usados

O termo cobre famílias de equipamento bastante diferentes, e saber qual é
qual ajuda a entender por que este projeto modela LMK e TR-31 em vez de,
digamos, PKCS#11 e certificados.

### HSM de pagamentos

O mais antigo e o mais rígido. Protege PINs de cartão, chaves de terminal e
criptogramas EMV. Há poucos fabricantes, e os equipamentos são certificados
sob o PCI PTS HSM.

É onde nasceram os conceitos de **LMK** (chave mestra local), **key block**
e a exigência operacional de dual control e split knowledge. As regras não
são recomendações: PCI PIN Security e PCI PTS HSM são requisitos contratuais
para quem processa transações de cartão.

O comando típico não é "assine" — é "verifique este PIN", "traduza este PIN
block desta chave para aquela", "gere uma chave de terminal".


### HSM de propósito geral

Protege chaves de PKI, assinatura de código, TLS, bancos de dados,
blockchain. Há vários fabricantes, e os equipamentos são tipicamente
validados em FIPS 140-3.

A interface padrão é **PKCS#11** — `C_GenerateKey`, `C_Sign`, `C_WrapKey` —
ou APIs próprias (JCE, CNG, KMIP). O modelo mental é o de um chaveiro com
objetos que têm atributos, e os atributos é que definem o que se pode fazer
com cada chave.

### HSM em nuvem

Os grandes provedores de nuvem oferecem HSM como serviço. Fisicamente são os
mesmos módulos, operados pelo provedor, com o cliente controlando as chaves.
O interesse conceitual está no problema novo que criam: **como você confia
num módulo que não está na sua sala?** A resposta envolve atestação remota,
e é uma área em movimento.

### Elementos seguros e TPMs

Primos pequenos: o TPM da placa-mãe, o elemento seguro de um telefone, o
smartcard, a chave de autenticação USB. Mesma
ideia — chave que não sai, operação mediada — com orçamento de área,
consumo e custo muito menores. Um cartão de crédito com chip é um HSM
minúsculo cuja produção passa de bilhões de unidades por ano.


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="40" y1="200" x2="660" y2="200" marker-end="url(#seta)"/>
<line class="ln" x1="40" y1="200" x2="40" y2="15" marker-end="url(#seta)"/>
<text x="350" y="222" text-anchor="middle" class="ts">interface: de serviço (comandos)  ←→  de biblioteca (objetos, sessões)</text>
<text x="26" y="108" class="ts" transform="rotate(-90 26 108)" text-anchor="middle">tamanho e custo do equipamento</text>
<rect class="cxd" x="70" y="30" width="190" height="56"/>
<text x="165" y="52" text-anchor="middle" class="tb">HSM de pagamento</text>
<text x="165" y="70" text-anchor="middle" class="ts">LMK, key block, PIN; PCI PTS HSM</text>
<rect class="cxa" x="400" y="30" width="200" height="56"/>
<text x="500" y="52" text-anchor="middle" class="tb">propósito geral</text>
<text x="500" y="70" text-anchor="middle" class="ts">PKCS#11, PKI, TLS; FIPS 140-3</text>
<rect class="cx" x="400" y="100" width="200" height="40"/>
<text x="500" y="118" text-anchor="middle" class="tb">HSM em nuvem</text>
<text x="500" y="132" text-anchor="middle" class="ts">os mesmos módulos; atestação remota</text>
<rect class="cxc" x="250" y="152" width="230" height="38"/>
<text x="365" y="168" text-anchor="middle" class="tb">elementos seguros e TPM</text>
<text x="365" y="182" text-anchor="middle" class="ts">cartão com chip, telefone, placa-mãe</text>
<circle cx="165" cy="105" r="6" fill="#7a1f1f"/>
<text x="178" y="109" class="ts td">este projeto</text>
</svg>
<figcaption>Figura 4.1 — As famílias de HSM. Este projeto modela a de pagamento: protocolo de serviço, sem sessão.</figcaption>
</figure>

### O que este projeto modela

O caminho de pagamentos: **LMK, key blocks TR-31, cerimônia de carga com
componentes, dual control físico**. A razão é didática — é a família onde os
mecanismos organizacionais (quem autoriza o quê, e como se prova) estão mais
explícitos e mais bem documentados publicamente.

Os quatro elementos, em poucas linhas cada. As seções 6, 7 e 8 explicam cada
um em detalhe.

- **LMK** (*Local Master Key*, chave mestra local). É a chave de topo do
  HSM. Ela fica só dentro do equipamento e nunca sai, nem cifrada. Todas as
  outras chaves que o HSM usa (de PIN, de MAC, de troca com outra
  instituição) ficam guardadas fora dele, cifradas sob a LMK. Para usar uma
  delas, o sistema do banco manda a chave cifrada junto com o pedido, e o
  HSM a decifra só por dentro. Quem rouba o banco de dados do banco leva
  chaves que não consegue abrir sem a LMK. Ver a seção 6.

- **Key block TR-31** (hoje norma ANSI X9.143). É o formato em que uma
  chave cifrada viaja e fica guardada. Tem duas partes: um cabeçalho em
  texto legível, que diz o que a chave pode fazer (por exemplo, "só
  verifica PIN" ou "não pode sair deste equipamento"), e a chave cifrada.
  Um código de autenticação (MAC) cobre as duas partes juntas. Por isso
  ninguém altera o cabeçalho para dar à chave um poder que ela não tinha:
  qualquer alteração invalida o bloco. Ver a seção 8.

- **Cerimônia de carga com componentes**. É o procedimento para pôr a LMK
  dentro do HSM sem que nenhuma pessoa a conheça inteira. A chave é dividida
  em partes (os componentes), e cada parte fica com um custodiante
  diferente. Na cerimônia, cada custodiante digita a sua parte, e o HSM
  junta as partes por XOR. Cada parte sozinha não revela nada da chave. A
  cada parte, o HSM devolve um valor de conferência curto (o KCV), que
  confirma a digitação sem mostrar a parte. Este princípio tem o nome de
  *split knowledge* (conhecimento dividido). Ver a seção 7.

- **Dual control físico**. É a regra de que uma operação crítica exige
  duas pessoas ao mesmo tempo. O *split knowledge* impede que uma pessoa
  *saiba* a chave inteira; o dual control impede que uma pessoa *aja*
  sozinha. Num equipamento comercial, cada pessoa se identifica com cartão e
  senha. Neste projeto, o HSM só aceita os comandos de cerimônia com dois
  botões da placa apertados ao mesmo tempo. Ver a seção 7.


<figure class="fig">
<svg viewBox="0 0 680 260" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="20" width="110" height="30"/><text x="65" y="40" text-anchor="middle">componente 1</text>
<rect class="cxa" x="10" y="60" width="110" height="30"/><text x="65" y="80" text-anchor="middle">componente 2</text>
<rect class="cxa" x="10" y="100" width="110" height="30"/><text x="65" y="120" text-anchor="middle">componente 3</text>
<text x="65" y="148" text-anchor="middle" class="ts">um custodiante cada</text>
<line class="ln" x1="120" y1="35" x2="200" y2="70" marker-end="url(#seta)"/>
<line class="ln" x1="120" y1="75" x2="200" y2="75" marker-end="url(#seta)"/>
<line class="ln" x1="120" y1="115" x2="200" y2="80" marker-end="url(#seta)"/>
<rect class="fr" x="190" y="10" width="250" height="160"/>
<text x="430" y="28" text-anchor="end" class="ts td">HSM</text>
<circle cx="225" cy="75" r="20" class="cx"/><text x="225" y="80" text-anchor="middle" class="tb">⊕</text>
<line class="ln" x1="245" y1="75" x2="300" y2="75" marker-end="url(#seta)"/>
<rect class="cxd" x="302" y="55" width="110" height="40"/>
<text x="357" y="73" text-anchor="middle" class="tb">LMK</text>
<text x="357" y="88" text-anchor="middle" class="ts">nunca sai</text>
<rect class="cx" x="210" y="120" width="210" height="36"/>
<text x="315" y="136" text-anchor="middle" class="ts">dual control: dois botões</text>
<text x="315" y="149" text-anchor="middle" class="ts">a cada componente</text>
<line class="lnd" x1="412" y1="75" x2="500" y2="75" marker-end="url(#seta-d)"/>
<text x="456" y="68" text-anchor="middle" class="ts">embrulha</text>
<rect class="cx" x="502" y="20" width="170" height="130"/>
<text x="587" y="40" text-anchor="middle" class="tb">fora do HSM</text>
<text x="587" y="56" text-anchor="middle" class="ts">banco de dados do banco</text>
<rect class="cxa" x="515" y="66" width="145" height="22"/><text x="587" y="81" text-anchor="middle" class="ts tm">key block: PIN</text>
<rect class="cxa" x="515" y="92" width="145" height="22"/><text x="587" y="107" text-anchor="middle" class="ts tm">key block: MAC</text>
<rect class="cxa" x="515" y="118" width="145" height="22"/><text x="587" y="133" text-anchor="middle" class="ts tm">key block: KEK</text>
<line class="ln" x1="587" y1="150" x2="587" y2="200" marker-end="url(#seta)"/>
<line class="ln" x1="587" y1="200" x2="357" y2="200"/>
<line class="ln" x1="357" y1="200" x2="357" y2="174" marker-end="url(#seta)"/>
<text x="470" y="216" text-anchor="middle" class="ts">a cada pedido, o bloco volta junto e é aberto só por dentro</text>
<text x="340" y="248" text-anchor="middle" class="ts">split knowledge: ninguém conhece a LMK inteira · dual control: ninguém age sozinho</text>
</svg>
<figcaption>Figura 4.2 — Os quatro elementos que o projeto modela: componentes, LMK, key blocks e dual control.</figcaption>
</figure>

A Fase 5 do plano acrescenta a interface de host, e a escolha dela foi
revista: em vez de um subconjunto de PKCS#11, um **command set ASCII** no
estilo dos HSM de pagamento. Não é troca de sintaxe. PKCS#11 é uma API de
*biblioteca* — objetos, sessões, atributos. Um command set de pagamento é um
protocolo de *serviço*, sem sessão e sem estado do lado do cliente, e essa
diferença muda como o dispositivo tem de se defender: cada comando chega
sozinho e precisa se bastar.
