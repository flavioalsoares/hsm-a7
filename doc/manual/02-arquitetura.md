# Parte II — Arquitetura interna

## 5. A fronteira criptográfica

É o conceito central, e num projeto bem feito ele é literal e desenhável.
Num documento de certificação FIPS existe um diagrama marcando o que está
dentro, o que está fora, e uma lista de **todas** as portas que atravessam.

Neste projeto:

<figure class="fig">
<svg viewBox="0 0 680 330" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10" y="120" width="100" height="60"/>
<text x="60" y="144" text-anchor="middle" class="tb">host (PC)</text>
<text x="60" y="160" text-anchor="middle" class="ts">hsmtool.py</text>
<text x="60" y="173" text-anchor="middle" class="ts">hsmhost.py</text>
<line class="ln" x1="110" y1="140" x2="178" y2="140" marker-end="url(#seta)"/>
<line class="ln" x1="178" y1="162" x2="110" y2="162" marker-end="url(#seta)"/>
<text x="144" y="133" text-anchor="middle" class="ts">UART</text>
<text x="144" y="178" text-anchor="middle" class="ts">115 200</text>
<rect class="fr" x="170" y="15" width="380" height="250"/>
<text x="540" y="32" text-anchor="end" class="ts td">FPGA: a fronteira</text>
<rect class="cx" x="190" y="45" width="140" height="90"/>
<text x="260" y="70" text-anchor="middle" class="tb">NEORV32</text>
<text x="260" y="88" text-anchor="middle" class="ts">RV32IMC, firmware em C</text>
<text x="260" y="102" text-anchor="middle" class="ts">política, estados, log</text>
<text x="260" y="116" text-anchor="middle" class="ts">IMEM em ROM</text>
<rect class="cx" x="380" y="45" width="155" height="90"/>
<text x="457" y="66" text-anchor="middle" class="tb">coprocessador (CFS)</text>
<text x="457" y="84" text-anchor="middle" class="ts">AES-256, SHA-256</text>
<text x="457" y="98" text-anchor="middle" class="ts">TRNG e testes de saúde</text>
<text x="457" y="112" text-anchor="middle" class="ts">Montgomery (RSA, ECC)</text>
<text x="457" y="126" text-anchor="middle" class="ts">DNA, XADC</text>
<line class="ln" x1="330" y1="90" x2="378" y2="90" marker-end="url(#seta)"/>
<line class="ln" x1="378" y1="90" x2="332" y2="90" marker-end="url(#seta)"/>
<rect class="cxd" x="190" y="160" width="345" height="50"/>
<text x="362" y="182" text-anchor="middle" class="tb">key store em BRAM</text>
<text x="362" y="198" text-anchor="middle" class="ts">LMK, slots, chaves em claro, estado do DRBG</text>
<line class="ln" x1="260" y1="135" x2="260" y2="158" marker-end="url(#seta)"/>
<rect class="cxc" x="190" y="222" width="345" height="32"/>
<text x="362" y="242" text-anchor="middle" class="ts">botões de dual control · display · LEDs</text>
<rect class="cx" x="580" y="160" width="95" height="70"/>
<text x="627" y="180" text-anchor="middle" class="tb">flash SPI</text>
<text x="627" y="196" text-anchor="middle" class="ts">bitstream</text>
<text x="627" y="210" text-anchor="middle" class="ts">≥ 0x400000:</text>
<text x="627" y="223" text-anchor="middle" class="ts">região segura</text>
<line class="ln" x1="535" y1="185" x2="578" y2="185" marker-end="url(#seta)"/>
<rect class="cxc" x="580" y="45" width="95" height="50"/>
<text x="627" y="66" text-anchor="middle" class="tb">DDR3</text>
<text x="627" y="82" text-anchor="middle" class="ts">sem ligação</text>
<line class="lnt" x1="535" y1="70" x2="578" y2="70"/>
<line class="lnd" x1="550" y1="62" x2="564" y2="78"/><line class="lnd" x1="564" y1="62" x2="550" y2="78"/>
<text x="10" y="295" class="ts"><tspan class="tb">entra:</tspan> pedidos, key blocks, dados, PIN blocks</text>
<text x="10" y="312" class="ts"><tspan class="tb">sai:</tspan> key blocks embrulhados, KCVs, criptogramas, MACs, vereditos, handles, log</text>
<text x="400" y="295" class="ts td"><tspan class="tb">nunca sai:</tspan> LMK, chave em claro, PIN em claro,</text>
<text x="400" y="312" class="ts td">estado do DRBG</text>
</svg>
<figcaption>Figura 5.1 — A fronteira criptográfica deste projeto. O que é segredo fica dentro da linha tracejada; a DDR3 nem tem caminho até o processador.</figcaption>
</figure>

**Dentro:** LMK, chaves de trabalho em claro, estado do DRBG.

**Fora:** key blocks embrulhados, KCVs, criptogramas, *handles*, log.

Nada da primeira lista atravessa para a segunda. Todo comando novo é
avaliado contra essa regra **antes** de ser implementado — é o único momento
barato de perceber que um comando vaza.

### Por que a fronteira precisa ser observável

Uma fronteira que você só pode *afirmar* não vale muito. Este projeto usa
UART, e não Ethernet, precisamente por isso: a UART sai por dois pinos
físicos identificáveis, e dá para prender um analisador lógico neles e
capturar tudo que o dispositivo já disse.

O critério de aceitação da Fase 3 explora isso literalmente: rodar a suíte
de testes inteira, capturar a UART, e fazer `grep` das chaves conhecidas do
teste contra a captura. Se aparecer um byte, o projeto falhou — e você
**sabe**, com evidência.

Com um stack de rede no meio, "nenhuma chave vazou" vira uma opinião sobre
dezenas de milhares de linhas de código de terceiros. Com dois fios, vira
uma medida.

### Por que a memória importa mais do que parece

Neste projeto as chaves ficam em BRAM — memória interna ao die do FPGA. Lê-la
exige decapsular o chip.

A DDR3 da placa é externa: o barramento passa por trilhas na PCB e chega a
conectores de expansão. Uma ponta de prova resolve. Por isso a DDR3 não é
apenas *evitada por convenção* — o barramento externo do processador está
**desligado na configuração**, de modo que não existe caminho lógico do SoC
até ela.

Essa é a diferença entre uma **política** e um **controle**: entre "o
firmware não escreve chave na memória externa" e "não há circuito ligando o
processador à memória externa". A primeira depende de todo programador
futuro; a segunda, não.

## 6. Hierarquia de chaves

Um HSM com dezesseis slots de chave não guarda dezesseis segredos. Guarda
**um** — e protege ou deriva todos os outros a partir dele.

Por isso uma chave de trabalho tem dois estados, e a figura separa os dois
lados da fronteira:

- **Em repouso, ela fica fora do HSM**, como key block cifrado sob a LMK, no
  banco de dados do host. Quem rouba o banco leva blocos que não abre.
- **Em uso, ela existe em claro só dentro do HSM.** A aplicação manda o bloco
  junto com o comando; o HSM o abre, usa a chave e a apaga no fim do comando.

<figure class="fig">
<svg viewBox="0 0 680 334" xmlns="http://www.w3.org/2000/svg">
<rect class="fr" x="10" y="10" width="660" height="150"/>
<text x="22" y="28" text-anchor="start" class="ts tb td">DENTRO DO HSM: a fronteira criptográfica</text>
<rect class="cxd" x="30" y="50" width="150" height="56"/><text x="105" y="72" text-anchor="middle" class="tb">LMK</text><text x="105" y="88" text-anchor="middle" class="ts">guardada aqui;</text><text x="105" y="100" text-anchor="middle" class="ts">nunca sai, nem embrulhada</text>
<line class="ln" x1="180" y1="78" x2="228" y2="78" marker-end="url(#seta)"/>
<text x="204" y="70" text-anchor="middle" class="ts">CMAC</text>
<rect class="cx" x="230" y="44" width="120" height="34"/><text x="290" y="60" text-anchor="middle" class="tb">KBEK</text><text x="290" y="72" text-anchor="middle" class="ts">cifra o corpo</text>
<rect class="cx" x="230" y="84" width="120" height="34"/><text x="290" y="100" text-anchor="middle" class="tb">KBAK</text><text x="290" y="112" text-anchor="middle" class="ts">autentica</text>
<line class="ln" x1="350" y1="80" x2="398" y2="80" marker-end="url(#seta)"/>
<text x="374" y="72" text-anchor="middle" class="ts">abrem</text>
<rect class="cxd" x="400" y="40" width="255" height="84"/><text x="527" y="60" text-anchor="middle" class="tb">chave de trabalho em claro</text><text x="527" y="78" text-anchor="middle" class="ts">só enquanto um comando a usa;</text><text x="527" y="92" text-anchor="middle" class="ts">apagada no fim do comando</text><text x="527" y="112" text-anchor="middle" class="ts tm">P0 V2 W2 C0 M0 K4 …</text>
<text x="340" y="140" text-anchor="middle" class="ts">KBEK e KBAK nascem da LMK a cada bloco e são apagadas depois;</text>
<text x="340" y="152" text-anchor="middle" class="ts">em claro, só a LMK fica guardada</text>
<line class="ln" x1="560" y1="206" x2="560" y2="166" marker-end="url(#seta)"/>
<text x="570" y="182" text-anchor="start" class="ts">vai junto com</text>
<text x="570" y="194" text-anchor="start" class="ts">cada comando</text>
<line class="ln" x1="130" y1="166" x2="130" y2="206" marker-end="url(#seta)"/>
<text x="140" y="182" text-anchor="start" class="ts">K0 gera, K6 importa:</text>
<text x="140" y="194" text-anchor="start" class="ts">sai como key block sob a LMK</text>
<rect class="lnt" x="10" y="206" width="660" height="122"/>
<text x="22" y="224" text-anchor="start" class="ts tb">FORA DO HSM: o banco de dados do host — key blocks X9.143, cifrados sob a LMK</text>
<rect class="cxa" x="20" y="232" width="120" height="44"/><text x="80" y="250" text-anchor="middle" class="tb">KEK (K0)</text><text x="80" y="266" text-anchor="middle" class="ts">troca com outro banco</text>
<rect class="cxa" x="150" y="232" width="120" height="44"/><text x="210" y="250" text-anchor="middle" class="tb">PIN (P0)</text><text x="210" y="266" text-anchor="middle" class="ts">zona, terminal</text>
<rect class="cxa" x="280" y="232" width="120" height="44"/><text x="340" y="250" text-anchor="middle" class="tb">BDK (B0)</text><text x="340" y="266" text-anchor="middle" class="ts">deriva os terminais</text>
<rect class="cxa" x="410" y="232" width="120" height="44"/><text x="470" y="250" text-anchor="middle" class="tb">dados, MAC</text><text x="470" y="266" text-anchor="middle" class="ts">D0, M0..M8</text>
<rect class="cxa" x="540" y="232" width="120" height="44"/><text x="600" y="250" text-anchor="middle" class="tb">CVV, PVV</text><text x="600" y="266" text-anchor="middle" class="ts">C0, V1, V2</text>
<text x="80" y="296" text-anchor="middle" class="ts">sob uma KEK, a chave</text>
<text x="80" y="308" text-anchor="middle" class="ts">vai a outra instituição</text>
<text x="340" y="296" text-anchor="middle" class="ts">deriva a IPEK de</text>
<text x="340" y="308" text-anchor="middle" class="ts">cada terminal</text>
<text x="535" y="302" text-anchor="middle" class="ts">sem a LMK, cada bloco é inútil</text>
</svg>
<figcaption>Figura 6.1 — A hierarquia de chaves, dentro e fora do HSM. Dentro, em claro, fica só a LMK. As chaves de trabalho ficam fora, como key blocks sob ela, e entram em claro só durante um comando.</figcaption>
</figure>

Neste equipamento há uma exceção à figura: as chaves criadas pelo console
(`gen-key`, `comp-load`) ficam também em slots dentro do HSM, na BRAM, e são
usadas por handle. Na flash, elas ficam só embrulhadas sob a LMK (seção 27).
As chaves da porta host seguem a figura.

Três razões, e vale entender cada uma porque elas explicam decisões
aparentemente arbitrárias mais adiante.

**Backup e migração.** Se cada chave fosse independente, mover o serviço para
outro HSM significaria mover N segredos, cada um com seu próprio
procedimento. Com a hierarquia, basta que o HSM novo tenha **a mesma LMK**. E
isso acontece sem que a LMK saia do HSM antigo.

A LMK nunca sai do HSM, nem embrulhada. O que existe fora dele são os
**componentes**: cada custodiante guarda o seu, em papel ou em cartão, num
envelope lacrado, num cofre. Nenhum componente sozinho revela nada da LMK
(seção 7). Para migrar, os mesmos custodiantes fazem no HSM novo a mesma
cerimônia que fizeram no antigo. O HSM novo junta os mesmos componentes, monta
a mesma LMK e mostra o mesmo KCV. Os key blocks não mudam: continuam no banco
de dados, e o HSM novo os abre como o antigo abria, porque eles sempre foram
apenas dados cifrados sob a LMK.

<figure class="fig">
<svg viewBox="0 0 680 250" xmlns="http://www.w3.org/2000/svg">
<rect class="fr" x="10" y="30" width="150" height="70"/><text x="85" y="52" text-anchor="middle" class="tb">HSM antigo</text><text x="85" y="70" text-anchor="middle" class="ts td">LMK: nunca sai</text><text x="85" y="86" text-anchor="middle" class="ts tm">KCV 7B1D2F</text>
<rect class="fr" x="520" y="30" width="150" height="70"/><text x="595" y="52" text-anchor="middle" class="tb">HSM novo</text><text x="595" y="70" text-anchor="middle" class="ts td">a mesma LMK, montada</text><text x="595" y="86" text-anchor="middle" class="ts tm">KCV 7B1D2F</text>
<rect class="cxd" x="215" y="20" width="250" height="90"/><text x="340" y="38" text-anchor="middle" class="ts tb td">no cofre, um envelope por custodiante</text>
<rect class="cxa" x="228" y="50" width="70" height="44"/><text x="263" y="70" text-anchor="middle" class="tb">A</text><text x="263" y="86" text-anchor="middle" class="ts">componente</text>
<rect class="cxa" x="305" y="50" width="70" height="44"/><text x="340" y="70" text-anchor="middle" class="tb">B</text><text x="340" y="86" text-anchor="middle" class="ts">componente</text>
<rect class="cxa" x="382" y="50" width="70" height="44"/><text x="417" y="70" text-anchor="middle" class="tb">C</text><text x="417" y="86" text-anchor="middle" class="ts">componente</text>
<line class="lnt" x1="215" y1="65" x2="162" y2="65" marker-end="url(#seta-t)"/>
<text x="188" y="124" text-anchor="middle" class="ts">1ª cerimônia</text>
<line class="ln" x1="465" y1="65" x2="518" y2="65" marker-end="url(#seta)"/>
<text x="492" y="124" text-anchor="middle" class="ts">cerimônia de migração</text>
<rect class="cxc" x="215" y="160" width="250" height="44"/><text x="340" y="178" text-anchor="middle" class="tb">banco de dados</text><text x="340" y="194" text-anchor="middle" class="ts">os key blocks, sob a LMK: não mudam</text>
<path class="lnt" d="M85,100 L85,182 L213,182" marker-start="url(#seta-t)"/>
<path class="ln" d="M465,182 L595,182 L595,102" marker-end="url(#seta)"/>
<text x="130" y="174" text-anchor="middle" class="ts">abria</text>
<text x="530" y="174" text-anchor="middle" class="ts">abre igual</text>
<text x="340" y="236" text-anchor="middle" class="ts">o que viaja são os componentes, separados, cada um com uma pessoa; a LMK inteira não existe fora de um HSM</text>
</svg>
<figcaption>Figura 6.2 — Migrar sem tirar a LMK do HSM. Os custodiantes repetem a cerimônia no HSM novo, que monta a mesma LMK; os key blocks continuam válidos.</figcaption>
</figure>

Em alguns equipamentos o próprio HSM gera a LMK e grava os componentes em
cartões, um por custodiante. A regra é a mesma: a LMK sai dividida, e nunca
inteira, nem embrulhada.

Neste equipamento, a LMK de desenvolvimento é montada pela cerimônia do
console, com os dois botões, e desde a fase 4 fica na flash (seção 27). Uma
placa nova, com os mesmos componentes, monta a mesma LMK e abre os mesmos key
blocks.

**Revogação em bloco.** Zeroizar a LMK invalida instantaneamente **todo** key
block protegido por ela, onde quer que esteja: em backup, em fita, no
servidor de outra filial. É a única operação de destruição que se consegue
executar em tempo constante sobre dados que não estão na sua posse.

**Separação de propósito.** KBEK (chave de cifra) e KBAK (chave de
autenticação) são derivadas por CMAC, com rótulos distintos, da chave que
protege o key block (a KBPK). Para os blocos guardados pelo equipamento, a
KBPK é a LMK; numa troca com outra instituição, é a KEK (seção 8). A chave
que cifra o corpo do key block nunca é a mesma que autentica seu cabeçalho.
Se fosse, quebrar uma quebraria as duas — e existem ataques que exploram
exatamente o reuso de chave entre modos de operação.

### Atributos de chave

Cada chave carrega metadados que **fazem parte** dela, no sentido de que
alterá-los invalida a autenticação. Estrutura usada neste projeto:

```c
typedef struct {
    uint8_t  in_use;
    uint8_t  usage[2];      // TR-31: 'B0'=BDK, 'K0'=KEK, 'D0'=dados...
    uint8_t  algorithm;     // 'A'=AES, 'T'=3DES
    uint8_t  mode_of_use;   // 'E'=cifrar, 'D'=decifrar, 'B'=ambos, 'N'=nenhum
    uint8_t  exportability; // 'E'=exportável, 'N'=não, 'S'=sensível
    uint8_t  key_len;
    uint8_t  key[32];       // BRAM. Nunca sai daqui em claro.
    uint8_t  kcv[3];
    uint32_t use_count;
} key_slot_t;
```

`exportability` é o campo que mais ensina. Uma chave marcada `'N'` não pode
sair do módulo **por caminho nenhum** — nem embrulhada. Se algum comando
conseguir exportá-la, o comando está errado. É exatamente o tipo de
propriedade que se testa exaustivamente, porque ela vale zero se houver um
único caminho esquecido.

`use_count` existe porque uso é informação: uma chave que devia ser usada
mil vezes por dia e foi usada um milhão indica alguém explorando a API.

## 7. Cerimônia de chave, split knowledge e dual control

A LMK não é gerada num lugar e copiada para outro. Ela é **montada dentro do
dispositivo**, a partir de componentes que nenhuma pessoa vê juntos.

<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10"  y="20" width="120" height="34"/><text x="70"  y="42" text-anchor="middle">componente A</text>
<rect class="cxa" x="10"  y="80" width="120" height="34"/><text x="70"  y="102" text-anchor="middle">componente B</text>
<rect class="cxa" x="10"  y="140" width="120" height="34"/><text x="70"  y="162" text-anchor="middle">componente C</text>
<circle class="cx" cx="210" cy="37" r="16"/><text x="210" y="42" text-anchor="middle" class="tb">⊕</text>
<circle class="cx" cx="210" cy="97" r="16"/><text x="210" y="102" text-anchor="middle" class="tb">⊕</text>
<circle class="cx" cx="210" cy="157" r="16"/><text x="210" y="162" text-anchor="middle" class="tb">⊕</text>
<line class="ln" x1="130" y1="37" x2="192" y2="37" marker-end="url(#seta)"/>
<line class="ln" x1="130" y1="97" x2="192" y2="97" marker-end="url(#seta)"/>
<line class="ln" x1="130" y1="157" x2="192" y2="157" marker-end="url(#seta)"/>
<line class="ln" x1="210" y1="53" x2="210" y2="79" marker-end="url(#seta)"/>
<line class="ln" x1="210" y1="113" x2="210" y2="139" marker-end="url(#seta)"/>
<text x="220" y="70" class="ts">acumulado</text>
<line class="ln" x1="226" y1="157" x2="300" y2="157" marker-end="url(#seta)"/>
<rect class="cxd" x="302" y="140" width="100" height="34"/><text x="352" y="162" text-anchor="middle" class="tb">LMK</text>
<rect class="cx" x="440" y="20" width="230" height="34"/><text x="555" y="42" text-anchor="middle" class="ts">KCV(A) = 3 bytes de AES_A(0…0)</text>
<rect class="cx" x="440" y="80" width="230" height="34"/><text x="555" y="102" text-anchor="middle" class="ts">KCV(B), de novo só do componente</text>
<rect class="cx" x="440" y="140" width="230" height="34"/><text x="555" y="162" text-anchor="middle" class="ts">KCV(C), e o KCV da LMK no fim</text>
<line class="lnt" x1="300" y1="37" x2="438" y2="37" marker-end="url(#seta-t)"/>
<line class="lnt" x1="300" y1="97" x2="438" y2="97" marker-end="url(#seta-t)"/>
<line class="lnt" x1="402" y1="157" x2="438" y2="157" marker-end="url(#seta-t)"/>
<text x="340" y="200" text-anchor="middle" class="ts">cada passo pede os dois botões · cada custodiante confere o KCV do que digitou · nenhum vê a LMK</text>
</svg>
<figcaption>Figura 7.1 — A montagem da LMK por componentes. O XOR com um componente desconhecido e uniforme não revela nada; o KCV confirma a digitação sem revelar a chave.</figcaption>
</figure>

Cada custodiante carrega apenas o seu componente. Nenhum componente isolado
revela nada sobre a LMK — é o argumento do one-time pad: XOR com material
desconhecido e uniforme não vaza informação. Isso é **split knowledge**.

### KCV: verificar sem revelar

A cada passo, o dispositivo devolve um **KCV** (*Key Check Value*): os três
bytes mais significativos do resultado de cifrar um bloco de zeros com a
chave.

É um resumo pequeno o suficiente para não ajudar um atacante — 24 bits não
permitem recuperar uma chave de 256 — e grande o suficiente para pegar
digitação errada, componente trocado ou cartão corrompido. O host calcula o
KCV esperado de forma independente e compara.

Repare no padrão: o dispositivo precisa provar que recebeu a coisa certa,
sem revelar a coisa. Essa tensão reaparece o tempo todo em criptografia
aplicada.

### Dual control

Split knowledge diz que ninguém *sabe* a chave inteira. Dual control diz que
ninguém *age* sozinho.

Neste projeto, `LMK_LOAD_COMPONENT` só é aceito com **dois botões físicos
pressionados simultaneamente**. É simplório e é exatamente o ponto: separa
fisicamente *quem digita* de *quem autoriza*. Um operador sozinho, mesmo com
acesso administrativo total ao host, não carrega componente nenhum.

Por que isso existe, além de desconfiança: um operador que **não pode** agir
sozinho não pode ser coagido com sucesso individual, não pode ser subornado
individualmente, e não pode cometer o erro sozinho. Remove-se a
possibilidade, não a tentação.

Num HSM comercial o mecanismo é mais rico — cada custodiante se autentica
com smartcard e PIN, e o log registra *quem* autorizou. Mas a estrutura é a
mesma, e a versão com dois botões torna visível o que a versão com
smartcards esconde atrás de conveniência.

### Por que a integridade do botão é código de segurança

Um contato mecânico produz dezenas de transições elétricas em poucos
milissegundos ao ser pressionado ou solto. Sem filtragem, um único toque
parece vários pressionamentos.

Se o firmware ler "pressionado" num ressalto que ocorreu **depois** de o
custodiante soltar o botão, ele registrou uma autorização que ninguém deu. O
mecanismo de autorização precisa refletir **intenção humana**, não estado
elétrico de contato — e a distância entre as duas coisas é uns 10 ms de
filtro.

### Guardar os componentes: o único backup da LMK

A LMK nunca sai do HSM, nem embrulhada (seção 6). Por isso **os componentes
são o único backup dela**. Se o HSM quebrar e os componentes tiverem sido
perdidos, a LMK deixa de existir em qualquer lugar, e com ela tudo o que
estava sob ela.

<figure class="fig">
<svg viewBox="0 0 680 272" xmlns="http://www.w3.org/2000/svg">
<rect class="cxd" x="10" y="20" width="170" height="46"/><text x="95" y="39" text-anchor="middle" class="tb">HSM quebrou</text><text x="95" y="55" text-anchor="middle" class="ts">ou foi zeroizado</text>
<rect class="cxd" x="10" y="80" width="170" height="46"/><text x="95" y="99" text-anchor="middle" class="tb">componentes perdidos</text><text x="95" y="115" text-anchor="middle" class="ts">ou incompletos</text>
<line class="lnd" x1="180" y1="43" x2="258" y2="68" marker-end="url(#seta-d)"/>
<line class="lnd" x1="180" y1="103" x2="258" y2="84" marker-end="url(#seta-d)"/>
<text x="219" y="140" text-anchor="middle" class="ts td">os dois juntos</text>
<rect class="cxc" x="260" y="48" width="160" height="56"/><text x="340" y="68" text-anchor="middle" class="tb">LMK</text><text x="340" y="84" text-anchor="middle" class="ts">não existe mais</text><text x="340" y="97" text-anchor="middle" class="ts">em lugar nenhum</text>
<line class="ln" x1="420" y1="76" x2="478" y2="76" marker-end="url(#seta)"/>
<rect class="cxc" x="480" y="48" width="190" height="56"/><text x="575" y="68" text-anchor="middle" class="tb">banco de dados</text><text x="575" y="84" text-anchor="middle" class="ts">key blocks intactos,</text><text x="575" y="97" text-anchor="middle" class="ts">que ninguém mais abre</text>
<path class="ln" d="M575,104 L575,150 L110,150" fill="none"/>
<line class="ln" x1="110" y1="150" x2="110" y2="172" marker-end="url(#seta)"/>
<line class="ln" x1="340" y1="150" x2="340" y2="172" marker-end="url(#seta)"/>
<line class="ln" x1="575" y1="150" x2="575" y2="172" marker-end="url(#seta)"/>
<rect class="cxa" x="10" y="174" width="200" height="66"/><text x="110" y="196" text-anchor="middle" class="tb">KEK e chaves de zona</text><text x="110" y="212" text-anchor="middle" class="ts">uma cerimônia nova</text><text x="110" y="225" text-anchor="middle" class="ts">com cada parceiro</text>
<rect class="cxa" x="240" y="174" width="200" height="66"/><text x="340" y="196" text-anchor="middle" class="tb">BDK</text><text x="340" y="212" text-anchor="middle" class="ts">chave inicial nova</text><text x="340" y="225" text-anchor="middle" class="ts">em todos os terminais</text>
<rect class="cxd" x="470" y="174" width="200" height="66"/><text x="570" y="192" text-anchor="middle" class="tb">chaves de PVV e de CVV</text><text x="570" y="207" text-anchor="middle" class="ts">reemitir todos os cartões:</text><text x="570" y="220" text-anchor="middle" class="ts">o PVV, o offset e o CVV</text><text x="570" y="233" text-anchor="middle" class="ts">foram feitos com a chave antiga</text>
<text x="340" y="262" text-anchor="middle" class="ts">o custo de refazer vai de uma cerimônia à reemissão da carteira inteira de cartões</text>
</svg>
<figcaption>Figura 7.2 — Sem HSM e sem componentes, a LMK se perde. Os key blocks sobrevivem, mas nenhum HSM os abre mais, e cada chave tem de ser refeita.</figcaption>
</figure>

| Chave perdida | O que é preciso refazer |
|---|---|
| KEK e chaves de zona | uma cerimônia nova com cada instituição parceira |
| BDK | carregar chave nova em **todos** os terminais |
| Chave de PVV ou de offset, chave de CVV | **reemitir todos os cartões**: o PVV, o offset e o CVV deles foram calculados com a chave antiga |

Por isso, guardar os componentes é parte da segurança, e não um detalhe
administrativo. A prática da categoria, que as regras do PCI PIN cobram
(seção 20):

- cada componente fica num envelope lacrado, com número de série, num cofre;
- cada componente tem o seu custodiante, e um substituto;
- todo acesso ao cofre fica registrado;
- ninguém tem acesso a mais de um componente.

Os componentes não são a única proteção, mas são a raiz de todas:

| Mecanismo | Protege contra | Precisa dos componentes? |
|---|---|---|
| Vários HSMs com a mesma LMK, carregados na mesma cerimônia | um HSM quebrar: os outros continuam | não, para continuar operando |
| Os componentes no cofre | todos os HSMs se perderem; trocar de equipamento | são eles |
| Exportar chave por chave sob uma KEK (`K4` no antigo, `K6` no novo) | migrar sem a LMK antiga | sim: a KEK nasce de componentes nos dois HSMs; e só sai a chave exportável (seção 8) |
| Trocar a LMK (rotação) | uma LMK velha demais | sim: o HSM precisa da antiga e da nova ao mesmo tempo, para traduzir cada key block |

O HSM protege a LMK contra **roubo**. Contra a **perda**, quem a protege é o
processo.

É uma escolha de projeto da categoria. O HSM poderia ter uma função "exporte a
LMK cifrada", mais cômoda. Mas uma LMK exportável é uma LMK roubável: quem
conseguisse usar essa função, ou a chave que a protege, levaria tudo. A
categoria escolheu o contrário: a LMK não sai, e o preço é a disciplina de
guardar os componentes.

Neste equipamento, a LMK de desenvolvimento é conhecida e está escrita nas
notas do projeto, e a perda não é problema. Mas o modelo é o mesmo: depois de
um `zeroize`, só os componentes trazem de volta os key blocks guardados.

## 8. Key blocks: por que o formato é feio

TR-31 (hoje ANSI X9.143) é o formato de troca de chaves da indústria de
pagamentos. Um key block é ASCII, tem cabeçalho legível, e parece
desnecessariamente complicado. Cada complicação existe por causa de um
incidente.

<figure class="fig">
<svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
<g class="tm">
<rect class="cxa" x="10"  y="40" width="22" height="30"/><text x="21"  y="60" text-anchor="middle">D</text>
<rect class="cxa" x="32"  y="40" width="64" height="30"/><text x="64"  y="60" text-anchor="middle">0112</text>
<rect class="cxd" x="96"  y="40" width="36" height="30"/><text x="114" y="60" text-anchor="middle">K0</text>
<rect class="cxa" x="132" y="40" width="22" height="30"/><text x="143" y="60" text-anchor="middle">A</text>
<rect class="cxd" x="154" y="40" width="22" height="30"/><text x="165" y="60" text-anchor="middle">B</text>
<rect class="cxa" x="176" y="40" width="36" height="30"/><text x="194" y="60" text-anchor="middle">00</text>
<rect class="cxd" x="212" y="40" width="22" height="30"/><text x="223" y="60" text-anchor="middle">N</text>
<rect class="cxa" x="234" y="40" width="36" height="30"/><text x="252" y="60" text-anchor="middle">00</text>
<rect class="cxa" x="270" y="40" width="36" height="30"/><text x="288" y="60" text-anchor="middle">00</text>
<rect class="cx"  x="306" y="40" width="230" height="30"/><text x="421" y="60" text-anchor="middle">corpo cifrado (hex)</text>
<rect class="cxv" x="536" y="40" width="134" height="30"/><text x="603" y="60" text-anchor="middle">MAC (hex)</text>
</g>
<text x="21"  y="88" text-anchor="middle" class="ts">versão</text>
<text x="64"  y="100" text-anchor="middle" class="ts">tamanho</text>
<text x="114" y="88" text-anchor="middle" class="ts td">uso</text>
<text x="143" y="100" text-anchor="middle" class="ts">alg.</text>
<text x="165" y="112" text-anchor="middle" class="ts td">modo</text>
<text x="194" y="88" text-anchor="middle" class="ts">versão da chave</text>
<text x="223" y="124" text-anchor="middle" class="ts td">exportab.</text>
<text x="252" y="100" text-anchor="middle" class="ts">opcionais</text>
<text x="288" y="112" text-anchor="middle" class="ts">reserv.</text>
<text x="421" y="90" text-anchor="middle" class="ts">tamanho da chave · chave · enchimento aleatório</text>
<text x="421" y="104" text-anchor="middle" class="ts">AES-CBC sob a KBEK</text>
<text x="603" y="90" text-anchor="middle" class="ts">CMAC sob a KBAK</text>
<path class="ln" d="M10,34 L10,26 L536,26 L536,34"/>
<text x="273" y="20" text-anchor="middle" class="ts">o MAC cobre o cabeçalho e o corpo em claro</text>
<rect class="cxd" x="20" y="148" width="640" height="48"/>
<text x="340" y="168" text-anchor="middle" class="tb td">Um caractere trocado no cabeçalho, e o MAC não confere mais.</text>
<text x="340" y="185" text-anchor="middle" class="ts">N → E (para exportar), K0 → D0 (para cifrar dados com a KEK): o bloco inteiro é recusado</text>
</svg>
<figcaption>Figura 8.1 — Anatomia de um key block X9.143, versão D. Em vermelho, os campos que um atacante gostaria de trocar.</figcaption>
</figure>

O cabeçalho declara o que a chave é: versão do formato, comprimento, **uso**
(`K0` = KEK, `B0` = BDK, `D0` = dados), algoritmo, **modo de uso** (só
cifrar, só decifrar, ambos) e **exportabilidade**.

### O ataque que o formato existe para impedir

Se o cabeçalho não fosse autenticado junto com o corpo, um atacante poderia
pegar um key block legítimo e:

- trocar `N` (não exportável) por `E` (exportável), e depois exportar a
  chave em claro por um caminho autorizado;
- trocar o uso de "só verificar PIN" para "cifrar dados arbitrários", e usar
  a chave de PIN como oráculo de cifra;
- trocar o algoritmo declarado, induzindo o módulo a usar a chave num modo
  para o qual ela não foi projetada.

A chave continuaria criptograficamente válida, o HSM a importaria sem
reclamar, e ela passaria a fazer algo que o dono nunca autorizou.

Isso **não é hipotético**. É a razão histórica pela qual os formatos
anteriores — os chamados *variant key blocks*, em que o tipo era codificado
por XOR com um vetor de controle — foram abandonados pela indústria. Bond e
Clulow mostraram famílias inteiras de ataques que consistiam em manipular
esses vetores para converter uma chave de um tipo em outro.

Consequência de projeto: **um byte errado no cabeçalho explode o MAC
inteiro**. É o comportamento desejado, e é o que torna a implementação
irritante de acertar.

### Autenticar com uma chave: o CMAC e o HMAC

O MAC do key block é um **código de autenticação de mensagem**: um valor
curto que só quem tem a chave calcula, e que muda se um bit da mensagem
mudar. Quem recebe recalcula e compara. Há dois jeitos padronizados de
fazer um MAC: a partir de uma **cifra de bloco** (o CMAC, NIST SP 800-38B) ou
a partir de uma **função de hash** (o HMAC, FIPS 198-1 e RFC 2104). Os dois
partem de uma ideia simples que não funciona, e a correção é o que dá nome a
cada um.

#### O CMAC

**1. O CBC-MAC, e por que ele sozinho não basta.** A ideia simples é cifrar
a mensagem em CBC, com IV zero, e ficar só com o último bloco:

```
    C1 = E_K( M1 )
    Cj = E_K( C(j-1) ⊕ Mj )        j = 2 .. q
    CBC-MAC = Cq
```

Com mensagens de **um tamanho fixo**, isso é seguro. Com tamanhos variáveis,
não é. Quem viu o MAC `T` de uma mensagem de um bloco `M` forja o MAC de
outra mensagem sem conhecer a chave:

```
    T = E_K( M )                              o MAC visto
    M' = M ‖ ( M ⊕ T )                        a mensagem forjada, 2 blocos
    CBC-MAC(M') = E_K( T ⊕ M ⊕ T ) = E_K( M ) = T
```

O segundo bloco anula o efeito do primeiro, e o MAC de `M'` é o mesmo `T`.
O preenchimento também cria ambiguidade: com zeros, `M` e `M ‖ 00` dão o
mesmo MAC. O retail MAC (seção 39.10) resolve parte disso com uma chave a
mais no último bloco. O CMAC resolve com uma marca no último bloco.

**2. As subchaves K1 e K2.** O CMAC deriva duas subchaves da chave `K`,
cifrando um bloco de zeros:

```
    L  = E_K( 00 00 ... 00 )
    K1 = dbl( L )
    K2 = dbl( K1 )

    dbl(x): desloca x um bit para a esquerda; se o bit que saiu era 1,
            faz XOR do último byte com 87 (bloco de 128 bits, AES)
                                    ou com 1B (bloco de 64 bits, 3DES)
```

`dbl` é a multiplicação por 2 num corpo finito de 2¹²⁸ (ou 2⁶⁴) elementos. A
constante `87` (ou `1B`) é o polinômio que define esse corpo. O que importa
na prática: `K1` e `K2` dependem da chave, são diferentes entre si, e quem
não tem a chave não as conhece.

**3. O último bloco.** É o único que muda em relação ao CBC-MAC:

- **completo** (a mensagem tem um múltiplo de 16 bytes, e não está vazia):
  XOR com `K1`;
- **incompleto, ou mensagem vazia**: preenchimento `80 00 … 00` até 16
  bytes, e XOR com `K2`.

A forja do item 1 deixa de funcionar: ela precisa pôr `T` na entrada do
bloco seguinte, mas o bloco que produziu `T` foi misturado com `K1`, e o
atacante não sabe com quanto. A ambiguidade do preenchimento também some: a
mensagem preenchida e a mensagem que já termina em `80 00 …` usam subchaves
diferentes. A mensagem vazia é um caso válido, e o código tem de tratá-lo: o
KAT do equipamento passa pelos três casos.


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="40" y="20" width="90" height="28"/><text x="85" y="39" text-anchor="middle" class="tm">M1</text>
<rect class="cxa" x="210" y="20" width="90" height="28"/><text x="255" y="39" text-anchor="middle" class="tm">M2</text>
<rect class="cxa" x="380" y="20" width="230" height="28"/><text x="495" y="39" text-anchor="middle" class="tm">Mq   (ou Mq ‖ 80 00…)</text>
<rect class="cx" x="40" y="100" width="90" height="30"/><text x="85" y="120" text-anchor="middle" class="ts">E, K</text>
<circle class="cx" cx="255" cy="76" r="12"/><text x="255" y="81" text-anchor="middle" class="tb">⊕</text>
<rect class="cx" x="210" y="100" width="90" height="30"/><text x="255" y="120" text-anchor="middle" class="ts">E, K</text>
<circle class="cx" cx="450" cy="76" r="12"/><text x="450" y="81" text-anchor="middle" class="tb">⊕</text>
<rect class="cxd" x="405" y="100" width="90" height="30"/><text x="450" y="120" text-anchor="middle" class="ts">E, K</text>
<rect class="cxc" x="530" y="62" width="110" height="28"/><text x="585" y="81" text-anchor="middle" class="tm">K1 ou K2</text>
<line class="ln" x1="85" y1="48" x2="85" y2="98" marker-end="url(#seta)"/>
<line class="ln" x1="255" y1="48" x2="255" y2="62" marker-end="url(#seta)"/>
<line class="ln" x1="255" y1="88" x2="255" y2="98" marker-end="url(#seta)"/>
<line class="ln" x1="450" y1="48" x2="450" y2="62" marker-end="url(#seta)"/>
<line class="ln" x1="530" y1="76" x2="464" y2="76" marker-end="url(#seta)"/>
<line class="ln" x1="450" y1="88" x2="450" y2="98" marker-end="url(#seta)"/>
<path class="ln" d="M130,115 L180,115 L180,76 L241,76" fill="none" marker-end="url(#seta)"/>
<path class="ln" d="M300,115 L350,115 L350,76 L436,76" fill="none" stroke-dasharray="4 3" marker-end="url(#seta)"/>
<text x="352" y="70" class="ts">…</text>
<line class="ln" x1="450" y1="130" x2="450" y2="160" marker-end="url(#seta)"/>
<rect class="cxv" x="390" y="162" width="120" height="28"/><text x="450" y="181" text-anchor="middle" class="tm">tag (16 bytes)</text>
<text x="85" y="160" text-anchor="middle" class="ts">o CBC-MAC de sempre…</text>
<text x="590" y="110" text-anchor="middle" class="ts">K1: último bloco completo</text>
<text x="590" y="124" text-anchor="middle" class="ts">K2: preenchido, ou vazio</text>
<text x="340" y="220" text-anchor="middle" class="ts">K1 e K2 saem de E_K(0): só quem tem a chave sabe o que entrou no último bloco</text>
</svg>
<figcaption>Figura 8.2 — O CMAC é o CBC-MAC com uma marca secreta no último bloco: K1 se ele está completo, K2 se foi preenchido.</figcaption>
</figure>

**4. Um exemplo com números**, com AES-256 e dois vetores do CAVP (o arquivo
`CMACGenAES256.rsp`, o mesmo do autoteste). O CAVP publica só os 5
primeiros bytes da tag; o resto é conta, conferida com a biblioteca
`cryptography`.

```
Vetor 16: mensagem de 16 bytes, um bloco completo -> K1
  K   916CD8119A4D7E825E01A86F93B0EEE4A46D29216115CC9EF67A784C19C1CA1E
  M   3310FC5BC910F4C9B9CF4957AC638AE7
  L   42E46BAC0156A5F74F0F5EC44CBA81F4      primeiro bit 0
  K1  85C8D75802AD4BEE9E1EBD88997503E8      L deslocado, sem o 87
  K2  0B91AEB0055A97DD3C3D7B1132EA0757      K1 começa com 1: deslocado, e 87
  M⊕K1   B6D82B03CBBDBF2727D1F4DF3516890F
  tag    03F045F886 F50D68CEC936775E3DA38A  (CAVP: 03f045f886)

Vetor 48: mensagem de 10 bytes, incompleta -> preenche, K2
  K   6C0B2C3C5FEC961AB84E68F56CA166586E5942FB2594B18A1DFDC4A8FDF07634
  M   F08F890875E139480489
  K2  10244D164A9A1967B97FEF1BC10D7721
  M ‖ 80 00 00 00 00 00   F08F890875E139480489800000000000
  (M ‖ 80 00…) ⊕ K2       E0ABC41E3F7B202FBDF66F1BC10D7721
  tag    B49C2239E7 8C31C52EE05C7649038E4C  (CAVP: b49c2239e7)
```

Nos dois casos a mensagem tem um bloco só, então a tag é a cifra do último
bloco já marcado: `E_K(M ⊕ K1)` e `E_K((M ‖ 80 00…) ⊕ K2)`.

#### O HMAC

**1. O hash com chave, e por que ele sozinho não basta.** A ideia simples é
pôr a chave antes da mensagem e calcular o hash: `H(K ‖ M)`. Com SHA-256,
isso é forjável. O SHA-256 processa a entrada em blocos de 64 bytes, e o
resultado é o **estado interno** depois do último bloco. Quem viu
`H(K ‖ M)` e sabe o tamanho de `K ‖ M` continua o cálculo a partir desse
estado e obtém `H(K ‖ M ‖ p ‖ X)` para qualquer `X`, sem conhecer `K` (`p` é o
preenchimento que o SHA-256 pôs no fim de `K ‖ M`). É o **ataque de extensão
de comprimento**. Pôr a chave no fim, `H(M ‖ K)`, troca esse problema por
outro: uma colisão de `H` sobre `M` vira uma colisão de MAC.

**2. As "subchaves" do HMAC.** O HMAC também tira duas chaves derivadas de
`K`, mas sem cifrar nada:

```
    K0 = K completada com zeros até 64 bytes (o bloco do SHA-256)
         ou, se K tem mais de 64 bytes, H(K) completada com zeros

    chave interna  = K0 ⊕ 36 36 36 ... 36      (ipad)
    chave externa  = K0 ⊕ 5C 5C 5C ... 5C      (opad)
```

As duas constantes só precisam ser diferentes uma da outra: as duas chaves
derivadas ficam diferentes em metade dos bits.

**3. As duas passadas.** O HMAC calcula o hash duas vezes:

```
    interno = H( (K0 ⊕ ipad) ‖ M )
    HMAC    = H( (K0 ⊕ opad) ‖ interno )
```

A passada externa fecha a extensão de comprimento. O que sai é o hash de uma
entrada de tamanho fixo (64 + 32 bytes), que começa com uma chave que o
atacante não conhece. Estender esse hash dá o hash de outra coisa, não o HMAC
de outra mensagem. O preço é pequeno: duas passadas de compressão a mais por
mensagem, qualquer que seja o tamanho dela. Os casos da chave estão no
item 2: chave curta é completada, chave de exatamente 64 bytes entra como
está, e chave longa passa antes pelo hash.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="cxc" x="20" y="30" width="130" height="30"/><text x="85" y="50" text-anchor="middle" class="tm">K0 ⊕ ipad</text>
<rect class="cxa" x="150" y="30" width="170" height="30"/><text x="235" y="50" text-anchor="middle" class="tm">M</text>
<rect class="cx" x="360" y="30" width="110" height="30"/><text x="415" y="50" text-anchor="middle" class="ts">SHA-256</text>
<rect class="cxa" x="510" y="30" width="150" height="30"/><text x="585" y="50" text-anchor="middle" class="tm">interno (32)</text>
<line class="ln" x1="320" y1="45" x2="358" y2="45" marker-end="url(#seta)"/>
<line class="ln" x1="470" y1="45" x2="508" y2="45" marker-end="url(#seta)"/>
<rect class="cxc" x="20" y="110" width="130" height="30"/><text x="85" y="130" text-anchor="middle" class="tm">K0 ⊕ opad</text>
<rect class="cxa" x="150" y="110" width="170" height="30"/><text x="235" y="130" text-anchor="middle" class="tm">interno (32)</text>
<rect class="cx" x="360" y="110" width="110" height="30"/><text x="415" y="130" text-anchor="middle" class="ts">SHA-256</text>
<rect class="cxv" x="510" y="110" width="150" height="30"/><text x="585" y="130" text-anchor="middle" class="tm">HMAC (32)</text>
<line class="ln" x1="320" y1="125" x2="358" y2="125" marker-end="url(#seta)"/>
<line class="ln" x1="470" y1="125" x2="508" y2="125" marker-end="url(#seta)"/>
<path class="lnt" d="M585,60 L585,85 L305,85 L305,108" fill="none" marker-end="url(#seta-t)"/>
<text x="20" y="22" class="ts">passada interna: qualquer tamanho de M</text>
<text x="20" y="102" class="ts">passada externa: entrada de tamanho fixo, 64 + 32 bytes</text>
<text x="340" y="180" text-anchor="middle" class="ts">o atacante vê só a saída externa: estendê-la não dá o HMAC de outra mensagem</text>
</svg>
<figcaption>Figura 8.3 — O HMAC: duas passadas de hash, cada uma com uma chave derivada de K. A externa fecha o ataque de extensão de comprimento.</figcaption>
</figure>

**4. Um exemplo com números**, o caso de teste 2 da RFC 4231 (o mesmo arquivo
do autoteste). A chave é `Jefe`, de 4 bytes; a mensagem é
`what do ya want for nothing?`.

```
  K0        4A656665 00000000 ... 00          4 bytes e 60 zeros
  K0⊕ipad   7C535053 36363636 ... 36
  K0⊕opad   16393A39 5C5C5C5C ... 5C
  interno   A2E485863D27F9D864AC8D802432A1ED477D8C4C6F349D16D4E7E917C629CAD7
  HMAC      5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843
                                                     (RFC 4231: o mesmo)

  só para comparar, H(K ‖ M), o que não usar:
            689A1A0FA183259E022C4D77A4EB0810A94E9090D132C5F8732CCCE2B36E3621
```

#### Comparação

**5. Quando usar cada um.**

| | CBC-MAC | Retail MAC | CMAC | HMAC |
|---|---|---|---|---|
| Base | cifra de bloco | DES e 3DES | cifra de bloco (AES, 3DES) | hash (SHA-256) |
| Mensagem de tamanho variável | forjável | melhor que o CBC-MAC; o preenchimento 1 é ambíguo (seção 39.10) | segura | segura |
| Tamanho da tag | um bloco | 4 ou 8 bytes | 16 bytes (AES), 8 (3DES) | 32 bytes (SHA-256) |
| Custo por bloco | 1 cifra | 1 DES | 1 cifra, mais 1 para `L` | 1 compressão, mais 2 fixas |
| Onde se usa | histórico | redes de pagamento com 3DES | key block X9.143, DUKPT AES, EMV moderno | TLS, IPsec, JWT, derivação de chave (HKDF) |
| Norma | ISO/IEC 9797-1 alg. 1 | ISO/IEC 9797-1 alg. 3, ANSI X9.19 | NIST SP 800-38B | FIPS 198-1, RFC 2104 |

A escolha costuma vir do que o equipamento já tem. Quem só tem uma cifra de
bloco faz CMAC; quem tem um hash faz HMAC. Num HSM de pagamento, a cifra de
bloco está em todo lugar, e o CMAC vem de graça.

**Por que o key block usa o CMAC também para derivar chaves.** A X9.143
deriva a KBEK e a KBAK pela NIST SP 800-108 em modo contador, que aceita
qualquer função pseudoaleatória. Um MAC seguro é uma função pseudoaleatória
da chave: sem a chave, a saída é indistinguível de bytes ao acaso. Com o
CMAC-AES, a derivação usa a mesma cifra que já cifra o corpo e autentica o
bloco, e a versão B faz o mesmo com o CMAC-TDES. O HMAC serviria do mesmo
jeito; a norma escolheu a primitiva que todo HSM de pagamento já tem.

**Neste equipamento.** O CMAC-AES-256 autentica e deriva no key block versão
D, é o MAC dos comandos `MAC_GENERATE`/`MAC_VERIFY` (console) e `M0`/`M2`
(porta host) com chave AES, e é o MAC do DUKPT AES (seção 37.4). O CMAC-TDES
faz o mesmo papel no key block versão B (seção 39.9). O HMAC-SHA-256 está no
SHA-256 do coprocessador e passa pelo autoteste a cada boot, mas hoje nenhum
comando o usa: o comando que o expunha (`0x13`, apêndice B) recebia a
chave em claro e foi removido. Os vetores dos dois estão na seção 42.2.

### KBPK, KBEK e KBAK: as três chaves de um key block

Três chaves participam de um key block, e só uma delas existe guardada:

| Chave | Nome | O que faz |
|---|---|---|
| **KBPK** | *Key Block Protection Key* | A chave que protege o bloco. Nunca cifra nada direto: só deriva as outras duas. |
| **KBEK** | *Key Block Encryption Key* | Cifra o corpo do bloco (a chave transportada). |
| **KBAK** | *Key Block Authentication Key* | Calcula o MAC sobre o cabeçalho e o corpo em claro. |

Qual chave é a KBPK depende de onde o bloco vai:

- **Bloco guardado pelo equipamento** (o que o `K0` devolve, o que o host
  manda a cada comando): a KBPK é a **LMK**.
- **Bloco trocado com outra instituição** (`K4` e `K6`): a KBPK é a **KEK**
  que as duas partes formaram por componentes. Uma KEK AES-256 dá a versão
  `D`; uma KEK 3DES dá a versão `B` (seção 39.9).

A KBEK e a KBAK são recalculadas a cada bloco e apagadas depois. Elas nunca
ficam em slot nenhum.


<figure class="fig">
<svg viewBox="0 0 680 250" xmlns="http://www.w3.org/2000/svg">
<rect class="cxd" x="20" y="95" width="110" height="46"/>
<text x="75" y="115" text-anchor="middle" class="tb">KBPK</text>
<text x="75" y="131" text-anchor="middle" class="ts">LMK ou KEK</text>
<rect class="cx" x="170" y="40" width="130" height="40"/><text x="235" y="58" text-anchor="middle" class="ts">CMAC(KBPK, 01·0000…)</text><text x="235" y="72" text-anchor="middle" class="ts">CMAC(KBPK, 02·0000…)</text>
<rect class="cx" x="170" y="156" width="130" height="40"/><text x="235" y="174" text-anchor="middle" class="ts">CMAC(KBPK, 01·0001…)</text><text x="235" y="188" text-anchor="middle" class="ts">CMAC(KBPK, 02·0001…)</text>
<line class="ln" x1="130" y1="110" x2="168" y2="62" marker-end="url(#seta)"/>
<line class="ln" x1="130" y1="126" x2="168" y2="174" marker-end="url(#seta)"/>
<rect class="cxd" x="330" y="45" width="80" height="30"/><text x="370" y="65" text-anchor="middle" class="tb">KBEK</text>
<rect class="cxd" x="330" y="161" width="80" height="30"/><text x="370" y="181" text-anchor="middle" class="tb">KBAK</text>
<line class="ln" x1="300" y1="60" x2="328" y2="60" marker-end="url(#seta)"/>
<line class="ln" x1="300" y1="176" x2="328" y2="176" marker-end="url(#seta)"/>
<rect class="cx" x="450" y="150" width="210" height="52"/>
<text x="555" y="170" text-anchor="middle" class="tb">1. MAC</text>
<text x="555" y="186" text-anchor="middle" class="ts">CMAC(KBAK, cabeçalho ‖ corpo em claro)</text>
<rect class="cx" x="450" y="34" width="210" height="52"/>
<text x="555" y="54" text-anchor="middle" class="tb">2. corpo cifrado</text>
<text x="555" y="70" text-anchor="middle" class="ts">AES-CBC(KBEK, IV = MAC)</text>
<line class="ln" x1="410" y1="176" x2="448" y2="176" marker-end="url(#seta)"/>
<line class="ln" x1="410" y1="60" x2="448" y2="60" marker-end="url(#seta)"/>
<line class="lnt" x1="555" y1="150" x2="555" y2="88" marker-end="url(#seta-t)"/>
<text x="562" y="124" class="ts">o MAC é o IV</text>
<text x="340" y="236" text-anchor="middle" class="ts">só um byte da entrada separa KBEK de KBAK; as duas saídas não têm nada em comum</text>
</svg>
<figcaption>Figura 8.4 — Da KBPK ao bloco, na versão D. As duas subchaves nascem por CMAC, servem a um bloco e são apagadas.</figcaption>
</figure>

**A derivação na versão D.** Cada subchave tem 256 bits, e o CMAC-AES
devolve 128. São duas chamadas por subchave, sobre 8 bytes de entrada:

```
    contador(1) . propósito(2) . 00 . algoritmo(2) . bits(2)

    contador    01 = primeira metade       02 = segunda metade
    propósito   0000 = KBEK (cifra)        0001 = KBAK (MAC)
    algoritmo   0004 = AES-256
    bits        0100 = 256
```

Um exemplo com números, do bloco publicado pela biblioteca `psec` (valor de
terceiros, seção 43.1). A KBPK é
`88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6`:

```
    KBEK, 1a chamada   CMAC(KBPK, 0100000000040100) = 396C9382A6E2E66A088774E1D6E46541
    KBEK, 2a chamada   CMAC(KBPK, 0200000000040100) = F5EAD67D7204F8DD0D7AE8FDA334D3AC
    KBAK, 1a chamada   CMAC(KBPK, 0100010000040100) = 4EF24317696213840451890756757E57
    KBAK, 2a chamada   CMAC(KBPK, 0200010000040100) = 3E0673483888F9B7F9B7517827F95022
```

A KBEK é a junção das duas primeiras saídas; a KBAK, a das duas últimas. Só
o terceiro byte da entrada muda entre elas, e as duas não têm nada em comum.

**O bloco, aberto.** O bloco publicado tem 112 caracteres, em três partes:
o cabeçalho, em claro; o corpo, cifrado; e o MAC. A figura mostra as três, e
o corpo depois de decifrado com a KBEK.

<figure class="fig">
<svg viewBox="0 0 680 372" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="16" text-anchor="start" class="ts tb">O BLOCO, COMO VIAJA: 112 CARACTERES ASCII</text>
<text x="10" y="46" text-anchor="start" class="ts">cabeçalho (16)</text>
<rect class="cxa" x="140" y="30" width="118" height="24"/><text x="146" y="46" text-anchor="start" class="tm">D0112P0AE00E0000</text>
<text x="270" y="46" text-anchor="start" class="ts">em claro: qualquer um lê</text>
<text x="10" y="76" text-anchor="start" class="ts">corpo cifrado (64)</text>
<rect class="cx" x="140" y="60" width="436" height="24"/><text x="146" y="76" text-anchor="start" class="tm">B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A2</text>
<text x="10" y="106" text-anchor="start" class="ts">MAC (32)</text>
<rect class="cxv" x="140" y="90" width="224" height="24"/><text x="146" y="106" text-anchor="start" class="tm">7E8E31DA05F7425509593D03A457DC34</text>
<text x="376" y="106" text-anchor="start" class="ts">CMAC-AES sob a KBAK, sobre o cabeçalho</text>
<text x="376" y="118" text-anchor="start" class="ts">e o corpo EM CLARO</text>
<line class="grade" x1="10" y1="128" x2="670" y2="128"/>
<text x="10" y="144" text-anchor="start" class="ts tb">O CABEÇALHO, CAMPO A CAMPO (a tabela abaixo explica cada número)</text>
<rect class="cxa" x="100" y="152" width="30" height="30"/><text x="115" y="173" text-anchor="middle" class="tm" font-size="15">D</text>
<text x="115" y="198" text-anchor="middle" class="ts tb">1</text>
<text x="115" y="212" text-anchor="middle" class="ts">versão</text>
<rect class="cxa" x="130" y="152" width="120" height="30"/><text x="190" y="173" text-anchor="middle" class="tm" font-size="15">0112</text>
<text x="190" y="198" text-anchor="middle" class="ts tb">2</text>
<text x="190" y="226" text-anchor="middle" class="ts">tamanho</text>
<rect class="cxd" x="250" y="152" width="60" height="30"/><text x="280" y="173" text-anchor="middle" class="tm" font-size="15">P0</text>
<text x="280" y="198" text-anchor="middle" class="ts tb">3</text>
<text x="280" y="212" text-anchor="middle" class="ts td">uso</text>
<rect class="cxa" x="310" y="152" width="30" height="30"/><text x="325" y="173" text-anchor="middle" class="tm" font-size="15">A</text>
<text x="325" y="198" text-anchor="middle" class="ts tb">4</text>
<text x="325" y="226" text-anchor="middle" class="ts">algoritmo</text>
<rect class="cxd" x="340" y="152" width="30" height="30"/><text x="355" y="173" text-anchor="middle" class="tm" font-size="15">E</text>
<text x="355" y="198" text-anchor="middle" class="ts tb">5</text>
<text x="355" y="212" text-anchor="middle" class="ts td">modo</text>
<rect class="cxa" x="370" y="152" width="60" height="30"/><text x="400" y="173" text-anchor="middle" class="tm" font-size="15">00</text>
<text x="400" y="198" text-anchor="middle" class="ts tb">6</text>
<text x="400" y="226" text-anchor="middle" class="ts">v. da chave</text>
<rect class="cxd" x="430" y="152" width="30" height="30"/><text x="445" y="173" text-anchor="middle" class="tm" font-size="15">E</text>
<text x="445" y="198" text-anchor="middle" class="ts tb">7</text>
<text x="445" y="212" text-anchor="middle" class="ts td">exportab.</text>
<rect class="cxa" x="460" y="152" width="60" height="30"/><text x="490" y="173" text-anchor="middle" class="tm" font-size="15">00</text>
<text x="490" y="198" text-anchor="middle" class="ts tb">8</text>
<text x="490" y="226" text-anchor="middle" class="ts">opcionais</text>
<rect class="cxa" x="520" y="152" width="60" height="30"/><text x="550" y="173" text-anchor="middle" class="tm" font-size="15">00</text>
<text x="550" y="198" text-anchor="middle" class="ts tb">9</text>
<text x="550" y="212" text-anchor="middle" class="ts">reservado</text>
<line class="grade" x1="10" y1="244" x2="670" y2="244"/>
<text x="10" y="260" text-anchor="start" class="ts tb">O CORPO, DEPOIS DE DECIFRADO: AES-CBC SOB A KBEK, COM O MAC COMO IV</text>
<rect class="cxa" x="20" y="270" width="39" height="26"/><text x="26" y="287" text-anchor="start" class="tm">0080</text>
<rect class="cxd" x="59" y="270" width="224" height="26"/><text x="65" y="287" text-anchor="start" class="tm">3F419E1CB7079442AA37474C2EFBF8B8</text>
<rect class="cxc" x="283" y="270" width="197" height="26"/><text x="289" y="287" text-anchor="start" class="tm">1C2965473CE206BB855B01533782</text>
<text x="39" y="312" text-anchor="middle" class="ts">tamanho:</text>
<text x="39" y="324" text-anchor="middle" class="ts">128 bits</text>
<text x="171" y="312" text-anchor="middle" class="ts td">a chave, 16 bytes</text>
<text x="171" y="324" text-anchor="middle" class="ts">(aqui, AES-128)</text>
<text x="381" y="312" text-anchor="middle" class="ts">enchimento aleatório,</text>
<text x="381" y="324" text-anchor="middle" class="ts">14 bytes</text>
<text x="496" y="280" text-anchor="start" class="ts">2 + 16 + 14 = 32 bytes:</text>
<text x="496" y="293" text-anchor="start" class="ts">dois blocos AES; o</text>
<text x="496" y="306" text-anchor="start" class="ts">enchimento completa</text>
<text x="496" y="319" text-anchor="start" class="ts">o último</text>
<path class="lnt" d="M590,84 L590,138 L660,138 L660,262" marker-end="url(#seta-t)"/>
<text x="340" y="358" text-anchor="middle" class="ts">o mesmo cabeçalho e a mesma chave, com outro enchimento, dão outro corpo cifrado e outro MAC</text>
</svg>
<figcaption>Figura 8.5 — Um key block de verdade: o vetor publicado do KAT, aberto. Em vermelho, os campos que limitam o que a chave pode fazer, e a chave.</figcaption>
</figure>

Os campos do cabeçalho, pelos números da figura:

| Nº | Campo | Posição | Valor | O que diz |
|--|--------|-----|----|----------------------------------------|
| 1 | Versão | 1 | `D` | A versão do formato. `D` é a do AES: KBEK e KBAK derivadas por CMAC-AES, MAC de 16 bytes. A versão `B` é a do 3DES (seção 39.9). Quem abre o bloco escolhe a versão; o bloco não a escolhe |
| 2 | Tamanho | 2–5 | `0112` | O comprimento do bloco inteiro, em caracteres, com o cabeçalho |
| 3 | Uso | 6–7 | `P0` | Para que a chave serve. `P0` é chave de cifra de PIN. Outros: `K0` (KEK), `D0` (dados), `M0`–`M8` (MAC), `B0` (BDK), `C0` (CVV), `V1`/`V2` (verificação de PIN) |
| 4 | Algoritmo | 8 | `A` | `A` é AES; `T` é 3DES |
| 5 | Modo | 9 | `E` | O que se pode fazer com a chave. `E` só cifra; `D` só decifra; `B` faz os dois. Para MAC: `G` gera, `V` verifica, `C` os dois. `X` só deriva outras chaves |
| 6 | Versão da chave | 10–11 | `00` | `00`: a chave não tem controle de versão |
| 7 | Exportabilidade | 12 | `E` | Se a chave pode sair do HSM. `E`: só em key block, sob uma chave de confiança. `N`: nunca sai. `S`: sai também em formatos antigos |
| 8 | Blocos opcionais | 13–14 | `00` | Quantos blocos opcionais vêm depois do cabeçalho; aqui, nenhum. Este equipamento recusa bloco com opcionais |
| 9 | Reservado | 15–16 | `00` | Sem uso; sempre `00` |

Os campos 3, 5 e 7 são os que um atacante quer trocar: com `P0` mudado para
`D0`, a chave de PIN cifraria e decifraria dados, e o PIN sairia por um
comando de dados (seção 15). O MAC cobre o cabeçalho; por isso qualquer
caractere trocado faz o bloco inteiro ser recusado.

O corpo em claro tem três partes: o tamanho da chave **em bits** (`0080` é
128), a chave, e um enchimento aleatório. O enchimento completa o corpo
até um múltiplo do bloco AES. A norma também permite um enchimento maior,
para esconder o tamanho da chave de quem só vê o bloco. Como o enchimento é aleatório, embrulhar a mesma chave duas
vezes dá dois blocos diferentes: é por isso que o embrulho não tem KAT
(seção 42), só a abertura.

O CMAC-AES com a KBAK sobre o cabeçalho e esse corpo em claro dá
`7E8E31DA05F7425509593D03A457DC34`, o MAC do bloco: ele é íntegro. O
corpo tem 2 + 16 + 14 = 32 bytes, múltiplo de 16, e o bloco tem
16 + 2 × 32 + 2 × 16 = 112 caracteres. Os valores foram conferidos com a
biblioteca `cryptography` e com `host/tr31.py`.

### Exportabilidade: quando a chave pode ir para outra instituição

Uma chave 3DES é exportável? Uma chave AES é? A resposta não depende do
algoritmo. Depende do campo 7 do cabeçalho, a **exportabilidade**:

| Valor | O que significa | Neste equipamento |
|---|---|---|
| `E` | sai, mas só em key block, sob uma KEK | o `K4` exporta |
| `N` | nunca sai; pode ser usada normalmente | o `K4` recusa, com `12` |
| `S` | sai também em formatos antigos, fora de key block | igual ao `E`, porque aqui só existe key block |

Quem escolhe o valor é quem cria a chave: o `K0` e o `comp-load` o recebem no
pedido. Depois, ninguém o muda: o campo está sob o MAC, e trocar `N` por `E`
faz o bloco inteiro ser recusado (Figura 8.1).

"Sair do HSM" tem dois sentidos, e a exportabilidade controla só um deles:

1. **Sob a LMK.** Toda chave de trabalho "sai" o tempo todo: o `K0` devolve o
   key block, e ele fica no banco de dados (seção 24.14). Isso não é
   exportar. Só um HSM com a mesma LMK abre o bloco, e a chave continua no
   domínio do HSM.
2. **Sob uma KEK** (`K4`). É a exportação de verdade: a chave vai para outra
   instituição, que tem a mesma KEK.

<figure class="fig">
<svg viewBox="0 0 680 304" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="16" text-anchor="start" class="ts tb">1. SOB A LMK: NÃO É EXPORTAR</text>
<rect class="fr" x="10" y="28" width="140" height="62"/><text x="80" y="52" text-anchor="middle" class="tb">HSM</text><text x="80" y="70" text-anchor="middle" class="ts">K0 gera</text>
<rect class="cxc" x="240" y="36" width="170" height="46"/><text x="325" y="55" text-anchor="middle" class="tb">banco de dados</text><text x="325" y="71" text-anchor="middle" class="ts">key block sob a LMK</text>
<line class="ln" x1="150" y1="50" x2="238" y2="50" marker-end="url(#seta)"/>
<line class="ln" x1="238" y1="70" x2="150" y2="70" marker-end="url(#seta)"/>
<text x="194" y="44" text-anchor="middle" class="ts">guarda</text>
<text x="194" y="84" text-anchor="middle" class="ts">volta a cada uso</text>
<text x="436" y="50" text-anchor="start" class="ts">só um HSM com a mesma LMK abre</text>
<text x="436" y="64" text-anchor="start" class="ts">o bloco: a chave continua no</text>
<text x="436" y="78" text-anchor="start" class="ts">domínio do HSM, qualquer que seja</text>
<text x="436" y="92" text-anchor="start" class="ts">a exportabilidade</text>
<line class="grade" x1="10" y1="108" x2="670" y2="108"/>
<text x="10" y="126" text-anchor="start" class="ts tb">2. SOB UMA KEK: EXPORTAR (K4 NUM HSM, K6 NO OUTRO)</text>
<rect class="fr" x="10" y="140" width="130" height="60"/><text x="75" y="164" text-anchor="middle" class="tb">HSM A</text><text x="75" y="182" text-anchor="middle" class="ts tm">K4</text>
<rect class="cxd" x="185" y="142" width="155" height="56"/><text x="262" y="161" text-anchor="middle" class="tb">exportabilidade?</text><text x="262" y="177" text-anchor="middle" class="ts">E ou S: segue</text><text x="262" y="190" text-anchor="middle" class="ts">N: recusa (12)</text>
<rect class="cxd" x="380" y="142" width="140" height="56"/><text x="450" y="161" text-anchor="middle" class="tb">força da KEK?</text><text x="450" y="177" text-anchor="middle" class="ts">a mesma ou maior: sai</text><text x="450" y="190" text-anchor="middle" class="ts">menor: recusa (13)</text>
<rect class="fr" x="560" y="140" width="110" height="60"/><text x="615" y="164" text-anchor="middle" class="tb">HSM B</text><text x="615" y="182" text-anchor="middle" class="ts tm">K6</text>
<line class="ln" x1="140" y1="170" x2="183" y2="170" marker-end="url(#seta)"/>
<line class="ln" x1="340" y1="170" x2="378" y2="170" marker-end="url(#seta)"/>
<line class="ln" x1="520" y1="170" x2="558" y2="170" marker-end="url(#seta)"/>
<text x="340" y="222" text-anchor="middle" class="ts">o bloco sob a KEK: versão D com KEK AES, versão B com KEK 3DES</text>
<rect class="cxv" x="10" y="240" width="660" height="50"/>
<text x="340" y="260" text-anchor="middle" class="tb">N não impede usar: impede sair</text>
<text x="340" y="278" text-anchor="middle" class="ts">uma chave N cifra, traduz PIN e faz MAC normalmente; só o K4 a recusa</text>
</svg>
<figcaption>Figura 8.6 — Os dois sentidos de "sair". Sob a LMK, a chave vai para o banco de dados e continua do HSM; sob uma KEK, ela passa por duas checagens antes de ir para outra instituição.</figcaption>
</figure>

A segunda checagem da figura é a **regra de força**: uma chave nunca sai
embrulhada por outra mais fraca (seção 39.9). Para uma chave 3DES:

| KEK de destino | Leva chave 3DES dupla | Leva chave 3DES tripla | Formato do bloco |
|---|---|---|---|
| AES | sim | sim | versão D |
| 3DES tripla | sim | sim | versão B |
| 3DES dupla | sim | **não** (`13`) | versão B |

Exemplos neste equipamento:

- Uma chave de PIN 3DES dupla, criada com `E`, sai pelo `K4` sob uma KEK AES
  ou 3DES. É o caso da chave de zona trocada com a bandeira.
- A mesma chave, criada com `N`, cifra e traduz PIN normalmente, mas o `K4` a
  recusa.
- A IPEK que o `I0` entrega sai **uma vez**, sob a KEK do injetor, já marcada
  com `N`: quem a recebe não pode reexportá-la (seção 37).
- A BDK não tem comando de saída. Ela só deriva chaves (modo `X`).

A regra é a mesma da LMK, só que configurável. A LMK é `N` por natureza, sem
exceção (seção 7). Uma chave de trabalho é `N` ou `E` conforme a decisão de
quem a criou, e o key block garante que essa decisão não muda depois.

### Por que escrever o parser duas vezes

Neste projeto o TR-31 é implementado em C no firmware e em Python no host, e
os dois validam-se mutuamente sobre blocos aleatórios.

É de longe a forma mais rápida de aprender o padrão de verdade, porque a
menor divergência — um byte de preenchimento, uma ordem de campo, um
comprimento incluído ou não na contagem — aparece imediatamente como MAC
inválido. Não dá para "quase" implementar TR-31: ou os dois lados concordam
em cada byte, ou nada funciona.

## 9. Máquina de estados: a chave de switch

<figure class="fig">
<svg viewBox="0 0 680 268" xmlns="http://www.w3.org/2000/svg">
<rect class="cxc" x="20"  y="40" width="150" height="50" rx="10"/><text x="95"  y="62" text-anchor="middle" class="tb">UNINITIALIZED</text><text x="95"  y="78" text-anchor="middle" class="ts">sem LMK</text>
<rect class="cx"  x="265" y="40" width="150" height="50" rx="10"/><text x="340" y="62" text-anchor="middle" class="tb">AUTHORIZED</text><text x="340" y="78" text-anchor="middle" class="ts">não atende produção</text>
<rect class="cxv" x="510" y="40" width="150" height="50" rx="10"/><text x="585" y="62" text-anchor="middle" class="tb">OPERATIONAL</text><text x="585" y="78" text-anchor="middle" class="ts">só o serviço</text>
<rect class="cxd" x="265" y="175" width="150" height="50" rx="10"/><text x="340" y="197" text-anchor="middle" class="tb td">TAMPERED</text><text x="340" y="213" text-anchor="middle" class="ts">absorvente</text>
<line class="ln" x1="170" y1="58" x2="263" y2="58" marker-end="url(#seta)"/>
<text x="216" y="50" text-anchor="middle" class="ts">3º componente</text>
<text x="216" y="74" text-anchor="middle" class="ts">(dois botões)</text>
<line class="ln" x1="415" y1="58" x2="508" y2="58" marker-end="url(#seta)"/>
<text x="461" y="50" text-anchor="middle" class="ts">ativar</text>
<text x="461" y="74" text-anchor="middle" class="ts">(dois botões)</text>
<path class="ln" d="M585,40 L585,20 L95,20 L95,38" marker-end="url(#seta)"/>
<path class="ln" d="M340,40 L340,20"/>
<text x="460" y="14" text-anchor="middle" class="ts">zeroize (dois botões)</text>
<path class="lnd" d="M95,90 L95,200 L263,200" marker-end="url(#seta-d)"/>
<path class="lnd" d="M340,90 L340,173" marker-end="url(#seta-d)"/>
<path class="lnd" d="M585,90 L585,200 L417,200" marker-end="url(#seta-d)"/>
<text x="180" y="190" text-anchor="middle" class="ts td">autoteste reprovado</text>
<text x="500" y="190" text-anchor="middle" class="ts td">tamper, sensor, erro grave</text>
<path class="lnt" d="M300,225 C300,248 380,248 380,225" marker-end="url(#seta-t)"/>
<text x="340" y="264" text-anchor="middle" class="ts">zeroize apaga, e o estado fica</text>
</svg>
<figcaption>Figura 9.1 — A máquina de estados. As setas pretas exigem mão humana no equipamento; as vermelhas, o próprio equipamento dispara.</figcaption>
</figure>

HSMs comerciais têm uma chave física de três posições no painel. Este é o
modelo.

Comandos sensíveis — carga de componente, exportação de material derivado da
LMK, mudança de política — existem **apenas** em `AUTHORIZED`. E
`AUTHORIZED` é um estado no qual o dispositivo **não atende produção** e no
qual só se entra por ação física deliberada.

O raciocínio: em operação normal, a superfície de ataque deve ser mínima. Em
`OPERATIONAL`, o dispositivo faz o trabalho e nada mais — não carrega chave,
não exporta LMK, não muda política. Um invasor que comprometa
**totalmente** o host de produção ainda não carrega componente de LMK,
porque o dispositivo não aceita aquele opcode naquele estado, e mudar de
estado exige mão humana no equipamento.

`TAMPERED` é absorvente, e **mais absorvente do que este texto dizia até a
Fase 3 ser implementada**: não se sai dele por software, ponto. Nem por
zeroize.

A distinção é fina e importa. O `ZEROIZE` funciona em `TAMPERED` — é
exatamente ali que ele mais precisa funcionar — e apaga toda chave. Mas o
estado **fica**. Apagar o que o dispositivo protegia não desfaz o veredito
que ele deu sobre si mesmo; um módulo que se cura de tamper não detectou
tamper nenhum, apenas registrou um incômodo.

Sair de `TAMPERED` exige energia removida e um boot em que o autoteste
passe. Se a causa era física, ele não passa — que é o comportamento certo.

E um dispositivo em `TAMPERED` deve responder o mínimo possível: o estado
existe para proteger o que restou, não para continuar servindo. Só quatro
comandos respondem ali: `SELFTEST`, para dizer **o que** reprovou, `ZEROIZE`,
para apagar, e, desde a Fase 6, `ENV_READ` e `AUDIT_READ`, para saber por quê.

## 10. Aleatoriedade: onde HSM vira ciência

Um HSM é tão bom quanto seu gerador. Chave previsível é chave pública, e o
histórico de falhas nessa área é longo e caro.

A arquitetura padrão tem duas camadas:

<figure class="fig">
<svg viewBox="0 0 680 190" xmlns="http://www.w3.org/2000/svg">
<rect class="fr" x="10" y="20" width="330" height="120"/>
<text x="20" y="36" class="ts td">hardware: vê toda amostra, 100 milhões por segundo</text>
<rect class="cx" x="25" y="50" width="130" height="70"/>
<text x="90" y="72" text-anchor="middle" class="tb">fonte física</text>
<text x="90" y="88" text-anchor="middle" class="ts">osciladores em anel</text>
<text x="90" y="102" text-anchor="middle" class="ts">ruído, com viés</text>
<line class="ln" x1="155" y1="85" x2="188" y2="85" marker-end="url(#seta)"/>
<rect class="cx" x="190" y="50" width="135" height="70"/>
<text x="257" y="72" text-anchor="middle" class="tb">testes contínuos</text>
<text x="257" y="88" text-anchor="middle" class="ts">RCT e APT</text>
<text x="257" y="102" text-anchor="middle" class="ts">SP 800-90B</text>
<line class="ln" x1="325" y1="85" x2="388" y2="85" marker-end="url(#seta)"/>
<rect class="cxa" x="390" y="50" width="130" height="70"/>
<text x="455" y="72" text-anchor="middle" class="tb">DRBG</text>
<text x="455" y="88" text-anchor="middle" class="ts">CTR_DRBG, AES-256</text>
<text x="455" y="102" text-anchor="middle" class="ts">SP 800-90A</text>
<line class="ln" x1="520" y1="85" x2="568" y2="85" marker-end="url(#seta)"/>
<rect class="cxd" x="570" y="58" width="100" height="54"/>
<text x="620" y="82" text-anchor="middle" class="tb">chaves</text>
<text x="620" y="98" text-anchor="middle" class="ts">enchimento, k</text>
<line class="lnd" x1="257" y1="120" x2="257" y2="156" marker-end="url(#seta-d)"/>
<rect class="cxd" x="150" y="158" width="220" height="28"/>
<text x="260" y="177" text-anchor="middle" class="ts td">falhou: TAMPERED, o DRBG para</text>
<text x="455" y="140" text-anchor="middle" class="ts">firmware: estica e uniformiza</text>
<text x="455" y="154" text-anchor="middle" class="ts">a entropia; não a cria</text>
</svg>
<figcaption>Figura 10.1 — O caminho da aleatoriedade. O hardware testa toda amostra; o firmware decide o que fazer com uma falha.</figcaption>
</figure>

### Por que não usar a fonte física diretamente

Ruído físico tem viés e correlação. Osciladores em anel num FPGA — a fonte
usada neste projeto — são sensíveis a temperatura e a tensão de alimentação.
E um atacante que controle a fonte de alimentação pode **reduzir a entropia**
sem que nada pareça errado do lado de fora.

O DRBG existe para transformar entropia imperfeita mas *suficiente* num
fluxo computacionalmente indistinguível de aleatório. Ele não cria entropia
— ele a estica e a uniformiza.

### Testes de saúde: o coração da coisa

SP 800-90B exige que a fonte seja monitorada **continuamente**, não validada
uma vez na fábrica. Dois testes obrigatórios:

**RCT** (*Repetition Count Test*) — dispara se a mesma amostra se repete
acima de um limiar. Pega a falha catastrófica: o oscilador parou, a fonte
travou num valor, o pino soltou.

**APT** (*Adaptive Proportion Test*) — janela de 512 ou 1024 amostras,
dispara se um valor domina a janela. Pega a degradação: a fonte ainda
oscila, mas ficou enviesada.

Falha em qualquer um → `TAMPERED`, DRBG parado, indicador vermelho. Não é
paranoia: é a diferença entre "gerei uma chave fraca e não sei" e "me
recusei a gerar".


O limiar do RCT sai de uma conta simples. Se a fonte tem `H` bits de entropia
por amostra, a chance de a mesma amostra aparecer `C` vezes seguidas é no
máximo `2^(−H·(C−1))`. A norma fixa a taxa de alarme falso em `2^−20`. Com a
hipótese deste projeto, `H = 0,5`, o limiar é `C = 1 + 20/0,5 = 41`
(`scripts/health-cutoffs.py`). A Figura 10.2 mostra a conta.

<figure class="fig">
<svg viewBox="0 0 680 260" xmlns="http://www.w3.org/2000/svg">
<line class="ln" x1="60" y1="220" x2="650" y2="220" marker-end="url(#seta)"/>
<line class="ln" x1="60" y1="220" x2="60" y2="15" marker-end="url(#seta)"/>
<text x="355" y="252" text-anchor="middle" class="ts">C, repetições seguidas da mesma amostra</text>
<text x="20" y="120" class="ts" transform="rotate(-90 20 120)" text-anchor="middle">log₂ da chance (fonte sadia)</text>
<g class="ts">
<text x="60" y="235" text-anchor="middle">1</text><text x="170" y="235" text-anchor="middle">11</text><text x="280" y="235" text-anchor="middle">21</text><text x="390" y="235" text-anchor="middle">31</text><text x="500" y="235" text-anchor="middle">41</text><text x="610" y="235" text-anchor="middle">51</text>
<text x="52" y="224" text-anchor="end">0</text><text x="52" y="166" text-anchor="end">−10</text><text x="52" y="108" text-anchor="end">−20</text><text x="52" y="50" text-anchor="end">−30</text>
</g>
<line class="grade" x1="60" y1="162" x2="640" y2="162"/><line class="grade" x1="60" y1="104" x2="640" y2="104"/><line class="grade" x1="60" y1="46" x2="640" y2="46"/>
<line x1="60" y1="220" x2="448" y2="15" stroke="#2d4f73" stroke-width="2"/>
<text x="150" y="150" class="ts" fill="#2d4f73">H = 1,0</text>
<line x1="60" y1="220" x2="610" y2="75" stroke="#7a1f1f" stroke-width="2.2"/>
<text x="230" y="196" class="ts td">H = 0,5</text>
<line x1="500" y1="220" x2="500" y2="104" stroke="#7a1f1f" stroke-dasharray="5 3"/>
<line x1="60" y1="104" x2="500" y2="104" stroke="#7a1f1f" stroke-dasharray="5 3"/>
<circle cx="500" cy="104" r="5" fill="#7a1f1f"/>
<text x="508" y="124" class="ts td">C = 41: alarme falso 2⁻²⁰</text>
<line x1="280" y1="220" x2="280" y2="104" stroke="#2d4f73" stroke-dasharray="5 3"/>
<circle cx="280" cy="104" r="5" fill="#2d4f73"/>
<text x="288" y="118" class="ts" fill="#2d4f73">C = 21 com H = 1</text>
</svg>
<figcaption>Figura 10.2 — O limiar do RCT. Quanto menos entropia se supõe, mais repetições a fonte sadia produz, e mais alto fica o limiar.</figcaption>
</figure>

Escrever esses testes ensina mais sobre certificação de módulo criptográfico
que qualquer texto sobre o assunto — eles são boa parte do motivo de uma
avaliação levar meses.

## 11. Self-test: por que o dispositivo se recusa a funcionar

FIPS 140-3 exige que o módulo rode testes de resposta conhecida (**KAT**,
*Known Answer Test*) na inicialização, **antes** de aceitar qualquer comando,
e que entre em estado de erro se qualquer um falhar.

Parece burocracia. Não é, e o raciocínio é bonito:

> Um AES que cifra errado não produz erro. Produz criptograma.

Você não descobre nada até tentar decifrar — possivelmente meses depois,
possivelmente em outro dispositivo, possivelmente sobre o único backup que
existia. Um bit preso numa memória, uma violação de temporização marginal
que só aparece a 60 °C, uma corrupção na configuração do FPGA: todos se
manifestam como criptografia silenciosamente errada.

Os KAT são o único momento em que o dispositivo consegue dizer **"eu não
estou funcionando"** antes de causar dano.


<figure class="fig">
<svg viewBox="0 0 680 170" xmlns="http://www.w3.org/2000/svg">
<rect class="cx" x="10" y="60" width="80" height="40" rx="8"/><text x="50" y="85" text-anchor="middle" class="tb">liga</text>
<line class="ln" x1="90" y1="80" x2="128" y2="80" marker-end="url(#seta)"/>
<rect class="cx" x="130" y="40" width="200" height="80"/>
<text x="230" y="60" text-anchor="middle" class="tb">POST (KATs)</text>
<text x="230" y="78" text-anchor="middle" class="ts">AES, SHA, HMAC, CMAC, DRBG</text>
<text x="230" y="92" text-anchor="middle" class="ts">fonte de entropia, key store,</text>
<text x="230" y="106" text-anchor="middle" class="ts">key block, RSA (verificação)</text>
<line class="ln" x1="330" y1="65" x2="438" y2="40" marker-end="url(#seta)"/>
<text x="372" y="36" class="ts">todos passam</text>
<rect class="cxv" x="440" y="15" width="230" height="44"/>
<text x="555" y="34" text-anchor="middle" class="tb">aceita comandos</text>
<text x="555" y="50" text-anchor="middle" class="ts">e restaura o estado da flash</text>
<line class="lnd" x1="330" y1="95" x2="438" y2="120" marker-end="url(#seta-d)"/>
<text x="372" y="134" class="ts td">um reprova</text>
<rect class="cxd" x="440" y="100" width="230" height="44"/>
<text x="555" y="119" text-anchor="middle" class="tb td">TAMPERED</text>
<text x="555" y="135" text-anchor="middle" class="ts">só SELFTEST, ZEROIZE e leitura</text>
<text x="230" y="150" text-anchor="middle" class="ts">os mesmos vetores rodam na simulação e na placa</text>
</svg>
<figcaption>Figura 11.1 — O autoteste no boot. Um AES que cifra errado não dá erro; dá criptograma. O KAT é o único momento de descobrir isso antes do dano.</figcaption>
</figure>

Neste projeto os mesmos vetores rodam nos testbenches de simulação **e** no
POST em hardware. Isso é deliberado e diagnóstico: se um KAT passa na
simulação e falha no POST, o problema está no barramento ou na integração,
não no núcleo criptográfico.

E há uma regra que decorre disso, adotada como inviolável neste projeto:

> **Se um KAT falha, o bug está no código, não no vetor.** Não ajustar
> vetor, não relaxar assert, não marcar teste como ignorado.

Um teste enfraquecido para passar é pior que teste nenhum, porque agora
existe uma afirmação falsa de correção, e alguém vai confiar nela.

## 12. Zeroização: apagar é mais difícil do que parece

```c
    memset(chave, 0, 32);   /* ...e a função termina aqui */
```

Para o compilador, isso é um *dead store*: escrita num buffer que ninguém lê
depois. O padrão C **permite** eliminá-lo, e com otimização ativada o
compilador elimina. A chave permanece na memória, intacta, e o código
*parece* correto na revisão — inclusive para um revisor experiente.


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<text x="165" y="18" text-anchor="middle" class="tb">o que o programador escreve</text>
<rect class="cx" x="20" y="28" width="290" height="110"/>
<g class="tm"><text x="32" y="50">usa(chave);</text><text x="32" y="70">memset(chave, 0, 32);</text><text x="32" y="90">return;</text></g>
<text x="32" y="118" class="ts">parece apagar</text>
<line class="ln" x1="310" y1="83" x2="368" y2="83" marker-end="url(#seta)"/>
<text x="339" y="76" text-anchor="middle" class="ts">-Os</text>
<text x="515" y="18" text-anchor="middle" class="tb">o que o compilador gera</text>
<rect class="cxd" x="370" y="28" width="290" height="110"/>
<g class="tm"><text x="382" y="50">usa(chave);</text><text x="382" y="70" fill="#999" text-decoration="line-through">memset(chave, 0, 32);</text><text x="382" y="90">return;</text></g>
<text x="382" y="118" class="ts td">ninguém lê depois: a escrita some</text>
<rect class="cxd" x="370" y="150" width="290" height="40"/>
<text x="515" y="168" text-anchor="middle" class="ts">memória depois do return:</text>
<text x="515" y="182" text-anchor="middle" class="tm td">3F 41 9E 1C B7 07 94 42 …</text>
<rect class="cxv" x="20" y="150" width="290" height="40"/>
<text x="165" y="168" text-anchor="middle" class="ts">com wipe() (volatile + barreira):</text>
<text x="165" y="182" text-anchor="middle" class="tm">00 00 00 00 00 00 00 00 …</text>
</svg>
<figcaption>Figura 12.1 — O apagamento que o compilador elimina. A chave continua na memória, e o código parece certo na revisão.</figcaption>
</figure>

A solução é forçar o compilador a tratar cada escrita como efeito colateral
observável:

```c
void wipe(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0u;
    __asm__ __volatile__("" ::: "memory");
}
```

`volatile` impede a eliminação; a barreira de memória impede reordenamento.

Zeroização é **requisito explícito** do FIPS 140-3, e a exigência vai além de
chamar a função: um módulo certificado precisa demonstrar que o material foi
efetivamente destruído. Por isso, neste projeto, o comando `ZEROIZE`
sobrescreve a região com padrão e depois com zeros, e o **teste faz dump da
região e verifica**. "Chamei a função de apagar" não é evidência.

## 13. Log de auditoria: por que antes, não depois

O registro é gravado **antes** de executar o comando. Isso é contraintuitivo
— parece natural registrar o resultado.

O motivo: um log escrito depois só registra sucesso. Tentativa que falhou,
comando que travou o dispositivo, sequência que causou reset — nada disso
aparece. E é exatamente essa a informação que importa numa investigação.

Um atacante sondando a API produz **muitos erros e poucos sucessos**. Um log
de sucessos mostra um dispositivo perfeitamente saudável enquanto ele está
sendo mapeado.


<figure class="fig">
<svg viewBox="0 0 680 230" xmlns="http://www.w3.org/2000/svg">
<text x="10" y="30" class="tb">pedidos</text>
<g>
<rect class="cxv" x="120" y="14" width="80" height="26"/><text x="160" y="32" text-anchor="middle" class="ts">ok</text>
<rect class="cxd" x="210" y="14" width="80" height="26"/><text x="250" y="32" text-anchor="middle" class="ts">recusado</text>
<rect class="cxd" x="300" y="14" width="80" height="26"/><text x="340" y="32" text-anchor="middle" class="ts">recusado</text>
<rect class="cxd" x="390" y="14" width="80" height="26"/><text x="430" y="32" text-anchor="middle" class="ts">recusado</text>
<rect class="cxd" x="480" y="14" width="80" height="26"/><text x="520" y="32" text-anchor="middle" class="ts">travou</text>
<rect class="cxv" x="570" y="14" width="80" height="26"/><text x="610" y="32" text-anchor="middle" class="ts">ok</text>
</g>
<text x="10" y="100" class="tb">log depois</text>
<rect class="cxv" x="120" y="84" width="80" height="26"/><text x="160" y="102" text-anchor="middle" class="ts">ok</text>
<rect class="cxv" x="570" y="84" width="80" height="26"/><text x="610" y="102" text-anchor="middle" class="ts">ok</text>
<text x="385" y="102" text-anchor="middle" class="ts">(nada: tudo parece saudável)</text>
<text x="10" y="170" class="tb">log antes</text>
<rect class="cx" x="120" y="154" width="80" height="26"/><text x="160" y="172" text-anchor="middle" class="ts">#101 ok</text>
<rect class="cx" x="210" y="154" width="80" height="26"/><text x="250" y="172" text-anchor="middle" class="ts">#102 recusa</text>
<rect class="cx" x="300" y="154" width="80" height="26"/><text x="340" y="172" text-anchor="middle" class="ts">#103 recusa</text>
<rect class="cx" x="390" y="154" width="80" height="26"/><text x="430" y="172" text-anchor="middle" class="ts">#104 recusa</text>
<rect class="cxd" x="480" y="154" width="80" height="26"/><text x="520" y="172" text-anchor="middle" class="ts">#105 …</text>
<rect class="cx" x="570" y="154" width="80" height="26"/><text x="610" y="172" text-anchor="middle" class="ts">#106 ok</text>
<text x="520" y="200" text-anchor="middle" class="ts td">sem resultado: o pedido que travou</text>
<text x="340" y="222" text-anchor="middle" class="ts">o contador monotônico (#101, #102…) acusa registro apagado</text>
</svg>
<figcaption>Figura 13.1 — O mesmo ataque visto por dois logs. Só o log gravado antes de executar mostra a sondagem e o pedido que derrubou o equipamento.</figcaption>
</figure>

Requisitos que decorrem:

- **contador monotônico**, para detectar remoção de entradas;
- **gravação antes da execução**, para capturar o que travou;
- **sem material de chave**, obviamente;
- **armazenamento que sobrevive à queda de energia**, senão o ataque termina
  com um puxão no cabo.

## 14. Ciclo de vida de uma chave

Amarrando as seções anteriores: uma chave, do nascimento à morte, e onde
cada mecanismo entra.

| Fase | O que acontece | Mecanismo |
|---|---|---|
| **Geração** | Dentro do módulo, a partir do DRBG | Testes de saúde da fonte, POST |
| **Atribuição** | Recebe atributos: uso, modo, exportabilidade | Estrutura do slot |
| **Distribuição** | Sai embrulhada em key block, ou nunca sai | TR-31, KBEK/KBAK, `exportability` |
| **Armazenamento** | BRAM interna; backup como key block | Fronteira, hierarquia sob LMK |
| **Uso** | Só operações permitidas pelo uso e pelo modo de uso | Mediação, máquina de estados |
| **Rotação** | Nova chave gerada, antiga marcada | `use_count`, política |
| **Destruição** | Zeroize, com prova | `wipe()`, verificação por dump |


<figure class="fig">
<svg viewBox="0 0 680 200" xmlns="http://www.w3.org/2000/svg">
<rect class="cxa" x="10"  y="70" width="85" height="50" rx="8"/><text x="52"  y="92" text-anchor="middle" class="tb">geração</text><text x="52"  y="108" text-anchor="middle" class="ts">DRBG</text>
<rect class="cx"  x="105" y="70" width="85" height="50" rx="8"/><text x="147" y="92" text-anchor="middle" class="tb">atributos</text><text x="147" y="108" text-anchor="middle" class="ts">uso, modo</text>
<rect class="cx"  x="200" y="70" width="85" height="50" rx="8"/><text x="242" y="92" text-anchor="middle" class="tb">distribuição</text><text x="242" y="108" text-anchor="middle" class="ts">key block</text>
<rect class="cx"  x="295" y="70" width="85" height="50" rx="8"/><text x="337" y="92" text-anchor="middle" class="tb">guarda</text><text x="337" y="108" text-anchor="middle" class="ts">sob a LMK</text>
<rect class="cxv" x="390" y="70" width="85" height="50" rx="8"/><text x="432" y="92" text-anchor="middle" class="tb">uso</text><text x="432" y="108" text-anchor="middle" class="ts">mediado</text>
<rect class="cx"  x="485" y="70" width="85" height="50" rx="8"/><text x="527" y="92" text-anchor="middle" class="tb">rotação</text><text x="527" y="108" text-anchor="middle" class="ts">nova chave</text>
<rect class="cxd" x="580" y="70" width="90" height="50" rx="8"/><text x="625" y="92" text-anchor="middle" class="tb td">destruição</text><text x="625" y="108" text-anchor="middle" class="ts">com prova</text>
<line class="ln" x1="95" y1="95" x2="103" y2="95" marker-end="url(#seta)"/>
<line class="ln" x1="190" y1="95" x2="198" y2="95" marker-end="url(#seta)"/>
<line class="ln" x1="285" y1="95" x2="293" y2="95" marker-end="url(#seta)"/>
<line class="ln" x1="380" y1="95" x2="388" y2="95" marker-end="url(#seta)"/>
<line class="ln" x1="475" y1="95" x2="483" y2="95" marker-end="url(#seta)"/>
<line class="ln" x1="570" y1="95" x2="578" y2="95" marker-end="url(#seta)"/>
<path class="lnt" d="M527,70 C527,30 432,30 432,68" marker-end="url(#seta-t)"/>
<text x="480" y="36" text-anchor="middle" class="ts">volta ao uso</text>
<text x="670" y="150" text-anchor="end" class="ts td">a fase mais subestimada:</text>
<text x="670" y="164" text-anchor="end" class="ts td">backup, fita, slot esquecido</text>
<text x="10" y="150" class="ts">nasce dentro;</text>
<text x="10" y="164" class="ts">nunca vem de fora em claro</text>
</svg>
<figcaption>Figura 14.1 — O ciclo de vida de uma chave. Uma chave que "não é mais usada" e continua num backup ainda está viva.</figcaption>
</figure>

A parte que quase sempre é subestimada é a **destruição**. Uma chave que
"não é mais usada" mas continua num backup de fita, num slot que ninguém
limpou, ou na memória de um módulo que foi para o lixo, continua sendo uma
chave viva do ponto de vista do atacante.
