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

<figure class="fig">
<svg viewBox="0 0 680 300" xmlns="http://www.w3.org/2000/svg">
<rect class="cxd" x="270" y="10" width="140" height="46"/>
<text x="340" y="30" text-anchor="middle" class="tb">LMK</text>
<text x="340" y="46" text-anchor="middle" class="ts">nunca sai, nem embrulhada</text>
<line class="ln" x1="340" y1="56" x2="340" y2="84" marker-end="url(#seta)"/>
<text x="350" y="76" class="ts">CMAC, por propósito</text>
<rect class="cx" x="200" y="86" width="120" height="40"/><text x="260" y="104" text-anchor="middle" class="tb">KBEK</text><text x="260" y="118" text-anchor="middle" class="ts">cifra o corpo</text>
<rect class="cx" x="360" y="86" width="120" height="40"/><text x="420" y="104" text-anchor="middle" class="tb">KBAK</text><text x="420" y="118" text-anchor="middle" class="ts">autentica</text>
<line class="ln" x1="340" y1="126" x2="340" y2="152" marker-end="url(#seta)"/>
<text x="350" y="146" class="ts">protegem</text>
<rect class="cxa" x="20" y="154" width="640" height="30"/>
<text x="340" y="174" text-anchor="middle">key blocks X9.143, guardados fora do HSM (banco de dados do host)</text>
<line class="ln" x1="80" y1="184" x2="80" y2="206" marker-end="url(#seta)"/>
<line class="ln" x1="210" y1="184" x2="210" y2="206" marker-end="url(#seta)"/>
<line class="ln" x1="340" y1="184" x2="340" y2="206" marker-end="url(#seta)"/>
<line class="ln" x1="470" y1="184" x2="470" y2="206" marker-end="url(#seta)"/>
<line class="ln" x1="600" y1="184" x2="600" y2="206" marker-end="url(#seta)"/>
<rect class="cx" x="20"  y="208" width="120" height="44"/><text x="80"  y="226" text-anchor="middle" class="tb">KEK (K0)</text><text x="80"  y="242" text-anchor="middle" class="ts">troca com outro banco</text>
<rect class="cx" x="150" y="208" width="120" height="44"/><text x="210" y="226" text-anchor="middle" class="tb">PIN (P0)</text><text x="210" y="242" text-anchor="middle" class="ts">zona, terminal</text>
<rect class="cx" x="280" y="208" width="120" height="44"/><text x="340" y="226" text-anchor="middle" class="tb">BDK (B0)</text><text x="340" y="242" text-anchor="middle" class="ts">deriva os terminais</text>
<rect class="cx" x="410" y="208" width="120" height="44"/><text x="470" y="226" text-anchor="middle" class="tb">dados, MAC</text><text x="470" y="242" text-anchor="middle" class="ts">D0, M0..M3</text>
<rect class="cx" x="540" y="208" width="120" height="44"/><text x="600" y="226" text-anchor="middle" class="tb">CVV, PVV</text><text x="600" y="242" text-anchor="middle" class="ts">C0, V1, V2</text>
<line class="lnt" x1="80" y1="252" x2="80" y2="278" marker-end="url(#seta-t)"/>
<text x="90" y="284" class="ts">sob a KEK, a chave viaja até outra instituição</text>
<line class="lnt" x1="340" y1="252" x2="340" y2="278" marker-end="url(#seta-t)"/>
<text x="350" y="284" class="ts">IPEK de cada terminal; uma chave por transação</text>
</svg>
<figcaption>Figura 6.1 — A hierarquia de chaves. O HSM guarda um segredo, a LMK; todas as outras chaves existem como key blocks sob ela.</figcaption>
</figure>
Três razões, e vale entender cada uma porque elas explicam decisões
aparentemente arbitrárias mais adiante.

**Backup e migração.** Se cada chave fosse independente, mover o serviço para
outro HSM significaria mover N segredos, cada um com seu próprio
procedimento. Com a hierarquia, você move a LMK — por cerimônia, em
componentes — e todos os key blocks existentes continuam válidos, porque eles
sempre foram apenas dados cifrados sob ela.

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
<figcaption>Figura 8.2 — Da KBPK ao bloco, na versão D. As duas subchaves nascem por CMAC, servem a um bloco e são apagadas.</figcaption>
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
terceiros, seção 42.1). A KBPK é
`88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6`:

```
    KBEK, 1a chamada   CMAC(KBPK, 0100000000040100) = 396C9382A6E2E66A088774E1D6E46541
    KBEK, 2a chamada   CMAC(KBPK, 0200000000040100) = F5EAD67D7204F8DD0D7AE8FDA334D3AC
    KBAK, 1a chamada   CMAC(KBPK, 0100010000040100) = 4EF24317696213840451890756757E57
    KBAK, 2a chamada   CMAC(KBPK, 0200010000040100) = 3E0673483888F9B7F9B7517827F95022
```

A KBEK é a junção das duas primeiras saídas; a KBAK, a das duas últimas. Só
o terceiro byte da entrada muda entre elas, e as duas não têm nada em comum.

**O bloco, aberto.** O bloco publicado tem 112 caracteres:

```
    D0112P0AE00E0000                  cabeçalho, 16 caracteres
    B82679114F470F54 0165EDFBF7E250FC
    EA43F810D215F8D2 07E2E417C07156A2  corpo cifrado, 32 bytes
    7E8E31DA05F74255 09593D03A457DC34  MAC, 16 bytes
```

Decifrar o corpo com a KBEK em AES-CBC, com o MAC como IV, dá:

```
    0080  3F419E1CB7079442AA37474C2EFBF8B8  1C2965473CE206BB855B01533782
    bits  a chave, 16 bytes                 enchimento aleatório, 14 bytes
```

O CMAC-AES com a KBAK sobre o cabeçalho e esse corpo em claro dá
`7E8E31DA05F7425509593D03A457DC34`, o MAC do bloco: ele é íntegro. O
corpo tem 2 + 16 + 14 = 32 bytes, múltiplo de 16, e o bloco tem
16 + 2 × 32 + 2 × 16 = 112 caracteres. Os valores foram conferidos com a
biblioteca `cryptography` e com `host/tr31.py`.

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
