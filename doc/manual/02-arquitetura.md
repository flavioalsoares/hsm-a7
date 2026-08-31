# Parte II — Arquitetura interna

## 5. A fronteira criptográfica

É o conceito central, e num projeto bem feito ele é literal e desenhável.
Num documento de certificação FIPS existe um diagrama marcando o que está
dentro, o que está fora, e uma lista de **todas** as portas que atravessam.

Neste projeto:

```
                    ┌───────────────── FPGA ─────────────────┐
   host (PC)        │                                        │
   ┌────────┐  UART │  ┌──────────┐      ┌────────────────┐  │
   │hsmtool │◄─────►│  │ NEORV32  │◄────►│ AES-256 (CFS)  │  │
   │  .py   │ 115k2 │  │  RV32IMC │      │ SHA-256        │  │
   └────────┘       │  │          │      │ TRNG           │  │
                    │  └────┬─────┘      └────────────────┘  │
                    │       │                                │
                    │  ┌────▼──────────────────────────────┐ │
                    │  │ Key store  (BRAM — NUNCA DDR3)    │ │
                    │  │ LMK + 16 slots + estado           │ │
                    │  └───────────────────────────────────┘ │
                    └────────────────────────────────────────┘
```

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

```
        LMK  (Local Master Key)
         │    nunca sai, nem embrulhada
         │
         ├── KBEK / KBAK ── derivadas por CMAC, uma por propósito
         │      │
         │      └── protegem key blocks TR-31
         │
         └── chaves de trabalho: BDK, KEK, chaves de dados, ZMK, ZPK...
```

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
autenticação) são derivadas da LMK por CMAC com rótulos distintos. A chave
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

```
    LMK = componente_A ⊕ componente_B ⊕ componente_C
```

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

```
   D0112K0AB00N0000  <corpo cifrado em AES-CBC>  <CMAC>
   ^^^^^^^^^^^^^^^^
   cabeçalho, em claro, mas COBERTO PELO MAC
```

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

### Por que escrever o parser duas vezes

Neste projeto o TR-31 é implementado em C no firmware e em Python no host, e
os dois validam-se mutuamente sobre blocos aleatórios.

É de longe a forma mais rápida de aprender o padrão de verdade, porque a
menor divergência — um byte de preenchimento, uma ordem de campo, um
comprimento incluído ou não na contagem — aparece imediatamente como MAC
inválido. Não dá para "quase" implementar TR-31: ou os dois lados concordam
em cada byte, ou nada funciona.

## 9. Máquina de estados: a chave de switch

```
UNINITIALIZED ──LMK completa──► AUTHORIZED ──ativar──► OPERATIONAL
      ▲                              │                      │
      └──────────── zeroize ─────────┴──── tamper/zeroize ───┘
                                     ▼
                                 TAMPERED
```

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
existe para proteger o que restou, não para continuar servindo. Só dois
comandos respondem ali — `SELFTEST`, para dizer **o que** reprovou, e
`ZEROIZE`, para apagar.

## 10. Aleatoriedade: onde HSM vira ciência

Um HSM é tão bom quanto seu gerador. Chave previsível é chave pública, e o
histórico de falhas nessa área é longo e caro.

A arquitetura padrão tem duas camadas:

```
  fonte física  ──►  testes de saúde  ──►  DRBG  ──►  chaves
  (ruído)            RCT + APT             AES-CTR
  entropia bruta     SP 800-90B            SP 800-90A
```

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
| **Uso** | Só operações permitidas pelo modo de uso | Mediação, máquina de estados |
| **Rotação** | Nova chave gerada, antiga marcada | `use_count`, política |
| **Destruição** | Zeroize, com prova | `wipe()`, verificação por dump |

A parte que quase sempre é subestimada é a **destruição**. Uma chave que
"não é mais usada" mas continua num backup de fita, num slot que ninguém
limpou, ou na memória de um módulo que foi para o lixo, continua sendo uma
chave viva do ponto de vista do atacante.
