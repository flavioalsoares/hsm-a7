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
blockchain. Vários fabricantes, tipicamente validados em FIPS 140-3,
YubiHSM.

A interface padrão é **PKCS#11** — `C_GenerateKey`, `C_Sign`, `C_WrapKey` —
ou APIs próprias (JCE, CNG, KMIP). O modelo mental é o de um chaveiro com
objetos que têm atributos, e os atributos é que definem o que se pode fazer
com cada chave.

### HSM em nuvem

AWS CloudHSM, Azure Managed HSM, Google Cloud HSM. Fisicamente são os
mesmos módulos, operados pelo provedor, com o cliente controlando as chaves.
O interesse conceitual está no problema novo que criam: **como você confia
num módulo que não está na sua sala?** A resposta envolve atestação remota,
e é uma área em movimento.

### Elementos seguros e TPMs

Primos pequenos: TPM na placa-mãe, Secure Enclave, smartcard, YubiKey. Mesma
ideia — chave que não sai, operação mediada — com orçamento de área,
consumo e custo muito menores. Um cartão de crédito com chip é um HSM
minúsculo cuja produção passa de bilhões de unidades por ano.

### O que este projeto modela

O caminho de pagamentos: **LMK, key blocks TR-31, cerimônia de carga com
componentes, dual control físico**. A razão é didática — é a família onde os
mecanismos organizacionais (quem autoriza o quê, e como se prova) estão mais
explícitos e mais bem documentados publicamente.

A Fase 5 do plano acrescenta um subconjunto de PKCS#11, para mostrar a outra
interface sobre o mesmo núcleo.
