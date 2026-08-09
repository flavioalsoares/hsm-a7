# Parte VII — Criptografia de pagamento

Esta parte existe porque o modelo de referência deste projeto passou a ser
um **HSM de pagamento comercial**. Entender o que
esses equipamentos fazem o dia inteiro é o que separa "sei o que é uma
fronteira criptográfica" de "sei por que aquele comando existe".

Aviso que vale para o capítulo inteiro: **este projeto não implementa nada
do que está aqui.** A seção 38 explica o que dele é implementável e o que
não é, e por quê. O material abaixo é para entender o domínio, não para
copiar em código.

> **Independência e fontes.** Este capítulo **não nomeia fabricante nem
> produto**, de propósito. O modelo de estudo é a *categoria* — HSM de
> pagamento — e nada aqui alega vínculo, endosso ou compatibilidade com
> equipamento comercial algum.
>
> Todo o conteúdo vem de **normas públicas** (ISO 9564, ANSI X9.24 e X9.143,
> NIST SP 800-38B) e de **literatura acadêmica publicada**. Nada é derivado
> de documentação proprietária: tabela de comandos, código de erro e esquema
> de chave de manual de fabricante são material licenciado e **não entram
> aqui**.

> **Sobre os layouts de bytes.** Descrevo a *estrutura* e o *porquê* de cada
> construção, não o mapa exato de nibbles. Isso é deliberado: os layouts
> normativos estão na ISO 9564, na ANSI X9.24 e nas especificações das
> bandeiras, e a regra deste projeto proíbe escrever valor normativo de
> memória. Quem for implementar tem de ler a norma — e essa é a lição, não
> um contratempo.

---

## 34. PIN blocks — por que um PIN não viaja sozinho

Um PIN de quatro dígitos tem 10.000 valores possíveis. Cifrar isso
diretamente com uma chave, sozinho, é um desastre: o mesmo PIN produz sempre
o mesmo criptograma, e um dicionário de 10.000 entradas quebra tudo em
tempo nenhum.

A solução é o **PIN block**: um bloco de tamanho fixo que combina o PIN com
o **número da conta** (PAN) antes de cifrar. Duas consequências, e as duas
importam:

1. O criptograma de um mesmo PIN é **diferente para cada conta**. O
   dicionário morre.
2. O PIN block fica **amarrado à conta**. Um PIN block capturado numa
   transação não serve para outra conta — pelo menos é essa a intenção.

A ISO 9564-1 padroniza vários formatos. Interessam três.

### 34.1 Formato 0 (ANSI X9.8) — o que existe em todo lugar

O mais antigo e o mais difundido. A ideia:

```
   campo do PIN   comprimento + digitos do PIN + preenchimento fixo
   campo do PAN   parte do numero da conta, alinhada
   PIN block      cifra( campo_PIN  XOR  campo_PAN )
```

Bloco de 64 bits, porque nasceu para DES.

**Onde ele é fraco, e não é na cifra:**

- **O preenchimento é fixo.** Sabendo o formato, o atacante conhece boa
  parte do bloco em claro antes de começar.
- **O bloco não é autenticado.** Nada prova que aquele PIN block é o que o
  emissor mandou. Autenticidade vem de fora, se vier.
- **64 bits é pouco.** Com DES, o tamanho de bloco vira problema estatístico
  antes de o tamanho de chave virar.
- **O PAN é fornecido por quem chama.** Esta é a pior. Se o atacante
  controla o PAN que entra no XOR, ele controla metade do bloco — e é daí
  que saem os ataques de tradução da seção 15.3.

### 34.2 Formato 1 — quando não há conta

Usa preenchimento **aleatório** e não inclui o PAN. Existe para o caso em
que o número da conta não está disponível no momento de formar o bloco.

O preço é exatamente o que o formato 0 comprava: **o bloco não está amarrado
a conta nenhuma**. Um PIN block formato 1 capturado vale para qualquer conta
que aceite formato 1. Por isso ele é restrito a trechos onde outra coisa
garante o vínculo.

### 34.3 Formato 3 — o remendo intermediário

Como o formato 0, mas com preenchimento **aleatório** em vez de fixo. Tapa o
buraco do "atacante já conhece metade do bloco" sem mexer no resto. Continua
com bloco de 64 bits e continua não autenticado.

### 34.4 Formato 4 — o de AES, e o único que este projeto poderia fazer

Reprojetado para AES, bloco de 128 bits. A estrutura tem **duas passagens de
cifra**, e é isso que importa:

```
   bloco A   controle + comprimento + digitos do PIN + preenchimento ALEATORIO
   bloco B   campo do PAN, alinhado em 128 bits
   
   intermediario = AES( K, bloco A )
   bloco C       = intermediario XOR bloco B
   PIN block     = AES( K, bloco C )
```

Compare com o formato 0, que é **uma** cifra sobre um XOR. A diferença não é
cosmética:

- No formato 0, controlar o campo do PAN é controlar diretamente a entrada
  da cifra. No formato 4, o XOR com o PAN acontece **depois** de uma
  passagem de AES — o atacante não controla mais a entrada, controla a
  entrada de uma função que ele não sabe inverter.
- O preenchimento aleatório faz o mesmo PIN, na mesma conta, produzir blocos
  diferentes a cada vez.
- 128 bits de bloco elimina o problema estatístico do DES.

**Este é o único formato que este projeto poderia implementar de verdade**,
porque é o único que usa AES — e AES é o que existe no fabric.

---

## 35. Tradução de PIN — o comando mais perigoso que existe

Uma transação com cartão atravessa domínios de chave diferentes: terminal,
adquirente, bandeira, emissor. Cada domínio tem a sua chave. O PIN precisa
chegar do primeiro ao último **sem nunca aparecer em claro fora de um HSM**.

Quem faz isso é a **tradução de PIN block** — o comando `CA` de um
de pagamento. Ele:

1. recebe o PIN block cifrado sob a chave de entrada,
2. decifra **dentro** da fronteira,
3. recifra sob a chave de saída (possivelmente noutro formato),
4. devolve o novo PIN block.

O PIN existe em claro por microssegundos, dentro do módulo, e nunca sai.

**Por que é o comando mais perigoso:** ele é, por construção, um oráculo. O
chamador escolhe as chaves, escolhe o PAN, escolhe os formatos, e observa se
a operação teve sucesso. Todos os ataques da seção 15.3 nascem daí — o
módulo nunca revela o PIN, revela apenas *se deu certo*, e isso basta quando
se pode perguntar milhares de vezes.

Se você entender um único comando de HSM de pagamento a fundo, que seja
este.

---

## 36. Verificação de PIN — PVV e IBM 3624

O emissor precisa decidir se o PIN digitado está certo. Guardar os PINs
numa base seria insano, então guarda-se um **valor derivado** de quatro
dígitos, e a verificação recalcula e compara.

Duas famílias dominam.

### 36.1 PVV (Visa)

Combinam-se dígitos do PAN, um índice de chave e o PIN; cifra-se o conjunto
com um par de chaves PVK; **decimaliza-se** o resultado; guardam-se quatro
dígitos. Para verificar, o emissor refaz a conta com o PIN apresentado e
compara.

Repare no que ele **não** faz: não guarda o PIN e não permite recuperá-lo.
Quatro dígitos de PVV não determinam o PIN — várias entradas colidem, e é
proposital.

### 36.2 IBM 3624 e o *offset*

Cifra-se um dado de validação derivado do PAN, decimaliza-se, e obtêm-se
alguns dígitos: o **PIN natural**. Como o cliente quer escolher o próprio
PIN, guarda-se o **offset** — a diferença dígito a dígito, módulo 10, entre
o PIN escolhido e o natural.

O offset **não é secreto**: ele pode ser impresso, transportado, guardado em
claro. Sem a chave, ele não diz nada sobre o PIN.

### 36.3 A decimalização, e por que ela é o ponto fraco

Cifrar produz **hexadecimal**. PIN é **decimal**. A ponte entre os dois é
uma tabela:

```
   hex:    0 1 2 3 4 5 6 7 8 9 A B C D E F
   tabela: 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
```

Essa tabela, que parece detalhe de formatação, é a origem do ataque mais
instrutivo da literatura de HSM — **Bond e Zieliński, 2003**. Algumas APIs
deixavam o *chamador* fornecê-la. Fornecendo tabelas degeneradas e
observando apenas "verificou / não verificou", recupera-se um PIN de quatro
dígitos em cerca de **quinze chamadas**, contra cinco mil de força bruta.

O ataque está detalhado na **seção 15.2**. Aqui só o alerta que ele deixa:

> Um parâmetro que parece configuração inofensiva pode ser a superfície de
> ataque inteira.

E é por isso que o checklist deste projeto pergunta, para todo comando
novo, *o que ele vaza se for chamado em laço com entradas escolhidas*.

---

## 37. DUKPT — uma chave por transação

Imagine um milhão de terminais em campo. Se todos compartilham a mesma
chave, um terminal aberto na bancada de alguém compromete a rede inteira.
Se cada um tem chave própria, é preciso distribuir e gerenciar um milhão de
chaves.

**DUKPT** (*Derived Unique Key Per Transaction*) resolve os dois de uma vez:

- Existe uma **BDK** (*Base Derivation Key*), que fica só no HSM do
  adquirente e **nunca vai para o terminal**.
- Cada terminal recebe, na personalização, uma chave inicial derivada da BDK
  com o identificador dele.
- A cada transação, o terminal deriva uma **chave nova** e **apaga a
  anterior**.
- O terminal envia o **KSN** (*Key Serial Number*) — identificador do
  dispositivo mais um contador de transação. Com o KSN e a BDK, o HSM do
  adquirente rederiva exatamente a mesma chave.

As três propriedades que isso compra:

1. **Compromisso isolado.** Abrir um terminal não dá nada sobre os outros.
2. **Sigilo do passado.** As chaves usadas já foram apagadas no terminal;
   quem o abrir agora não decifra o que passou por ele ontem.
3. **Nada para distribuir.** O HSM rederiva; não existe base de um milhão de
   chaves para sincronizar.

### 37.1 X9.24-1 (TDES) e X9.24-3 (AES)

| | TDES DUKPT (X9.24-1) | AES DUKPT (X9.24-3) |
|---|---|---|
| Cifra | 3DES de duas chaves | AES-128/192/256 |
| Registradores de chave futura | 21 | 32 |
| Derivação | esquema próprio, histórico | função de derivação uniforme |
| Situação | legado, em desativação | o caminho adiante |

A variante AES não é só "a mesma coisa com outra cifra": a derivação foi
reescrita para ser uniforme e para suportar chaves de propósitos diferentes
a partir da mesma raiz — separação de chaves construída no esquema, em vez
de convencionada por fora.

**A variante AES é implementável neste projeto.** A TDES não, e o motivo é
o assunto da próxima seção.

---

## 38. O que este projeto pode e o que não pode ensinar

A separação não é por dificuldade. É por **hardware** e por **procedência
de vetor de teste**.

| Assunto | Aqui? | O que decide |
|---|---|---|
| PIN block formato 4 | **sim** | é AES, e AES é o que existe no fabric |
| PIN block formato 0 e 3 | **estrutura sim** | a construção e as fraquezas se ensinam; a cifra real é DES |
| Tradução de PIN | **sim** | o valor está no formato do comando e no oráculo, não na cifra |
| Ataque de decimalização | **sim, e é o melhor item** | é ataque de **API**. Reproduz-se num esquema com AES, sem 3DES e sem vetor de bandeira |
| DUKPT AES (X9.24-3) | **sim** | cabe no hardware AES-only |
| CVV / CVC | **não** | inerentemente 3DES; não há variante AES em uso |
| PVV | **não** | idem — mas o *ataque* sobre ele se ensina sem ele |
| DUKPT TDES (X9.24-1) | **não** | idem |

### 38.1 Um HSM precisa de 3DES?

A resposta depende de qual HSM, e a diferença ensina mais que a resposta.

**HSM de propósito geral, hoje: não.** O NIST desautorizou o TDEA para
*cifrar* a partir de 2024 (SP 800-131A Rev. 2). Ele sobrevive apenas como
algoritmo de **decifração legada** — para abrir o que foi cifrado antes.
Projeto novo usa AES, e um módulo que ofereça 3DES para cifrar dados novos
está oferecendo um pé no passado.

**HSM de pagamento em produção: sim, na prática.** Um módulo sem 3DES
não conversa com a rede. PIN blocks sob ZPK de 3DES, PVV e CVV sob chaves
3DES, terminais DUKPT TDES aos milhões em campo — tudo isso existe agora, em
operação, movendo dinheiro. Um módulo que só faça AES é inútil como
substituto de um que está instalado.

**E aqui está o ponto que vale o capítulo:** a migração para key blocks e
para AES foi mandatada em fases pelo PCI e levou **mais de uma década**.
Não porque AES seja difícil, mas porque trocar criptografia numa rede com
milhões de pontas não é decisão técnica — é logística, contrato e prazo
regulatório. Terminal em campo não se atualiza por vontade; norma de
mensagem não muda sozinha; e cada elo da cadeia precisa aceitar o novo
formato *antes* que o anterior possa ser desligado.

É por isso que criptografia obsoleta sobrevive tanto em pagamentos. Não é
descuido: é o custo real de mover um ecossistema.

**Este projeto: não, e a ausência é conteúdo.** Não há requisito de
interoperar com ninguém, então não há a pressão que mantém o 3DES vivo lá
fora. A restrição vira lição em vez de limitação.

### 38.2 Por que não há 3DES aqui

Não é omissão: é decisão registrada. O coprocessador deste projeto amarra o
tamanho de chave em **AES-256, sem caminho para AES-128** — porque um modo
mais fraco alcançável por escrita em registrador é um *downgrade* de graça
para quem tomar o barramento. Acrescentar um núcleo DES contradiz esse
princípio no mesmo bloco.

É defensável ter um motor legado, separado e rotulado como tal — que é
honestamente o que um HSM de pagamento real tem, porque o mundo ainda roda
3DES. Mas é escolha consciente, e fica para quando a fase chegar.

### 38.3 O obstáculo maior são os vetores

A regra inviolável deste projeto diz que, se um teste de resposta conhecida
falha, **o erro está no código, não no vetor** — e isso só vale se a
procedência do vetor for verificável por terceiros. AES, SHA, HMAC, CMAC e
CTR_DRBG têm vetores públicos do NIST e do IETF, com hash registrado.

Criptografia de pagamento não tem esse luxo. Os vetores da ANSI X9.24-3
estão atrás de paywall; os de CVV e PVV vivem em documentação de bandeira e
em manual de fabricante. Sem vetor autoritativo não há KAT, e "implementei e
parece certo" é exatamente o que a regra existe para proibir.

**Consequência prática:** onde não houver vetor público, o item não entra —
ou entra explicitamente marcado como não verificado. Preferir a lacuna
honesta à cobertura fingida é o mesmo critério que orienta o resto do
documento.

### 38.4 Uma regra que não se negocia

⚠ **Nenhum número de cartão real, nunca.** Pela mesma razão que nenhuma
chave de produção. Gerar CVV ou PIN para um PAN que existe deixa de ser
exercício, e o fato de o dispositivo ser de brinquedo não muda isso.
