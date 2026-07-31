# Arquitetura de um HSM, explicada por dentro

Documento de fundo do projeto. Explica **por que** um módulo criptográfico é
construído do jeito que é, e como cada conceito aparece — ou vai aparecer —
neste FPGA.

O `PLANO.md` diz o que fazer e em que ordem. Este arquivo diz o motivo.
`doc/fase1-notas.md` registra o que já foi feito e como foi verificado.

> **Este dispositivo não é um HSM.** Não há PUF, malha antitamper, sensores
> físicos, RNG certificado nem validação FIPS/PCI. É um objeto de estudo.
> Nenhuma chave de produção entra aqui.

---

## 1. O problema que um HSM resolve

Software normal guarda chaves em memória do processo. Quem tem acesso à
máquina — root, um dump de memória, um bug de leitura fora de limites — tem
a chave. Não há como distinguir "usar a chave" de "copiar a chave".

Um HSM existe para tornar essas duas coisas diferentes. Ele oferece uma
**interface de operações**, não de acesso: você manda "assine isto", nunca
"me devolva a chave". A chave nasce dentro, vive dentro e morre dentro.

Isso muda a pergunta de segurança. Não é mais "quem consegue ler a memória?",
e sim: **"o que a API permite deduzir sobre a chave, se for chamada um milhão
de vezes com entradas escolhidas?"** Praticamente todo o resto da arquitetura
decorre disso.

### As três propriedades

1. **Confinamento.** Existe uma fronteira física, e material de chave em
   claro não a atravessa.
2. **Mediação.** Toda operação passa por uma verificação de política antes de
   executar — estado do dispositivo, autorização, atributos da chave.
3. **Evidência.** O que aconteceu fica registrado de forma que o registro
   sobreviva à falha e não possa ser reescrito para omitir a tentativa.

Um cofre sem mediação é só um cofre com uma porta aberta. Uma API mediada sem
confinamento é uma sugestão. Sem evidência, você nunca sabe se alguma das
outras duas falhou.

---

## 2. A fronteira criptográfica

É o conceito central, e neste projeto ele é literal e observável.

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
**Fora:** key blocks wrapped, KCVs, criptogramas, handles, log de auditoria.

Nada da primeira lista atravessa para a segunda. Todo comando novo é avaliado
contra essa regra **antes** de ser implementado — está no checklist do
`CLAUDE.md`, e não é cerimônia: é o único momento barato de perceber que um
comando vaza.

### Por que a UART antes de Ethernet

Porque a fronteira precisa ser **auditável**, não apenas afirmada.

A UART sai por dois pinos físicos identificáveis (T15/T14). Dá para pôr um
analisador lógico em T14 e capturar tudo que o dispositivo já disse. O
critério de aceitação da Fase 3 usa exatamente isso: rodar a suíte inteira,
capturar a UART, e fazer `grep` das chaves conhecidas do teste contra a
captura. Se aparecer um byte, o projeto falhou — e você **sabe**.

Com Ethernet, "nenhuma chave vazou" vira uma opinião sobre um stack de rede.
Com dois fios, vira uma medida.

### Por que chaves só em BRAM

A BRAM é memória interna ao die. Para lê-la é preciso decapsular o chip.

A DDR3 da placa é externa: o barramento passa por trilhas na PCB e chega a
conectores. Uma ponta de prova resolve. Por isso a DDR3 não é apenas evitada
por convenção — o barramento externo (`XBUS_EN`) está **desligado no
processador**, de forma que não existe caminho físico do SoC até ela. A regra
virou estrutura em vez de disciplina.

Mesma lógica para o debugger on-chip: `OCD_EN => false`. O OCD dá leitura e
escrita irrestritas de memória via JTAG. Num dispositivo com a LMK em BRAM,
isso é literalmente um comando de extração de chave. É o generic mais
importante do wrapper.

---

## 3. Hierarquia de chaves: por que não guardar as chaves

Um HSM com 16 slots não guarda 16 chaves. Guarda **uma** — e deriva ou
protege todas as outras com ela.

```
        LMK  (Local Master Key)
         │    nunca sai, nem wrapped
         │
         ├── KBEK/KBAK ── derivadas por CMAC, por propósito
         │      │
         │      └── protegem key blocks TR-31
         │
         └── slots de trabalho (BDK, KEK, chaves de dados...)
```

Três razões para essa estrutura:

**Backup e migração.** Se cada chave fosse independente, mover o serviço para
outro HSM significaria mover N chaves. Com a hierarquia, você move a LMK (por
cerimônia, em componentes) e todos os key blocks continuam válidos.

**Revogação em bloco.** Zeroizar a LMK invalida instantaneamente todo key
block que existe no mundo protegido por ela. É a única operação de destruição
que você consegue executar em tempo constante sobre dados que não estão na
sua posse.

**Separação de propósito.** KBEK e KBAK são derivadas da LMK por CMAC com
rótulos diferentes. A chave que cifra o corpo nunca é a mesma que autentica o
cabeçalho. Se fosse, um atacante que quebrasse uma quebraria as duas — e há
ataques que exploram exatamente reuso de chave entre modos.

### A cerimônia de LMK

A LMK não é gerada e depois copiada. Ela é **montada** dentro do dispositivo,
a partir de componentes que ninguém vê juntos:

```
LMK = componente_A XOR componente_B XOR componente_C
```

Cada custodiante carrega apenas o seu, e nenhum componente isolado revela
nada sobre a LMK (é o argumento do one-time pad: XOR com material
desconhecido). Isso é **split knowledge**.

A cada passo, o dispositivo devolve um **KCV** — Key Check Value, os 3 bytes
mais significativos de AES-ECB sobre um bloco de zeros. É um "hash de
verificação" pequeno o bastante para não ajudar um atacante e grande o
bastante para pegar digitação errada. O host confere o KCV final contra o
valor calculado independentemente. Se bater, os três componentes entraram
certos.

**Dual control em hardware.** `LMK_LOAD_COMPONENT` só é aceito com os dois
botões pressionados simultaneamente. É simplório e é o ponto: separa
fisicamente *quem digita* de *quem autoriza*. Um operador sozinho, mesmo com
acesso total ao host, não carrega componente nenhum.

Escolhi SW2 e SW5, os extremos da fileira, para dificultar pressionar os dois
com uma mão só. E o debounce de 10 ms não é detalhe de usabilidade: um
ressalto de contato lido como pressionamento vale por uma autorização que
ninguém deu — o custodiante que soltou o botão não consentiu com o segundo
pulso.

---

## 4. Key blocks TR-31: por que o formato é feio

TR-31 (hoje ANSI X9.143) é o formato de troca de chaves da indústria de
pagamentos. Um key block é ASCII, tem cabeçalho legível e parece
desnecessariamente complicado. Cada complicação existe por um incidente.

```
  D0112K0AB00N0000  <corpo cifrado em AES-CBC>  <CMAC>
  ^^                 cabeçalho, em claro
```

**Por que o cabeçalho é autenticado junto com o corpo.** O cabeçalho diz o
que a chave é: seu uso (`K0` = KEK, `B0` = BDK, `D0` = dados), seu algoritmo,
seu modo de uso (só cifrar, só decifrar, ambos), e sua **exportabilidade**.

Se o cabeçalho não fosse coberto pelo MAC, um atacante poderia pegar um key
block legítimo e trocar `N` (não exportável) por `E` (exportável), ou trocar
"só verificar PIN" por "cifrar dados arbitrários". A chave continuaria
válida, o HSM a importaria, e ela faria algo que o dono nunca autorizou. Isso
não é hipotético — é a razão histórica pela qual formatos anteriores (key
blocks "variant") foram abandonados.

Por isso: **um byte errado no cabeçalho explode o MAC inteiro.** É o
comportamento desejado.

**Por que escrever o parser duas vezes.** Em C no firmware e em Python no
host, validando um contra o outro em 100 blocos aleatórios. É de longe a
forma mais rápida de aprender o padrão de verdade, porque a menor divergência
— um byte de padding, uma ordem de campo, um comprimento incluído ou não —
aparece imediatamente como MAC inválido. Você não pode "quase" implementar
TR-31.

---

## 5. Máquina de estados: a chave de switch

```
UNINITIALIZED ──LMK completa──► AUTHORIZED ──ativar──► OPERATIONAL
      ▲                              │                      │
      └──────────── zeroize ─────────┴──── tamper/zeroize ───┘
                                     ▼
                                 TAMPERED
```

HSMs comerciais têm uma chave física de três posições. O modelo é este:
comandos sensíveis existem **apenas** em `AUTHORIZED`, um estado em que o
dispositivo só entra com intervenção física deliberada e no qual ele não
serve produção.

A ideia é que a superfície de ataque em operação normal seja mínima. Em
`OPERATIONAL`, o dispositivo faz o trabalho e nada mais: não carrega chave,
não exporta LMK, não muda política. Um invasor que comprometa totalmente o
host de produção ainda não consegue carregar componente de LMK, porque o
dispositivo simplesmente não aceita aquele opcode naquele estado.

`TAMPERED` é absorvente: uma vez lá, só sai por zeroize. E `ST_NORMAL` no
firmware exclui `TAMPERED` de propósito — um dispositivo comprometido
responde o mínimo possível.

---

## 6. Aleatoriedade: onde HSM vira ciência

Um HSM é tão bom quanto seu gerador. Chave previsível é chave pública.

A arquitetura padrão tem duas camadas:

```
  fonte física (ruído)  ──►  health tests  ──►  DRBG  ──►  chaves
     neoTRNG, ROs           RCT + APT        CTR_DRBG
     entropia bruta         SP 800-90B       AES-256
```

**Por que não usar a fonte física direto.** Ruído físico tem viés e
correlação. Osciladores em anel num FPGA são sensíveis a temperatura e a
tensão de alimentação — e um atacante que controle a fonte pode reduzir a
entropia sem que nada pareça errado. O DRBG existe para transformar entropia
imperfeita mas *suficiente* num fluxo computacionalmente indistinguível de
aleatório.

**Por que os health tests são o coração.** SP 800-90B exige que a fonte seja
monitorada continuamente, não validada uma vez:

- **RCT** (Repetition Count Test) — dispara se a mesma amostra se repete
  demais. Pega a falha catastrófica: o oscilador parou, a fonte travou em um
  valor.
- **APT** (Adaptive Proportion Test) — janela de 512/1024 amostras, dispara
  se um valor domina. Pega a degradação: a fonte ainda oscila, mas enviesada.

Falha em qualquer um → `TAMPERED`, DRBG parado, LED vermelho. Não é
paranoia: é a diferença entre "gerei uma chave fraca e não sei" e "me recusei
a gerar".

Escrever esses testes ensina mais sobre certificação de HSM que qualquer
whitepaper — eles são o motivo de um HSM real levar meses de validação.

---

## 7. Self-test: por que o dispositivo se recusa a funcionar

FIPS 140-3 exige que um módulo criptográfico rode testes de resposta conhecida
(KAT) na inicialização, **antes** de aceitar qualquer comando, e que ele entre
em estado de erro se qualquer um falhar.

Parece burocracia. Não é. O raciocínio: um AES que cifra errado não produz
erro visível — produz criptograma. Você não descobre nada até tentar
decifrar, possivelmente meses depois, possivelmente em outro dispositivo. Um
bit preso numa BRAM, uma violação de timing marginal, uma corrupção de
configuração: todos se manifestam como cripto silenciosamente errada.

Os KAT são o único momento em que o dispositivo pode dizer "eu não estou
funcionando" antes de causar dano.

Os mesmos vetores rodam nos testbenches de simulação **e** no POST. Isso é
deliberado e diagnóstico: se um KAT passa no testbench e falha no POST, o
problema está no barramento ou na integração, não no core.

**Regra inviolável nº 5 do projeto:** se um KAT falha, o bug está no código,
não no vetor. Não ajustar vetor, não relaxar assert, não marcar teste como
skip. Um teste enfraquecido para passar é pior que teste nenhum, porque agora
existe uma afirmação falsa de correção.

---

## 8. Zeroização: apagar é mais difícil do que parece

`memset(chave, 0, 32)` no fim de uma função é, para o compilador, um **dead
store**: escrita num buffer que ninguém lê depois. O padrão C permite
eliminá-lo, e com `-O2`/`-Os` o compilador elimina. A chave fica na memória,
intacta, e o código *parece* correto.

Por isso `fw/src/wipe.c` usa ponteiro `volatile` — cada escrita vira efeito
colateral observável e não pode ser descartada — seguido de barreira de
memória.

Isso já está no lugar, mesmo a Fase 1 não movimentando chave nenhuma, e os
buffers de frame são limpos após cada comando. O motivo é simples: são esses
mesmos buffers que vão carregar componente de LMK e key block na Fase 3.
Retroajustar limpeza depois é como se lembrar tarde demais.

O `ZEROIZE` de verdade vai além: sobrescreve a região de BRAM com padrão e
depois zeros, e o teste **prova** que apagou, fazendo dump da região e
verificando. "Chamei a função de apagar" não é evidência.

---

## 9. Log de auditoria: por que antes, não depois

O registro é gravado **antes** de executar o comando. Isso é contraintuitivo
— parece que você registraria o resultado.

O motivo é que um log escrito depois só registra sucesso. Tentativa que
falhou, comando que travou o dispositivo, sequência que causou reset: nada
disso aparece. E é exatamente essa a informação que importa numa investigação.
Um atacante sondando a API produz muitos erros e poucos sucessos; um log de
sucessos mostra um dispositivo saudável enquanto está sendo mapeado.

Contador monotônico para detectar remoção de entradas. Sem material de chave,
obviamente.

---

## 10. Por que este projeto é honesto sobre o que não é

Vale nomear as ausências, porque cada uma corresponde a um mecanismo real que
existe em HSM de verdade:

| Ausente aqui | O que faz num HSM real |
|---|---|
| Malha antitamper | Grade de trilhas na resina; rompimento → zeroize imediato |
| Sensores físicos | Temperatura, tensão, luz, movimento → detecta ataque invasivo |
| PUF | Raiz de confiança que não existe como dado armazenado |
| RNG certificado | Fonte de entropia validada por laboratório |
| Bateria | Mantém chaves e detectores vivos sem alimentação |
| Validação FIPS/PCI | Terceiro que tenta quebrar e documenta o que conseguiu |

E há uma ausência específica desta placa que é instrutiva: o pino `VCCBATT`
(F8) do core board QMTECH está ligado ao rail 1V8, sem bateria. Isso significa
que a chave de bitstream em BBRAM **se perde a cada power-off**.

Aqui isso é desejável — nada persiste no hardware, tudo é recuperável por
JTAG. E é exatamente o comportamento de um HSM comercial cuja bateria
descarregou: ele acorda zeroizado e inútil, o que é a falha segura correta.

### A regra do eFUSE

Nenhuma operação de eFUSE acontece neste projeto. `program_efuse`,
`CFG_AES_ONLY`, `W_DIS`/`R_DIS`, qualquer flag `-efuse`: são OTP, e o erro é
um brick permanente. Chave de bitstream só em BBRAM, que é recuperável.

Regra prática: se a operação contém a palavra eFUSE, ela não acontece.
Tutorial que mande queimar fusível é lido, documentado e não executado.

O JTAG também nunca é desabilitado — é a única via de recuperação, e um
projeto de estudo precisa poder voltar atrás.

---

## 11. O que foi construído até aqui (Fase 1)

Infraestrutura confiável antes de qualquer cripto. Nenhum dos conceitos
acima está implementado ainda — o que existe é o chão sobre o qual eles vão
ficar de pé.

### Estrutura

```
rtl/soc/clk_rst_gen.v      MMCM 50→100 MHz + reset
rtl/soc/debounce.v         filtro de ressalto dos botões
rtl/soc/neorv32_wrapper.vhd   configuração do processador
rtl/top/hsm_top.v          toplevel, único arquivo com nome de pino
fw/src/{main,cmd,state,wipe}.c   firmware
host/hsmtool.py            CLI e codec do protocolo
```

### O SoC e o que está desligado nele

NEORV32 (submódulo fixado em v1.13.3), RV32IMC, IMEM 16 KB, DMEM 8 KB, UART0,
GPIO, CLINT. A lista do que está **desligado** é mais informativa:

| Desligado | Por quê |
|---|---|
| `OCD_EN` | Debugger dá leitura/escrita de memória por JTAG — extração de chave |
| `ICACHE`/`DCACHE` | Inúteis (BRAM já é 1 ciclo) e nocivas: tempo dependente do dado é canal lateral |
| `XBUS`/`SMC` | Sem barramento externo, não há caminho físico até a DDR3 |
| `IO_TRACER` | Buffer de trace é observabilidade que não se quer |
| `Zkne`/`Zknd`/`Zknh` | AES e SHA vão para o fabric via CFS — usar a instrução pronta pularia o que se quer aprender |

`BOOT_MODE_SELECT = 2` (imagem na IMEM), não bootloader. Com bootloader,
qualquer um com acesso à UART reprograma o dispositivo e contorna a máquina de
estados inteira — é o problema de autenticidade de firmware de um HSM real.
Efeito colateral bem-vindo: a IMEM vira **ROM**, então a memória de código não
é gravável em tempo de execução.

### O protocolo

```
pedido    LEN(2) | CMD(1)    | PAYLOAD | CRC32(4)
resposta  LEN(2) | STATUS(1) | PAYLOAD | CRC32(4)
```

Big-endian; `LEN` cobre CMD/STATUS + PAYLOAD. O CRC32 cobre `LEN` + corpo —
incluir o `LEN` importa, porque é o campo que um atacante usaria para induzir
leitura fora do buffer. Polinômio IEEE 802.3 refletido, idêntico ao
`zlib.crc32`, o que mantém o host trivial.

Metade dos bugs de HSM caseiro nasce de enquadramento frouxo. Este é fechado
desde o primeiro commit.

**O timeout de inter-byte é o que impede negação de serviço com um byte.** Sem
ele, um host que morre no meio de um frame deixa o parser esperando para
sempre e o dispositivo mudo. É rearmado a cada byte, não por frame, porque um
key block TR-31 leva ~45 ms a 115200 e um timeout de frame teria de ser
afrouxado até deixar de proteger.

### O dispositivo é mudo até ser perguntado

Não há banner de boot. Um banner vaza versão e identidade para quem só
escuta, e um `printf` de depuração esquecido é canal lateral permanente. Há um
testbench (`tb_soc_silent`) que falha no dia em que alguém adicionar um — e
que exige silêncio **e** vida, porque firmware travado também fica quieto.

### Resultados

| | |
|---|---|
| LUTs | 2240 / 20800 (10,8%) |
| BRAM | 3,5 / 50 (7%) |
| DSP | 0 / 90 — reservados para o RSA da Fase 7 |
| Timing | WNS +0,637 ns @ 100 MHz (Fmax ≈ 107 MHz) |
| Firmware | 1652 B text, 1572 B bss |
| Aceitação | 10.000 pings, **0 erros**, mediana 4,36 ms, máx 6,50 ms |

A margem de timing já caiu de +5,95 para +0,637 ns conforme o SoC entrou. Os
cores de cripto da Fase 2 vão apertar mais — as alavancas estão em
`doc/fase1-notas.md`.

---

## 12. O que a Fase 1 ensinou que não estava no plano

Coisas descobertas fazendo, todas registradas em detalhe nos documentos
específicos:

**Verificação encontra o que revisão não encontra.** O `tb_hsm_top` reprovou a
primeira versão do toplevel com `led=1111x`: registradores sem valor inicial e
reset síncrono deixam uma janela indefinida entre a configuração do FPGA e o
primeiro clock. Em hardware o Vivado teria inicializado implicitamente e nada
apareceria — mas a intenção precisa estar escrita, não herdada da ferramenta.

**Testar contra si mesmo não é testar.** O CRC32 tem três implementações
independentes — firmware C, testbench Verilog, host Python. Divergência ali
apareceria como `STATUS_BAD_CRC` intermitente, dos sintomas mais enganosos que
existem. Os vetores do `selftest` do host são fixos, não gerados pelo próprio
módulo: se fossem gerados, o teste só provaria que o código concorda consigo
mesmo.

**Cuidado ao "corrigir" um teste que falha.** Quando `tb_soc_boot` reprovou
esperando `\n` e recebendo `\r\n`, a tentação é ajustar a expectativa. Fui
verificar na fonte do NEORV32 (`neorv32_uart.c:308`) que o driver realmente
expande LF em CRLF **antes** de mexer. Ajustar expectativa ao resultado
observado é como se erra um KAT.

**Hardware expõe o que simulação não pode.** O `hsmtool` escolhia a primeira
`/dev/ttyUSB*` — que na bancada é o **adaptador JTAG**, porque o "DLC9LP" é um
FT232H que também cria porta serial. O sintoma seria timeout sem explicação,
apontando para o firmware quando o problema é o cabo. Nenhum teste sem
hardware pegaria: o pty do teste de transporte não tem VID:PID.

**Configurar é melhor que corrigir.** O NEORV32 tem como alvo a newlib e seu
`neorv32_newlib.c` não compila contra a picolibc do Debian. A saída não foi
patch: são 359 linhas de syscall stubs que um firmware freestanding não usa,
e excluí-los da lista de fontes é configuração, não modificação do core. O
submódulo continua intocado.

---

## 13. Ordem de trabalho, e a regra que a sustenta

**Nada vai para a placa sem passar antes no testbench.**

Depurar cripto por UART, no hardware, sem visibilidade interna, é a forma mais
lenta possível de descobrir que faltou um byte no padding. Um erro de
enquadramento em simulação custa segundos; o mesmo erro na bancada custa uma
tarde e várias hipóteses erradas.

A Fase 1 já demonstrou o retorno: dois defeitos reais (o `X` no LED, o CRLF)
foram pegos em simulação, e o único que escapou até o hardware foi o único
que a simulação estruturalmente não podia ver.

**Próximo:** Fase 2 — engines e self-test. AES-256 e SHA-256 no fabric via
CFS, neoTRNG, health tests SP 800-90B, POST com KAT. Correção antes de
desempenho.

---

## 14. Leitura

- **FIPS 140-3** e a norma derivada ISO/IEC 19790 — requisitos de módulo
  criptográfico; a seção de self-test explica o capítulo 7 daqui
- **NIST SP 800-90A/B/C** — DRBG, fontes de entropia, construções
- **ANSI X9.143** (sucessor do TR-31) — key blocks
- **PCI PIN Security Requirements** — de onde vêm dual control e split
  knowledge como exigência, não boa prática
- Anderson, *Security Engineering*, capítulos sobre APIs de segurança — o
  material clássico sobre ataques de API a HSM, que é o assunto da Fase 3
