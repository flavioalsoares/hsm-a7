# Ideia: componentes da LMK em smartcards

*Ideia registrada em 2026-11-25, a pedido do usuário. **Não implementada.** O
manual descreve o que existe; este texto descreve uma possibilidade. Ela
aprofunda os itens 1, 3 e 4 da lista de ideias da Cerimônia da LMK
(`PLANO.md`).*

## A pergunta

> Dá para pôr a LMK em cartões, como num HSM de pagamento comercial, em que
> são precisos dois smartcards para o acesso?

Sim. O padrão da categoria tem duas coisas diferentes que costumam ir para
cartões, e vale separá-las.

## O que a categoria faz

| Papel do cartão | O que ele guarda | O que ele controla |
|---|---|---|
| **Cartão de componente** | um componente da LMK, protegido por PIN | *split knowledge*: ninguém tem a LMK inteira. Cada custodiante insere o seu cartão e digita o seu PIN; o HSM soma os componentes (XOR) |
| **Cartão de autorização** | uma credencial do operador, protegida por PIN | *dual control*: dois cartões, de duas pessoas, colocam o HSM no estado autorizado, para comandos sensíveis |

As normas públicas (PCI PIN, X9.24) exigem os dois princípios, mas não dizem
como o fabricante divide a chave entre os cartões. Este texto não supõe o
esquema de nenhum fabricante (regra "não copiar documentação de fabricante").
O que é público e comum: cada componente vai num cartão próprio, com o seu
PIN; o cartão vale só com o PIN; e a LMK é a soma dos componentes, conferida
pelo KCV.

## O que existe aqui hoje

| Papel | Hoje |
|---|---|
| Componentes | 3, em hexadecimal, digitados no console (`0x20`). O custodiante confere o KCV de cada um. Guardados em papel, em envelopes lacrados (manual, seção 7) |
| Dual control | os dois botões (SW2 e SW5): prova que duas mãos estavam ali, não quem eram |

## Como seria com cartões

```
 custodiante A ── cartão A + PIN ──┐
 custodiante B ── cartão B + PIN ──┼──► leitor ──► HSM: LMK = A ⊕ B (⊕ C)
 custodiante C ── cartão C + PIN ──┘                  KCV conferido
```

O cartão seria um **Java Card** com um applet pequeno: guarda o componente,
só o entrega depois do PIN certo, e bloqueia depois de poucas tentativas
erradas. Com 2 cartões em vez de 3, a LMK teria 2 componentes, o que cruza
com o item 5 da lista (número de componentes configurável).

### Onde fica o leitor: a pergunta que decide

| Leitor | Esforço | O que se ganha | O que continua faltando |
|---|---|---|---|
| **No PC**, pela USB (o leitor PC/SC que o usuário já tem) | 1 a 2 semanas: applet, carga do applet, `hsmtool` lendo o cartão | componente guardado em cartão com PIN, e não em papel | o componente passa em claro pelo PC até a UART, como hoje. É o desvio "console e host na mesma máquina" |
| **Na placa**, com um soquete de cartão ligado ao FPGA | várias semanas: ISO 7816 T=0 em RTL ou firmware (clock do cartão, I/O half-duplex, ATR, APDU), soquete, níveis de tensão, modelo de cartão para o `xsim` | o componente vai do cartão ao HSM sem passar pelo PC | o PIN precisa de entrada local: os botões livres e o display, como no item 1 da lista |

Com o leitor no PC, a ideia melhora o **armazenamento** dos componentes, mas não
o **caminho**. Só o leitor na placa fecha os dois. Pela regra "aderência antes de
variação", o caminho certo é o da placa, porque é o que a categoria faz.

## Dual control com cartões

Os dois botões poderiam virar dois cartões de autorização, com PIN. A prova
passaria de "duas mãos" para "duas pessoas identificadas", que é a propriedade
que falta na tabela da Cerimônia no `PLANO.md`. É o mesmo leitor, e outro applet,
ou o mesmo com outro papel.

## O que a ideia muda

- **Regra nº 4**: o leitor na placa exige um modelo de cartão para a simulação.
- **Cerimônia**: novo procedimento, nova seção no manual quando existir.
- **Compras**: Java Cards de desenvolvimento, com as chaves de gestão padrão
  ("unfused"); um soquete de cartão, se o leitor for na placa.
- **Encontro com outra ideia**: o mesmo leitor e os mesmos cartões servem ao
  cartão EMV de teste (`doc/ideia-cartao-emv.md`).

## O conjunto de três cartões (proposta do usuário, 2026-11-25)

| Cartão | Papel | Ideia |
|---|---|---|
| 1 | componente A da LMK, ou autorização do custodiante A | `ideia-lmk-em-cartao.md` |
| 2 | componente B da LMK, ou autorização do custodiante B | `ideia-lmk-em-cartao.md` |
| 3 | cartão de banco simulado, PAN `999999…`, para a transação com ARQC | `ideia-cartao-emv.md` |

Os três podem ser do mesmo modelo de Java Card, com applets diferentes, e o
mesmo leitor PC/SC serve a todos. Componente e autorização são papéis
distintos: decidir se os cartões 1 e 2 fazem um, o outro, ou os dois (dois
applets no mesmo cartão, ou cartões a mais). Comprar alguns de reserva: um
Java Card com as chaves de gestão erradas digitadas vezes demais fica travado
para sempre.

## Quando reabrir

Depois da fase 8. Ordem sugerida: Shamir (item 4, sem hardware) → leitor no PC
(aprende o applet e o cartão) → leitor na placa (fecha o caminho).
