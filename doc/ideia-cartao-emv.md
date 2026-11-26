# Ideia: cartão EMV de teste num Java Card

*Ideia registrada em 2026-11-25, a pedido do usuário. **Não implementada.**
Depende da etapa 8.10 (ARQC), que ainda não existe.*

## A pergunta

> Com o leitor de cartões que tenho, se eu comprar cartões "virgens", consigo
> gravar neles o PAN de teste?

Sim, se o cartão for um **Java Card com GlobalPlatform**, com as chaves de
gestão padrão. Cartão de memória (EEPROM simples) não serve: o ARQC é uma
conta feita dentro do chip, e cartão de memória não roda programa.

## Por que o cartão do banco não serve

- A chave do cartão (MK) fica dentro do chip, que nunca a entrega.
- A chave do emissor (IMK) existe só nos HSMs do banco.
- Regra do projeto: nenhum PAN real, nunca.

Com o cartão do banco, daria para pedir um ARQC, mas não para conferi-lo.
(Estas explicações vão para o manual como casos de uso quando a 8.10 existir;
ver `PLANO.md`, decisões da 8.10.)

## O que entraria no cartão

| Peça | O que é |
|---|---|
| Applet EMV | programa que responde como cartão de pagamento (SELECT, GET PROCESSING OPTIONS, GENERATE AC). Há applets abertos, de pesquisa e ensino: escolher um com licença compatível e conferir que variantes de ARQC ele faz |
| Ferramenta de carga | programa no PC que instala o applet pelo leitor PC/SC (o GlobalPlatformPro, por exemplo) |
| Personalização | o PAN `999999…`, a validade, e a MK do cartão, derivada pelo nosso HSM de uma IMK de teste: o papel de uma bureau de personalização |

## O ciclo

```
 PC, script "terminal" (pyscard)
   │ SELECT, GPO, GENERATE AC ──► cartão (applet EMV, PAN 999999…)
   │ ◄── ARQC, ATC, dados
   │ ARQC + dados ──► hsm_ponte ──► HSM: confere com a IMK
   │ ◄── ARPC
   │ EXTERNAL AUTHENTICATE / 2º GENERATE AC ──► o cartão confere o ARPC
```

## Limites

- O cartão só funciona no laboratório: o BIN `999999` não existe em rede
  nenhuma. Não passar em terminal real.
- A IMK e a MK são de teste, como a LMK de desenvolvimento.

## Custo

Java Cards de desenvolvimento custam poucos dólares cada. Esforço de 1 a 2
semanas além da 8.10: escolher e entender o applet, personalizar, e escrever
o script de terminal com as recusas.

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

Depois da 8.10, que usa um cartão simulado em Python. Trocar o cartão em
Python pelo Java Card é uma etapa à parte. O mesmo leitor e os mesmos cartões
servem aos componentes da LMK (`doc/ideia-lmk-em-cartao.md`).
