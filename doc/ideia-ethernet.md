# Ideia: porta host em Ethernet, com TCP/IP na placa

*Ideia registrada em 2026-11-25, a pedido do usuário. **Não implementada.** É
a candidata mais forte a uma fase 9, porque fecha o desvio que o `PLANO.md`
chama de aderência, e não de melhoria: console e host separados.*

## A pergunta

> O hardware e o software são suficientes para Ethernet com TCP/IP?

Sim. O limite é a BRAM, não os LUTs, o clock ou a CPU.

## O que a placa tem

| Peça | Situação |
|---|---|
| PHY RTL8211EG, na daughterboard | existe; GMII (1 Gbit/s) e MII (10/100) |
| Pinagem do PHY | **não está no projeto**: não há XDC oficial de Ethernet. Sai do esquemático (`doc/datasheets/DB-FPGA-XC7A35T-DDR3-V03.pdf`) e se confere na placa |
| MAC Ethernet | **não existe**: o NEORV32 não tem. Core aberto de terceiros (pela escada de submódulo do `CLAUDE.md`) ou próprio |

## Recursos (medidos em 2026-11-24)

| Recurso | Livre | O que o Ethernet usaria |
|---|---|---|
| LUTs | ~12 700 (61%) | MAC a 100 Mbit/s: ~1 000 a 2 000 |
| Clock | — | MII a 100 Mbit/s: 25 MHz vindos do PHY. GMII exige 125 MHz e aperta o timing; 100 Mbit/s basta |
| **BRAM** | 24,5 blocos hoje; **8,5 depois da 8.9b** (o firmware passa de 64 KB e a ROM vai a 128 KB) | FIFOs do MAC, 2 a 4 blocos; buffers da pilha na DMEM |

## A pilha TCP/IP

| Pilha | Código | RAM | Comentário |
|---|---|---|---|
| uIP | ~5 KB | ~2 a 4 KB | uma conexão por vez. Cabe hoje |
| lwIP (BSD) | ~20 a 40 KB | ~15 a 30 KB | várias conexões. Cabe na IMEM; precisa de DMEM maior, isto é, BRAM |

Saída para a falta de BRAM: buffers de rede na DDR3, com o controlador MIG
(5 000 a 8 000 LUTs). Só mensagens do host poderiam ir para lá, nunca chave em
claro (regra nº 2).

## O que pesa na decisão

1. **A pilha de rede fica dentro da fronteira.** Hoje o `hsm_ponte.py`, no PC,
   interpreta o TCP. Na placa, um bug no parser de IP ou TCP é um bug do HSM.
   Precisa de testbench próprio, com modelo de PHY (regra nº 4).
2. **O objetivo é separar console e host**: host na Ethernet, console sozinho
   na UART. Uma conexão TCP (uIP) já fecha o desvio; é o primeiro degrau.

## Esforço

3 a 5 semanas: MAC e pinagem, ~1 semana; pilha e integração com o despachante
ASCII, 1 a 2 semanas; testbench com modelo de PHY e suíte, ~1 semana.

## Quando reabrir

Ao fechar a fase 8, na decisão sobre uma fase 9.
