# Fase 6 — tamper e ataques

*Iniciada em 2026-11-04.*

Um HSM comercial percebe que está fora das condições em que dá para confiar
nele, e apaga as chaves sozinho. Num equipamento de verdade isso vem de malha
no invólucro, chave de tampa e sensores, com bateria, e funciona até desligado.
Esta placa não tem nada disso, então só sobra o que o próprio chip mede.

O plano tem cinco frentes. Duas estão feitas:

| Frente | Situação |
|---|---|
| Sensores de ambiente pelo XADC | feita |
| Perda de lock do MMCM | feita |
| Glitch de clock pelo DRP do MMCM, e contramedidas | não começada |
| Bitstream cifrado com chave em BBRAM | não começada, ver o aviso no fim |
| Experimento de RO-PUF (`doc/puf-experimento.md`) | não começado |

## O que dispara

| Bit | Condição | Limite | Quem detecta |
|---|---|---|---|
| `0x01` | temperatura alta | acima de 85 °C | `ALM[0]` do XADC |
| `0x02` | VCCINT | fora de 0,95 a 1,05 V | `ALM[1]` |
| `0x04` | VCCAUX | fora de 1,71 a 1,89 V | `ALM[2]` |
| `0x08` | VCCBRAM | fora de 0,95 a 1,05 V | `ALM[3]` |
| `0x10` | temperatura baixa | abaixo de 0 °C | comparação em `hsm_xadc.v` |
| `0x20` | sensor parado | sem fim de sequência por 168 ms | contador em `hsm_xadc.v` |
| `0x40` | perda de lock | `LOCKED` cai sem o SW1 | `clk_rst_gen.v`, pelo GPIO |

O chip é o `XC7A35T-1FTG256C`, de grau comercial (manual do core board). As
faixas são as condições recomendadas da Tabela 2 do DS181 v1.27. Os códigos e
as funções de transferência vêm da UG480 v1.9, e o erro dos sensores, de ±4 °C
e ±1%, da Tabela 65 do DS181. Não há margem somada: o limite é o da folha de
dados.

⚠ **O alarme de temperatura do XADC só olha para cima.** O registrador `54h` é
o limite de rearme, não um piso. Frio é o ataque clássico de remanência de
memória, então o piso de 0 °C é uma comparação nossa sobre a leitura.

## Como se divide

É a mesma divisão do TRNG: o hardware detecta e retém, o firmware responde.

- **Os limites moram no bitstream.** São atributos `INIT` do primitivo, e o
  `DWE` do DRP está amarrado em zero. O firmware não tem como afrouxar um
  limite nem limpar um alarme: o CFS só tem registradores de leitura aqui.
- **A retenção não tem reset.** Quem sai da faixa e aperta o SW1 não apaga a
  prova, e o boot seguinte a encontra. Só reconfigurar o FPGA limpa. É a exceção
  deliberada à convenção de reset síncrono, nos dois módulos.
- **O firmware é dono da resposta** (`fw/src/ambiente.c`), porque as chaves
  estão na DMEM, que o bloco de sensores não alcança.

A perda de lock já reafirmava o reset desde a fase 1, mas a CPU voltava sem
saber o que tinha acontecido. O flip-flop retido mora no domínio do oscilador,
o único que corre com o MMCM fora de lock, e chega ao firmware pelo bit 2 do
GPIO. O SW1 também derruba o `LOCKED`, pelo `RST` do MMCM, e isso é pedido, não
ataque: `ja_travou` limpa enquanto o reset está afirmado.

O MMCM não volta sozinho: depois que o `LOCKED` cai, ele exige um `RST`
([UG953](https://docs.amd.com/r/en-US/ug953-vivado-7series-libraries/MMCME2_BASE)).
A primeira versão não pedia esse reset, e o `tb_tamper` reprovou: a CPU ficava
presa, a resposta não rodava e a LMK continuava na flash até alguém apertar o
SW1. Agora `religa` pulsa o `RST` por 16 ciclos a cada 1,3 ms enquanto não
travar. A repetição cobre um clock que volta instável.

## A resposta

Sem dual control, como o autoteste reprovado: pessoas precisam de duas pessoas,
um dispositivo que se descobre comprometido não precisa de ninguém.

1. Apaga a BRAM e o CFS, em microssegundos.
2. Vai para `TAMPERED`.
3. Grava o registro `0x0F` no log, com a causa no argumento.
4. Apaga as duas cópias da região segura da flash.
5. Programa o resultado no registro.

⚠ **Esta ordem é a exceção declarada a "log antes de executar".** Tensão caindo
pode ser energia acabando, e a chave tem de sumir antes de se gastar um
milissegundo escrevendo na flash. Decisão confirmada pelo usuário em 2026-11-04.

No boot, a checagem vem depois do POST e **antes** de restaurar da flash: fora
da faixa, a chave não volta para a BRAM. Sensor que não dá leitura também é
violação. No laço principal, o firmware olha entre comandos, porque não há
interrupção: um comando em curso termina antes.

**Sair de `TAMPERED`.** O SW1 não sai, porque a retenção sobrevive e o boot
responde de novo. Desligar sai: o FPGA reconfigura, a flash está vazia, e o
dispositivo volta em `UNINITIALIZED`, com o log intacto, pedindo cerimônia. Um
HSM comercial pode manter o estado de violado até alguém recomissionar. Aqui
ficou assim por decisão do usuário.

## Duas correções que a fase trouxe

- **`SELFTEST` em `TAMPERED` não restaura mais da flash.** Ele chamava
  `persist_restaura()` sem olhar o estado. Se apagar a flash tivesse falhado, o
  autoteste traria a LMK de volta para a BRAM de um dispositivo violado.
- **`AUDIT_READ` responde em `TAMPERED`.** O log é o que se quer ler depois de
  uma violação, e ler não vaza chave.

## Comando novo: `ENV_READ` (`0x2E`)

Console, todos os estados, sem dual control e fora do log, como os demais
comandos de leitura. Devolve retido, agora, válido e os quatro códigos de 12
bits. Quem converte é o host: `python3 host/hsmtool.py env`.

## O que isso não protege

Vale escrever sem rodeio: é uma demonstração do mecanismo, não proteção real.

- **Com a placa desligada, nada é detectado.** Quem tirar a flash com um gravador
  lê a LMK em claro. Limitação aceita desde a fase 4, e sensor nenhum a fecha.
- **Abrir a placa não dispara nada,** porque não há invólucro.
- **O JTAG alcança o XADC pelo outro lado** e pode mudar os limites. Fechar o JTAG
  seria eFUSE, e isso não acontece neste projeto.
- **Um glitch curto pode passar.** O alarme usa média de 16 leituras, algo na
  faixa de 100 µs. É o que a frente de glitch vai medir.
- **O oscilador parado para o próprio detector de lock.** A queda é vista quando
  o clock voltar. Enquanto ele não volta, nada roda: a CPU está parada, mas a
  LMK continua na flash. A resposta só acontece depois.
- **A varredura do DRP não tem timeout.** Se um `DRDY` se perdesse, ela esperaria
  para sempre. Antes da primeira leitura válida, o boot trataria isso como
  violação. Depois dela, os valores do `env` e o piso de 0 °C ficariam
  congelados, embora os alarmes de hardware continuem ativos. Só apareceu em
  simulação, com o reset solto dentro do GSR; o acesso por JTAG na placa não
  provocou isso.

## Estado da verificação

Em 2026-11-05, bitstream SHA-256 `74d413f00caa44ab…`.

**Simulação:** os 19 testbenches implementados passam (`tb_hmac_kat` é esqueleto
e não conta). `tb_tamper` leva 3 h 15 e prova as duas violações de ponta a ponta,
com a LMK na flash: 90 °C pelo laço principal e parada de clock pelo boot.

**Síntese:** timing **+0,471 ns**, 0 critical warnings, 7699 LUTs (37,0%), 7698 FF
(18,5%), BRAM 13, XADC 1. Arquivado em `doc/timing_fase6.txt` e
`doc/utilization_fase6.txt`.

**Placa, sem falso disparo:** gravada com a LMK `6935C4` na flash, subiu em
`OPERATIONAL`, POST verde, nada retido. `confere` com 10 de 10 voltas pela serial
e 100 de 100 pela ponte, 40,5 °C ao fim. Pelo JTAG, os registradores confirmam os
limites do `INIT` (`50h = B5ED`, `54h = A93A`).

**Placa, com o alarme real** (procedimento em `doc/bancada.md`): baixados os
limites de temperatura pelo JTAG, `TAMPERED`, comandos recusados, `env` com
`temperatura alta`, registro `TAMPER` com resultado `OK` no log, e `SELFTEST` não
tirou de `TAMPERED`. Reconfigurado da flash: `UNINITIALIZED`, 0 de 3 componentes,
`sem registro persistente`, log intacto, retenção limpa, limites de volta ao
`INIT`.

**Não provado na placa:**

- Perda de lock: não há como parar o oscilador por software. Só simulação.
- Alarmes de tensão, de temperatura baixa e de sensor parado: só simulação.
- O SW1 não apagar a retenção: só simulação.
- D5 aceso e `tPr` no display: precisam de alguém olhando.
- Tempo de resposta: o estado foi conferido até 12 s depois do disparo, e isso
  não mede a latência.

## Bitstream cifrado: aviso antes de começar

`VCCBATT` está no rail de 1,8 V e não há bateria, então a chave em BBRAM some a
cada desligamento. Com o bitstream cifrado na flash, a placa não sobe sozinha
até a chave ser recarregada por JTAG. Esta frente muda a rotina de bancada, e
só começa com o usuário presente.
