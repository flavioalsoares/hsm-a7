# Fase 6 — tamper e ataques

*Iniciada em 2026-11-04.*

Um HSM comercial percebe que está fora das condições em que dá para confiar
nele, e apaga as chaves sozinho. Num equipamento de verdade isso vem de malha
no invólucro, chave de tampa e sensores, com bateria, e funciona até desligado.
Esta placa não tem nada disso, então só sobra o que o próprio chip mede.

O plano tem cinco frentes:

| Frente | Situação |
|---|---|
| Sensores de ambiente pelo XADC | feita |
| Perda de lock do MMCM | feita |
| Glitch de clock, e contramedidas | feita |
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
  faixa de 100 µs. O pulso de clock medido aqui não aciona nenhum sensor.
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

**Glitch e dupla execução, em 2026-11-06,** bitstream SHA-256 `a0f8c1d02414bf03…`:
os 21 testbenches implementados passam, em 8 h 41, com `tb_glitch` e `tb_confere`
novos. Timing e recursos iguais aos arquivados, porque o firmware mora em BRAM e o
injetor fica fora deste bitstream. Firmware com 23 700 bytes de código, POST em
10,19 ms. Na placa: POST verde, LMK preservada na troca de bitstream, `confere` com
10 de 10 voltas pela serial e 100 de 100 pela ponte, nada retido.

**Não provado na placa:**

- Perda de lock: não há como parar o oscilador por software. Só simulação.
- Alarmes de tensão, de temperatura baixa e de sensor parado: só simulação.
- O SW1 não apagar a retenção: só simulação.
- D5 aceso e `tPr` no display: precisam de alguém olhando.
- Tempo de resposta: o estado foi conferido até 12 s depois do disparo, e isso
  não mede a latência.

## Glitch de clock

A teoria está no manual, seção 17. Aqui fica como o ataque é montado.

### Por que não pelo DRP

O plano dizia "via DRP do MMCM". A XAPP888 (v1.8) exige o MMCM em reset durante
a reconfiguração, ou um reset depois dela, e o modelo de simulação recusa a
escrita fora de reset. Reset para o clock e reinicia o SoC, o que não é um pulso.
Por isso o DRP foi descartado como injetor, e o ataque usa o `BUFGMUX`.

### O injetor

`rtl/soc/glitch_inj.v`, ligado só com `HSM_ATAQUE`. O MMCM ganha um segundo clock
no `CLKOUT1`, e um `BUFGMUX` troca o clock do SoC por ele durante o pulso. A
realimentação do MMCM não passa pelo mux, então o `LOCKED` não cai e o detector
de perda de lock não vê nada.

O injetor faz o papel do equipamento externo: escuta a linha RX e não fala com a
CPU. **O firmware é o de produção**, e por isso uma contramedida é medida no
mesmo código que vai para a placa. Ele se configura por um frame que o firmware
recusa com `UNKNOWN_CMD`:

```
CMD 0xF7 | 'G' | 'L' | ATRASO(3) | LARGURA(1) | BYTES(2)
```

Depois do CRC desse frame ele fica armado. No fim do byte número `BYTES` do pedido
seguinte, espera `ATRASO` ciclos e liga o clock rápido por `LARGURA` ciclos dele.
Dispara uma vez e desarma. O disparo por contagem de bytes vem de fora, como o de
um atacante, com a incerteza de quando o firmware atende o byte.

```bash
HSM_ATAQUE=1 GLITCH_DIV=5 vivado -mode batch -source scripts/build.tcl
BIT=build/ataque/hsm_ataque.bit ./scripts/program.sh flash
python3 host/glitch.py --alvo encrypt --handle 1 --de 0 --ate 100000 --passo 200
```

`GLITCH_DIV` divide o VCO de 1000 MHz. `constraints/ataque.xdc` tira o clock rápido
da análise de timing, porque ele existe para violá-la; o domínio de 100 MHz
continua analisado. Sem `HSM_ATAQUE`, o bitstream de produção sai igual, exceto
pela data no cabeçalho.

`tb_glitch` prova a largura, o atraso, o disparo único e o `LOCKED` firme. Ele
**não** mostra a falha: simulação RTL não tem atraso de porta, então o clock rápido
não viola nada ali. Só a placa mostra o erro.

### A janela de falha

`SELFTEST` como alvo, pulso de 255 ciclos, a 40 °C:

| Pulso | Tentativas | Passou | Autoteste reprovou | Resposta inválida | CPU travou |
|---|---|---|---|---|---|
| 143 MHz | 7334 | 7334 | 0 | 0 | 0 |
| 167 MHz | 551 | 551 | 0 | 0 | 0 |
| 200 MHz | 551 | 542 | 8 | 1 | 0 |
| 250 MHz | 317 | 27 | 25 | 0 | 265 |

O timing garante cerca de 105 MHz, e este chip atravessa 167 MHz. A janela útil
fica perto de 200 MHz, onde a CPU segue viva. Com o `SELFTEST` como alvo, um
resultado errado aceito não é mensurável; para isso servem `ENCRYPT` e
`MAC_VERIFY`.

### Contramedida: dupla execução e erro grave

O que sai ao host é calculado duas vezes e comparado: `keystore_cbc_confere()` para
cifrar e decifrar, e `keystore_cmac()` e `keystore_cmac_verifica()` para MAC, nas
duas portas. O key block fica de fora, porque o MAC dele já reprova um corpo errado.

Quando as execuções discordam, o comando devolve `CRYPTO_FAIL` (`0x32`, ou `91` no
ASCII) e nada sai. As chaves ficam: é o meio-termo decidido pelo usuário, porque
recomissionar nem sempre é viável ou barato. O equipamento marca **erro grave**: bit
`0x80` no `retido` do `ENV_READ` e D5 aceso com o display ainda em `OPE`, o que o
separa de `tPr`. O flag vale até o próximo boot, e o log guarda o comando recusado.
Os comandos seguintes continuam funcionando.

**A chave é carregada para cada execução.** A primeira versão carregava uma vez, e
a placa mostrou o defeito: resultados errados com CRC válido, nenhum `CRYPTO_FAIL`.
As duas execuções concordavam no erro. A explicação está no manual, seção 17.4,
"falha de modo comum". `tb_confere` cobra duas cargas por pedido, além de sabotar a
segunda execução e exigir a recusa, a LMK no lugar e a chave ainda utilizável.

O `tb_confere` não teria achado esse defeito sozinho: ele força o erro onde o teste
escolhe. Quem valida esta contramedida é a medição na placa.

### Resultado na placa

Pulso de 200 MHz, 255 ciclos, `ENCRYPT` de 256 bytes. "Errado" é sucesso com
resultado errado e CRC válido.

| Firmware | Tentativas | Errado | `CRYPTO_FAIL` |
|---|---|---|---|
| Sem dupla execução | ~270 | 2 | não existia |
| Chave carregada uma vez | 3601 | 4 | 0 |
| Chave carregada a cada execução | 13 506 | **0** | 15 em 2703 |

A última linha soma duas varreduras; só na segunda, de 2703 tentativas, o status
das recusas foi classificado. Os `CRYPTO_FAIL` caem em duas janelas de cerca de
900 ciclos, separadas por 34 000: a carga de chave de cada execução. A primeira é
onde caíam os resultados errados da versão anterior, e isso confirma a falha de modo
comum. Bitstreams diferentes têm posicionamento diferente, mas a falha continua
acontecendo: o que mudou foi ela ser vista.

Fora dessas janelas, o pulso dá em duas recusas sem consequência. Durante a
conferência do pedido, `BAD_CRC`; durante a montagem da resposta, dados certos com
CRC errado, que o host recusa.

`MAC_VERIFY` com tag errada, 5002 tentativas: nenhuma tag falsa aceita, nenhum
`CRYPTO_FAIL`, 482 `BAD_CRC` e 5 respostas inválidas.

O erro grave foi visto depois de uma falha real, sem reiniciar: `retido = 0x80`, o
`ENCRYPT` seguinte certo, o flag ainda ligado, KCV da LMK igual e `CRYPTO_FAIL` no
log. D5 aceso precisa de alguém olhando.

**O que isso não prova.** Zero em 13 506 é uma medida, não uma garantia: vale para
este pulso, este chip e este bitstream. O injetor dá um pulso só, e um ataque com
dois pulsos iguais, um em cada execução, não foi medido. A comparação e a resposta
depois dela seguem sendo ponto comum.

### O que o modelo não representa

Um pulso aplicado de fora, no pino do oscilador, passaria pelo MMCM, que o
filtraria. O injetor interno reproduz a violação de timing, não o caminho físico.
Aqui, o ataque externo mais provável seria pela tensão.

## Bitstream cifrado: aviso antes de começar

`VCCBATT` está no rail de 1,8 V e não há bateria, então a chave em BBRAM some a
cada desligamento. Com o bitstream cifrado na flash, a placa não sobe sozinha
até a chave ser recarregada por JTAG. Esta frente muda a rotina de bancada, e
só começa com o usuário presente.
