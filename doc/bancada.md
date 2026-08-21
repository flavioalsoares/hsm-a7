# Bancada — hardware, gravação e diagnóstico

Notas de **operação da bancada**: falhas físicas, gravação, e como decidir
onde está um defeito. Nada disto entra no manual — o manual é sobre como um
HSM funciona, não sobre manutenção eletrônica. Ver `doc/manual/`.

---

## A regra que vale mais que todas as outras

**`Done = 1` prova que a sequência de configuração terminou. Não prova que
o dispositivo funciona.**

Já custou duas sessões neste projeto, por dois motivos diferentes: uma vez
contato oxidado no cabo flat do JTAG, outra vez inicialização de Block RAM
não aplicada. Nos dois casos: `Done = 0x1`, `No CRC error`, `EOS = 1`, MMCM
travado — e dispositivo mudo.

---

## Gravar na flash, não na SRAM

```bash
./scripts/program.sh flash     # persistente, sobe sozinho no power-on
./scripts/program.sh           # SRAM, volátil
```

**Prefira a flash.** Não é só conveniência de não perder no desligamento:
nesta bancada a configuração por JTAG demonstrou **não aplicar a
inicialização das Block RAMs**, e a inicialização de BRAM é de onde a IMEM
do NEORV32 tira o código. O sintoma é devastador e não se parece com o que
é:

| carregado por | teste de ROM | teste de RAM | dispositivo |
|---|---|---|---|
| JTAG | **512 de 512 erradas** | 0 erros | mudo, D1 piscando |
| flash SPI | 0 erros | 0 erros | responde `ping`, `version`, `dna` |

Mesmo bitstream, mesmo dispositivo, mesma sessão. Só muda o caminho de
configuração.

Por que o resto do design funciona: LUT e flip-flop são configurados
corretamente pelos dois caminhos. Por isso o heartbeat pisca, os LEDs
acendem e uma UART em hardware puro fala — enquanto a CPU, que busca
instrução da BRAM, não executa uma instrução sequer.

Nada de eFUSE, nunca — `PLANO.md` §0. Flash é regravável; eFUSE é OTP e o
erro é permanente.

---

## Bitstream de diagnóstico — `rtl/diag/`

Um design **sem CPU, sem NEORV32, sem firmware**. Só contadores, um par de
UART de trinta linhas e um teste de Block RAM. Existe para reprovar a
camada física inteira sem nenhuma ajuda de software.

```bash
vivado -mode batch -source scripts/build-diag.tcl
BIT=build/hsm_diag.bit ./scripts/program.sh flash
```

O que observar:

```
D1              pisca a 1 Hz            MMCM travado, 100 MHz vivo
D2..D5          luz corrida, ~4 Hz      cada pino de LED, um a um
UART 115200     "HSM-DIAG nnnn Rrrrr Wwwww Zzzzzzzzz Bab"
eco de qualquer byte recebido           T15, o sentido de entrada
```

- `Rrrrr` erros na BRAM **inicializada pelo bitstream** (o caso da IMEM)
- `Wwwww` erros de escrita/leitura em BRAM
- `Zzzzzzzzz` a quinta palavra lida da ROM. Deve ser `2345678B`

A luz corrida acende os LEDs **separados no tempo** de propósito: pino
morto vira buraco na sequência, e buraco se vê de longe. O contador na
mensagem prova que a UART está viva *agora*, não que sobrou lixo num
buffer.

`Z` não é decoração: é a medida que **não depende de hipótese de latência**.
Se a memória tiver um ciclo a mais que o esperado, um placar de erros alto
e uma memória zerada dão o mesmo número — mas dão valores diferentes em `Z`.

**Controle direto do display de 7 segmentos.** A UART aceita três bytes
`0xAA <seg> <an>` e aplica os valores **crus** nos pinos:

```bash
python3 -c "
import serial,time,serial.tools.list_ports as lp
p=next(x.device for x in lp.comports() if x.vid==0x10c4)
s=serial.Serial(p,115200); time.sleep(0.15)
s.write(bytes([0xAA, 0xA4, 0b111])); s.close()"     # desenha '222'
```

**Estado dos botões de dual control.** A mensagem periódica traz o campo
`Bab` no fim, com `1 = pressionado` para `M6`/`btn_a` e `P6`/`btn_b`. Foi
com ele que a ordem física no silk foi fechada.

⚠ A mensagem sai a cada **500 ms**: um toque curto cai entre duas amostras e
some. **Segure** o botão por mais de um segundo, ou repita. Duas tentativas
pareceram negativas por causa disso, e a conclusão apressada teria sido
"este botão não está neste pino".

Truque que resolveu: em vez de pedir "aperte o SW2" e torcer para a janela
coincidir, usar um **padrão codificado** — uma pressão isolada num botão,
pausa, três no outro. O padrão se identifica sozinho, sem sincronizar nada.

Foi assim que a polaridade e o mapeamento do display foram determinados
(`doc/pinout.md`). A alternativa — varredura fixa em RTL — custaria um
bitstream por hipótese; aqui o ciclo de experimento é de dois segundos.
Qualquer byte que não seja `0xAA` continua ecoando normalmente, então o
teste de eco não é afetado.


---

## Discriminadores

| sintoma | causa provável |
|---|---|
| cadeia JTAG `empty` **sempre**, em todas as frequências | FPGA sem alimentação, ou JTAG fisicamente aberto |
| `empty` **às vezes**, IDCODE ora sim ora não | mau contato de sinal |
| IDCODE OK, gravação com `CRC Error` | integridade do cabo sob volume de dados |
| `Done=1` + `EOS=1` + MMCM travado, e mudo | **não é a camada física** — grave o `hsm_diag` |
| adaptador USB enumera e cai em < 1 s | contato ou entrega de corrente |
| CPU parada, fabric vivo, mesmo bitstream que já funcionou | inicialização de BRAM — grave pela flash |

⚠ **Cabo USB "só de carga" NUNCA enumera.** Se o `dmesg` mostra o
dispositivo aparecendo, o par de dados existe; o problema é contato ou
corrente. Confirmado numa sessão em que o FT232H enumerava e caía em
0,2–0,8 s.

⚠ **O CP2102 aparecer no `lsusb` não prova nada sobre a alimentação da
placa** — ele vive da própria USB e enumera com o trilho principal
desligado. Duas `/dev/ttyUSB*` com o gravador ligado é o normal: o FT232H
também cria porta serial. O `hsmtool.py` escolhe por VID:PID
(CP2102 = `10c4:ea60`).

⚠ **Hub USB não é causa provável de gravação corrompida** — e esta entrada
existe porque a afirmação contrária já foi documentada aqui como se fosse
fato, e estava errada. O USB tem CRC e retransmissão próprios: um hub não
entrega bytes errados em silêncio, ele erra ou fica lento. O `CRC Error` que
aparece é do **FPGA**, sobre o bitstream recebido — ou seja, os bytes saíram
bons do adaptador e chegaram ruins ao chip, e a corrupção é no **cabo flat**,
que é o trecho sem proteção nenhuma. Porta direta ajuda em latência e
corrente; suspeitar do hub antes do cabo já custou tempo aqui.

⚠ **`grep` sobre a saída do `openFPGALoader`**: ela contém bytes NUL, e o
`ugrep` desta máquina trata entrada com NUL como binária — `-q` devolve
"não encontrei" mesmo havendo casamento. Sempre `| tr -d '\0'` antes. Já
produziu falsos "nenhum FPGA na cadeia" com o link perfeito.

---

## Voltagens e temperatura, sem instanciar nada

O XADC é legível por JTAG pelo hardware manager do Vivado, sem o design
precisar instanciar o SYSMON:

```tcl
open_hw_manager; connect_hw_server
current_hw_target [lindex [get_hw_targets] 0]; open_hw_target
current_hw_device [lindex [get_hw_devices] 0]
refresh_hw_device -update_hw_probes false [current_hw_device]
set sm [lindex [get_hw_sysmons] 0]; refresh_hw_sysmon $sm
foreach p {TEMPERATURE VCCINT VCCAUX VCCBRAM} { puts "$p [get_property $p $sm]" }
```

Medido nesta placa: `VCCINT 0,987 V`, `VCCAUX 1,774 V`, `VCCBRAM 0,987 V`,
`36,7 °C`. Todos dentro da faixa, um pouco no lado baixo.

---

## Um instrumento errado é pior que nenhum instrumento

Duas vezes nesta bancada o **teste** é que estava errado, e nas duas o
resultado tinha cara de defeito de hardware:

1. **ROM otimizada para fora.** O teste de Block RAM preenchia a memória
   com `f(endereço)`. O Vivado percebeu que era uma função calculável,
   jogou a memória fora e passou a computar o valor com um DSP, que
   absorveu um registrador e desalinhou a comparação. Resultado: 512 erros
   de 512 com a BRAM sadia. Conserto: preencher com sequência de LFSR, que
   não tem forma fechada em função do índice.

2. **Bit de start com largura arbitrária.** O contador de baud corria livre
   e não realinhava no carregamento do byte. Em simulação passava porque
   `MSG_DIV` era múltiplo de `BAUD_DIV` e a fase caía certa *por acidente*.

3. **Um teste que afirmava um palpite.** `tb_hsm_top` conferia que o display
   estava apagado com `seg_an_o = 111` — valor que vinha de
   `AN_ACTIVE_LOW = 1` no toplevel, que era **chute**. A medida em hardware
   mostrou o contrário: o dígito habilita com `1`, então desabilitado é
   `000`. O teste passou meses verde afirmando algo falso.

   Este caso é diferente dos outros dois e por isso merece nota: corrigir o
   valor esperado **não** é enfraquecer teste. O teste conferia contra uma
   *suposição*; a suposição foi refutada por experimento, e o valor esperado
   passou a ter procedência. A regra nº 5 proíbe ajustar o vetor para o
   código passar — não proíbe substituir palpite por medida.

Nos três casos o defeito só apareceu em hardware, e o teste **não era capaz
de reprová-lo**. Depois de consertar, verificar revertendo o conserto: se o
teste não falha, ele não testa nada.
