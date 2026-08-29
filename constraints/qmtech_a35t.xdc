## QMTECH XC7A35T-FTG256 core board + daughterboard
##
## Fonte dos pinos: doc/pinout.md. Core board e daughterboard verificados nos
## esquematicos oficiais (doc/datasheets/) e, em boa parte, em hardware no
## projeto irmao ~/Projetos/MSXInArt/msxinart, que roda na mesma placa.
##
## REGRA: nenhum pino entra aqui sem fonte. Nao chutar -- pino errado num banco
## de I/O pode danificar a placa.

## ---------------------------------------------------------------- clock
## SYS_CLK 50 MHz -- N11, presente em todos os XDC oficiais e rodando em HW.
## A duvida sobre CLOCK_DEDICATED_ROUTE esta resolvida: o MSXInArt sintetiza,
## roteia e roda com create_clock direto em N11, sem waiver.
set_property -dict {PACKAGE_PIN N11 IOSTANDARD LVCMOS33} [get_ports sys_clk_i]
create_clock -period 20.000 -name sys_clk [get_ports sys_clk_i]

## ---------------------------------------------------------------- reset
## SW1 da daughterboard. Ativo baixo, pull-up 4,7k na placa.
set_property -dict {PACKAGE_PIN B7 IOSTANDARD LVCMOS33} [get_ports rst_n_i]

## ---------------------------------------------------------------- UART
## CP2102 do core board -- sai pela mesma USB, sem cabo extra (/dev/ttyUSB*).
## Canal do hsmtool.py. Sao pinos fisicos identificaveis: da para por o
## analisador logico em T14 e provar que nenhuma chave em claro cruza a
## fronteira criptografica (PLANO secao 4).
set_property -dict {PACKAGE_PIN T15 IOSTANDARD LVCMOS33} [get_ports uart_rxd_i]
set_property -dict {PACKAGE_PIN T14 IOSTANDARD LVCMOS33} [get_ports uart_txd_o]

## ------------------------------------------------- botoes (dual control)
## Os dois botoes que autorizam LMK_LOAD_COMPONENT. ATIVOS EM NIVEL BAIXO
## (pull-up 4,7k, fecham para GND) -- o firmware le !btn como "pressionado".
## SW2 e SW5 sao o par mais afastado DISPONIVEL: dificultam pressionar os dois
## com uma mao so, que e o ponto da separacao entre quem digita e quem autoriza.
## Nao sao os extremos da fileira -- os extremos sao SW1 e SW5, e SW1 e o reset.
## Debounce obrigatorio -- um glitch aqui aceita componente de LMK sem
## autorizacao real.
set_property -dict {PACKAGE_PIN M6 IOSTANDARD LVCMOS33} [get_ports btn_a_i]  ;# SW2
set_property -dict {PACKAGE_PIN P6 IOSTANDARD LVCMOS33} [get_ports btn_b_i]  ;# SW5
## RESERVA: SW3=N6, SW4=R5, livres. Sao os dois botoes que sobram na placa
## filha -- candidatos naturais a um ZEROIZE fisico da fase 3, que e o unico
## comando que faz sentido nao depender do host.
## ATENCAO: estes dois pinos vem do ESQUEMATICO, nunca foram medidos. SW2 e
## SW5 so viraram fato depois de um padrao codificado no rtl/diag/ (uma
## pressao, pausa, tres pressoes) -- ver doc/pinout.md. Quem for usar SW3/SW4
## mede primeiro; assumir a ordem do silk ja custou uma sessao de bancada.

## ---------------------------------------------------------------- LEDs
## D1..D5 da daughterboard. ATIVOS EM NIVEL BAIXO: catodo no pino do FPGA,
## anodo via 1k em 3V3 -- '0' acende.
## Cores VERIFICADAS 2026-08-09: os cinco sao VERMELHOS. O requisito "LED
## vermelho para TAMPERED" da PLANO secao 3 esta atendido e VAZIO -- a cor nao
## distingue nada aqui. Quem carrega estado e o display de 7 segmentos.
set_property -dict {PACKAGE_PIN R6 IOSTANDARD LVCMOS33} [get_ports {led_o[0]}]  ;# D1 heartbeat
set_property -dict {PACKAGE_PIN T5 IOSTANDARD LVCMOS33} [get_ports {led_o[1]}]  ;# D2 atividade UART
set_property -dict {PACKAGE_PIN R7 IOSTANDARD LVCMOS33} [get_ports {led_o[2]}]  ;# D3 OPERATIONAL
set_property -dict {PACKAGE_PIN T7 IOSTANDARD LVCMOS33} [get_ports {led_o[3]}]  ;# D4 POST/KAT
set_property -dict {PACKAGE_PIN R8 IOSTANDARD LVCMOS33} [get_ports {led_o[4]}]  ;# D5 TAMPERED

## ------------------------------------------------ display 7-seg (estado)
## 3 digitos multiplexados -- casa exatamente com Uni / Aut / OPE / tPr.
## TODO: polaridade (anodo ou catodo comum) e o mapeamento bit->segmento NAO
## foram verificados em hardware. Confirmar antes de escrever a tabela de
## fontes, ou descobrir acendendo um segmento por vez.
set_property -dict {PACKAGE_PIN T10 IOSTANDARD LVCMOS33} [get_ports {seg_o[0]}]  ;# a
set_property -dict {PACKAGE_PIN K13 IOSTANDARD LVCMOS33} [get_ports {seg_o[1]}]  ;# b
set_property -dict {PACKAGE_PIN P11 IOSTANDARD LVCMOS33} [get_ports {seg_o[2]}]  ;# c
set_property -dict {PACKAGE_PIN R11 IOSTANDARD LVCMOS33} [get_ports {seg_o[3]}]  ;# d
set_property -dict {PACKAGE_PIN R10 IOSTANDARD LVCMOS33} [get_ports {seg_o[4]}]  ;# e
set_property -dict {PACKAGE_PIN N9  IOSTANDARD LVCMOS33} [get_ports {seg_o[5]}]  ;# f
set_property -dict {PACKAGE_PIN K12 IOSTANDARD LVCMOS33} [get_ports {seg_o[6]}]  ;# g
set_property -dict {PACKAGE_PIN P9  IOSTANDARD LVCMOS33} [get_ports {seg_o[7]}]  ;# dp
set_property -dict {PACKAGE_PIN T9  IOSTANDARD LVCMOS33} [get_ports {seg_an_o[0]}]
set_property -dict {PACKAGE_PIN P10 IOSTANDARD LVCMOS33} [get_ports {seg_an_o[1]}]
set_property -dict {PACKAGE_PIN T8  IOSTANDARD LVCMOS33} [get_ports {seg_an_o[2]}]

## --------------------------------------------- pinos ocupados (nao usar)
## microSD da daughterboard -- o HSM nao usa, mas registrado para evitar
## colisao: J5=CS, K5=MOSI, E6=CLK, B5=MISO, B6/J4/A7=DAT1/DAT2/CD.
## ATENCAO: os XDC oficiais LED.xdc e key.xdc sao do core board SEM
## daughterboard e usam E6/K5 como reset/botao. Com a daughterboard montada
## isso aciona linhas do cartao SD. Ver doc/pinout.md.

## ----------------------------------------- SPI flash (log -- fases 4/5)
## MT25QL128, 16 MB -- a MESMA flash que guarda o bitstream. Log e blobs vao
## num offset acima da imagem de configuracao (sugerido 0x400000).
## Acesso da logica do usuario exige a primitiva STARTUPE2 para o CCLK: os
## pinos de configuracao sao dedicados e NAO levam PACKAGE_PIN aqui.
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]

## ------------------------------------------------------------ bitstream
## BBRAM apenas. NUNCA eFUSE -- ver PLANO.md secao 0.
set_property BITSTREAM.GENERAL.COMPRESS TRUE [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]
set_property CFGBVS VCCO [current_design]
## Fase 6, quando chegar a hora:
#set_property BITSTREAM.ENCRYPTION.ENCRYPT YES [current_design]
#set_property BITSTREAM.ENCRYPTION.ENCRYPTKEYSELECT BBRAM [current_design]
