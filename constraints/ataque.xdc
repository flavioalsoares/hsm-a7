## Bitstream de ataque: o clock rapido existe para violar o timing, entao a
## ferramenta nao tenta fecha-lo. O dominio de 100 MHz continua analisado.
set rapido [get_clocks -of_objects [get_pins -hierarchical -filter {NAME =~ *u_mmcm*/CLKOUT1}]]
set normal [get_clocks -of_objects [get_pins -hierarchical -filter {NAME =~ *u_mmcm*/CLKOUT0}]]
set_clock_groups -physically_exclusive -group $rapido -group $normal
set_false_path -from $rapido -to $rapido
set_false_path -from [get_clocks sys_clk] -to $rapido
