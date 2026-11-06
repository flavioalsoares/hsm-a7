# constraints/puf.xdc -- so o bitstream do experimento de RO-PUF.
#
# O clock do contador sai de um anel, sem relacao com o clock do sistema. A
# contagem so e lida depois de o anel parar e de assentar, e o limpa so muda com
# o anel parado.
create_clock -name ro_clk -period 3.000 [get_pins u_ro_bufg/O]
set_clock_groups -asynchronous -group [get_clocks ro_clk] \
    -group [get_clocks -include_generated_clocks sys_clk]
