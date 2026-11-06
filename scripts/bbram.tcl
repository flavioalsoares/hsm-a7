# Grava ou apaga a chave na BBRAM, ou carrega um bitstream cifrado na SRAM.
# Destino da chave fixo: bbr. Ver PLANO.md, secao 0.
#
#   ACAO=grava vivado -mode batch -source scripts/bbram.tcl
#   ACAO=apaga vivado -mode batch -source scripts/bbram.tcl
#   ACAO=carrega ARQ=build/cifrado/hsm_puf.bit \
#       vivado -mode batch -source scripts/bbram.tcl
#
# Todas limpam a configuracao do FPGA. Bitstream cifrado carrega por aqui: pelo
# openFPGALoader ele falha com DEC Error, mesmo com a chave certa.
open_hw_manager
connect_hw_server -allow_non_jtag
current_hw_target [lindex [get_hw_targets] 0]
open_hw_target
set_property PARAM.FREQUENCY 1000000 [current_hw_target]
set d [lindex [get_hw_devices xc7a35t*] 0]
current_hw_device $d
refresh_hw_device -update_hw_probes false $d
if {$::env(ACAO) eq "grava"} {
    create_hw_bitstream -hw_device $d -nky build/chave/bitstream.nky build/puf/hsm_puf.bit
    program_hw_devices -key bbr $d
    puts "BBRAM gravada"
} elseif {$::env(ACAO) eq "apaga"} {
    create_hw_bitstream -hw_device $d -nky build/chave/bitstream.nky build/puf/hsm_puf.bit
    program_hw_devices -key bbr -clear $d
    puts "BBRAM apagada"
} elseif {$::env(ACAO) eq "carrega"} {
    set_property PROGRAM.FILE $::env(ARQ) $d
    program_hw_devices $d
    refresh_hw_device -update_hw_probes false $d
    foreach p {BIT01_DECRYPTOR_ENABLE BIT14_DONE_PIN BIT27_HMAC_ERROR} {
        puts "$p [get_property REGISTER.CONFIG_STATUS.$p $d]"
    }
} else {
    error "ACAO deve ser grava, apaga ou carrega"
}
close_hw_target
disconnect_hw_server
