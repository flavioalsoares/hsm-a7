# scripts/build-puf.tcl -- bitstream do experimento de RO-PUF (fase 6).
#
# NAO E O HSM. Ver rtl/puf/hsm_puf_top.v e doc/puf-experimento.md. Sem CPU, sem
# firmware e sem chave. Sai em build/puf/hsm_puf.bit, e nao sobrescreve nada.
#
# Carrega na SRAM, por JTAG, sem tocar a flash:
#   BIT=build/puf/hsm_puf.bit ./scripts/program.sh
# Volta para a producao com um reset da configuracao (openFPGALoader -r).
#
# Nenhuma operacao de eFUSE, nunca -- PLANO.md secao 0.

set part   xc7a35tftg256-1
set top    hsm_puf_top
set outdir ./build/puf

file mkdir $outdir
create_project -in_memory -part $part

add_files rtl/soc/clk_rst_gen.v
add_files rtl/crypto/hsm_xadc.v
add_files [glob rtl/puf/*.v]

read_xdc constraints/qmtech_a35t.xdc
read_xdc constraints/puf.xdc

synth_design -top $top -part $part

# Posicao de cada anel. Quatro colunas do MESMO tipo de tile (CLBLL_L), 16
# linhas cada, todas abaixo do clock row da regiao X1Y1. Um anel ocupa um CLB:
# NAND e tres inversores numa fatia, tres inversores e o tampao na outra. Anel
# i: coluna i/16, linha i%16. Os vizinhos para parear ficam na mesma coluna.
set colunas {36 40 44 58}
set y0      55

for {set i 0} {$i < 64} {incr i} {
    set x [lindex $colunas [expr {$i / 16}]]
    set y [expr {$y0 + $i % 16}]
    set s0 SLICE_X${x}Y${y}
    set s1 SLICE_X[expr {$x + 1}]Y${y}
    set base "g_ro\[$i\].u_ro"

    set celulas [list [get_cells $base/u_nand]]
    for {set k 1} {$k < 7} {incr k} {
        lappend celulas [get_cells "$base/g_inv\[$k\].u_inv"]
    }
    lappend celulas [get_cells $base/u_tap]
    lappend aneis($x) {*}$celulas

    # Pinos travados: o roteador nao pode trocar a entrada de um LUT.
    set_property LOCK_PINS {I0:A5 I1:A6} [lindex $celulas 0]
    for {set k 1} {$k < 8} {incr k} {
        set_property LOCK_PINS {I0:A6} [lindex $celulas $k]
    }

    for {set k 0} {$k < 8} {incr k} {
        set sitio [expr {$k < 4 ? $s0 : $s1}]
        set bel   [lindex {A6LUT B6LUT C6LUT D6LUT} [expr {$k % 4}]]
        place_cell [lindex $celulas $k] $sitio/$bel
    }
}

# Nada mais entra nos CLBs dos aneis.
foreach x $colunas {
    set pb [create_pblock pb_x$x]
    resize_pblock $pb -add SLICE_X${x}Y${y0}:SLICE_X[expr {$x + 1}]Y[expr {$y0 + 15}]
    set_property EXCLUDE_PLACEMENT 1 $pb
    add_cells_to_pblock $pb $aneis($x)
}

# O laco e o objeto do experimento.
set_property ALLOW_COMBINATORIAL_LOOPS TRUE [get_nets -hier -filter {NAME =~ *u_ro/s[*}]
set_property SEVERITY {Warning} [get_drc_checks LUTLP-1]

opt_design
place_design

# O anel 0 e roteado sozinho, e a rota dele vira a rota de todos. Assim a
# diferenca entre aneis nao vem do roteador: e o ponto da secao 2 do documento.
# A rota fixa e relativa, e as quatro colunas tem os mesmos tiles em volta.
set nets0 {}
for {set k 0} {$k < 7} {incr k} { lappend nets0 [get_nets "g_ro\[0\].u_ro/s\[$k\]"] }
route_design -nets $nets0
for {set k 0} {$k < 7} {incr k} {
    set n0 [lindex $nets0 $k]
    set_property IS_ROUTE_FIXED 1 $n0
    set rota($k) [get_property FIXED_ROUTE $n0]
}
# A rota vem com o nome de cada tile; desloca-se para a posicao de cada anel.
proc desloca {rota dx dy} {
    regsub -all {_X(\d+)Y(\d+)/} $rota {_X[expr {\1 + $dx}]Y[expr {\2 + $dy}]/} t
    return [subst -nobackslashes $t]
}
set tiles_x {0 2 4 14}    ;# colunas de tile em relacao a primeira
for {set i 1} {$i < 64} {incr i} {
    set dx [lindex $tiles_x [expr {$i / 16}]]
    set dy [expr {$i % 16}]
    for {set k 0} {$k < 7} {incr k} {
        set_property FIXED_ROUTE [desloca $rota($k) $dx $dy] \
            [get_nets "g_ro\[$i\].u_ro/s\[$k\]"]
    }
}
route_design

# Prova da simetria: o formato da rota e o lugar de cada anel, para conferir.
set saida [open $outdir/rotas.txt w]
for {set i 0} {$i < 64} {incr i} {
    set forma {}
    for {set k 0} {$k < 7} {incr k} {
        regsub -all {_X[0-9]+Y[0-9]+} [get_property ROUTE [get_nets "g_ro\[$i\].u_ro/s\[$k\]"]] {} r
        lappend forma $r
    }
    set locs [get_property LOC [get_cells "g_ro\[$i\].u_ro/u_nand"]]
    puts $saida "$i $locs [join $forma { | }]"
}
close $saida

report_timing_summary -file $outdir/timing.txt
report_utilization    -file $outdir/utilization.txt
report_power          -file $outdir/power.txt

write_bitstream -force $outdir/hsm_puf.bit
puts "OK -> $outdir/hsm_puf.bit"
