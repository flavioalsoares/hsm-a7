# scripts/build-diag.tcl -- bitstream de diagnostico de bancada.
#
# NAO E O HSM. Ver o cabecalho de rtl/diag/hsm_diag_top.v para o que ele
# faz e por que existe. Nao ha SoC, nao ha firmware, nao ha cripto -- e
# justamente esse o ponto: se este bitstream fala pela UART, o caminho
# fisico esta inteiro e a culpa do silencio e do SoC.
#
# Sai em build/hsm_diag.bit. NAO sobrescreve build/hsm_top.bit.
#
# Gravar com:
#   BIT=build/hsm_diag.bit ./scripts/program.sh
#
# Como o hsm_top: SRAM apenas, volatil. Nenhuma operacao de eFUSE, nunca
# -- PLANO.md secao 0.

set part    xc7a35tftg256-1
set top     hsm_diag_top
set outdir  ./build

file mkdir $outdir

create_project -in_memory -part $part

add_files rtl/soc/clk_rst_gen.v
add_files rtl/diag/hsm_diag_top.v
add_files rtl/diag/hsm_memtest.v

# Mesmo XDC do design de verdade. Deliberado: se a pinagem estiver errada,
# o diagnostico tem de errar igual. Um XDC proprio "que funciona" so
# provaria que dois arquivos diferentes discordam.
read_xdc constraints/qmtech_a35t.xdc

synth_design -top $top -part $part
opt_design
place_design
route_design

# Conteudo inicial que o bitstream VAI carregar nas Block RAMs.
#
# Existe para separar duas causas que produzem o mesmo sintoma quando a
# memoria le zero em hardware: a ferramenta nao emitiu a inicializacao, ou
# o dispositivo nao a reteve. Sem esta consulta as duas sao
# indistinguiveis de fora, e levam a consertos opostos.
puts "=== INIT das Block RAMs ==="
foreach c [get_cells -hier -filter {PRIMITIVE_TYPE =~ BMEM.*}] {
    puts "  celula: $c"
    foreach p {INIT_00 INIT_01} {
        if {![catch {set v [get_property $p $c]}]} {
            puts "    $p = $v"
        }
    }
}
puts "=== fim INIT ==="

report_timing_summary -file $outdir/timing_diag.txt
report_utilization    -file $outdir/utilization_diag.txt

write_bitstream -force $outdir/hsm_diag.bit
puts "OK -> $outdir/hsm_diag.bit"
