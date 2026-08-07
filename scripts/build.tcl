# Build nao-interativo. Uso: vivado -mode batch -source scripts/build.tcl
# PROIBIDO neste projeto: program_efuse, CFG_AES_ONLY, qualquer opcao -efuse.
set part    xc7a35tftg256-1
set top     hsm_top
set outdir  ./build
set neorv32 ./third_party/neorv32

file mkdir $outdir
create_project -in_memory -part $part

# ---------------------------------------------------------------------
# Core externo: NEORV32 (submodulo, fixado na tag v1.13.3)
#
# Usa a lista oficial do upstream em vez de um glob proprio -- a ordem e
# o conjunto de arquivos sao responsabilidade de quem mantem o core.
# Tudo vai para a biblioteca VHDL 'neorv32', como o projeto exige.
# ---------------------------------------------------------------------
set flist $neorv32/rtl/file_list_soc.f
if {![file exists $flist]} {
    error "submodulo ausente: $neorv32 -- rode 'git submodule update --init --recursive'"
}
set fh [open $flist r]
set neorv32_files [string map [list {$NEORV32_HOME} $neorv32] [read $fh]]
close $fh

# A imagem da IMEM vem do NOSSO firmware (fw/, 'make image'), nao da copia
# de exemplo do submodulo. Substituir na lista em vez de copiar por cima
# mantem third_party/ limpo -- ver doc/submodulos.md.
set fw_image fw/neorv32_imem_image.vhd
if {![file exists $fw_image]} {
    error "firmware nao compilado: $fw_image ausente -- rode 'make -C fw image'"
}
set neorv32_files [lsearch -all -inline -not $neorv32_files \
                   $neorv32/rtl/core/neorv32_imem_image.vhd]

# O CFS do upstream e um template de exemplo feito para ser substituido --
# e o ponto de extensao PROJETADO do core (doc/submodulos.md, grau 2 da
# escada). O nosso entra na mesma biblioteca, com a mesma entidade. Se um
# dia a entidade mudar la, isto quebra na compilacao, que e o modo certo
# de descobrir.
set cfs_upstream $neorv32/rtl/core/neorv32_cfs.vhd
if {[lsearch -exact $neorv32_files $cfs_upstream] < 0} {
    error "neorv32_cfs.vhd nao esta na lista do upstream -- o ponto de\
           extensao mudou de nome; reveja doc/submodulos.md"
}
set neorv32_files [lsearch -all -inline -not $neorv32_files $cfs_upstream]

add_files $neorv32_files
set_property library neorv32 [get_files $neorv32_files]

add_files $fw_image
set_property library neorv32 [get_files $fw_image]

add_files rtl/crypto/neorv32_cfs.vhd
set_property library neorv32 [get_files rtl/crypto/neorv32_cfs.vhd]

# ---------------------------------------------------------------------
# Cores de cripto (submodulos, fixados por SHA de commit), com os patches
# de patches/ aplicados sobre uma COPIA em build/patched/ -- third_party/
# nunca e tocado. Verilog puro; vao para a biblioteca padrao, de onde
# hsm_cfs.v os instancia.
# ---------------------------------------------------------------------
if {[catch {exec ./scripts/apply-patches.sh} saida]} {
    error "falha aplicando patches:\n$saida"
}
puts $saida

foreach d {aes sha256} {
    set src [glob -nocomplain build/patched/$d/*.v]
    if {[llength $src] == 0} {
        error "build/patched/$d vazio -- scripts/apply-patches.sh nao produziu RTL"
    }
    add_files $src
}

# ---------------------------------------------------------------------
# Codigo proprio do projeto
#
# neorv32_cfs.vhd sai do glob: ja foi adicionado acima, na biblioteca
# 'neorv32'. Adiciona-lo de novo na biblioteca padrao criaria duas
# entidades de mesmo nome.
# ---------------------------------------------------------------------
foreach f [glob -nocomplain rtl/*/*.v rtl/*/*.vhd] {
    if {$f eq "rtl/crypto/neorv32_cfs.vhd"} { continue }
    add_files $f
}
read_xdc constraints/qmtech_a35t.xdc

# ---------------------------------------------------------------------
synth_design -top $top -part $part
write_checkpoint -force $outdir/post_synth.dcp
report_utilization -file $outdir/utilization_synth.txt

opt_design
place_design

# phys_opt_design entrou quando os cores de cripto chegaram. Ate a fase 1
# o fluxo simples bastava, com folga de +0,637 ns; com AES e SHA no fabric
# a margem virou disputada, e medir mostrou que estas duas passagens valem
# quase 1 ns. Sao poucos minutos de ferramenta -- barato perto de baixar o
# clock do sistema, que era a alternativa.
phys_opt_design
route_design
phys_opt_design

write_checkpoint -force $outdir/post_route.dcp
report_timing_summary -file $outdir/timing.txt
report_utilization    -file $outdir/utilization.txt

write_bitstream -force $outdir/$top.bit
puts "OK -> $outdir/$top.bit"
