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

add_files $neorv32_files
set_property library neorv32 [get_files $neorv32_files]

add_files $fw_image
set_property library neorv32 [get_files $fw_image]

# ---------------------------------------------------------------------
# Codigo proprio do projeto
# ---------------------------------------------------------------------
foreach f [glob -nocomplain rtl/*/*.v rtl/*/*.vhd] { add_files $f }
read_xdc constraints/qmtech_a35t.xdc

# ---------------------------------------------------------------------
synth_design -top $top -part $part
write_checkpoint -force $outdir/post_synth.dcp
report_utilization -file $outdir/utilization_synth.txt

opt_design
place_design
route_design
write_checkpoint -force $outdir/post_route.dcp
report_timing_summary -file $outdir/timing.txt
report_utilization    -file $outdir/utilization.txt

write_bitstream -force $outdir/$top.bit
puts "OK -> $outdir/$top.bit"
