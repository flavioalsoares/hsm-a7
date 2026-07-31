# Firmware do HSM. Usa a infraestrutura de build do NEORV32.
#
#   make image   -> neorv32_imem_image.vhd  (embutido no bitstream)
#   make exe     -> neorv32_exe.bin         (upload pelo bootloader)
#   make clean_all
#
# NAO usar 'make install' nem 'make all': o alvo install copia a imagem para
# dentro de third_party/neorv32/rtl/core/, sujando o submodulo. Ver
# doc/submodulos.md. O build da FPGA substitui o arquivo na lista, sem tocar
# no submodulo.

NEORV32_HOME ?= ../third_party/neorv32

# O NEORV32 assume o toolchain xPack (riscv-none-elf-). No Debian/Ubuntu o
# pacote gcc-riscv64-unknown-elf instala com outro prefixo. Sobrescrever com:
#   make RISCV_PREFIX=riscv-none-elf- image
RISCV_PREFIX ?= riscv64-unknown-elf-

# DEPENDENCIAS DE PACOTE (Debian/Ubuntu):
#   gcc-riscv64-unknown-elf        compilador
#   picolibc-riscv64-unknown-elf   biblioteca C
#
# O compilador sozinho nao basta: ele fornece apenas os headers freestanding
# (stdint, stdbool, stddef, stdarg), e neorv32.h precisa de inttypes.h,
# stdlib.h, stdio.h, string.h, fcntl.h e unistd.h. Nao ha libnewlib para
# RISC-V nos repositorios; picolibc e o equivalente.
#
# Nosso codigo em si nao usa libc nenhuma -- a dependencia vem do header do
# NEORV32.

# Precisa casar com o wrapper: RISCV_ISA_C + RISCV_ISA_M + Zicntr.
# Compilar para uma ISA maior que a sintetizada da instrucao ilegal em
# tempo de execucao -- e o tipo de erro que so aparece no caminho raro.
MARCH ?= rv32imc_zicsr_zifencei
MABI  ?= ilp32

# -Os: a IMEM tem 16 KB. Tamanho importa mais que velocidade aqui.
EFFORT ?= -Os

APP_SRC = $(wildcard ./src/*.c)
APP_INC = -I ./include

# ---------------------------------------------------------------------
# Excluir os syscall stubs da newlib
#
# neorv32_newlib.c sao 359 linhas de _open/_read/_write/_sbrk/_exit etc.,
# necessarias so para quem usa printf, malloc ou arquivos. Este firmware
# nao usa nada disso: lacos explicitos, wipe() proprio, sem alocacao
# dinamica (CLAUDE.md).
#
# Alem de desnecessario, o arquivo nao compila contra a picolibc: ele
# declara 'extern int errno' enquanto a picolibc declara errno como
# thread-local. O NEORV32 tem a newlib como alvo, nao a picolibc.
#
# Excluir e CONFIGURACAO, nao modificacao do core -- degrau 0 da escada de
# doc/submodulos.md, sem patch e sem tocar em third_party/. O 'override' e
# necessario porque common.mk reatribui CORE_SRC com '=' e venceria uma
# atribuicao simples feita aqui.
#
# Se algum dia o firmware precisar de libc de verdade, a saida certa NAO e
# reincluir este arquivo com um patch: e trocar para o toolchain xPack
# (riscv-none-elf-gcc), que embute a newlib e e o que o upstream testa.
# ---------------------------------------------------------------------
override CORE_SRC = \
    $(filter-out %/neorv32_newlib.c, $(wildcard $(NEORV32_HOME)/sw/lib/source/*.c)) \
    $(NEORV32_HOME)/sw/common/crt0.S

# -Wall -Wextra por padrao no codigo proprio. Num parser que processa
# entrada arbitraria do host, warning ignorado costuma ser bug de limite.
USER_FLAGS += -Wall -Wextra -Werror

# O gcc do Debian nao acha a picolibc sozinho: ela vive fora do sysroot do
# compilador e so entra pelo arquivo de specs. Sem isto, neorv32.h falha em
# <inttypes.h>. Com o toolchain xPack (que ja embute newlib) isto e
# desnecessario -- deixar vazio nesse caso:
#   make PICOLIBC_SPECS= image
PICOLIBC_SPECS ?= --specs=picolibc.specs
USER_FLAGS += $(PICOLIBC_SPECS)

include $(NEORV32_HOME)/sw/common/common.mk
