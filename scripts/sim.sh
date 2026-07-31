#!/usr/bin/env bash
#
# Simulacao de um testbench. Uso: scripts/sim.sh tb_clk_rst
#                                 scripts/sim.sh            (roda todos)
#
# Usa o xsim do Vivado, nao o iverilog, por dois motivos: o MMCME2_BASE e
# primitiva Xilinx (precisa das unisims) e o NEORV32 e VHDL (mixed-language).
#
# Criterio de aprovacao: o testbench precisa imprimir "PASS" e nenhum "FAIL".
# Nao relaxar isso -- ver CLAUDE.md, regra 5.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SETTINGS="${VIVADO_SETTINGS:-/opt/AMD/2026.1/Vivado/settings64.sh}"
NEORV32="$ROOT/third_party/neorv32"
WORK="$ROOT/build/sim"

if [ ! -f "$SETTINGS" ]; then
    echo "ERRO: Vivado nao encontrado em $SETTINGS" >&2
    echo "      defina VIVADO_SETTINGS=/caminho/para/settings64.sh" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$SETTINGS" >/dev/null

mkdir -p "$WORK"
cd "$WORK"

# ---------------------------------------------------------------------
# NEORV32 -> biblioteca 'neorv32', compilada uma vez e cacheada.
#
# Sao 57 arquivos VHDL; recompilar a cada testbench torna a suite
# inutilizavel. O marcador guarda o SHA do submodulo, entao trocar de
# versao do core forca a recompilacao.
# ---------------------------------------------------------------------
compile_neorv32() {
    if [ ! -f "$NEORV32/rtl/file_list_soc.f" ]; then
        echo "ERRO: submodulo ausente -- rode 'git submodule update --init --recursive'" >&2
        exit 1
    fi

    # A imagem da IMEM vem do nosso firmware. Entra no hash do cache para
    # que recompilar o firmware invalide a biblioteca -- senao a simulacao
    # roda silenciosamente contra o binario anterior, que e o pior tipo de
    # resultado: verde e mentiroso.
    local fw_image="$ROOT/fw/neorv32_imem_image.vhd"
    if [ ! -f "$fw_image" ]; then
        echo "ERRO: firmware nao compilado -- rode 'make -C fw image'" >&2
        exit 1
    fi

    local sha
    sha="$(git -C "$NEORV32" rev-parse HEAD)-$(sha256sum "$fw_image" | cut -c1-16)"

    if [ -f .neorv32_lib_sha ] && [ "$(cat .neorv32_lib_sha)" = "$sha" ]; then
        return 0
    fi

    echo "=== compilando NEORV32 ($(git -C "$NEORV32" describe --tags)) + firmware na lib 'neorv32'"
    local files
    files="$(sed "s|\$NEORV32_HOME|$NEORV32|" "$NEORV32/rtl/file_list_soc.f" \
             | grep -v 'neorv32_imem_image\.vhd$')"
    files="$files $fw_image"

    # shellcheck disable=SC2086
    if ! xvhdl -work neorv32 $files > neorv32_compile.log 2>&1; then
        echo "--- falha compilando o NEORV32:"
        tail -30 neorv32_compile.log
        exit 1
    fi
    echo "$sha" > .neorv32_lib_sha
}

# ---------------------------------------------------------------------
run_one() {
    local tb="$1"
    local src="$ROOT/sim/tb/$tb.v"

    if [ ! -f "$src" ]; then
        echo "ERRO: $src nao existe" >&2
        return 1
    fi

    echo "=== $tb"

    # wrapper VHDL do projeto (biblioteca padrao, nao 'neorv32')
    if ! xvhdl "$ROOT"/rtl/soc/*.vhd > "${tb}_vhdl.log" 2>&1; then
        echo "--- falha compilando VHDL do projeto:"; tail -20 "${tb}_vhdl.log"; return 1
    fi

    if ! xvlog "$ROOT"/rtl/soc/*.v "$ROOT"/rtl/top/*.v "$src" \
               "$XILINX_VIVADO/data/verilog/src/glbl.v" \
               > "${tb}_compile.log" 2>&1; then
        echo "--- falha de compilacao:"; tail -20 "${tb}_compile.log"; return 1
    fi

    if ! xelab -L unisims_ver -L neorv32 -s "${tb}_sim" "$tb" glbl \
               > "${tb}_elab.log" 2>&1; then
        echo "--- falha de elaboracao:"; tail -20 "${tb}_elab.log"; return 1
    fi

    xsim "${tb}_sim" -runall > "${tb}_sim.log" 2>&1 || true
    grep -E "^\[$tb\]" "${tb}_sim.log" || true

    if ! grep -q "\[$tb\] PASS" "${tb}_sim.log"; then
        echo "--- $tb: FALHOU (log em $WORK/${tb}_sim.log)"
        return 1
    fi
    echo "--- $tb: OK"
    return 0
}

compile_neorv32

if [ $# -ge 1 ]; then
    run_one "$1"
    exit $?
fi

# sem argumento: roda todos os testbenches implementados
fails=0
for src in "$ROOT"/sim/tb/tb_*.v; do
    tb="$(basename "$src" .v)"
    if grep -q "NAO IMPLEMENTADO" "$src"; then
        echo "=== $tb: pulado (ainda nao implementado)"
        continue
    fi
    run_one "$tb" || fails=$((fails + 1))
done

if [ "$fails" -gt 0 ]; then
    echo "=== $fails testbench(es) falharam"
    exit 1
fi
echo "=== todos os testbenches passaram"
