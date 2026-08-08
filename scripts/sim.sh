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

# Vetores KAT no formato do $readmemh. Regenerar e barato e evita o pior
# resultado possivel: um testbench rodando sobre vetores de uma versao
# anterior e passando.
# Cores de terceiros com os patches de patches/ aplicados sobre uma copia.
# third_party/ nunca e tocado -- ver o cabecalho de apply-patches.sh.
"$ROOT/scripts/apply-patches.sh" > "$ROOT/build/patches.log" 2>&1 || {
    echo "ERRO ao aplicar patches:" >&2; cat "$ROOT/build/patches.log" >&2; exit 1; }

if [ -d "$ROOT/vectors/aes" ]; then
    python3 "$ROOT/scripts/mkvectors.py" > "$ROOT/build/mkvectors.log" 2>&1 || {
        echo "ERRO ao gerar vetores:" >&2; cat "$ROOT/build/mkvectors.log" >&2; exit 1; }
fi

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

    # O nosso CFS tambem entra nesta biblioteca (ver abaixo), entao editar
    # rtl/crypto/neorv32_cfs.vhd precisa invalidar o cache. Sem isto a
    # simulacao rodaria contra a versao anterior do coprocessador.
    local cfs_ours="$ROOT/rtl/crypto/neorv32_cfs.vhd"

    # hsm_entropy.vhd entra na mesma biblioteca: ele instancia
    # neoTRNG_cell, entidade do upstream que mora em 'neorv32'.
    local ent_ours="$ROOT/rtl/crypto/hsm_entropy.vhd"

    local sha
    sha="$(git -C "$NEORV32" rev-parse HEAD)-$(sha256sum "$fw_image" | cut -c1-16)-$(sha256sum "$cfs_ours" | cut -c1-16)-$(sha256sum "$ent_ours" | cut -c1-16)"

    if [ -f .neorv32_lib_sha ] && [ "$(cat .neorv32_lib_sha)" = "$sha" ]; then
        return 0
    fi

    echo "=== compilando NEORV32 ($(git -C "$NEORV32" describe --tags)) + firmware + CFS na lib 'neorv32'"

    # O CFS do upstream e um template feito para ser substituido -- ponto de
    # extensao projetado, grau 2 da escada do doc/submodulos.md. Filtra-se o
    # arquivo dele e compila-se o nosso, na mesma biblioteca e com a mesma
    # entidade. third_party/ fica intocado.
    local files
    files="$(sed "s|\$NEORV32_HOME|$NEORV32|" "$NEORV32/rtl/file_list_soc.f" \
             | grep -v 'neorv32_imem_image\.vhd$' \
             | grep -v 'neorv32_cfs\.vhd$')"
    files="$files $fw_image $cfs_ours $ent_ours"

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

    # Cores de cripto externos (submodulos). Entram na compilacao de todos
    # os testbenches; os que nao os instanciam simplesmente os ignoram na
    # elaboracao.
    local cripto=()
    [ -d "$ROOT/build/patched/aes" ]    && cripto+=("$ROOT"/build/patched/aes/*.v)
    [ -d "$ROOT/build/patched/sha256" ] && cripto+=("$ROOT"/build/patched/sha256/*.v)

    if ! xvlog -i "$WORK/../vectors" \
               "${cripto[@]}" \
               "$ROOT"/rtl/crypto/*.v \
               "$ROOT"/rtl/soc/*.v "$ROOT"/rtl/top/*.v \
               "$ROOT"/rtl/diag/*.v "$src" \
               "$XILINX_VIVADO/data/verilog/src/glbl.v" \
               > "${tb}_compile.log" 2>&1; then
        echo "--- falha de compilacao:"; tail -20 "${tb}_compile.log"; return 1
    fi

    # -L work e necessario para o CFS: neorv32_cfs.vhd mora na biblioteca
    # 'neorv32' (o neorv32_top instancia 'entity neorv32.neorv32_cfs', nao
    # ha escolha) e instancia hsm_cfs, que e Verilog e cai na biblioteca
    # padrao. Sem isto o xelab deixa o coprocessador como caixa preta, com
    # um WARNING que passa despercebido e um dispositivo que nao boota.
    if ! xelab -L unisims_ver -L neorv32 -L work -s "${tb}_sim" "$tb" glbl \
               > "${tb}_elab.log" 2>&1; then
        echo "--- falha de elaboracao:"; tail -20 "${tb}_elab.log"; return 1
    fi

    # Instancia sem binding vira caixa preta com saidas em Z, e o xelab
    # segue em frente com um WARNING. Isso ja custou uma rodada inteira:
    # o CFS ficou como caixa preta, o firmware nao encontrou o
    # coprocessador e o dispositivo nao bootou -- sintoma a tres camadas de
    # distancia da causa. Aqui e erro.
    if grep -q "remains a black box" "${tb}_elab.log"; then
        echo "--- $tb: instancia sem binding (caixa preta):"
        grep "remains a black box" "${tb}_elab.log"
        return 1
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
