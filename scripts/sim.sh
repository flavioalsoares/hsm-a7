#!/usr/bin/env bash
#
# Simulacao de um testbench. Uso: scripts/sim.sh tb_clk_rst
#                                 scripts/sim.sh            (roda todos)
#                                 scripts/sim.sh tb_a tb_b  (estes, em paralelo)
#
# Sem argumento, ou com mais de um, roda SIM_JOBS testbenches ao mesmo tempo (padrao 3). O xsim
# usa um core por simulacao; o limite pratico e a memoria. Cada testbench
# tem o proprio diretorio, build/sim/<tb>/, com a propria biblioteca 'work';
# so a biblioteca 'neorv32' (NEORV32 + firmware + CFS) e compartilhada, e e
# compilada uma vez antes de comecar. O testbench que pede outra variante
# de firmware roda sozinho, no fim, e a producao e restaurada depois dele.
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

# Os testbenches leem os vetores por "../vectors/", relativo ao diretorio
# de trabalho. Com um diretorio por testbench, ../vectors e build/sim/vectors.
ln -sfn "$ROOT/build/vectors" "$WORK/vectors"

# ---------------------------------------------------------------------
# NEORV32 -> biblioteca 'neorv32', compilada uma vez e cacheada.
#
# Sao 57 arquivos VHDL; recompilar a cada testbench torna a suite
# inutilizavel. O marcador guarda o SHA do submodulo, entao trocar de
# versao do core forca a recompilacao.
# ---------------------------------------------------------------------
compile_neorv32() {
    # Variante do firmware: vazio e a producao. Um testbench pede outra pela
    # diretiva "sim-firmware: VAR=1" (hoje so o tb_rsa_mr, com HSM_TESTE_MR).
    # A variante em uso fica anotada em fw/.variante; trocar de variante
    # recompila tudo (-B), senao objetos de uma entrariam na outra.
    local variante="${1:-}"
    local marca="$ROOT/fw/.variante"
    local atual=""
    [ -f "$marca" ] && atual="$(cat "$marca")"
    if [ ! -f "$NEORV32/rtl/file_list_soc.f" ]; then
        echo "ERRO: submodulo ausente -- rode 'git submodule update --init --recursive'" >&2
        exit 1
    fi

    # A imagem da IMEM vem do nosso firmware. Entra no hash do cache para
    # que recompilar o firmware invalide a biblioteca -- senao a simulacao
    # roda silenciosamente contra o binario anterior, que e o pior tipo de
    # resultado: verde e mentiroso.
    local fw_image="$ROOT/fw/neorv32_imem_image.vhd"

    # ...mas invalidar o cache so resolve metade. A outra metade e ESTA:
    # se alguem editar o C e rodar a simulacao, a imagem no disco continua
    # sendo a de antes, e o testbench valida um firmware que nao existe
    # mais. Verde e mentiroso de novo, pela porta do lado.
    #
    # Descoberto em 2026-08-29 do jeito mais util possivel: uma sabotagem
    # deliberada de fw/src/keystore.c PASSOU na simulacao. Nao passou
    # porque o teste era fraco -- passou porque o codigo sabotado nunca
    # chegou a ser compilado. Um teste que nunca ve o codigo em teste e
    # pior que teste nenhum.
    local fw_desatualizado=0
    if [ "$variante" != "$atual" ]; then
        fw_desatualizado=1
    elif [ ! -f "$fw_image" ]; then
        fw_desatualizado=1
    else
        local src
        for src in "$ROOT"/fw/src/*.c "$ROOT"/fw/include/*.h "$ROOT"/fw/Makefile; do
            [ -f "$src" ] || continue
            if [ "$src" -nt "$fw_image" ]; then
                fw_desatualizado=1
                break
            fi
        done
    fi

    if [ "$fw_desatualizado" = "1" ]; then
        echo "=== firmware desatualizado -- recompilando${variante:+ (variante $variante)}"
        # shellcheck disable=SC2086
        if ! make -s -B -C "$ROOT/fw" $variante image >/dev/null; then
            echo "ERRO: 'make -C fw image' falhou." >&2
            echo "      Toolchain: gcc-riscv64-unknown-elf + picolibc-riscv64-unknown-elf" >&2
            echo "      Prefixo diferente? make RISCV_PREFIX=... -C fw image" >&2
            exit 1
        fi
        if [ -n "$variante" ]; then
            echo "$variante" > "$marca"
        else
            rm -f "$marca"
        fi
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
variante_de() {
    sed -n 's/.*sim-firmware: *//p' "$ROOT/sim/tb/$1.v" | head -1
}

# Roda num subshell: o cd para o diretorio do testbench nao vaza.
run_one() (
    local tb="$1"
    local src="$ROOT/sim/tb/$tb.v"

    if [ ! -f "$src" ]; then
        echo "ERRO: $src nao existe" >&2
        return 1
    fi

    echo "=== $tb"

    # Firmware: o de producao, ou a variante que o testbench pedir. Na suite
    # em paralelo a biblioteca ja foi preparada, e ninguem pode recompila-la
    # com outros testbenches rodando.
    if [ -z "${SIM_LIB_PRONTA:-}" ]; then
        compile_neorv32 "$(variante_de "$tb")"
    fi

    # Diretorio proprio. A biblioteca 'neorv32' vem do diretorio comum.
    local dir="$WORK/$tb"
    mkdir -p "$dir/xsim.dir"
    ln -sfn "$WORK/xsim.dir/neorv32" "$dir/xsim.dir/neorv32"
    cd "$dir"

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

    # Testbench de bitstream separado: o proprio arquivo pede o define.
    local defs=() d
    for d in $(sed -n 's/.*sim-define: *//p' "$src"); do defs+=(-d "$d"); done

    if ! xvlog "${defs[@]}" -i "$WORK/../vectors" \
               "${cripto[@]}" \
               "$ROOT"/rtl/crypto/*.v \
               "$ROOT"/rtl/soc/*.v "$ROOT"/rtl/top/*.v \
               "$ROOT"/rtl/diag/*.v "$ROOT"/rtl/puf/*.v "$ROOT"/sim/models/*.v "$src" \
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

    # Curva analogica do XADC. O nome e fixo no RTL; aqui escolhe-se o
    # conteudo. Sem curva propria o testbench recebe a nominal -- sensor
    # sem estimulo le zero, e o dispositivo se daria por violado.
    if [ -f "$ROOT/sim/stim/$tb.txt" ]; then
        cp "$ROOT/sim/stim/$tb.txt" xadc_stim.txt
    else
        cp "$ROOT/sim/stim/nominal.txt" xadc_stim.txt
    fi

    # Limite de relogio. Um testbench travado (sem timeout interno, ou com
    # um laco que nunca chega nele) prenderia a suite para sempre. O padrao
    # e 6 h, quase o dobro do mais lento medido (tb_tamper, 3 h 15). Um
    # testbench pede outro limite pela diretiva "sim-timeout: <segundos>";
    # SIM_TIMEOUT no ambiente vale para todos.
    local limite
    limite="$(sed -n 's/.*sim-timeout: *\([0-9][0-9]*\).*/\1/p' "$src" | head -1)"
    limite="${SIM_TIMEOUT:-${limite:-21600}}"

    local t0 t1 rc=0 res
    t0="$(date +%s)"
    timeout "$limite" xsim "${tb}_sim" -runall > "${tb}_sim.log" 2>&1 || rc=$?
    t1="$(date +%s)"
    grep -E "^\[$tb\]" "${tb}_sim.log" || true

    # Criterio do cabecalho: PASS impresso E nenhum FAIL. Ate 2026-11-09 o
    # script so procurava o PASS; os testbenches so imprimem PASS com zero
    # erros, mas a regra nao pode depender de cada testbench lembrar disso.
    if [ "$rc" -eq 124 ]; then
        res="TIMEOUT"
        echo "--- $tb: FALHOU -- passou do limite de ${limite} s (log em $dir/${tb}_sim.log)"
    elif grep -q "\[$tb\] FAIL" "${tb}_sim.log"; then
        res="FAIL"
        echo "--- $tb: FALHOU -- o log tem FAIL (log em $dir/${tb}_sim.log)"
    elif ! grep -q "\[$tb\] PASS" "${tb}_sim.log"; then
        res="FAIL"
        echo "--- $tb: FALHOU (log em $dir/${tb}_sim.log)"
    else
        res="PASS"
        echo "--- $tb: OK"
    fi

    # Tempo de cada rodada, para acompanhar a suite sem medir a mao.
    [ -f "$WORK/tempos.csv" ] || echo "data,testbench,segundos,resultado,commit" > "$WORK/tempos.csv"
    echo "$(date -Iseconds),$tb,$((t1 - t0)),$res,$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo ?)" \
        >> "$WORK/tempos.csv"

    [ "$res" = "PASS" ]
)

# Testbench de variante: roda e depois devolve fw/ e a biblioteca a
# producao. Sem isso o build do Vivado pegaria o firmware de teste.
run_variante() {
    local rc=0
    run_one "$1" || rc=$?
    echo "=== restaurando o firmware de producao"
    compile_neorv32 ""
    return "$rc"
}

if [ $# -eq 1 ]; then
    if [ -n "$(variante_de "$1")" ]; then
        run_variante "$1"
    else
        run_one "$1"
    fi
    exit $?
fi

# ---------------------------------------------------------------------
# A suite (ou os testbenches pedidos), SIM_JOBS por vez.
# ---------------------------------------------------------------------
JOBS="${SIM_JOBS:-3}"

# Ultima duracao medida, em segundos. Sem medida conta como a mais longa,
# para comecar cedo.
duracao() {
    local d=""
    [ -f "$WORK/tempos.csv" ] && \
        d="$(awk -F, -v t="$1" '$2 == t { d = $3 } END { print d }' "$WORK/tempos.csv")"
    echo "${d:-999999}"
}

producao=() variantes=()
if [ $# -gt 1 ]; then
    fontes=()
    for tb in "$@"; do fontes+=("$ROOT/sim/tb/$tb.v"); done
else
    fontes=("$ROOT"/sim/tb/tb_*.v)
fi
for src in "${fontes[@]}"; do
    tb="$(basename "$src" .v)"
    [ -f "$src" ] || { echo "ERRO: $src nao existe" >&2; exit 1; }
    if grep -q "NAO IMPLEMENTADO" "$src"; then
        echo "=== $tb: pulado (ainda nao implementado)"
        continue
    fi
    if [ -n "$(variante_de "$tb")" ]; then
        variantes+=("$tb")
    else
        producao+=("$tb")
    fi
done

# Os mais longos primeiro: o total fica perto do mais longo sozinho.
mapfile -t ordem < <(for tb in "${producao[@]}"; do echo "$(duracao "$tb") $tb"; done \
                     | sort -rn | cut -d' ' -f2)

compile_neorv32 ""
export SIM_LIB_PRONTA=1

echo "=== ${#ordem[@]} testbenches, $JOBS por vez; saida de cada um em $WORK/<tb>.saida"
inicio="$(date +%s)"
rodando=0
for tb in "${ordem[@]}"; do
    if [ "$rodando" -ge "$JOBS" ]; then
        wait -n || true
        rodando=$((rodando - 1))
    fi
    (
        t0="$(date +%s)"
        rc=0
        run_one "$tb" > "$WORK/$tb.saida" 2>&1 || rc=$?
        echo "$rc" > "$WORK/$tb.rc"
        r="OK"; [ "$rc" -eq 0 ] || r="FALHOU"
        echo "--- $(date +%H:%M) $tb: $r ($(( ($(date +%s) - t0) / 60 )) min)"
    ) &
    rodando=$((rodando + 1))
done
wait
unset SIM_LIB_PRONTA

fails=0
for tb in "${ordem[@]}"; do
    if [ "$(cat "$WORK/$tb.rc" 2>/dev/null || echo 1)" != "0" ]; then
        fails=$((fails + 1))
        echo "=== $tb falhou:"
        cat "$WORK/$tb.saida"
    fi
done

for tb in "${variantes[@]}"; do
    run_variante "$tb" || fails=$((fails + 1))
done

echo "=== suite: $(( ($(date +%s) - inicio) / 60 )) min"
if [ "$fails" -gt 0 ]; then
    echo "=== $fails testbench(es) falharam"
    exit 1
fi
echo "=== todos os testbenches passaram"
