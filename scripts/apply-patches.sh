#!/usr/bin/env bash
#
# Aplica os patches de patches/ sobre uma COPIA dos submodulos, em
# build/patched/. Saida usada por scripts/sim.sh e scripts/build.tcl.
#
# Por que copia, e nao no lugar:
#
#   Aplicar patch dentro de third_party/ deixaria o submodulo sujo. Isso
#   quebra tres coisas de uma vez -- 'git submodule update' descartaria a
#   mudanca em silencio, scripts/mirror-deps.sh se recusaria a rodar, e o
#   pin continuaria dizendo 837c5cc3 enquanto o bitstream conteria outra
#   coisa. Procedencia quebrada e exatamente o que doc/submodulos.md
#   existe para impedir.
#
#   Com a copia, third_party/ fica byte a byte igual ao upstream e o
#   diff da modificacao fica visivel em patches/, versionado, revisavel.
#
# E idempotente: reconstroi build/patched/ do zero a cada execucao. Patch
# aplicado duas vezes e uma das formas classicas de o build passar hoje e
# falhar amanha.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/patched"

# submodulo -> subdiretorio de RTL dentro dele
declare -A RTL_DIR=(
    [sha256]="src/rtl"
    [aes]="src/rtl"
)

rm -rf "$OUT"
mkdir -p "$OUT"

for mod in "${!RTL_DIR[@]}"; do
    src="$ROOT/third_party/$mod/${RTL_DIR[$mod]}"
    dst="$OUT/$mod"

    if [ ! -d "$src" ]; then
        echo "ERRO: submodulo ausente: third_party/$mod" >&2
        echo "      rode 'git submodule update --init --recursive'" >&2
        exit 1
    fi

    mkdir -p "$dst"
    cp "$src"/*.v "$dst/"

    # Os patches sao opcionais: um submodulo sem patches so e copiado.
    shopt -s nullglob
    patches=("$ROOT/patches/$mod"/*.patch)
    shopt -u nullglob

    for p in "${patches[@]}"; do
        # --forward faz um patch ja aplicado virar erro em vez de reversao
        # silenciosa. Aqui isso nao deveria acontecer (o diretorio e novo),
        # mas o modo de falhar importa mais que a probabilidade.
        if ! patch -p1 -s --forward -d "$dst" < "$p"; then
            echo "ERRO: falhou aplicar $(basename "$p") em $mod" >&2
            echo "      o upstream provavelmente mudou -- ver doc/submodulos.md" >&2
            exit 1
        fi
        echo "=== $mod: $(basename "$p")"
    done
done

# O submodulo tem de continuar limpo. Se esta checagem falhar, alguem
# editou third_party/ direto -- que e a coisa que o projeto proibe.
for mod in "${!RTL_DIR[@]}"; do
    if [ -n "$(git -C "$ROOT/third_party/$mod" status --porcelain)" ]; then
        echo "ERRO: third_party/$mod esta sujo." >&2
        echo "      Patches vao em patches/, nunca no submodulo." >&2
        exit 1
    fi
done

echo "=== RTL com patch em build/patched/"
