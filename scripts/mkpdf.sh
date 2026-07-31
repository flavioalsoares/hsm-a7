#!/usr/bin/env bash
#
# Gera o manual em PDF a partir de doc/manual/*.md
#
#   ./scripts/mkpdf.sh          -> doc/hsm-a7-manual.pdf
#
# Caminho: pandoc (markdown -> HTML autocontido) + Chrome headless
# (HTML -> PDF). Nao usa LaTeX de proposito: o texlive desta maquina esta
# incompleto (falta xcolor) e instalar exigiria privilegio. O par
# pandoc+Chrome tambem da controle total da tipografia via CSS.
#
# O PDF NAO e byte-reproduzivel: o Chrome embute data de criacao e um
# identificador no arquivo. Rodar duas vezes sobre a mesma fonte da PDFs
# diferentes, com conteudo identico. Por isso 'git status' acusa mudanca
# depois de regerar -- se nao houve mudanca de texto, descarte com
# 'git checkout -- doc/hsm-a7-manual.pdf'.
#
# (Contraste com scripts/mirror-deps.sh, onde a reprodutibilidade importa
# porque o artefato e uma afirmacao de procedencia. Aqui e so um documento.)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/doc/manual"
OUT="$ROOT/doc/hsm-a7-manual.pdf"
TMP="$ROOT/build/manual"

command -v pandoc >/dev/null 2>&1 || {
    echo "ERRO: pandoc nao encontrado (sudo apt install pandoc)" >&2; exit 1; }

CHROME="$(command -v google-chrome || command -v chromium || true)"
[ -n "$CHROME" ] || {
    echo "ERRO: google-chrome ou chromium nao encontrado" >&2; exit 1; }

mkdir -p "$TMP"

# A ordem dos arquivos e a ordem do livro.
PARTES=(
    "$SRC/00-capa.md"
    "$SRC/01-fundamentos.md"
    "$SRC/02-arquitetura.md"
    "$SRC/03-ataques.md"
    "$SRC/04-certificacao.md"
    "$SRC/05-projeto.md"
    "$SRC/06-roadmap.md"
    "$SRC/07-apendices.md"
)

for f in "${PARTES[@]}"; do
    [ -f "$f" ] || { echo "ERRO: falta $f" >&2; exit 1; }
done

echo "=== pandoc -> HTML"
pandoc "${PARTES[@]}" \
    --from markdown+fenced_divs+pipe_tables+yaml_metadata_block \
    --to html5 \
    --standalone \
    --toc --toc-depth=2 \
    --css "$SRC/estilo.css" \
    --embed-resources \
    --metadata lang=pt-BR \
    -o "$TMP/manual.html"

echo "=== Chrome -> PDF"
"$CHROME" --headless --disable-gpu --no-sandbox \
    --print-to-pdf="$OUT" \
    --no-pdf-header-footer \
    --virtual-time-budget=20000 \
    "file://$TMP/manual.html" 2>&1 | grep -v '^\[' || true

if [ ! -f "$OUT" ]; then
    echo "ERRO: PDF nao foi gerado" >&2
    exit 1
fi

echo
echo "=== $OUT  ($(du -h "$OUT" | cut -f1))"
command -v pdfinfo >/dev/null 2>&1 && pdfinfo "$OUT" | grep -E '^(Pages|Page size)'
