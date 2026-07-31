#!/usr/bin/env bash
#
# Espelho local dos cores externos. Uso:
#   scripts/mirror-deps.sh [diretorio_de_saida]
#
# Gera, para cada submodulo, um tarball reproduzivel do codigo-fonte exato
# que esta fixado, mais um manifesto com os hashes.
#
# POR QUE ISTO EXISTE
#
# O pin por SHA no submodulo garante INTEGRIDADE: o SHA do git e o hash do
# conteudo, entao ninguem consegue entregar bytes diferentes sob o mesmo
# identificador. O que ele nao garante e DISPONIBILIDADE -- se o upstream
# apagar a tag ou fizer force-push, o objeto pode ser coletado e voce perde
# a capacidade de buscar aquele commit.
#
# Este espelho cobre a disponibilidade sem criar obrigacao de manutencao,
# que e o custo que um fork traria. Ver doc/submodulos.md.
#
# O ARTEFATO E REPRODUZIVEL: 'git archive' fixa os mtimes pelo commit e o
# 'gzip -n' omite o timestamp do cabecalho. Rodar duas vezes da o mesmo
# SHA-256. Isso e o que torna o manifesto verificavel por terceiros.
#
# NAO COMMITAR a saida: build/ esta no .gitignore. O destino do arquivo e
# armazenamento offline (NAS, backup, anexo de release) -- guardar no
# proprio repositorio anularia o motivo de usar submodulo.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/build/mirror}"

cd "$ROOT"

if [ -z "$(git submodule status)" ]; then
    echo "nenhum submodulo neste repositorio" >&2
    exit 0
fi

mkdir -p "$OUT"
MANIFEST="$OUT/MANIFEST.txt"

{
    echo "# Espelho de dependencias externas -- hsm-a7"
    echo "# Gerado em: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Reproduzir: scripts/mirror-deps.sh"
    echo
} > "$MANIFEST"

fails=0

while read -r _ path _; do
    [ -d "$path" ] || continue

    name="$(basename "$path")"

    # Submodulo sujo => o espelho nao representaria o que esta fixado.
    # Recusar e o comportamento certo: um artefato de procedencia que nao
    # corresponde ao pin e pior que nenhum artefato.
    if [ -n "$(git -C "$path" status --porcelain)" ]; then
        echo "ERRO: '$path' tem modificacoes locais nao commitadas." >&2
        echo "      O espelho representaria algo que o pin nao descreve." >&2
        echo "      Ver doc/submodulos.md: nao editar third_party/ direto." >&2
        fails=$((fails + 1))
        continue
    fi

    sha="$(git -C "$path" rev-parse HEAD)"
    short="$(git -C "$path" rev-parse --short HEAD)"
    tree="$(git -C "$path" rev-parse HEAD^{tree})"
    url="$(git config -f .gitmodules --get "submodule.$path.url" || echo '?')"
    tag="$(git -C "$path" describe --tags --exact-match 2>/dev/null || echo '(sem tag exata)')"

    tarball="$OUT/${name}-${tag}-${short}.tar.gz"

    git -C "$path" archive --format=tar --prefix="${name}-${tag}/" HEAD \
        | gzip -n -9 > "$tarball"

    sum="$(sha256sum "$tarball" | cut -d' ' -f1)"
    size="$(du -h "$tarball" | cut -f1)"

    {
        echo "[$path]"
        echo "  url          = $url"
        echo "  tag          = $tag"
        echo "  commit       = $sha"
        echo "  tree         = $tree"
        echo "  arquivo      = $(basename "$tarball")  ($size)"
        echo "  sha256       = $sum"
        echo
    } >> "$MANIFEST"

    echo "  $name  $tag  $short  ($size)"

done < <(git submodule status | sed 's/^[-+U ]//')

if [ "$fails" -gt 0 ]; then
    echo "=== $fails submodulo(s) sujo(s) -- espelho incompleto" >&2
    exit 1
fi

echo
echo "=== espelho em $OUT"
echo "=== manifesto: $MANIFEST"
echo
echo "Copie para armazenamento OFFLINE. Restaurar a partir do tarball:"
echo "  tar xzf <arquivo>.tar.gz"
echo "  sha256sum -c  # conferir contra o manifesto antes de usar"
