#!/usr/bin/env bash
#
# Baixa os vetores KAT das fontes oficiais, confere hash e extrai.
#
#   ./scripts/fetch-vectors.sh            # baixa e extrai
#   ./scripts/fetch-vectors.sh --check    # so confere o que ja esta no repo
#
# Os vetores JA ESTAO versionados em vectors/. Este script existe para
# reproduzir e para auditar: qualquer um pode rodar e confirmar que os
# numeros no repositorio sao os do NIST e da IETF, e nao algo que alguem
# digitou.
#
# Regra do projeto (CLAUDE.md): nao escrever vetores "de memoria". Se um
# KAT falha, o bug esta no codigo, nao no vetor -- e isso so vale se a
# procedencia do vetor for verificavel.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VEC="$ROOT/vectors"
TMP="$ROOT/build/vectors"

# url  sha256-do-arquivo-baixado
AES_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip"
AES_SHA="a203b16c9246b2ebae31dee5de21a606be80cf78ceabaca37150236fa098eb60"

SHA_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip"
SHA_SHA="929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8"

HMAC_URL="https://www.rfc-editor.org/rfc/rfc4231.txt"
HMAC_SHA="72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b"

DRBG_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip"
DRBG_SHA="5f7e5658ebd5b4e6785a7b12fa32333511d2acc2f2d9c5ae1ffa16b699377769"

# ---------------------------------------------------------------------

check_repo() {
    echo "=== conferindo vectors/ contra o MANIFEST"
    cd "$VEC"
    if grep -E '^[0-9a-f]{64}  ' MANIFEST.txt | sha256sum -c --quiet; then
        echo "    OK -- todos os vetores conferem"
        return 0
    fi
    echo "    FALHOU -- algum vetor foi alterado" >&2
    return 1
}

if [ "${1:-}" = "--check" ]; then
    check_repo
    exit $?
fi

fetch() {
    local url="$1" want="$2" dest="$3"
    if [ -f "$dest" ] && [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$want" ]; then
        echo "    (cache) $(basename "$dest")"
        return 0
    fi
    echo "    baixando $(basename "$dest")"
    curl -sSLf -o "$dest" "$url"
    local got
    got="$(sha256sum "$dest" | cut -d' ' -f1)"
    if [ "$got" != "$want" ]; then
        echo "ERRO: hash nao confere para $url" >&2
        echo "      esperado $want" >&2
        echo "      obtido   $got" >&2
        echo "      NAO usar este arquivo." >&2
        rm -f "$dest"
        exit 1
    fi
}

mkdir -p "$TMP" "$VEC"/{aes,sha,hmac,drbg}

echo "=== baixando"
fetch "$AES_URL"  "$AES_SHA"  "$TMP/KAT_AES.zip"
fetch "$SHA_URL"  "$SHA_SHA"  "$TMP/shabytetestvectors.zip"
fetch "$HMAC_URL" "$HMAC_SHA" "$TMP/rfc4231.txt"
fetch "$DRBG_URL" "$DRBG_SHA" "$TMP/drbgtestvectors.zip"

echo "=== extraindo"
unzip -qo "$TMP/KAT_AES.zip" 'ECB*256.rsp' 'CBC*256.rsp' -d "$VEC/aes/"
unzip -qjo "$TMP/shabytetestvectors.zip" \
      'shabytetestvectors/SHA256ShortMsg.rsp' \
      'shabytetestvectors/SHA256LongMsg.rsp' -d "$VEC/sha/"
cp "$TMP/rfc4231.txt" "$VEC/hmac/"

# CTR_DRBG vem num zip dentro do zip, e o arquivo completo tem 785 KB com
# 3DES e AES-128/192 que este projeto nao usa. Filtra para [AES-256 ...].
unzip -qo "$TMP/drbgtestvectors.zip" 'drbgvectors_no_reseed.zip' -d "$TMP/"
unzip -qjo "$TMP/drbgvectors_no_reseed.zip" 'CTR_DRBG.rsp' -d "$TMP/"

python3 - "$TMP/CTR_DRBG.rsp" "$VEC/drbg/CTR_DRBG_AES256.rsp" <<'PY'
import re, sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text()
out, keep, header = [], False, True
for ln in src.splitlines(keepends=True):
    if ln.startswith('#') and header:
        out.append(ln); continue
    header = False
    m = re.match(r'^\[(\S+)\s+(use df|no df)\]', ln)
    if m:
        keep = (m.group(1) == 'AES-256')
    if keep:
        out.append(ln)
pathlib.Path(sys.argv[2]).write_text(''.join(out))
PY

echo
check_repo
