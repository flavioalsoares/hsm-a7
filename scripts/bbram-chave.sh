#!/usr/bin/env bash
# Cria a chave do bitstream cifrado, se ainda nao existir. Nao sobrescreve:
# trocar a chave invalida todo bitstream ja cifrado com ela.
set -euo pipefail
cd "$(dirname "$0")/.."
K=build/chave/bitstream.nky
if [ -e "$K" ]; then echo "chave ja existe: $K"; exit 0; fi
mkdir -p build/chave
chmod 700 build/chave
umask 077
h() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }
printf 'Device xc7a35t;\nKey 0 %s;\nKey StartCBC %s;\nKey HMAC %s;\n' \
    "$(h 32)" "$(h 16)" "$(h 32)" > "$K"
echo "chave criada: $K"
