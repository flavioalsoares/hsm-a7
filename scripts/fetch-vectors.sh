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

# CMAC -- fase 3. E ele que deriva KBEK/KBAK da LMK e autentica o key block,
# entao um erro aqui nao aparece como "MAC errado": aparece como key block
# que nao importa em lugar nenhum, ou pior, que importa onde nao devia.
CMAC_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/cmactestvectors.zip"
CMAC_SHA="bdda4edade394c9a2ae74d9cd0921caa120c911a5e735e37abf39d0d5f062be1"

# RSA -- fase 7. Assinatura PKCS#1 v1.5 do FIPS 186-3.
RSA_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip"
RSA_SHA="8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c"

# ECDSA -- fase 7. Curva P-256 com SHA-256, do FIPS 186-4.
ECDSA_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip"
ECDSA_SHA="fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752"

# X9.143 / TR-31 versao D -- LEIA O MANIFEST ANTES DE CONFIAR NESTE.
#
# Nao e vetor do CAVP e nao ha como ser: o CAVP valida ALGORITMO, e
# X9.143 e FORMATO. A norma que traz o exemplo e paga. Este vem do
# arquivo de testes da biblioteca psec (MIT), da funcao que o autor
# chama de "known values from 3rd parties" -- fonte secundaria, fixada
# por commit e por hash, e nada alem disso.
#
# Fixado por COMMIT de proposito: `master` e alvo movel, e um vetor cujo
# hash muda sozinho nao e vetor, e uma expectativa.
TR31_URL="https://raw.githubusercontent.com/knovichikhin/psec/cb315e98d4399207f54da42282654d840fe3bb82/tests/test_tr31.py"
TR31_SHA="e1f42adaed9e2335dc837ba3278310bec0e9a9b2238ec7b38c87c0516addf491"

# TDES (3DES): os KATs da SP 800-20 e os testes de varias mensagens (MMT),
# do CAVP. Entram na fase 8. Nos KATs as tres chaves sao iguais (KEYs), e o
# que se testa e o DES; os MMT2 tem duas chaves e os MMT3, tres.
TDES_KAT_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/KAT_TDES.zip"
TDES_KAT_SHA="19d8841f84ae3415350b069a4768bd416c05a0533ee43e905ab099adb8ccb374"
TDES_MMT_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/tdesmmt.zip"
TDES_MMT_SHA="04db93728ebf994330b0ba4555d397f8f03c29fd8547d9d586219fabe00e8c78"

# PIN block ISO 9564-1 formato 4: a norma e paga, e nao ha vetor oficial
# publico. Valores do arquivo de testes da mesma biblioteca, fixados por
# commit e por hash. Fonte secundaria, como a do key block.
PIN_URL="https://raw.githubusercontent.com/knovichikhin/psec/90ccbf3ae0ef15527751ac225668ed31ef756a16/tests/test_pinblock.py"
PIN_SHA="6d1880ab9cfdee975452de6905c5172465ee5ea89a528450dfb3e88b1685667e"

# Verificacao de PIN, offset e PVV: os metodos estao em norma paga e em
# documentacao de bandeira. Valores do arquivo de testes da mesma biblioteca,
# no mesmo commit. Fonte secundaria.
PINV_URL="https://raw.githubusercontent.com/knovichikhin/psec/90ccbf3ae0ef15527751ac225668ed31ef756a16/tests/test_pin.py"
PINV_SHA="4abfa08f7934fdba39b3182bd8ac3f183f546bede28b317dec2e1eb75b1e2938"

# CVV, CVV2 e iCVV: o metodo esta em documentacao de bandeira, sem vetor
# oficial publico. Sete valores de TRES fontes independentes, cada arquivo
# fixado por commit e por hash. Fonte secundaria. Ver o MANIFEST.
#   psec (MIT): o teste e o exemplo da documentacao da funcao
CVV_PSEC_T_URL="https://raw.githubusercontent.com/knovichikhin/psec/90ccbf3ae0ef15527751ac225668ed31ef756a16/tests/test_cvv.py"
CVV_PSEC_T_SHA="c376802d0ca558952c04b85372fff96206b74c8b2b53713cb5c487a5d63310b4"
CVV_PSEC_D_URL="https://raw.githubusercontent.com/knovichikhin/psec/90ccbf3ae0ef15527751ac225668ed31ef756a16/psec/cvv.py"
CVV_PSEC_D_SHA="da57b3a769877f81ce82530b1554c47c4720e41d6cddd59983b12128617fcc5f"
#   jPOS (AGPL): o teste do modulo de seguranca em software
CVV_JPOS_URL="https://raw.githubusercontent.com/jpos/jPOS/71a6ccbd006432010e3c61ec8e1583c2c0eebca5/jpos/src/test/java/org/jpos/security/jceadapter/JCESecurityModuleTest.java"
CVV_JPOS_SHA="697bca950f02b1f3561d149c87dc253296ca2b0951affe9fbc1f4590ab686fe6"
#   jmeter-iso8583 (MIT): o teste e a classe base, que tem a chave
CVV_JM_T_URL="https://raw.githubusercontent.com/tilln/jmeter-iso8583/b90aaecfa532e2e662404f7018218fdbb9c294aa/src/test/java/nz/co/breakpoint/jmeter/iso8583/CalculateCVVFunctionTest.java"
CVV_JM_T_SHA="e9e12d5fa710353dfa2c61a75ade0a3e2a6045b523a89fb176f5c126ae2ab3d6"
CVV_JM_B_URL="https://raw.githubusercontent.com/tilln/jmeter-iso8583/b90aaecfa532e2e662404f7018218fdbb9c294aa/src/test/java/nz/co/breakpoint/jmeter/iso8583/ISO8583TestBase.java"
CVV_JM_B_SHA="76934fc3951901d2666848bb06d0540b09d6b1f523489ed1b23974feb765263a"

# X9.143 / TR-31 versao B (KBPK 3DES) -- fase 8, etapa 8.7. Valores conhecidos
# de TERCEIROS, do mesmo arquivo de testes do psec, num commit mais novo que o
# do vetor da versao D (o mesmo dos vetores de PIN e de CVV).
TR31B_URL="https://raw.githubusercontent.com/knovichikhin/psec/90ccbf3ae0ef15527751ac225668ed31ef756a16/tests/test_tr31.py"
TR31B_SHA="e1f42adaed9e2335dc837ba3278310bec0e9a9b2238ec7b38c87c0516addf491"

# DUKPT TDES (X9.24-1:2009, anexo A.4) -- fase 8, etapa 8.8a. Valores de
# TERCEIROS: o arquivo de testes do projeto openemv/dukpt (LGPL-2.1), que os
# transcreve da norma. Decisao do usuario em 2026-11-22: uma fonte basta.
DUKPT_TDES_URL="https://raw.githubusercontent.com/openemv/dukpt/0a1ac4f66106af2b25dafeebf7c2d6b4dcb92b2a/test/dukpt_tdes_test.c"
DUKPT_TDES_SHA="469cbcb0bfb2b20023adf063b15af488c47fd21e9b8dc31b738f89800b05b2a3"
# DUKPT AES (suplemento de vetores da X9.24-3:2017) -- etapa 8.8b. Mesma fonte e
# mesmo commit: BDK AES-128 e BDK AES-256.
DUKPT_AES128_URL="https://raw.githubusercontent.com/openemv/dukpt/0a1ac4f66106af2b25dafeebf7c2d6b4dcb92b2a/test/dukpt_aes128_test.c"
DUKPT_AES128_SHA="c23f8d711cd7c7bf1fa9397ae7cc7e6ba4f39222c6e6961d685161e417c71d2f"
DUKPT_AES256_URL="https://raw.githubusercontent.com/openemv/dukpt/0a1ac4f66106af2b25dafeebf7c2d6b4dcb92b2a/test/dukpt_aes256_test.c"
DUKPT_AES256_SHA="f8ba32d73aa16e2b5c20a50a27ff3538fb71b23e9e5fa27dd13b1c4af6fcea04"

# Retail MAC (ISO/IEC 9797-1 algoritmo 3, X9.19) -- fase 8, etapa 8.9a. Sem vetor
# oficial publico. Duas fontes independentes (decisao do usuario, 2026-11-23):
#   psec (MIT), o teste da funcao, no mesmo commit do CVV
RMAC_PSEC_URL="https://raw.githubusercontent.com/knovichikhin/psec/90ccbf3ae0ef15527751ac225668ed31ef756a16/tests/test_mac.py"
RMAC_PSEC_SHA="d5c36aa09db80492434d4021d544c17304b017c3e7cc4fc19936b824eacfb518"
#   RustCrypto retail-mac (MIT/Apache-2.0), o exemplo da ISO/IEC 9797-1:2011 B.4
RMAC_RUST_URL="https://raw.githubusercontent.com/RustCrypto/MACs/753c4b6c040989f3f68672991fe7c87cf528f564/retail-mac/README.md"
RMAC_RUST_SHA="9209750f7280b7c164b46ed7e111758064083ee9c75d817a1e557d34ed84fac7"

# DUKPT, MAC e dados (etapa 8.9b). Duas fontes: os mesmos arquivos do openemv/dukpt
# (acima) e o moov-io/dukpt (Apache-2.0). As respostas (dados TDES, CMAC e dados
# AES de uso 2001/3001) so o moov-io traz: fonte unica, decisao do usuario
# (2026-11-23).
DUKPT_MOOV_DES_URL="https://raw.githubusercontent.com/moov-io/dukpt/f7749173f1b84d51be6dfc140b8be006d66a56a9/pkg/des/des_test.go"
DUKPT_MOOV_DES_SHA="885221afbf2c97bdfa9c80a467c78127c1fdc6f13c946b0ad364e2bd3df46285"
DUKPT_MOOV_AES_URL="https://raw.githubusercontent.com/moov-io/dukpt/f7749173f1b84d51be6dfc140b8be006d66a56a9/pkg/aes/aes_test.go"
DUKPT_MOOV_AES_SHA="1efb54a00a385ca8e0bc5aa24c63ab4a5bfa35fa1a6179a9b2aed633831b4979"

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

mkdir -p "$TMP" "$VEC"/{aes,sha,hmac,drbg,cmac,tr31,rsa,ecdsa,pinblock,pinverif,cvv,tdes,dukpt,mac}

echo "=== baixando"
fetch "$AES_URL"  "$AES_SHA"  "$TMP/KAT_AES.zip"
fetch "$SHA_URL"  "$SHA_SHA"  "$TMP/shabytetestvectors.zip"
fetch "$HMAC_URL" "$HMAC_SHA" "$TMP/rfc4231.txt"
fetch "$DRBG_URL" "$DRBG_SHA" "$TMP/drbgtestvectors.zip"
fetch "$CMAC_URL" "$CMAC_SHA" "$TMP/cmactestvectors.zip"
fetch "$TR31_URL" "$TR31_SHA" "$TMP/psec_test_tr31.py"
fetch "$TR31B_URL" "$TR31B_SHA" "$TMP/psec_test_tr31_b.py"
fetch "$PIN_URL" "$PIN_SHA" "$TMP/psec_test_pinblock.py"
fetch "$PINV_URL" "$PINV_SHA" "$TMP/psec_test_pin.py"
fetch "$CVV_PSEC_T_URL" "$CVV_PSEC_T_SHA" "$TMP/psec_test_cvv.py"
fetch "$CVV_PSEC_D_URL" "$CVV_PSEC_D_SHA" "$TMP/psec_cvv.py"
fetch "$CVV_JPOS_URL" "$CVV_JPOS_SHA" "$TMP/jpos_JCESecurityModuleTest.java"
fetch "$CVV_JM_T_URL" "$CVV_JM_T_SHA" "$TMP/jm_CalculateCVVFunctionTest.java"
fetch "$CVV_JM_B_URL" "$CVV_JM_B_SHA" "$TMP/jm_ISO8583TestBase.java"
fetch "$DUKPT_TDES_URL" "$DUKPT_TDES_SHA" "$TMP/openemv_dukpt_tdes_test.c"
fetch "$DUKPT_AES128_URL" "$DUKPT_AES128_SHA" "$TMP/openemv_dukpt_aes128_test.c"
fetch "$DUKPT_AES256_URL" "$DUKPT_AES256_SHA" "$TMP/openemv_dukpt_aes256_test.c"
fetch "$RMAC_PSEC_URL" "$RMAC_PSEC_SHA" "$TMP/psec_test_mac.py"
fetch "$RMAC_RUST_URL" "$RMAC_RUST_SHA" "$TMP/rustcrypto_retail_mac_README.md"
fetch "$DUKPT_MOOV_DES_URL" "$DUKPT_MOOV_DES_SHA" "$TMP/moov_des_test.go"
fetch "$DUKPT_MOOV_AES_URL" "$DUKPT_MOOV_AES_SHA" "$TMP/moov_aes_test.go"
fetch "$TDES_KAT_URL" "$TDES_KAT_SHA" "$TMP/KAT_TDES.zip"
fetch "$TDES_MMT_URL" "$TDES_MMT_SHA" "$TMP/tdesmmt.zip"
fetch "$RSA_URL" "$RSA_SHA" "$TMP/186-3rsatestvectors.zip"
fetch "$ECDSA_URL" "$ECDSA_SHA" "$TMP/186-4ecdsatestvectors.zip"

echo "=== extraindo"
unzip -qo "$TMP/KAT_AES.zip" 'ECB*256.rsp' 'CBC*256.rsp' -d "$VEC/aes/"
# Etapa 8.8b: o AES-128 em software, so para o DUKPT AES. So ECB, do mesmo zip.
unzip -qo "$TMP/KAT_AES.zip" 'ECB*128.rsp' -d "$VEC/aes/"
unzip -qjo "$TMP/shabytetestvectors.zip" \
      'shabytetestvectors/SHA256ShortMsg.rsp' \
      'shabytetestvectors/SHA256LongMsg.rsp' -d "$VEC/sha/"
cp "$TMP/rfc4231.txt" "$VEC/hmac/"

# CMAC: a geracao com AES-256 e, desde a etapa 8.7, com 3DES de duas e de tres
# chaves (o key block versao B). O resto do zip (AES-128/192 e a verificacao)
# este projeto nao usa.
mkdir -p "$VEC/cmac"
unzip -qjo "$TMP/cmactestvectors.zip" 'CMACGenAES256.rsp' \
      'CMACGenTDES2.rsp' 'CMACGenTDES3.rsp' -d "$VEC/cmac/"

# RSA: SigGen15 vem duas vezes -- o .txt e o .rsp mais o expoente privado d,
# que o KAT de assinatura precisa. A geracao PKCS#1 v1.5 e as chaves completas (p, q, d) da geracao de
# chave por primos provaveis, mais o KAT de primalidade dela. O resto do zip
# (PSS, X9.31, as chaves de 3072) nao e usado.
mkdir -p "$VEC/rsa"
unzip -qjo "$TMP/186-3rsatestvectors.zip" 'SigGen15_186-3.rsp' \
      'SigGen15_186-3.txt' \
      'KeyGen_RandomProbablyPrime3_3.rsp' \
      'KeyGen_186-3_RandomProbablyPrime3_3_KAT.txt' -d "$VEC/rsa/"

# ECDSA: so a curva P-256 e, onde ha hash, o SHA-256. O zip tem 15 curvas e
# 5 hashes. SigGen.txt e o que traz `d` e `k`; o .rsp so tem a chave publica.
mkdir -p "$VEC/ecdsa" "$TMP/ecdsa"
unzip -qjo "$TMP/186-4ecdsatestvectors.zip" \
      '186-4ecdsatestvectors/KeyPair.rsp' '186-4ecdsatestvectors/PKV.rsp' \
      '186-4ecdsatestvectors/SigGen.txt' '186-4ecdsatestvectors/SigVer.rsp' \
      -d "$TMP/ecdsa/"
for f in KeyPair.rsp PKV.rsp SigGen.txt SigVer.rsp; do
    python3 "$ROOT/scripts/_filtra_ecdsa.py" "$TMP/ecdsa/$f" "$VEC/ecdsa/${f%.*}_P256.${f##*.}"
done

# X9.143: um vetor so, copiado literalmente da tupla do arquivo de
# origem. A extracao e mecanica e falha se achar numero diferente de um.
python3 "$ROOT/scripts/_extrai_tr31b.py" \
        "$TMP/psec_test_tr31_b.py" "$VEC/tr31/x9143_B_TDES.rsp"
python3 "$ROOT/scripts/_extrai_tr31.py" \
        "$TMP/psec_test_tr31.py" "$VEC/tr31/x9143_D_AES256.rsp"

# TDES: so os modos ECB e CBC. Os zips trazem tambem CFB e OFB, que este
# projeto nao usa.
unzip -qjo "$TMP/KAT_TDES.zip" 'KAT_TDES/TECB*.rsp' \
      'KAT_TDES/TCBCinvperm.rsp' 'KAT_TDES/TCBCpermop.rsp' \
      'KAT_TDES/TCBCsubtab.rsp' 'KAT_TDES/TCBCvarkey.rsp' \
      'KAT_TDES/TCBCvartext.rsp' -d "$VEC/tdes/"
unzip -qjo "$TMP/tdesmmt.zip" 'TECBMMT2.rsp' 'TECBMMT3.rsp' \
      'TCBCMMT2.rsp' 'TCBCMMT3.rsp' -d "$VEC/tdes/"

# PIN block, formatos 4 e 0: valores copiados literalmente. A extracao
# falha se o arquivo de origem nao tiver exatamente um de cada.
python3 "$ROOT/scripts/_extrai_pinblock.py" \
        "$TMP/psec_test_pinblock.py" "$VEC/pinblock/iso9564_f4.rsp" \
        "$VEC/pinblock/iso9564_f0.rsp"

# Verificacao de PIN: 24 valores copiados literalmente.
python3 "$ROOT/scripts/_extrai_pinverif.py" \
        "$TMP/psec_test_pin.py" "$VEC/pinverif/psec_pin.rsp"

# CVV: 7 valores de 3 fontes, copiados literalmente. A extracao falha se
# alguma fonte nao tiver exatamente a quantidade esperada.
python3 "$ROOT/scripts/_extrai_cvv.py" "$TMP" "$VEC/cvv/cvv.rsp"

# DUKPT TDES: IPEK e 34 transacoes, copiadas literalmente. A extracao falha
# se algum vetor faltar ou tiver o tamanho errado.
python3 "$ROOT/scripts/_extrai_dukpt_tdes.py" \
        "$TMP/openemv_dukpt_tdes_test.c" "$VEC/dukpt/x924_1_tdes.rsp"
# DUKPT AES: chave inicial e 15 transacoes de cada arquivo. As linhas
# comentadas no arquivo de origem nao entram.
python3 "$ROOT/scripts/_extrai_dukpt_aes.py" \
        "$TMP/openemv_dukpt_aes128_test.c" "$VEC/dukpt/x924_3_aes128.rsp" 128
python3 "$ROOT/scripts/_extrai_dukpt_aes.py" \
        "$TMP/openemv_dukpt_aes256_test.c" "$VEC/dukpt/x924_3_aes256.rsp" 256

# DUKPT, MAC e dados: 63 transacoes de 2 fontes, copiadas literalmente.
python3 "$ROOT/scripts/_extrai_dukpt_mac.py" "$TMP" "$VEC/dukpt/dukpt_mac_dados.rsp"

# Retail MAC: 6 valores de 2 fontes, copiados literalmente. A extracao falha se
# alguma fonte nao tiver exatamente a quantidade esperada.
python3 "$ROOT/scripts/_extrai_retail_mac.py" "$TMP" "$VEC/mac/retail_mac.rsp"

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
