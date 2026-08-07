#!/usr/bin/env bash
#
# Grava o bitstream na placa QMTECH Artix-7.
#
#   ./scripts/program.sh          # volatil: RAM de configuracao do FPGA
#   ./scripts/program.sh flash    # persistente: SPI flash MT25QL128
#
# ---------------------------------------------------------------------
# PROIBIDO NESTE PROJETO -- ver PLANO.md secao 0
#
# Nenhuma operacao de eFUSE, em nenhuma circunstancia: program_efuse,
# CFG_AES_ONLY, W_DIS/R_DIS, qualquer flag -efuse. Sao OTP e o erro e um
# brick permanente. Se algum tutorial mandar queimar fusivel, o tutorial e
# lido, documentado e NAO executado.
#
# Chave de bitstream, quando existir (fase 6), so em BBRAM -- que nesta
# placa se perde no power-off, porque VCCBATT (F8) esta ligado ao rail 1V8
# e nao ha bateria. Isso e desejavel aqui: nada persiste no hardware.
#
# openFPGALoader nao faz eFUSE por acidente; o modo padrao e SRAM. Este
# script nunca passa opcao que mude isso.
# ---------------------------------------------------------------------
#
# Adaptador JTAG: caixa marcada "Xilinx DLC9LP", mas o clone traz um FTDI
# FT232H que se apresenta como Digilent (0403:6014). Perfil correto:
# digilent_hs2 -- validado no projeto irmao msxinart, mesma placa e mesmo
# cabo (XC7A35T detectado, idcode 0x362d093).
#
set -euo pipefail

cd "$(dirname "$0")/.."

CABLE="${CABLE:-digilent_hs2}"
BIT="build/hsm_top.bit"
BIN="build/hsm_top.bin"
FPGA_PART="xc7a35tftg256"

if ! command -v openFPGALoader >/dev/null 2>&1; then
    echo "ERRO: openFPGALoader nao encontrado." >&2
    echo "      sudo apt install -y openfpgaloader" >&2
    exit 1
fi

# --- preflight ------------------------------------------------------
#
# Duas checagens, e a segunda e a que importa. Ver o adaptador no USB NAO
# significa que a placa esta la: o FT232H e alimentado pelo PC e enumera
# sozinho, com a placa desligada. Quem responde a pergunta certa e o
# --detect, que le o IDCODE pela cadeia JTAG.

if ! lsusb 2>/dev/null | grep -q '0403:6014'; then
    echo "ERRO: adaptador JTAG nao encontrado no USB (esperado 0403:6014)." >&2
    echo "      O cabo 'DLC9LP' e um FT232H; confira se esta plugado no PC." >&2
    exit 1
fi

if ! openFPGALoader -c "$CABLE" --detect 2>&1 | grep -qi 'xc7a35t\|idcode'; then
    echo "ERRO: adaptador presente, mas nenhum FPGA na cadeia JTAG." >&2
    echo >&2
    echo "  O adaptador abriu normalmente -- o problema esta do lado da placa:" >&2
    echo "    - placa sem alimentacao (o JTAG NAO alimenta a placa)" >&2
    echo "    - cabo flat solto ou invertido no header de 6 pinos" >&2
    echo >&2
    echo "  Sinal util: com a placa alimentada pela USB, o CP2102 do core" >&2
    echo "  board aparece como 10c4:ea60 e cria outra /dev/ttyUSB*." >&2
    if lsusb 2>/dev/null | grep -q '10c4:ea60'; then
        echo "  Agora: CP2102 PRESENTE (placa alimentada) -- suspeitar do cabo flat." >&2
    else
        echo "  Agora: CP2102 AUSENTE -- a placa provavelmente esta sem alimentacao." >&2
    fi
    echo >&2
    echo "  Se a placa estiver ligada e ainda falhar, pode ser o driver" >&2
    echo "  ftdi_sio prendendo a interface do FT232H:" >&2
    echo "    sudo modprobe -r ftdi_sio" >&2
    exit 1
fi

case "${1:-ram}" in
    ram)
        [ -f "$BIT" ] || {
            echo "ERRO: $BIT nao existe -- rode o build antes:" >&2
            echo "      make -C fw image && vivado -mode batch -source scripts/build.tcl" >&2
            exit 1; }

        echo "Gravando $BIT na RAM de configuracao (volatil, cabo: $CABLE)..."
        echo "Some no power-off. E o modo certo para bring-up."
        openFPGALoader -c "$CABLE" "$BIT"
        ;;

    flash)
        [ -f "$BIN" ] || {
            echo "ERRO: $BIN nao existe." >&2
            echo "      Gere com: write_cfgmem no Vivado, ou use o modo 'ram'." >&2
            exit 1; }

        echo "Gravando $BIN na SPI flash (PERSISTENTE, cabo: $CABLE)..."
        echo "A placa passara a carregar este bitstream a cada power-on."
        openFPGALoader -c "$CABLE" -f --fpga-part "$FPGA_PART" "$BIN"
        ;;

    *)
        echo "Uso: $0 [ram|flash]" >&2
        exit 2
        ;;
esac

# --- verificacao: DONE subiu? --------------------------------------
#
# O openFPGALoader termina com status 0 mesmo quando a configuracao NAO
# completa. Ja aconteceu aqui: link USB instavel corrompeu o bitstream em
# transito, o comando disse "Pronto", e o FPGA ficou EM BRANCO -- a
# sequencia JTAG apaga a memoria de configuracao antes de carregar, entao
# uma falha no meio deixa menos do que havia antes.
#
# O sintoma na bancada e cruel de diagnosticar: todos os LEDs apagados
# (sao ativos em nivel baixo, e pino sem projeto fica em pull-up) e o
# dispositivo mudo na serial. Parece firmware travado. Nao e -- nao ha
# firmware.
#
# STAT e o registro de status de configuracao do 7-series. Interessam:
#   Done       1 = configuracao completa, projeto rodando
#   CRC Error  bitstream chegou corrompido -> link, nao arquivo
echo
echo "Conferindo o registro de status da configuracao..."
stat="$(openFPGALoader -c "$CABLE" --read-register STAT 2>&1 || true)"

if echo "$stat" | grep -qi 'CRC error'; then
    echo >&2
    echo "ERRO: CRC Error no bitstream. O FPGA esta EM BRANCO." >&2
    echo >&2
    echo "  Os bytes se corromperam a caminho do FPGA. O arquivo em disco" >&2
    echo "  esta bom -- o problema e o link JTAG." >&2
    echo >&2
    echo "  Causa mais comum aqui: adaptador JTAG num hub USB. O FT232H em" >&2
    echo "  modo MPSSE faz milhares de transferencias pequenas para empurrar" >&2
    echo "  1,25 MB; hub encadeado, ou dividido com a USB da placa, acrescenta" >&2
    echo "  latencia e disputa de corrente. Ligar o JTAG direto numa porta da" >&2
    echo "  placa-mae resolve." >&2
    echo >&2
    echo "  Sinal de confirmacao: o numero do Device em 'lsusb' mudando" >&2
    echo "  sozinho e re-enumeracao." >&2
    exit 1
fi

if ! echo "$stat" | grep -qE '^Done +0x1'; then
    echo >&2
    echo "ERRO: DONE nao subiu. A configuracao nao completou e o FPGA" >&2
    echo "      esta EM BRANCO (a memoria de configuracao ja foi apagada)." >&2
    echo >&2
    echo "$stat" | grep -E '^(Done|EOS|INIT Complete|ID Error|MMCM lock)' >&2
    exit 1
fi

echo "  Done = 0x1, sem CRC error -- configuracao completa."
echo
echo "Pronto. Verificacao, em ordem de custo:"
echo "  1. D1 piscando a 1 Hz      -> MMCM travado, dominio de 100 MHz vivo"
echo "  2. D2 aceso                -> main() chegou ao laco de comandos"
echo "  3. python3 host/hsmtool.py ping"
echo "  4. python3 host/hsmtool.py dna"
echo
echo "O dispositivo e mudo ate ser perguntado: terminal aberto nao mostra"
echo "nada, e isso e o comportamento correto."
