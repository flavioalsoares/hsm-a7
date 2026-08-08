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

# Clock do JTAG. O padrao do openFPGALoader e 6 MHz e o cabo flat desta
# bancada nao aguenta: a leitura do IDCODE passa (poucos bits), mas a
# transferencia de 1,25 MB chega com CRC Error e deixa o FPGA em branco.
# A 1 MHz passa. Gravar leva ~12 s em vez de ~2 s, o que e irrelevante
# perto de depurar um FPGA em branco.
#
# Com cabo bom da para subir: CABLE_FREQ=6000000 ./scripts/program.sh
CABLE_FREQ="${CABLE_FREQ:-1000000}"
# Sobrescritivel para o bitstream de diagnostico de bancada:
#   BIT=build/hsm_diag.bit ./scripts/program.sh
BIT="${BIT:-build/hsm_top.bit}"
BIN="build/hsm_top.bin"
FPGA_PART="xc7a35tftg256"

if ! command -v openFPGALoader >/dev/null 2>&1; then
    echo "ERRO: openFPGALoader nao encontrado." >&2
    echo "      sudo apt install -y openfpgaloader" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# CUIDADO com grep sobre a saida do openFPGALoader.
#
# Ela contem bytes NUL (na linha de frequencia). O grep desta maquina e o
# ugrep, que classifica entrada com NUL como binaria e faz '-q' devolver
# "nao encontrei" mesmo havendo casamento -- diferente do GNU grep. O
# resultado sao falsos "nenhum FPGA na cadeia JTAG" com o link perfeito,
# que ja custou tempo de diagnostico na bancada.
#
# Por isso todo filtro sobre essa saida passa por 'tr -d "\0"' antes.
# Nao trocar por 'grep -a': depende de qual grep esta instalado, e a
# limpeza explicita funciona nos dois.
# ---------------------------------------------------------------------
det() { openFPGALoader -c "$CABLE" --freq "$CABLE_FREQ" --detect 2>&1 | tr -d '\0'; }

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

if ! det | grep -qi 'xc7a35t\|idcode'; then
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

# --- o link esta ESTAVEL, e nao so vivo? ----------------------------
#
# Um --detect que passa prova que o link funciona AGORA, para poucos bits.
# A gravacao empurra 1,25 MB. Mau contato no cabo flat de 6 pinos degrada a
# segunda muito antes de impedir a primeira -- foi assim que um bitstream
# chegou com CRC Error e deixou o FPGA em branco (doc/fase2-notas.md).
#
# Custa ~5 s e evita apagar a configuracao sem conseguir carregar a nova.
# Preferir recusar a gravar por cima de um link duvidoso: aqui, falhar
# antes de comecar e melhor do que falhar no meio.
STABILITY_TRIES="${STABILITY_TRIES:-5}"
echo "Conferindo estabilidade do link JTAG ($STABILITY_TRIES leituras)..."
falhas=0
for _ in $(seq 1 "$STABILITY_TRIES"); do
    if ! det | grep -q 'idcode'; then
        falhas=$((falhas + 1))
    fi
done

if [ "$falhas" -gt 0 ]; then
    echo >&2
    echo "ERRO: link JTAG instavel -- $falhas de $STABILITY_TRIES leituras falharam." >&2
    echo "      NAO vou gravar: comecar e falhar no meio deixa o FPGA em branco." >&2
    echo >&2
    echo "  Causa mais comum nesta bancada: mau contato no cabo flat de 6" >&2
    echo "  pinos. Sintoma que confirma: mexer no cabo com a mao muda o LED" >&2
    echo "  do adaptador. Reencaixar as duas pontas, conferindo a orientacao." >&2
    echo >&2
    echo "  Se a cadeia vier VAZIA e baixar a frequencia nao ajudar" >&2
    echo "  ('--freq 500000'), o problema e conexao, nao integridade de" >&2
    echo "  sinal -- sinal ruim melhora com clock menor, fio solto nao." >&2
    exit 1
fi
echo "  $STABILITY_TRIES de $STABILITY_TRIES -- link estavel."
echo

case "${1:-ram}" in
    ram)
        [ -f "$BIT" ] || {
            echo "ERRO: $BIT nao existe -- rode o build antes:" >&2
            echo "      make -C fw image && vivado -mode batch -source scripts/build.tcl" >&2
            exit 1; }

        echo "Gravando $BIT na RAM de configuracao (volatil, cabo: $CABLE @ $CABLE_FREQ Hz)..."
        echo "Some no power-off. E o modo certo para bring-up."
        openFPGALoader -c "$CABLE" --freq "$CABLE_FREQ" "$BIT"
        ;;

    flash)
        [ -f "$BIN" ] || {
            echo "ERRO: $BIN nao existe." >&2
            echo "      Gere com: write_cfgmem no Vivado, ou use o modo 'ram'." >&2
            exit 1; }

        echo "Gravando $BIN na SPI flash (PERSISTENTE, cabo: $CABLE)..."
        echo "A placa passara a carregar este bitstream a cada power-on."
        openFPGALoader -c "$CABLE" --freq "$CABLE_FREQ" -f --fpga-part "$FPGA_PART" "$BIN"
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
stat="$(openFPGALoader -c "$CABLE" --freq "$CABLE_FREQ" --read-register STAT 2>&1 | tr -d '\0' || true)"

# CUIDADO: a linha e "CRC Error       No CRC error" quando esta tudo bem.
# Um 'grep -i "CRC error"' casa com o ROTULO e dispara sempre -- foi um
# falso positivo que ja abortou uma gravacao bem-sucedida aqui. O padrao
# tem de ancorar no VALOR, nao no rotulo.
if echo "$stat" | grep -qE '^CRC Error[[:space:]]+CRC error'; then
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
