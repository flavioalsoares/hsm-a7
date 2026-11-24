#!/usr/bin/env python3
"""SHA-256 da memoria de codigo, como o GET_BUILD o calcula no equipamento.

A IMEM tem 128 KB, e o hash e sobre os 128 KB inteiros. Mas a ROM fisica
NAO tem 128 KB: o NEORV32 (neorv32_imem_rom.vhd, v1.13.3) a dimensiona pela
IMAGEM, arredondada para a potencia de 2 de cima, e decodifica so os bits de
endereco dela. O resto do espaco da IMEM espelha a ROM. Com 62 788 bytes de
firmware, a ROM tem 64 KB, e os enderecos de 64 KB a 128 KB leem a imagem de
novo. Este modelo repete isso: imagem, zeros ate a potencia de 2, e a
repeticao ate os 128 KB. Achado em 2026-11-24, quando o tb_uart_frame acusou
o hash da IMEM de 128 KB.

    mkfwhash.py              imprime o hash de fw/elf.bin
    mkfwhash.py --hex        grava build/vectors/fw_hash.hex para o testbench

Quem usa: scripts/sim.sh (depois de compilar o firmware) e `hsmtool build`.
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMEM_BYTES = 128 * 1024


def fw_hash(caminho=None):
    dados = pathlib.Path(caminho or ROOT / "fw" / "elf.bin").read_bytes()
    return hashlib.sha256(imem_vista(dados)).digest()


def imem_vista(dados):
    """Os IMEM_BYTES que a CPU le, a partir do endereco 0."""
    if len(dados) > IMEM_BYTES:
        raise SystemExit("firmware maior que a IMEM")
    rom = 4
    while rom < len(dados):
        rom *= 2
    return dados.ljust(rom, b"\0") * (IMEM_BYTES // rom)


if __name__ == "__main__":
    h = fw_hash()
    if "--hex" in sys.argv:
        out = ROOT / "build" / "vectors"
        out.mkdir(parents=True, exist_ok=True)
        (out / "fw_hash.hex").write_text("".join("%02x\n" % b for b in h))
    print(h.hex())
