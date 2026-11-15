#!/usr/bin/env python3
"""SHA-256 da memoria de codigo, como o GET_BUILD o calcula no equipamento.

A IMEM tem 64 KB; o firmware ocupa o comeco, e o resto e zero. O hash e
sobre os 64 KB inteiros.

    mkfwhash.py              imprime o hash de fw/elf.bin
    mkfwhash.py --hex        grava build/vectors/fw_hash.hex para o testbench

Quem usa: scripts/sim.sh (depois de compilar o firmware) e `hsmtool build`.
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMEM_BYTES = 64 * 1024


def fw_hash(caminho=None):
    dados = pathlib.Path(caminho or ROOT / "fw" / "elf.bin").read_bytes()
    if len(dados) > IMEM_BYTES:
        raise SystemExit("firmware maior que a IMEM")
    return hashlib.sha256(dados.ljust(IMEM_BYTES, b"\0")).digest()


if __name__ == "__main__":
    h = fw_hash()
    if "--hex" in sys.argv:
        out = ROOT / "build" / "vectors"
        out.mkdir(parents=True, exist_ok=True)
        (out / "fw_hash.hex").write_text("".join("%02x\n" % b for b in h))
    print(h.hex())
