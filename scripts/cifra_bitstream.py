#!/usr/bin/env python3
"""Cifra um bitstream de Artix-7 com a chave da BBRAM.

    python3 scripts/cifra_bitstream.py entrada.bit chave.nky saida.bit

AES-256-CBC e HMAC-SHA-256, com o HMAC dentro da parte cifrada. A saida
carrega por JTAG ou pela flash, com a mesma chave ja na BBRAM.

O cabecalho seleciona a BBRAM, sempre. O bit 31 do CTL0 escolheria a outra
origem de chave, que este projeto proibe (PLANO.md, secao 0). Aqui ele fica
em zero, e o script confere isso antes de escrever.
"""
import argparse
import hashlib
import hmac
import re
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NOP = 0x20000000
SYNC = 0xAA995566
W_CMD = 0x30008001
W_CRC = 0x30000001
W_MASK = 0x3000C001
W_CTL0 = 0x3000A001
W_CTL1 = 0x30030001
CMD_RCRC = 7
CMD_DESYNC = 0x0D
DEC = 0x40                  # CTL0: decifrar
ORIGEM_CHAVE = 0x80000000   # CTL0 bit 31: tem de ficar em zero
INVERTE = bytes(int("{:08b}".format(i)[::-1], 2) for i in range(256))


def inverte32(dados):
    """Inverte os 32 bits de cada palavra: o motor ve os bits ao contrario."""
    saida = bytearray(len(dados))
    for i in range(4):
        saida[i::4] = dados[3 - i::4]
    return bytes(saida).translate(INVERTE)


def le_nky(nome):
    texto = open(nome).read()

    def campo(rotulo, n):
        m = re.search(r"Key\s+%s\s+([0-9a-fA-F]{%d});" % (rotulo, n), texto)
        if not m:
            sys.exit("%s: campo %s ausente" % (nome, rotulo))
        return bytes.fromhex(m.group(1))

    return campo("0", 64), campo("StartCBC", 32), campo("HMAC", 64)


def le_bitstream(nome):
    """Devolve os bytes depois do cabecalho do .bit, ou o .bin inteiro."""
    b = open(nome, "rb").read()
    if b[:2] != b"\x00\x09":
        return b
    i = 13                  # campos a, b, c, d, e depois do cabecalho fixo
    while True:
        if b[i:i + 1] == b"e":
            return b[i + 5:i + 5 + struct.unpack(">I", b[i + 1:i + 5])[0]]
        i += 3 + struct.unpack(">H", b[i + 1:i + 3])[0]


def corpo_cifravel(palavras):
    """Separa o preambulo em claro do corpo, e ajusta o corpo para decifrar."""
    sync = palavras.index(SYNC)
    inicio = next(i for i in range(sync, sync + 32)
                  if palavras[i] == W_CMD and palavras[i + 1] == 0x12) + 3
    c = list(palavras[inicio:])
    fim = None
    i = 0
    while i < len(c):
        h = c[i]
        tipo = h >> 29
        if tipo == 1:
            n = h & 0x7FF
            if h == W_CRC:
                c[i], c[i + 1] = W_CMD, CMD_RCRC
            elif h == W_CMD and c[i + 1] == CMD_DESYNC:
                fim = i
                break
            elif h == W_CTL0:
                c[i + 1] |= DEC
            i += 1 + n
            if n == 0 and i < len(c) and c[i] >> 29 == 2:
                i += 1 + (c[i] & 0x7FFFFFF)
        elif tipo == 2:
            i += 1 + (h & 0x7FFFFFF)
        else:
            i += 1
    if fim is None:
        sys.exit("bitstream sem DESYNC")
    return palavras[:inicio], c[:fim]


def monta(bruto, chave, iv, chave_mac, ctl1, mascara):
    palavras = list(struct.unpack(">%dI" % (len(bruto) // 4), bruto))
    preambulo, corpo = corpo_cifravel(palavras)
    # So a primeira escrita de cada CTL abre a mascara inteira. As demais so
    # precisam manter o DEC ligado.
    viu_ctl0 = viu_ctl1 = False
    for i in range(len(corpo) - 3):
        if corpo[i] != W_MASK:
            continue
        if corpo[i + 2] == W_CTL0:
            corpo[i + 1] = corpo[i + 1] | DEC if viu_ctl0 else mascara
            viu_ctl0 = True
        elif corpo[i + 2] == W_CTL1 and not viu_ctl1:
            corpo[i + 1] = mascara
            corpo[i + 3] = ctl1
            viu_ctl1 = True
    while len(corpo) % 16:
        corpo.append(NOP)
    dados = struct.pack(">%dI" % len(corpo), *corpo)

    ipad = bytes(x ^ 0x36 for x in chave_mac) + b"\x36" * 32
    opad = bytes(x ^ 0x5C for x in chave_mac) + b"\x5C" * 32
    pad1 = b"\x80" + bytes(55) + struct.pack(">Q", (64 + len(dados)) * 8)
    pad2 = b"\x80" + bytes(23) + struct.pack(">Q", 96 * 8)
    tag = hmac.new(chave_mac, dados, hashlib.sha256).digest()
    claro = bytearray(ipad + dados + pad1 + bytes(256) + opad + bytes(32) + pad2 + tag)
    for i in range(16):
        claro[i] ^= iv[i]       # o IV entra antes da inversao de bits
    enc = Cipher(algorithms.AES(chave), modes.CBC(bytes(16))).encryptor()
    cifrado = inverte32(enc.update(inverte32(bytes(claro))) + enc.finalize())

    ctl0 = 0x40
    cab = [W_MASK, 0x40, W_CTL0, ctl0, 0x3001C001, 0] + [NOP] * 14
    cab += [0x30016004] + list(struct.unpack(">4I", iv))
    cab += [0x30034001, len(cifrado) // 4]
    if ctl0 & ORIGEM_CHAVE or cab[1] & ORIGEM_CHAVE:
        sys.exit("cabecalho pede chave fora da BBRAM: recusado")
    saida = struct.pack(">%dI" % (len(preambulo) + len(cab)), *(preambulo + cab)) + cifrado
    if len(saida) % 4:
        sys.exit("tamanho impar")
    falta = max(0, (len(bruto) - len(saida)) // 4)
    return saida + struct.pack(">I", NOP) * falta


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("entrada")
    p.add_argument("nky")
    p.add_argument("saida")
    p.add_argument("--ctl1", type=lambda x: int(x, 0), default=0x1F3D0)
    a = p.parse_args()
    chave, iv, chave_mac = le_nky(a.nky)
    b = monta(le_bitstream(a.entrada), chave, iv, chave_mac, a.ctl1, 0xFFFFFFFF)
    if a.saida.endswith(".bit"):
        # mesmo cabecalho do .bit original, com o novo comprimento
        orig = open(a.entrada, "rb").read()
        i = len(orig) - len(le_bitstream(a.entrada)) - 4
        b = orig[:i] + struct.pack(">I", len(b)) + b
    open(a.saida, "wb").write(b)
    print("%s: %d bytes" % (a.saida, len(b)))


if __name__ == "__main__":
    main()
