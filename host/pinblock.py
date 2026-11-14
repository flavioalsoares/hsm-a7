#!/usr/bin/env python3
"""PIN block ISO 9564-1 formato 4 (AES), do lado do host.

O formato esta escrito duas vezes: aqui e em fw/src/pinblock.c. As duas
implementacoes tem de concordar; se uma ler a norma errado, o teste acusa.

    campo do PIN (16 bytes):
        nibble 0      4            (controle: formato 4)
        nibble 1      tamanho do PIN, 4 a 12
        nibbles 2-15  o PIN em BCD, e depois o enchimento A
        bytes 8-15    aleatorios

    campo do PAN (16 bytes):
        nibble 0      tamanho do PAN menos 12 (0 se o PAN tem 12 ou menos)
        nibbles 1-19  o PAN em BCD; com menos de 12 digitos, zeros a
                      esquerda ate 12; o resto do campo e zero

    bloco = AES( AES(campo do PIN) XOR campo do PAN )

⚠ Neste modulo o PIN existe em claro. Ele faz o papel do TERMINAL e o do
destino da traducao, para testar o equipamento. No equipamento, o PIN em
claro so existe dentro da fronteira.

⚠ Nenhum PAN real, nunca. Os testes usam numeros inventados.
"""

import os

BLOCO = 16
PIN_MIN = 4
PIN_MAX = 12
PAN_MAX = 19


class PinErro(ValueError):
    """PIN, PAN ou bloco invalido."""


def _aes(chave):
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    return Cipher(algorithms.AES(chave), modes.ECB())


def _cifra(chave, bloco):
    return _aes(chave).encryptor().update(bloco)


def _decifra(chave, bloco):
    return _aes(chave).decryptor().update(bloco)


def campo_pin(pin, aleatorio=None):
    """Os 16 bytes do campo do PIN. `aleatorio`: 8 bytes, ou sorteados."""
    if not (PIN_MIN <= len(pin) <= PIN_MAX) or not pin.isdigit() \
            or not pin.isascii():
        raise PinErro("PIN: de 4 a 12 digitos")
    if aleatorio is None:
        aleatorio = os.urandom(8)
    if len(aleatorio) != 8:
        raise PinErro("aleatorio: 8 bytes")
    nibbles = "4%X%s" % (len(pin), pin)
    nibbles = nibbles.ljust(16, "A")
    return bytes.fromhex(nibbles) + bytes(aleatorio)


def campo_pan(pan):
    """Os 16 bytes do campo do PAN."""
    if not (1 <= len(pan) <= PAN_MAX) or not pan.isdigit() \
            or not pan.isascii():
        raise PinErro("PAN: de 1 a 19 digitos")
    m = len(pan) - 12 if len(pan) > 12 else 0
    nibbles = "%X%s" % (m, pan.rjust(12, "0"))
    return bytes.fromhex(nibbles.ljust(32, "0"))


def le_campo_pin(campo):
    """O PIN de um campo em claro. Levanta PinErro se o formato esta errado."""
    if len(campo) != BLOCO:
        raise PinErro("campo do PIN: 16 bytes")
    nib = campo[:8].hex().upper()
    if nib[0] != "4":
        raise PinErro("controle diferente de 4")
    n = int(nib[1], 16)
    if not PIN_MIN <= n <= PIN_MAX:
        raise PinErro("tamanho do PIN fora de 4 a 12")
    pin = nib[2:2 + n]
    if not pin.isdigit():
        raise PinErro("digito de PIN invalido")
    if nib[2 + n:] != "A" * (14 - n):
        raise PinErro("enchimento diferente de A")
    return pin


def cifra(chave, pin, pan, aleatorio=None):
    """PIN block formato 4, 16 bytes."""
    a = _cifra(chave, campo_pin(pin, aleatorio))
    b = bytes(x ^ y for x, y in zip(a, campo_pan(pan)))
    return _cifra(chave, b)


def decifra(chave, bloco, pan):
    """O PIN de um PIN block formato 4."""
    if len(bloco) != BLOCO:
        raise PinErro("PIN block: 16 bytes")
    b = _decifra(chave, bloco)
    a = bytes(x ^ y for x, y in zip(b, campo_pan(pan)))
    return le_campo_pin(_decifra(chave, a))
