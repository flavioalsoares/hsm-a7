#!/usr/bin/env python3
"""Chave privada RSA e de curva P-256 em PKCS#8 (DER), do lado do host.

E o conteudo do key block de uma chave assimetrica neste projeto. Aqui a
codificacao e a da biblioteca `cryptography`, que e a implementacao
independente: o firmware tem a sua, em fw/src/pkcs8.c, e as duas sao
confrontadas em host/test_pkcs8.py.

⚠ Neste modulo a chave privada existe em claro. Ele serve aos testes, que
fazem o papel de outro sistema.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def _der(chave):
    return chave.private_bytes(serialization.Encoding.DER,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())


def rsa_der(p, q, e, d=None):
    """PKCS#8 de uma chave RSA, a partir dos primos e de `e`. Sem `d`, usa
    e^-1 mod (p-1)(q-1), como o firmware."""
    if d is None:
        d = pow(e, -1, (p - 1) * (q - 1))
    pub = rsa.RSAPublicNumbers(e, p * q)
    priv = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1),
                                 pow(q, -1, p), pub)
    return _der(priv.private_key(unsafe_skip_rsa_key_validation=True))


def ec_der(d):
    """PKCS#8 de uma chave P-256, a partir do escalar privado."""
    return _der(ec.derive_private_key(d, ec.SECP256R1()))


def le(der):
    """A chave de um PKCS#8: objeto da biblioteca `cryptography`."""
    return serialization.load_der_private_key(der, None)
