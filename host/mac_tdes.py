"""Retail MAC (ISO/IEC 9797-1, algoritmo 3; ANSI X9.19) e 3DES-CBC de dados
(etapa 8.9a) -- a referencia em Python.

Escrito uma segunda vez, separado de `fw/src/keystore.c`, pela mesma razao do
key block: duas leituras da norma que discordam acusam o erro. O DES aqui e o
da biblioteca `cryptography`, e nao `host/des.py`, para o C e o Python nao
dividirem o motor.

O retail MAC, com a chave dupla K . K':

  1. preenche a mensagem ate um multiplo de 8 bytes:
       preenchimento 1: zeros (nada, se ja for multiplo);
       preenchimento 2: um byte 80, e zeros.
  2. CBC com DES simples sob K, IV zero, sobre todos os blocos: H.
  3. MAC = E_K( D_K'( H ) ), e sai a parte da esquerda (4 a 8 bytes).

O passo 3 sobre o ultimo bloco da cadeia e o 3DES de chave dupla K . K' sobre
o ultimo bloco: so a saida passa pelas duas chaves. Por isso o MAC custa um
DES por bloco, e nao tres.

A mensagem vazia e recusada aqui e no equipamento: com o preenchimento 1 a
norma a trata como um caso a parte, e nenhuma fonte de valores a cobre.
"""

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

BLOCO = 8
PREENCHIMENTOS = (1, 2)
TAMANHOS = (4, 8)


class MacErro(ValueError):
    pass


def _ecb(chave, bloco, cifrar=True):
    c = Cipher(TripleDES(chave), modes.ECB())
    o = c.encryptor() if cifrar else c.decryptor()
    return o.update(bloco) + o.finalize()


def preenche(msg, metodo):
    if metodo == 1:
        return msg + bytes((-len(msg)) % BLOCO)
    if metodo == 2:
        msg = msg + b"\x80"
        return msg + bytes((-len(msg)) % BLOCO)
    raise MacErro("preenchimento %r: so 1 e 2" % (metodo,))


def retail_mac(chave, msg, metodo=1, tamanho=8):
    """O retail MAC de `msg` sob a chave dupla `chave` (16 bytes)."""
    if len(chave) != 16:
        raise MacErro("retail MAC: chave dupla, 16 bytes")
    if tamanho not in TAMANHOS:
        raise MacErro("tamanho %r: so 4 e 8" % (tamanho,))
    if not msg:
        raise MacErro("mensagem vazia")
    k, k2 = chave[:8], chave[8:]
    m = preenche(msg, metodo)
    h = bytes(BLOCO)
    for i in range(0, len(m), BLOCO):
        h = _ecb(k, bytes(a ^ b for a, b in zip(h, m[i:i + BLOCO])))
    h = _ecb(k, _ecb(k2, h, cifrar=False))
    return h[:tamanho]


def cbc(chave, iv, dados, cifrar):
    """3DES-CBC, chave dupla ou tripla, sem preenchimento."""
    if len(chave) not in (16, 24) or len(iv) != BLOCO:
        raise MacErro("3DES-CBC: chave de 16 ou 24 bytes e IV de 8")
    if not dados or len(dados) % BLOCO:
        raise MacErro("3DES-CBC: dados multiplos de 8 bytes")
    c = Cipher(TripleDES(chave), modes.CBC(iv))
    o = c.encryptor() if cifrar else c.decryptor()
    return o.update(dados) + o.finalize()
