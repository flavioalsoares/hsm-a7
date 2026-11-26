"""DUKPT TDES (ANSI X9.24-1:2009, etapa 8.8a) e DUKPT AES (ANSI X9.24-3:2017,
etapa 8.8b) -- a referencia em Python.

Escrito uma segunda vez, separado de `fw/src/dukpt.c`, pela mesma razao do
key block: duas leituras da norma que discordam acusam o erro. O DES aqui e
o da biblioteca `cryptography`, e nao `host/des.py`, para o C e o Python
nao dividirem o motor.

O esquema, em tres passos:

  1. IPEK (chave inicial do terminal), da BDK e do KSN inicial:
         k    = os 8 bytes da esquerda do KSN, com o contador zerado
         IPEK = 3DES(BDK, k) || 3DES(BDK ^ C0C0C0C000000000C0C0C0C000000000, k)

  2. chave de transacao, da IPEK e do contador de 21 bits do KSN: para cada
     bit 1 do contador, do mais alto para o mais baixo, o bit entra no
     registrador do KSN e a chave passa pelo processo nao reversivel
     (`_nrkgp`). Sao no maximo 10 passos, porque o contador de um KSN valido
     nunca tem mais de 10 bits 1.

  3. a variante de PIN: chave ^ 00000000000000FF00000000000000FF. O PIN
     block formato 0 vai cifrado em 3DES sob essa chave.

O HSM so faz o lado do adquirente: da BDK e do KSN que veio com a transacao,
ele refaz a chave do terminal. O terminal guarda as chaves futuras; aqui nao
ha registro nenhum.
"""

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

KSN_LEN = 10
CONTADOR_BITS = 21
CONTADOR_MASCARA = (1 << CONTADOR_BITS) - 1
MAX_UNS = 10                       # bits 1 no contador de um KSN valido

_C0 = bytes.fromhex("C0C0C0C000000000C0C0C0C000000000")
VARIANTE_PIN = bytes.fromhex("00000000000000FF00000000000000FF")


class DukptErro(ValueError):
    pass


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _tdes(chave, bloco):
    e = Cipher(TripleDES(chave), modes.ECB()).encryptor()
    return e.update(bloco) + e.finalize()


def _des(chave8, bloco):
    return _tdes(chave8 * 3, bloco)


def tdes_decifra(chave, bloco):
    d = Cipher(TripleDES(chave), modes.ECB()).decryptor()
    return d.update(bloco) + d.finalize()


def contador(ksn):
    if len(ksn) != KSN_LEN:
        raise DukptErro("KSN de %d bytes: sao 10" % len(ksn))
    return int.from_bytes(ksn[-3:], "big") & CONTADOR_MASCARA


def ksn_valido(ksn):
    """O que o HSM aceita: contador diferente de zero (zero e a propria
    IPEK, que nunca cifra transacao) e com no maximo 10 bits 1."""
    c = contador(ksn)
    return c != 0 and bin(c).count("1") <= MAX_UNS


def ipek(bdk, ksn):
    if len(bdk) != 16:
        raise DukptErro("BDK TDES de %d bytes: so 16" % len(bdk))
    base = (int.from_bytes(ksn, "big") & ~CONTADOR_MASCARA).to_bytes(KSN_LEN, "big")
    k = base[:8]
    return _tdes(bdk, k) + _tdes(_xor(bdk, _C0), k)


def _nrkgp(chave, reg):
    """Processo nao reversivel de geracao de chave (X9.24-1, A.2)."""
    def metade(k):
        e, d = k[:8], k[8:]
        return _xor(_des(e, _xor(reg, d)), d)
    direita = metade(chave)
    esquerda = metade(_xor(chave, _C0))
    return esquerda + direita


def chave_transacao(ipek_, ksn):
    c = contador(ksn)
    reg = int.from_bytes(ksn[2:], "big") & ~CONTADOR_MASCARA
    chave = ipek_
    for bit in range(CONTADOR_BITS - 1, -1, -1):
        if c & (1 << bit):
            reg |= 1 << bit
            chave = _nrkgp(chave, reg.to_bytes(8, "big"))
    return chave


def chave_pin(bdk, ksn):
    """A chave que cifra o PIN block da transacao `ksn`."""
    if not ksn_valido(ksn):
        raise DukptErro("KSN invalido: contador zero ou com mais de 10 bits 1")
    return _xor(chave_transacao(ipek(bdk, ksn), ksn), VARIANTE_PIN)


def cifra_pin(bdk, ksn, claro):
    return _tdes(chave_pin(bdk, ksn), claro)


def decifra_pin(bdk, ksn, bloco):
    return tdes_decifra(chave_pin(bdk, ksn), bloco)


# --------------------------------------------------------------------
# DUKPT AES (ANSI X9.24-3:2017) -- etapa 8.8b
#
# Uma funcao de derivacao so, por AES-ECB sobre 16 bytes de dados:
#
#   versao(1)=01 . contador de bloco(1) . uso(2) . algoritmo(2) . bits(2) .
#   8 bytes: o IKID (chave inicial) ou o IKID[4:8] e o contador (as outras)
#
# Uma chave de 256 bits sai de dois blocos (contador de bloco 1 e 2). O
# algoritmo e os bits sao os da chave DERIVADA. A chave que deriva e sempre
# AES (128 ou 256 aqui).
#
#   1. IK (chave inicial) = deriva(BDK, uso 8001, tipo da BDK, IKID)
#   2. para cada bit 1 do contador de 32 bits, do mais alto para o mais
#      baixo: o bit entra no registrador, e chave = deriva(chave, uso 8000,
#      tipo da BDK, IKID[4:8] || registrador)
#   3. chave de trabalho = deriva(chave da transacao, uso (1000 = PIN),
#      tipo pedido, IKID[4:8] || contador)
#
# Um contador valido tem de 1 a 16 bits 1.
# --------------------------------------------------------------------

AES_KSN_LEN = 12
AES_MAX_UNS = 16
USO_DERIVA_INICIAL = 0x8001
USO_DERIVA = 0x8000
USO_PIN = 0x1000
_ALG_AES = {16: 0x0002, 32: 0x0004}


def _aes_ecb(chave, bloco):
    from cryptography.hazmat.primitives.ciphers import algorithms
    e = Cipher(algorithms.AES(chave), modes.ECB()).encryptor()
    return e.update(bloco) + e.finalize()


def _aes_deriva(chave, uso, n_saida, dados8):
    if len(chave) not in _ALG_AES or n_saida not in _ALG_AES:
        raise DukptErro("DUKPT AES: so AES-128 e AES-256")
    saida = b""
    for blk in range(1, n_saida // 16 + 1):
        d = (bytes([1, blk]) + uso.to_bytes(2, "big")
             + _ALG_AES[n_saida].to_bytes(2, "big")
             + (n_saida * 8).to_bytes(2, "big") + dados8)
        saida += _aes_ecb(chave, d)
    return saida


def aes_contador(ksn):
    if len(ksn) != AES_KSN_LEN:
        raise DukptErro("KSN AES de %d bytes: sao 12" % len(ksn))
    return int.from_bytes(ksn[8:], "big")


def aes_ksn_valido(ksn):
    c = aes_contador(ksn)
    return c != 0 and bin(c).count("1") <= AES_MAX_UNS


def aes_ik(bdk, ikid):
    return _aes_deriva(bdk, USO_DERIVA_INICIAL, len(bdk), ikid)


def aes_chave_transacao(ik, ksn):
    c = aes_contador(ksn)
    reg = 0
    chave = ik
    for bit in range(31, -1, -1):
        if c & (1 << bit):
            reg |= 1 << bit
            chave = _aes_deriva(chave, USO_DERIVA, len(chave),
                                ksn[4:8] + reg.to_bytes(4, "big"))
    return chave


def aes_chave_pin(bdk, ksn, n_trabalho):
    """A chave de PIN AES de `n_trabalho` bytes (16 ou 32) da transacao."""
    if not aes_ksn_valido(ksn):
        raise DukptErro("KSN AES invalido: contador zero ou com mais de 16 bits 1")
    t = aes_chave_transacao(aes_ik(bdk, ksn[:8]), ksn)
    return _aes_deriva(t, USO_PIN, n_trabalho, ksn[4:12])


# --------------------------------------------------------------------
# MAC e dados com a chave da transacao (etapa 8.9b)
#
# TDES (X9.24-1, A.4.1): a chave da transacao, combinada por XOR com uma
# variante por uso; nas de dados, ainda a funcao de mao unica (cada metade
# cifrada em 3DES sob a propria chave). O MAC e o retail MAC (ISO 9797-1,
# algoritmo 3) com preenchimento 1; os dados vao em 3DES-CBC.
#
#   uso                bytes com FF     mao unica
#   MAC de pedido      6 e 14           nao
#   MAC de resposta    4 e 12           nao
#   dados de pedido    5 e 13           sim
#   dados de resposta  3 e 11           sim
#
# AES (X9.24-3): a mesma derivacao da chave de PIN, com outro uso:
#   2000 MAC de pedido, 2001 MAC de resposta (CMAC), 3000 dados de pedido,
#   3001 dados de resposta (AES-CBC).
#
# Pedido e resposta sao do ponto de vista do terminal: ele faz o MAC e cifra
# o pedido; o HSM do adquirente confere esse MAC e decifra, e faz o MAC e
# cifra a resposta.
# --------------------------------------------------------------------

MAC_PEDIDO, MAC_RESPOSTA, DADOS_PEDIDO, DADOS_RESPOSTA = range(4)
_VARIANTE = {MAC_PEDIDO: (6, 14), MAC_RESPOSTA: (4, 12),
             DADOS_PEDIDO: (5, 13), DADOS_RESPOSTA: (3, 11)}
_USO_AES = {MAC_PEDIDO: 0x2000, MAC_RESPOSTA: 0x2001,
            DADOS_PEDIDO: 0x3000, DADOS_RESPOSTA: 0x3001}


def chave_uso(bdk, ksn, uso):
    """A chave TDES da transacao `ksn` para o `uso` (MAC_PEDIDO...)."""
    if not ksn_valido(ksn):
        raise DukptErro("KSN invalido: contador zero ou com mais de 10 bits 1")
    k = bytearray(chave_transacao(ipek(bdk, ksn), ksn))
    for i in _VARIANTE[uso]:
        k[i] ^= 0xFF
    k = bytes(k)
    if uso in (DADOS_PEDIDO, DADOS_RESPOSTA):
        k = _tdes(k, k[:8]) + _tdes(k, k[8:])
    return k


def mac(bdk, ksn, uso, msg, tamanho=8):
    """O retail MAC (preenchimento 1) da mensagem, sob a chave de `uso`."""
    import mac_tdes
    if uso not in (MAC_PEDIDO, MAC_RESPOSTA):
        raise DukptErro("uso de MAC: MAC_PEDIDO ou MAC_RESPOSTA")
    return mac_tdes.retail_mac(chave_uso(bdk, ksn, uso), msg, 1, tamanho)


def dados(bdk, ksn, uso, iv, d, cifrar):
    """3DES-CBC sob a chave de dados de `uso`."""
    import mac_tdes
    if uso not in (DADOS_PEDIDO, DADOS_RESPOSTA):
        raise DukptErro("uso de dados: DADOS_PEDIDO ou DADOS_RESPOSTA")
    return mac_tdes.cbc(chave_uso(bdk, ksn, uso), iv, d, cifrar)


def aes_chave_uso(bdk, ksn, uso, n_trabalho):
    """A chave AES de trabalho de `n_trabalho` bytes para o `uso`."""
    if not aes_ksn_valido(ksn):
        raise DukptErro("KSN AES invalido: contador zero ou com mais de 16 bits 1")
    t = aes_chave_transacao(aes_ik(bdk, ksn[:8]), ksn)
    return _aes_deriva(t, _USO_AES[uso], n_trabalho, ksn[4:12])


def aes_mac(bdk, ksn, uso, n_trabalho, msg):
    """O CMAC (16 bytes) sob a chave AES de MAC de `uso`."""
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    if uso not in (MAC_PEDIDO, MAC_RESPOSTA):
        raise DukptErro("uso de MAC: MAC_PEDIDO ou MAC_RESPOSTA")
    c = CMAC(algorithms.AES(aes_chave_uso(bdk, ksn, uso, n_trabalho)))
    c.update(msg)
    return c.finalize()


def aes_dados(bdk, ksn, uso, n_trabalho, iv, d, cifrar):
    """AES-CBC sob a chave AES de dados de `uso`; `d` multiplo de 16."""
    from cryptography.hazmat.primitives.ciphers import algorithms
    if uso not in (DADOS_PEDIDO, DADOS_RESPOSTA):
        raise DukptErro("uso de dados: DADOS_PEDIDO ou DADOS_RESPOSTA")
    if not d or len(d) % 16 or len(iv) != 16:
        raise DukptErro("AES-CBC: dados multiplos de 16 e IV de 16")
    c = Cipher(algorithms.AES(aes_chave_uso(bdk, ksn, uso, n_trabalho)), modes.CBC(iv))
    o = c.encryptor() if cifrar else c.decryptor()
    return o.update(d) + o.finalize()
