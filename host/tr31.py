#!/usr/bin/env python3
"""host/tr31.py -- key block ANSI X9.143 (TR-31 versao D), lado do host.

FRONTEIRA: fora, com uma ressalva que precisa ser dita alto.

Este modulo SABE embrulhar e desembrulhar chave, e para isso precisa da
KBPK em claro. Ele existe para duas coisas, nenhuma delas producao:

  1. ser a SEGUNDA implementacao do formato. A primeira esta em
     fw/src/tr31.c, dentro da fronteira. Duas implementacoes
     independentes do mesmo formato se validam mutuamente -- e a menor
     divergencia entre elas aparece como MAC invalido, que e o jeito mais
     barato de aprender um formato binario.

  2. permitir ao host CONFERIR um key block que o dispositivo produziu
     sem pedir nada ao dispositivo.

O dispositivo de verdade nunca entrega a LMK a este arquivo. Quando o
hsmtool usa este modulo com uma KBPK, e numa sessao de bancada com chave
de brinquedo, e o comentario acima e a razao de nao ser mais que isso.

---------------------------------------------------------------------
O FORMATO, EM UMA TELA

Um key block versao D e uma string ASCII:

    cabecalho(16) || hex(corpo cifrado) || hex(MAC de 16 bytes)

    D 0112 P0 A E 00 E 00 00
    | |    |  | | |  | |  |
    | |    |  | | |  | |  +-- reservado, "00"
    | |    |  | | |  | +----- numero de blocos opcionais, "00"
    | |    |  | | |  +------- exportabilidade: E, N ou S
    | |    |  | | +---------- versao da chave, "00"
    | |    |  | +------------ modo de uso: E, D, B, N...
    | |    |  +-------------- algoritmo: 'A' = AES, 'T' = TDES
    | |    +----------------- uso: P0, D0, K0, M0, B0...
    | +---------------------- comprimento TOTAL do bloco, 4 digitos ASCII
    +------------------------ versao do formato: 'D'

Corpo em claro, antes de cifrar:

    comprimento da chave em BITS (2 bytes, big-endian) || chave || enchimento

O enchimento e ALEATORIO e leva o corpo a multiplo de 16. Ele nao e
decoracao: sem ele, o tamanho do bloco denunciaria o tamanho da chave --
e "esta e uma chave de 128 bits" ja e informacao para quem escolhe onde
gastar esforco.

---------------------------------------------------------------------
AS TRES DECISOES DE PROJETO QUE O FORMATO TOMA, E POR QUE

1. DUAS CHAVES DERIVADAS DA KBPK, NAO UMA.

   KBEK cifra o corpo, KBAK autentica. Sao derivadas por CMAC da mesma
   KBPK, com um campo de PROPOSITO diferente na entrada -- 0x0000 para
   cifrar, 0x0001 para autenticar. Se fossem a mesma chave, um atacante
   com um oraculo de MAC teria um oraculo de cifragem de graca. E a
   mesma separacao de chaves que o keystore aplica ao recusar decifrar
   com uma chave marcada 'E'.

2. O CABECALHO ENTRA NO MAC.

   Sao 16 bytes de ASCII em claro, legiveis por qualquer um -- e
   autenticados. Sem isso um atacante que nem consegue decifrar o corpo
   edita `exportabilidade: N` para `E`, ou o modo de uso de 'D' para
   'B', e devolve o bloco. O corpo continua o mesmo; a POLITICA e que
   muda. Chave protegida sob metadado nao protegido nao esta protegida.

3. O MAC E O IV.

   O CBC usa o proprio MAC como vetor de inicializacao. Duas
   consequencias: nao ha IV para transmitir, e dois blocos com a mesma
   chave e o mesmo enchimento nunca coincidem se qualquer bit do
   cabecalho diferir. E MAC-then-encrypt sobre o texto claro, que e o
   que permite recusar um bloco adulterado ANTES de acreditar no que
   decifrou.

---------------------------------------------------------------------
DEPENDENCIA

Usa `cryptography` (AES e CMAC) -- e usa DE PROPOSITO uma biblioteca de
terceiros em vez de reaproveitar qualquer coisa do firmware. Se as duas
implementacoes compartilhassem o AES, elas concordariam sobre um erro no
AES sem nunca discordar. A independencia e o teste.
"""

import os

VERSAO_D = "D"

# Campos do cabecalho -- espelham fw/include/keystore.h, em ASCII como na
# norma. Divergir daqui e produzir um bloco que o firmware recusa.
USO_BDK = "B0"
USO_KEK = "K0"
USO_DADOS = "D0"
USO_MAC = "M0"
USO_PIN = "P0"

ALG_AES = "A"
ALG_3DES = "T"

MODO_CIFRA = "E"
MODO_DECIFRA = "D"
MODO_AMBOS = "B"
MODO_NENHUM = "N"

EXP_SIM = "E"
EXP_NAO = "N"
EXP_SENSIVEL = "S"

CABECALHO_LEN = 16
MAC_LEN = 16
BLOCO_AES = 16

# Propositos da derivacao (X9.143). Dois valores, dois papeis.
_USO_KBEK = b"\x00\x00"
_USO_KBAK = b"\x00\x01"

# Identificador de algoritmo na derivacao, por tamanho da KBPK.
_ALG_DERIV = {16: 0x0002, 24: 0x0003, 32: 0x0004}


class Tr31Erro(ValueError):
    """Bloco malformado, MAC invalido, ou parametro fora da norma.

    UM tipo so, de proposito. Distinguir "MAC invalido" de "enchimento
    invalido" para quem chama e distinguir para quem ataca: e a diferenca
    entre recusar e explicar por que recusou. Ver o comentario de
    `desembrulha`.
    """


# ---------------------------------------------------------------------
# Primitivas -- importadas tarde para que o hsmtool funcione sem
# `cryptography` instalado. Nenhum outro comando precisa dela.
# ---------------------------------------------------------------------
def _primitivas():
    try:
        from cryptography.hazmat.primitives import cmac as _cmac
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as e:  # pragma: no cover
        raise Tr31Erro(
            "host/tr31.py precisa do pacote `cryptography`:\n"
            "    pip install cryptography\n"
            "Nenhum outro comando do hsmtool depende dele."
        ) from e
    return _cmac, Cipher, algorithms, modes


def cmac_aes(chave, msg):
    """CMAC-AES de uma mensagem inteira. 16 bytes."""
    _cmac, _C, algorithms, _m = _primitivas()
    c = _cmac.CMAC(algorithms.AES(chave))
    c.update(msg)
    return c.finalize()


def _cbc(chave, iv, dados, cifrar):
    _c, Cipher, algorithms, modes = _primitivas()
    ciph = Cipher(algorithms.AES(chave), modes.CBC(iv))
    op = ciph.encryptor() if cifrar else ciph.decryptor()
    return op.update(dados) + op.finalize()


# ---------------------------------------------------------------------
# Derivacao de KBEK e KBAK
# ---------------------------------------------------------------------
def deriva_subchaves(kbpk):
    """(KBEK, KBAK) a partir da KBPK, pelo KDF de contador da X9.143.

    Cada bloco de 16 bytes de saida e um CMAC sobre 8 bytes de dados de
    derivacao:

        contador(1) || proposito(2) || separador(1) || algoritmo(2) || bits(2)

    O contador e o que permite tirar 256 bits de uma primitiva que
    devolve 128 -- duas chamadas, entradas diferentes. O campo de
    PROPOSITO e o que impede KBEK e KBAK de serem a mesma coisa; e por
    ele que a separacao de chaves existe neste formato.
    """
    n = len(kbpk)
    if n not in _ALG_DERIV:
        raise Tr31Erro(f"KBPK de {n} bytes: a versao D exige AES-128, 192 ou 256")

    alg = _ALG_DERIV[n]
    bits = n * 8

    def deriva(proposito):
        saida = b""
        contador = 1
        while len(saida) < n:
            dados = (
                bytes([contador])
                + proposito
                + b"\x00"
                + alg.to_bytes(2, "big")
                + bits.to_bytes(2, "big")
            )
            saida += cmac_aes(kbpk, dados)
            contador += 1
        return saida[:n]

    return deriva(_USO_KBEK), deriva(_USO_KBAK)


# ---------------------------------------------------------------------
# Cabecalho
# ---------------------------------------------------------------------
def monta_cabecalho(uso, algoritmo, modo, exportabilidade,
                    total, versao_chave="00"):
    """Os 16 bytes ASCII, com o comprimento total ja preenchido."""
    if total > 9999:
        raise Tr31Erro(f"bloco de {total} caracteres nao cabe no campo de 4 digitos")
    cab = (
        VERSAO_D
        + f"{total:04d}"
        + uso
        + algoritmo
        + modo
        + versao_chave
        + exportabilidade
        + "00"      # blocos opcionais: nenhum
        + "00"      # reservado
    )
    if len(cab) != CABECALHO_LEN:
        raise Tr31Erro(f"cabecalho com {len(cab)} caracteres, esperado {CABECALHO_LEN}")
    return cab


_HEX_MAIUSCULO = set("0123456789ABCDEF")


def _valida_campos(cab):
    """As mesmas recusas de `cab_valido()` em fw/src/tr31.c.

    As duas implementacoes sao MAIS ESTRITAS que a norma em dois pontos, e
    de propria vontade -- se uma so fosse, a divergencia apareceria como
    bloco recusado de um lado e aceito do outro, que e exatamente o tipo
    de coisa que este par de implementacoes existe para pegar:

      - 'T' (3DES) e valido na X9.143 e nao existe neste hardware. Aceitar
        o byte seria produzir um bloco que promete 3DES a quem importar.

      - blocos opcionais nao sao suportados, e um bloco opcional
        IGNORADO ainda estaria no MAC: o MAC fecharia e o dispositivo
        teria aceitado um campo que nao entendeu. E assim que uma
        restricao de uso desaparece sem ninguem notar.
    """
    if cab["algoritmo"] != ALG_AES:
        raise Tr31Erro(f"algoritmo {cab['algoritmo']!r}: este projeto so faz AES")
    if cab["modo"] not in (MODO_CIFRA, MODO_DECIFRA, MODO_AMBOS, MODO_NENHUM):
        raise Tr31Erro(f"modo de uso {cab['modo']!r} invalido")
    if cab["exportabilidade"] not in (EXP_SIM, EXP_NAO, EXP_SENSIVEL):
        raise Tr31Erro(f"exportabilidade {cab['exportabilidade']!r} invalida")
    if cab["blocos_opcionais"] != "00":
        raise Tr31Erro("blocos opcionais nao suportados")


def le_cabecalho(bloco):
    """Decompoe os 16 primeiros caracteres. Nao valida MAC nenhum."""
    if len(bloco) < CABECALHO_LEN:
        raise Tr31Erro("bloco menor que o cabecalho")
    c = bloco[:CABECALHO_LEN]
    if c[0] != VERSAO_D:
        raise Tr31Erro(f"versao '{c[0]}': este projeto so faz a D (AES)")
    # `str.isdigit()` nao serve: ele aceita digito unicode ('\uFF11' e
    # digito), e o firmware compara byte a byte com '0'..'9'. Uma
    # divergencia de UM caractere exotico entre as duas implementacoes e
    # exatamente o que este par existe para nao ter.
    if not set(c[1:5]) <= set("0123456789"):
        raise Tr31Erro("campo de comprimento nao e decimal")
    return {
        "versao": c[0],
        "comprimento": int(c[1:5]),
        "uso": c[5:7],
        "algoritmo": c[7],
        "modo": c[8],
        "versao_chave": c[9:11],
        "exportabilidade": c[11],
        "blocos_opcionais": c[12:14],
        "reservado": c[14:16],
    }


# ---------------------------------------------------------------------
# Embrulhar
# ---------------------------------------------------------------------
def embrulha(kbpk, chave, uso=USO_DADOS, algoritmo=ALG_AES,
             modo=MODO_AMBOS, exportabilidade=EXP_SIM,
             versao_chave="00", enchimento=None):
    """Produz o key block ASCII.

    NAO E DETERMINISTICO: o enchimento vem do `os.urandom`. Isso e da
    norma e e desejavel -- mas tem uma consequencia de teste que vale
    registrar, porque ela decide como esta fase e verificada: nao existe
    KAT de embrulhar. So de DESEMBRULHAR, que por sorte e a direcao onde
    um erro custa caro.

    `enchimento` existe para os testes fixarem esses bytes. Em uso
    normal fica None.
    """
    if len(chave) == 0 or len(chave) > 999:
        raise Tr31Erro("chave de comprimento invalido")
    _valida_campos({
        "algoritmo": algoritmo,
        "modo": modo,
        "exportabilidade": exportabilidade,
        "blocos_opcionais": "00",
    })

    kbek, kbak = deriva_subchaves(kbpk)

    corpo = (len(chave) * 8).to_bytes(2, "big") + chave
    falta = (-len(corpo)) % BLOCO_AES
    if enchimento is None:
        corpo += os.urandom(falta)
    else:
        if len(enchimento) < falta:
            raise Tr31Erro(f"enchimento de {len(enchimento)} bytes, precisa de {falta}")
        corpo += enchimento[:falta]

    total = CABECALHO_LEN + 2 * len(corpo) + 2 * MAC_LEN
    cab = monta_cabecalho(uso, algoritmo, modo, exportabilidade, total, versao_chave)

    # O MAC cobre cabecalho + corpo EM CLARO, e so depois vira IV. A
    # ordem importa: autenticar o criptograma daria um MAC que nao diz
    # nada sobre a chave que esta la dentro.
    mac = cmac_aes(kbak, cab.encode("ascii") + corpo)
    cifrado = _cbc(kbek, mac, corpo, cifrar=True)

    return cab + cifrado.hex().upper() + mac.hex().upper()


# ---------------------------------------------------------------------
# Desembrulhar
# ---------------------------------------------------------------------
def desembrulha(kbpk, bloco):
    """Devolve (chave, cabecalho). Levanta Tr31Erro se algo nao fecha.

    TODA recusa levanta o MESMO tipo com a mesma forma. A tentacao de
    dizer "MAC invalido" em um caso e "enchimento invalido" em outro e
    forte porque ajuda a depurar -- e e exatamente o oraculo de padding
    classico: o atacante nao precisa da chave, precisa so que a vitima
    diga em qual etapa parou.

    A verificacao do MAC vem ANTES de olhar o conteudo decifrado, pelo
    mesmo motivo.
    """
    bloco = bloco.strip()
    cab = le_cabecalho(bloco)

    if cab["comprimento"] != len(bloco):
        raise Tr31Erro(
            f"campo de comprimento diz {cab['comprimento']}, bloco tem {len(bloco)}"
        )
    if len(bloco) % 2 != 0:
        raise Tr31Erro("bloco com numero impar de caracteres")

    corpo_hex = bloco[CABECALHO_LEN:-2 * MAC_LEN]
    mac_hex = bloco[-2 * MAC_LEN:]

    if len(corpo_hex) == 0:
        raise Tr31Erro("bloco sem corpo")
    if len(corpo_hex) % (2 * BLOCO_AES) != 0:
        raise Tr31Erro("corpo nao e multiplo do bloco do AES")

    # Hexadecimal MAIUSCULO, e so.
    #
    # `bytes.fromhex` aceitaria minuscula de graca, e o firmware nao --
    # entao a mesma chave teria duas grafias de bloco, com MACs
    # diferentes, porque o cabecalho entra no MAC como BYTES. Duas
    # grafias do "mesmo" bloco e o comeco de um problema de
    # canonicalizacao, e o lugar de fechar isso e aqui, nas duas
    # implementacoes ao mesmo tempo.
    if not set(corpo_hex + mac_hex) <= _HEX_MAIUSCULO:
        raise Tr31Erro("corpo ou MAC fora do hexadecimal maiusculo")
    cifrado = bytes.fromhex(corpo_hex)
    mac = bytes.fromhex(mac_hex)

    kbek, kbak = deriva_subchaves(kbpk)
    corpo = _cbc(kbek, mac, cifrado, cifrar=False)

    esperado = cmac_aes(kbak, bloco[:CABECALHO_LEN].encode("ascii") + corpo)
    if not _iguais(esperado, mac):
        raise Tr31Erro("MAC invalido")

    # So agora o conteudo decifrado merece credito.
    bits = int.from_bytes(corpo[:2], "big")
    if bits == 0 or bits % 8 != 0 or 2 + bits // 8 > len(corpo):
        raise Tr31Erro("comprimento de chave invalido")
    _valida_campos(cab)

    return corpo[2:2 + bits // 8], cab


def _iguais(a, b):
    """Comparacao em tempo constante.

    Aqui do lado de fora nao protege nada -- quem roda este script ja tem
    o bloco e a KBPK. Esta escrita assim porque a implementacao gemea em
    C faz o mesmo por necessidade, e as duas devem poder ser lidas lado a
    lado sem que uma pareca mais cuidadosa que a outra.
    """
    if len(a) != len(b):
        return False
    d = 0
    for x, y in zip(a, b):
        d |= x ^ y
    return d == 0
