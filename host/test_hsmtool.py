#!/usr/bin/env python3
"""Testes do transporte do hsmtool, sem placa.

    python3 host/test_hsmtool.py

O `hsmtool.py selftest` cobre o codec (montar e validar frames). Aqui se
testa a outra metade, que e onde moram os bugs chatos: leitura parcial,
timeout, e recuperacao depois de um frame ruim.

Para isso, um pty faz as vezes de porta serial e um modelo minimo do
dispositivo responde do outro lado. O modelo NAO prova concordancia com o
firmware -- quem prova isso e o tb_uart_frame, que roda o firmware de
verdade. O que se prova aqui e que o cliente se comporta quando a linha
se comporta mal.
"""

import os
import pty
import sys
import termios
import threading
import time
import tty

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hsmtool import (  # noqa: E402
    CMD_PING,
    CMD_GET_VERSION,
    FW_INTERBYTE_TIMEOUT_S,
    CrcError,
    FrameTimeout,
    HsmClient,
    HsmError,
    ProtocolError,
    crc32,
)


class FakeDevice(threading.Thread):
    """Modelo minimo do firmware, com injecao de falha.

    fault:
        None        -- comportamento normal
        'silent'    -- nao responde nada
        'truncate'  -- responde so os primeiros bytes do frame
        'badcrc'    -- responde com CRC corrompido
    """

    def __init__(self, fd, fault=None):
        super().__init__(daemon=True)
        self.fd = fd
        self.fault = fault
        self.stop = False
        self.requests = 0

    def _respond(self, status, payload):
        body = bytes([status]) + payload
        head = len(body).to_bytes(2, "big") + body
        frame = head + crc32(head).to_bytes(4, "big")

        if self.fault == "silent":
            return
        if self.fault == "badcrc":
            frame = frame[:-1] + bytes([frame[-1] ^ 0x01])
        if self.fault == "truncate":
            frame = frame[:3]

        os.write(self.fd, frame)

    def run(self):
        buf = b""
        while not self.stop:
            try:
                chunk = os.read(self.fd, 64)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk

            # enquadramento: LEN(2) + body(LEN) + CRC(4)
            while len(buf) >= 2:
                length = int.from_bytes(buf[0:2], "big")
                need = 2 + length + 4
                if len(buf) < need:
                    break
                frame, buf = buf[:need], buf[need:]
                self.requests += 1

                calc = crc32(frame[:2 + length])
                got = int.from_bytes(frame[2 + length:], "big")
                if calc != got:
                    self._respond(0x01, b"")        # STATUS_BAD_CRC
                    continue

                opcode = frame[2]
                if opcode == CMD_PING:
                    self._respond(0x00, b"PONG")
                elif opcode == CMD_GET_VERSION:
                    self._respond(0x00, bytes([0, 1, 0, 0]))
                else:
                    self._respond(0x10, b"")        # STATUS_UNKNOWN_CMD


def make_link(fault=None):
    master, slave = pty.openpty()
    for fd in (master, slave):
        tty.setraw(fd)
        attrs = termios.tcgetattr(fd)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSANOW, attrs)

    dev = FakeDevice(master, fault)
    dev.start()
    return dev, master, os.ttyname(slave), slave


FAILS = []


def check(name, cond, detail=""):
    if cond:
        print("ok    %s" % name)
    else:
        print("FAIL  %s %s" % (name, detail))
        FAILS.append(name)


def test_normal():
    dev, master, port, slave = make_link()
    try:
        with HsmClient(port, timeout=1.0) as c:
            payload = c.command(CMD_PING)
            check("ping normal", payload == b"PONG", repr(payload))

            payload = c.command(CMD_GET_VERSION)
            check("get_version", payload == bytes([0, 1, 0, 0]), repr(payload))

            # varias transacoes seguidas nao podem dessincronizar
            okall = all(c.command(CMD_PING) == b"PONG" for _ in range(50))
            check("50 pings seguidos", okall)
    finally:
        dev.stop = True
        os.close(master)
        os.close(slave)


def test_error_status():
    """Frame valido com STATUS != OK vira HsmError, nao excecao de protocolo.

    E o caminho que 'hsmtool dna' percorre hoje, ja que GET_DNA responde
    STATUS_NOT_IMPLEMENTED ate o CFS existir. Confundir "o dispositivo
    recusou" com "a linha esta ruim" manda o diagnostico para o lado errado.
    """
    dev, master, port, slave = make_link()
    try:
        with HsmClient(port, timeout=0.5) as c:
            status, payload = c.transact(0xAA)
            check("opcode desconhecido -> status", status == 0x10, hex(status))

            try:
                c.command(0xAA)
                check("status de erro vira HsmError", False, "nao levantou")
            except HsmError as e:
                check("status de erro vira HsmError", e.status == 0x10, str(e))
            except ProtocolError as e:
                check("status de erro vira HsmError", False,
                      "levantou ProtocolError: %s" % e)

            # e o canal continua utilizavel depois disso
            check("canal ok apos recusa", c.command(CMD_PING) == b"PONG")
    finally:
        dev.stop = True
        os.close(master)
        os.close(slave)


def test_timeout():
    dev, master, port, slave = make_link(fault="silent")
    try:
        with HsmClient(port, timeout=0.4) as c:
            t0 = time.perf_counter()
            try:
                c.command(CMD_PING)
                check("timeout de resposta", False, "nao levantou")
            except FrameTimeout:
                dt = time.perf_counter() - t0
                check("timeout de resposta", 0.3 < dt < 1.5, "%.2f s" % dt)
    finally:
        dev.stop = True
        os.close(master)
        os.close(slave)


def test_truncated():
    """Resposta cortada no meio: tem de dar timeout, nao travar nem
    devolver frame parcial como se fosse valido."""
    dev, master, port, slave = make_link(fault="truncate")
    try:
        with HsmClient(port, timeout=0.4) as c:
            try:
                c.command(CMD_PING)
                check("resposta truncada", False, "aceitou frame parcial")
            except FrameTimeout:
                check("resposta truncada", True)
            except ProtocolError as e:
                check("resposta truncada", True, "(%s)" % e)
    finally:
        dev.stop = True
        os.close(master)
        os.close(slave)


def test_badcrc():
    dev, master, port, slave = make_link(fault="badcrc")
    try:
        with HsmClient(port, timeout=0.5) as c:
            try:
                c.command(CMD_PING)
                check("CRC ruim na resposta", False, "aceitou")
            except CrcError:
                check("CRC ruim na resposta", True)
    finally:
        dev.stop = True
        os.close(master)
        os.close(slave)


def test_recovery():
    """Depois de um erro, resync() tem de deixar o canal utilizavel.

    E o mesmo criterio do lado do firmware (PLANO.md secao 2), visto do
    outro lado do fio: um frame ruim nao pode inutilizar a sessao.
    """
    dev, master, port, slave = make_link()
    try:
        with HsmClient(port, timeout=0.5) as c:
            # injeta lixo na linha, como se um frame anterior tivesse
            # ficado pela metade
            os.write(master, b"\xde\xad\xbe")
            time.sleep(FW_INTERBYTE_TIMEOUT_S * 0.5)
            c.resync()

            payload = c.command(CMD_PING)
            check("recupera apos lixo na linha", payload == b"PONG", repr(payload))
    finally:
        dev.stop = True
        os.close(master)
        os.close(slave)


def main():
    print("== transporte do hsmtool (pty + modelo do dispositivo)")
    test_normal()
    test_error_status()
    test_timeout()
    test_truncated()
    test_badcrc()
    test_recovery()
    print()
    if FAILS:
        print("FALHOU: %d verificacao(oes)" % len(FAILS))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
