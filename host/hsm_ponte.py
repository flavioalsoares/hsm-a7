#!/usr/bin/env python3
"""hsm_ponte.py -- ponte TCP <-> UART para a porta HOST (fase 5).

Num HSM de pagamento comercial o host conecta por TCP e manda mensagens
ASCII prefixadas por 2 bytes de comprimento. Esta placa so tem a UART, e o
firmware usa o MESMO enquadramento nela. Entao a ponte nao entende nada:
le 2 bytes de comprimento, le a mensagem, repassa; le a resposta do mesmo
jeito, devolve. Quem interpreta o ASCII e o firmware, dentro da fronteira
-- decisao de 2026-11-02, doc/fase5-notas.md.

    python3 host/hsm_ponte.py [--porta 1500] [--serial /dev/ttyUSB1]

Uma conexao por vez, um pedido por vez: o dispositivo e sincrono.

⚠ Enquanto a ponte roda, ela segura a serial, e o hsmtool (console) nao
consegue abri-la. E o efeito pratico de console e host dividirem a UART.
"""

import argparse
import os
import socket
import struct
import sys


def le(conn, n):
    buf = b""
    while len(buf) < n:
        c = conn.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


def main(argv=None):
    ap = argparse.ArgumentParser(description="ponte TCP <-> UART do HSM")
    ap.add_argument("--endereco", default="127.0.0.1",
                    help="onde escutar (padrao 127.0.0.1: so esta maquina)")
    ap.add_argument("--porta", type=int, default=1500)
    ap.add_argument("--serial", default=None, help="porta serial da placa")
    a = ap.parse_args(argv)

    import serial
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from hsmtool import default_port

    dev = a.serial or default_port()
    ser = serial.Serial(dev, 115200, timeout=3.0)
    ser.reset_input_buffer()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.endereco, a.porta))
    srv.listen(1)
    print("ponte: %s:%d <-> %s" % (a.endereco, a.porta, dev), flush=True)

    while True:
        conn, origem = srv.accept()
        print("ponte: conexao de %s:%d" % origem, flush=True)
        with conn:
            while True:
                cab = le(conn, 2)
                if cab is None:
                    break
                n = struct.unpack(">H", cab)[0]
                msg = le(conn, n)
                if msg is None:
                    break
                if n == 0 or not (0x30 <= msg[0] <= 0x7E):
                    # Isto viraria um frame BINARIO do console na UART. A
                    # ponte e a porta host: nao deixa passar.
                    print("ponte: mensagem recusada (nao e ASCII de host)",
                          flush=True)
                    break
                ser.write(cab + msg)
                # A ponte nao sabe qual comando e lento: o primeiro byte da
                # resposta pode demorar (o R0 gera um par RSA em segundos).
                # O resto chega em seguida, no prazo curto de sempre.
                ser.timeout = 120.0
                rcab = ser.read(2)
                ser.timeout = 3.0
                if len(rcab) != 2:
                    print("ponte: o dispositivo nao respondeu", flush=True)
                    break
                resp = ser.read(struct.unpack(">H", rcab)[0])
                conn.sendall(rcab + resp)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
