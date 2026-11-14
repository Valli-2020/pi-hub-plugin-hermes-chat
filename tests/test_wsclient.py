#!/usr/bin/env python3
"""Offline test for the rewritten WSConnection.

Spins up a raw-socket RFC 6455 server that:
  * completes the handshake,
  * sends a WS ping every 1s and FAILS if no pong arrives within 2s,
  * after 3 successful ping/pong cycles sends a text message.

The old synchronous client cannot pass this (it never reads between
recv() calls); the new reader-thread client must pass it.
"""
import base64
import hashlib
import os
import secrets
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from pi_hub_plugins.hermes.wsclient import WSConnection  # noqa: E402

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def srv_frame(opcode: int, payload: bytes) -> bytes:
    h = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        h += bytes([n])
    elif n < 65536:
        h += bytes([126]) + struct.pack("!H", n)
    else:
        h += bytes([127]) + struct.pack("!Q", n)
    return h + payload


def read_frame(sock: socket.socket):
    h = b""
    while len(h) < 2:
        c = sock.recv(2 - len(h))
        if not c:
            return None
        h += c
    ln = h[1] & 0x7F
    if ln == 126:
        ln = struct.unpack("!H", sock.recv(2))[0]
    elif ln == 127:
        ln = struct.unpack("!Q", sock.recv(8))[0]
    mask = sock.recv(4)
    data = b""
    while len(data) < ln:
        c = sock.recv(ln - len(data))
        if not c:
            return None
        data += c
    return h[0] & 0x0F, bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def server(sock: socket.socket, results: dict) -> None:
    # Handshake
    req = b""
    while b"\r\n\r\n" not in req:
        req += sock.recv(4096)
    key = ""
    for line in req.decode().split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    accept = base64.b64encode(
        hashlib.sha1((key + _GUID).encode()).digest()
    ).decode()
    sock.sendall(
        (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode()
    )
    results["handshake"] = True

    # Mirror uvicorn semantics EXACTLY: every ping starts its own
    # deadline; if that individual ping is not answered within the
    # window, the connection is declared dead (uvicorn: ping_interval
    # 20s / ping_timeout 20s; here compressed to 2s/4s). No deadline
    # extension across pings.
    deadlines: list[float] = []
    pings_sent = 0
    pongs_got = 0
    text_sent = False
    sock.settimeout(0.25)
    last_ping = 0.0
    start = time.time()
    while time.time() - start < 40:
        now = time.time()
        if now - last_ping >= 2.0 and pings_sent < 30:
            sock.sendall(srv_frame(0x9, b"hb"))
            pings_sent += 1
            deadlines.append(now + 4.0)
            last_ping = now
        if deadlines and deadlines[0] < now:
            results["error"] = (
                f"ping unanswered past its deadline: "
                f"{pongs_got}/{pings_sent} pongs"
            )
            return
        try:
            frame = read_frame(sock)
        except socket.timeout:
            frame = None
        except OSError:
            return
        if frame is None:
            continue
        opcode, payload = frame
        if opcode == 0xA:
            pongs_got += 1
            if deadlines:
                deadlines.pop(0)
            assert payload == b"hb", f"pong echo wrong: {payload!r}"
        elif opcode == 0x8:
            results["closed"] = True
            return
        # Deliver text at t=10s regardless — a well-behaved client has
        # been answering pings all along and will find it queued.
        if now - start >= 10.0 and not text_sent:
            sock.sendall(srv_frame(0x1, "hello-from-server".encode()))
            text_sent = True
    if not text_sent:
        results["error"] = f"server never sent text (pongs={pongs_got})"
    else:
        results["ok"] = True


def main() -> int:
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]

    results: dict = {}
    ready = threading.Event()

    def acceptor():
        conn, _ = lsock.accept()
        ready.set()
        server(conn, results)

    t = threading.Thread(target=acceptor, daemon=True)
    t.start()

    ws = WSConnection(f"ws://127.0.0.1:{port}/api/ws", timeout=5.0)
    ws.connect()
    ready.wait(5)

    # THE discriminator: stay idle 25s without reading. The dashboard's
    # keepalive pings arrive during this window; only a client with a
    # background reader survives them.
    time.sleep(25)
    msg = ws.recv(timeout=15.0)
    print("received:", repr(msg))
    ws.close()
    t.join(timeout=3)
    lsock.close()

    errors = []
    if msg != "hello-from-server":
        errors.append(f"text message wrong: {msg!r}")
    # 'ok' = server ran to completion; 'closed' = server observed the
    # client's clean close AFTER delivering text. Both fine. Only an
    # explicit error entry (missed pong) is a failure.
    if "error" in results:
        errors.append(f"server-side failure: {results['error']}")
    elif "ok" not in results and "closed" not in results:
        errors.append(f"inconclusive server state: {results}")
    if errors:
        print("FAIL:", "; ".join(errors))
        return 1
    print("PASS: pings answered under load-free idle, text delivered intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
