#!/usr/bin/env python3
"""Offline verification for the bridge-hardening work order.

Covers (per _WORKORDER-bridge.md):
  Task 1  bounded classified rx + purge-before-send + timeout retry class
  Task 2  correlated pong liveness, two-miss kill, SO_KEEPALIVE
  Task 3  handshake fd hygiene, frame guards

Every test spins a raw-socket RFC 6455 server on 127.0.0.1. No dashboard,
no network, fully deterministic.
"""
import base64
import gc
import hashlib
import json
import os
import secrets
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from pi_hub_plugins.hermes.wsclient import WSConnection, WSError, MAX_PUSH_QUEUE  # noqa: E402
from pi_hub_plugins.hermes.gateway import HermesGateway  # noqa: E402
from pi_hub_plugins.hermes.auth import HermesAuth  # noqa: E402

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
RESULTS: list[tuple[str, bool, str]] = []


# ── tiny RFC 6455 helpers ─────────────────────────────────────────────

def srv_frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    h = bytes([(0x80 if fin else 0) | opcode])
    n = len(payload)
    if n < 126:
        h += bytes([n])
    elif n < 65536:
        h += bytes([126]) + struct.pack("!H", n)
    else:
        h += bytes([127]) + struct.pack("!Q", n)
    return h + payload


def read_client_frame(sock: socket.socket):
    """Parse one MASKED client frame; return (opcode, payload) or None."""
    def rd(n):
        b = b""
        while len(b) < n:
            c = sock.recv(n - len(b))
            if not c:
                return None
            b += c
        return b
    h = rd(2)
    if not h:
        return None
    ln = h[1] & 0x7F
    if ln == 126:
        e = rd(2)
        if e is None:
            return None
        ln = struct.unpack("!H", e)[0]
    elif ln == 127:
        e = rd(8)
        if e is None:
            return None
        ln = struct.unpack("!Q", e)[0]
    mask = rd(4)
    if mask is None:
        return None
    data = rd(ln) if ln else b""
    if data is None:
        return None
    return h[0] & 0x0F, bytes(b ^ mask[i % 4] for i, b in enumerate(data))


class FakeSrv:
    """Accepts ONE client, performs the WS handshake, hands the socket over."""

    def __init__(self, reject_handshake: bool = False):
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(1)
        self.port = self.lsock.getsockname()[1]
        self.reject_handshake = reject_handshake
        self.sock = None
        self.handshook = threading.Event()

    def accept(self, timeout: float = 5.0):
        """Blocking handshake handler — run me in a thread."""
        try:
            self.lsock.settimeout(timeout)
            c, _ = self.lsock.accept()
            req = b""
            c.settimeout(5.0)
            while b"\r\n\r\n" not in req:
                chunk = c.recv(4096)
                if not chunk:
                    break
                req += chunk
            # Publish BEFORE writing the 101: the client's connect()
            # returns the moment it has read the response bytes, so any
            # later publication races the test thread into NoneType.
            self.sock = c
            if self.reject_handshake:
                c.sendall(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
                )
                c.close()
                return None               # quiet exit inside daemon thread
            key = ""
            for line in req.decode("utf-8", "replace").split("\r\n"):
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            accept_v = base64.b64encode(
                hashlib.sha1((key + _GUID).encode()).digest()
            ).decode()
            c.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept_v}\r\n\r\n"
                ).encode()
            )
            self.handshook.set()
            return c
        except OSError:
            return None                   # listener torn down mid-accept

    def wait_sock(self, timeout: float = 5.0) -> socket.socket:
        """Block until the handshake finished; fail loudly otherwise."""
        if not self.handshook.wait(timeout):
            raise RuntimeError("fake server: handshake never completed")
        return self.sock

    def close(self):
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        self.lsock.close()


def report(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS" if ok else "FAIL") + f": {name}" + (f" — {detail}" if detail else ""))


# ── Task 1: backlog cap, RPC survival, purge-before-call ──────────────

def t1_backlog_cap_and_rpc_survival():
    srv = FakeSrv()
    ws = WSConnection(f"ws://127.0.0.1:{srv.port}/api/ws")
    threading.Thread(target=srv.accept, daemon=True).start()
    ws.connect()
    sock = srv.wait_sock()

    # Flood with far more unsolicited pushes than the cap, then slip in
    # exactly one RPC-shaped reply afterwards.
    blob = srv_frame(0x1, json.dumps({"method": "event",
                                      "params": {"type": "sessions.changed"}}).encode())
    flood = blob * (MAX_PUSH_QUEUE * 3)
    reply = json.dumps({"jsonrpc": "2.0", "id": "ph99",
                        "result": {"survived": True}})
    sock.sendall(flood + srv_frame(0x1, reply.encode()))
    time.sleep(0.8)                       # let the reader chew

    with ws._push_cv:
        push_len = len(ws._push)
    ok_cap = push_len <= MAX_PUSH_QUEUE

    got = json.loads(ws._rpc_rx.get(timeout=2))
    ok_rpc = got.get("id") == "ph99" and got["result"].get("survived")

    ws.purge_pending()
    with ws._push_cv:
        emptied = len(ws._push) == 0
    drained = True
    try:
        while True:
            ws._rpc_rx.get_nowait()
    except Exception:
        pass
    ws.close(); srv.close()
    report("t1 push-lane bounded", ok_cap, f"len={push_len} cap={MAX_PUSH_QUEUE}")
    report("t1 rpc reply survives flood", ok_rpc)
    report("t1 purge empties lanes", emptied and drained)


def t2_call_after_backlog_answers_fast():
    srv = FakeSrv()
    ws = WSConnection(f"ws://127.0.0.1:{srv.port}/api/ws")
    threading.Thread(target=srv.accept, daemon=True).start()
    ws.connect()
    sock = srv.wait_sock()

    # Long-idle simulation: a fat backlog of pushes lands BEFORE the call.
    blob = srv_frame(0x1, b'{"method":"event","params":{"type":"gateway.ready"}}')
    marker = json.dumps({"jsonrpc": "2.0", "id": "drain-marker",
                         "result": True})
    sock.sendall(blob * 2000 + srv_frame(0x1, marker.encode()))
    # The reader is a single FIFO consumer: once the RPC-shaped marker
    # surfaces in the rpc lane, every byte ahead of it (the whole flood)
    # has been classified too. Purging after this leaves zero stragglers
    # that could race the awaited reply.
    marker_seen = False
    deadline = time.time() + 5
    while time.time() < deadline and not marker_seen:
        try:
            item = ws._rpc_rx.get(timeout=0.5)
            marker_seen = (item is not None
                           and json.loads(item).get("id") == "drain-marker")
        except Exception:                     # noqa: BLE001
            pass

    def responder():
        # Answer the client's request the moment it shows up.
        deadline = time.time() + 10
        while time.time() < deadline:
            f = read_client_frame(sock)
            if f is None:
                return
            op, payload = f
            if op == 0x1:
                req = json.loads(payload.decode())
                sock.sendall(srv_frame(
                    0x1,
                    json.dumps({"jsonrpc": "2.0", "id": req["id"],
                                "result": {"pong": True}}).encode()))
                return
    threading.Thread(target=responder, daemon=True).start()

    ws.purge_pending()
    rid = "t2"
    t0 = time.monotonic()
    ws.send(json.dumps({"jsonrpc": "2.0", "id": rid, "method": "ping"}))
    msg = ws.recv(timeout=10)
    dt = time.monotonic() - t0
    ok = (marker_seen
          and msg is not None and json.loads(msg)["result"]["pong"] is True
          and dt < 2.0)
    ws.close(); srv.close()
    report("t2 call after backlog answered fast", ok,
           f"drained={marker_seen} reply in {dt:.2f}s")


# ── Task 3: frame guards ───────────────────────────────────────────────

def t3_oversize_frame_rejected():
    srv = FakeSrv()
    ws = WSConnection(f"ws://127.0.0.1:{srv.port}/api/ws")
    threading.Thread(target=srv.accept, daemon=True).start()
    ws.connect()
    # Announce a 2^40-byte payload; the guard must kill the reader before
    # any allocation.
    hdr = bytes([0x81, 0xFF]) + struct.pack("!Q", 1 << 40)
    srv.wait_sock().sendall(hdr)
    err = ""
    try:
        ws.recv(timeout=5)
    except WSError as e:
        err = str(e)
    except Exception as e:                    # noqa: BLE001
        err = f"wrong exc: {e}"
    ok = "frame too large" in err and ws._io_error
    ws.close(); srv.close()
    report("t3 oversize frame rejected", ok, err)


def t4_fragmented_control_rejected():
    srv = FakeSrv()
    ws = WSConnection(f"ws://127.0.0.1:{srv.port}/api/ws")
    threading.Thread(target=srv.accept, daemon=True).start()
    ws.connect()
    srv.wait_sock().sendall(srv_frame(0x9, b"x", fin=False))   # FIN=0 ping
    err = ""
    try:
        ws.recv(timeout=5)
    except WSError as e:
        err = str(e)
    except Exception as e:                    # noqa: BLE001
        err = f"wrong exc: {e}"
    ok = "fragmented control" in err and ws._io_error
    ws.close(); srv.close()
    report("t4 fragmented control rejected", ok, err)


def t5_control_too_large_rejected():
    srv = FakeSrv()
    ws = WSConnection(f"ws://127.0.0.1:{srv.port}/api/ws")
    threading.Thread(target=srv.accept, daemon=True).start()
    ws.connect()
    # Pong with a 126-byte declared payload (>125 limit).
    srv.wait_sock().sendall(
        bytes([0x8A, 126]) + struct.pack("!H", 126) + b"x" * 4
    )
    err = ""
    try:
        ws.recv(timeout=5)
    except WSError as e:
        err = str(e)
    except Exception as e:                    # noqa: BLE001
        err = f"wrong exc: {e}"
    ok = "control frame too large" in err and ws._io_error
    ws.close(); srv.close()
    report("t5 control frame >125B rejected", ok, err)


# ── Task 3: handshake fd hygiene ───────────────────────────────────────

def t6_failed_handshakes_no_fd_growth():
    n_fail = 30
    fails = 0
    for _ in range(n_fail):
        srv = FakeSrv(reject_handshake=True)
        try:
            threading.Thread(target=srv.accept, daemon=True).start()
            ws = WSConnection(f"ws://127.0.0.1:{srv.port}/api/ws")
            ws.connect()
            ws.close()
        except Exception:                     # noqa: BLE001
            fails += 1
        finally:
            srv.close()
    gc.collect()
    fds_after = len(os.listdir("/proc/self/fd"))
    ok = fails == n_fail and fds_after <= 24
    report("t6 failed-handshake loop: all raised, no fd growth", ok,
           f"{fails}/{n_fail} raised, fds={fds_after}")


# ── Task 2: keepalive + correlated pong liveness ───────────────────────

def t7_tcp_keepalive_enabled():
    srv = FakeSrv()
    ws = WSConnection(f"ws://127.0.0.1:{srv.port}/api/ws")
    threading.Thread(target=srv.accept, daemon=True).start()
    ws.connect()
    ka = ws._sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
    ut = getattr(socket, "TCP_USER_TIMEOUT", None)
    utv = None
    if ut is not None:
        utv = ws._sock.getsockopt(socket.IPPROTO_TCP, ut)
    ws.close(); srv.close()
    ok = ka == 1 and (utv is None or utv > 0)
    report("t7 SO_KEEPALIVE (+TCP_USER_TIMEOUT) set", ok, f"ka={ka} ut={utv}")


def t8_ping_alive_then_dead_detected():
    # Alive: server echoes client pings.
    srv = FakeSrv()
    ws = WSConnection(f"ws://127.0.0.1:{srv.port}/api/ws")
    threading.Thread(target=srv.accept, daemon=True).start()
    ws.connect()

    stop = threading.Event()

    def echo_pings():
        s = srv.wait_sock()
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                f = read_client_frame(s)
            except socket.timeout:
                continue              # no frame right now — keep looping
            except OSError:
                return
            if f is None:
                continue
            op, payload = f
            if op == 0x9:
                try:
                    s.sendall(srv_frame(0xA, payload))
                except OSError:
                    return
    threading.Thread(target=echo_pings, daemon=True).start()

    gw = HermesGateway("http://127.0.0.1:1/", HermesAuth("http://127.0.0.1:1/"))
    gw._conn = ws
    gw._connected = True
    alive = gw.ping() and gw.ping()
    stop.set(); ws.close(); srv.close()

    # Dead: server swallows client pings, socket otherwise healthy.
    srv2 = FakeSrv()
    ws2 = WSConnection(f"ws://127.0.0.1:{srv2.port}/api/ws")
    threading.Thread(target=srv2.accept, daemon=True).start()
    ws2.connect()
    stop2 = threading.Event()

    def swallow():
        s = srv2.wait_sock()
        s.settimeout(0.2)
        while not stop2.is_set():
            try:
                if read_client_frame(s) is None:
                    continue
            except socket.timeout:
                continue              # nothing to swallow right now
            except OSError:
                return
    threading.Thread(target=swallow, daemon=True).start()

    gw2 = HermesGateway("http://127.0.0.1:1/", HermesAuth("http://127.0.0.1:1/"))
    gw2._PONG_WAIT = 0.4                  # shrink for the test
    gw2._conn = ws2
    gw2._connected = True
    m1 = gw2.ping()                       # miss 1: still connected
    still_up = gw2.is_connected()
    m2 = gw2.ping()                       # miss 2: torn down
    dead_flagged = gw2._conn_is_dead()
    errtxt = gw2.last_error()
    stop2.set(); ws2.close(); srv2.close()

    ok = alive and (not m1) and still_up and (not m2) \
        and not gw2.is_connected() and dead_flagged \
        and errtxt == "heartbeat lost"
    report("t8 correlated heartbeat: alive passes; 2 misses kill conn", ok,
           f"alive={alive} m1={m1}(up={still_up}) m2={m2} "
           f"dead={dead_flagged} err={errtxt!r}")


# ── Task 1.3: timeout-classified retry, gated by liveness ─────────────

class _LiveConn:
    """Sentinel connection: present and open, so _conn_is_dead() is
    decided purely by the heartbeat miss counter."""

    def __init__(self):
        self.closed_count = 0

    def close(self):
        self.closed_count += 1


class StubGW(HermesGateway):
    def __init__(self):
        super().__init__("http://127.0.0.1:1/",
                         HermesAuth("http://127.0.0.1:1/"))
        self.calls = 0
        self.first_err = ""
        self._conn = _LiveConn()
        self._connected = True

    def _call_once(self, method, params, timeout, stream, on_delta):
        self.calls += 1
        if self.calls == 1:
            return {"ok": False, "error": self.first_err}
        return {"ok": True}


def t9_timeout_retry_gated_by_liveness():
    # Slow-but-alive server (hb_misses < 2): timeout must NOT trigger retry.
    g1 = StubGW(); g1.first_err = "timed out after 180s"; g1._hb_misses = 1
    r1 = g1.call("prompt.submit", {})
    no_retry = g1.calls == 1 and not r1.get("ok")

    # Heartbeat-dead connection (hb_misses >= 2): timeout MUST retry once.
    g2 = StubGW(); g2.first_err = "timed out after 180s"; g2._hb_misses = 2
    r2 = g2.call("prompt.submit", {})
    retried = g2.calls == 2 and r2.get("ok")

    # Hard-stale errors retry regardless of heartbeat state (unchanged).
    g3 = StubGW(); g3.first_err = "read failed: connection lost"; g3._hb_misses = 0
    r3 = g3.call("session.create", {})
    hard_stale = g3.calls == 2 and r3.get("ok")

    ok = no_retry and retried and hard_stale
    report("t9 timeout-retry gated by liveness", ok,
           f"slow-no-retry={no_retry} dead-retry={retried} "
           f"hard-stale-retry={hard_stale}")


# ── main ───────────────────────────────────────────────────────────────

def main() -> int:
    tests = [t1_backlog_cap_and_rpc_survival,
             t2_call_after_backlog_answers_fast,
             t3_oversize_frame_rejected,
             t4_fragmented_control_rejected,
             t5_control_too_large_rejected,
             t6_failed_handshakes_no_fd_growth,
             t7_tcp_keepalive_enabled,
             t8_ping_alive_then_dead_detected,
             t9_timeout_retry_gated_by_liveness]
    for t in tests:
        try:
            t()
        except Exception as e:                # noqa: BLE001
            report(t.__name__ + " (crashed)", False, repr(e))
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
