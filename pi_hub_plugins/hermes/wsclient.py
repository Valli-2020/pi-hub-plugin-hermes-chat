"""Minimal stdlib RFC 6455 WebSocket client for the Hermes gateway.

Stdlib only. Text frames, continuation frames, ping/pong, close.
All reads go through one buffer (``_read``) — mixing buffered header
reads with raw ``recv()`` payload reads corrupts the stream whenever TCP
coalesces frames.

A daemon reader thread owns the socket for reading from the moment the
handshake completes. This keeps protocol-level keepalives alive: the
dashboard (bound to 0.0.0.0, i.e. non-loopback) runs uvicorn's WS ping
at 20s interval / 20s timeout and closes the connection with 1006 when a
ping goes unanswered. A client that only read during RPC calls used to
let every idle gap kill the socket (~every 50–100 s), forcing a
reconnect that wiped all plugin chat sessions. The reader thread
answers pings and buffers pushed frames continuously, whether or not
anyone is mid-call; ``recv()`` just waits on the message queue.

Backpressure: unsolicited frames are classified at enqueue time. Frames
that look like JSON-RPC responses (a top-level ``"id"`` key) go into an
unbounded lane so a real reply is never dropped; everything else (the
dashboard's gateway.ready / sessions.changed push storm) goes into a
bounded lane capped at MAX_PUSH_QUEUE with drop-oldest. A call purges
the push backlog before sending its request, so it only ever waits for
frames produced after it started.
"""

from __future__ import annotations

import base64
import hashlib
import json
import queue
import secrets
import socket
import struct
import threading
import time
import urllib.parse
from typing import Optional

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Hard frame/message limits (RFC 6455 §5.5 sanity + DoS guard).
MAX_FRAME_BYTES = 16 * 1024 * 1024        # one protocol frame's payload
MAX_MESSAGE_BYTES = 32 * 1024 * 1024      # assembled across continuations

# Unsolicited-frame backlog cap. Push frames beyond this are dropped
# oldest-first; RPC replies never land here.
MAX_PUSH_QUEUE = 256

# TCP keepalive knobs.
_TCP_KEEPIDLE = 30
_TCP_KEEPINTVL = 10
_TCP_KEEPCNT = 3


class WSError(Exception):
    """Raised on WebSocket connection, handshake, or framing errors."""


def _looks_like_rpc(text: str) -> bool:
    """Cheap classification of an incoming text frame.

    True when the payload parses as a dict carrying a top-level ``id``
    key, i.e. plausibly a reply to one of our requests. Never raises.
    """
    try:
        obj = json.loads(text)
    except Exception:
        return False
    return isinstance(obj, dict) and "id" in obj


class WSConnection:
    """Client-side WebSocket over plain ws:// (loopback use)."""

    def __init__(self, url: str, timeout: float = 20.0):
        p = urllib.parse.urlparse(url)
        self._host = p.hostname or "127.0.0.1"
        self._port = p.port or 80
        self._path = p.path or "/"
        if p.query:
            self._path += "?" + p.query
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._buf = bytearray()
        self._closed = False           # local close() called
        self._io_error = False         # reader hit a socket-level error
        self._reader_err = ""          # why the reader died (diagnostics)
        self._sndlock = threading.Lock()
        self._rpc_rx: "queue.Queue[Optional[str]]" = queue.Queue()
        # Bounded push lane + Condition so drop-oldest can evict under
        # the same lock the reader enqueues through.
        self._push_cv = threading.Condition()
        self._push: list[str] = []
        # Ping/pong liveness correlation.
        self._pending_pongs: "queue.Queue[bytes]" = queue.Queue()
        self._reader: Optional[threading.Thread] = None

    # ── handshake ──────────────────────────────────────────────────────

    def connect(self) -> None:
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        expect = base64.b64encode(
            hashlib.sha1((key + _GUID).encode()).digest()
        ).decode()

        sock: Optional[socket.socket] = None
        try:
            sock = socket.create_connection(
                (self._host, self._port), timeout=self._timeout
            )
            self._tune_sock(sock)
            sock.sendall(
                (
                    f"GET {self._path} HTTP/1.1\r\n"
                    f"Host: {self._host}:{self._port}\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode()
            )

            head = bytearray()
            while b"\r\n\r\n" not in head:
                chunk = sock.recv(4096)
                if not chunk:
                    raise WSError("connection closed during handshake")
                head += chunk

            raw, _, rest = bytes(head).partition(b"\r\n\r\n")
            text = raw.decode("utf-8", "replace")
            status = text.split("\r\n", 1)[0]
            if "101" not in status:
                raise WSError(f"handshake failed: {status}")
            if expect not in text:
                raise WSError("invalid Sec-WebSocket-Accept")

            # Success path only now: publish state and start the reader.
            self._sock = sock
            self._buf = bytearray(rest)
            self._closed = False
            self._io_error = False
            self._reader_err = ""
            while not self._pending_pongs.empty():
                self._pending_pongs.get_nowait()   # stale tokens from prior conns
            self._reader = threading.Thread(
                target=self._reader_loop, name="ws-reader", daemon=True
            )
            self._reader.start()
            sock = None                             # ownership transferred
        finally:
            # Any failure above closes the fresh fd exactly once; the
            # success path has already nulled ``sock``, leaving close()
            # to own the published socket.
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    @staticmethod
    def _tune_sock(sock: socket.socket) -> None:
        """TCP-level liveness: keepalive probes catch a silently dead
        peer even when we send nothing ourselves."""
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        tcp = socket.IPPROTO_TCP
        idle = getattr(socket, "TCP_KEEPIDLE", None)
        if idle is not None:
            try:
                sock.setsockopt(tcp, idle, _TCP_KEEPIDLE)
                sock.setsockopt(tcp, getattr(socket, "TCP_KEEPINTVL"),
                                _TCP_KEEPINTVL)
                sock.setsockopt(tcp, getattr(socket, "TCP_KEEPCNT"),
                                _TCP_KEEPCNT)
            except OSError:
                pass
        ut = getattr(socket, "TCP_USER_TIMEOUT", None)
        if ut is not None:
            try:
                # ~keepidle + intvl*cnt window, ms. A stuck connection
                # errors out instead of blocking sendall forever.
                sock.setsockopt(tcp, ut, (_TCP_KEEPIDLE + _TCP_KEEPINTVL * _TCP_KEEPCNT) * 1000)
            except OSError:
                pass

    # ── reader thread ──────────────────────────────────────────────────

    def _reader_loop(self) -> None:
        """Continuously read the socket; answer pings; queue messages.

        Runs for the life of the connection. ``close()`` closes the
        socket, which unblocks the pending read and ends the thread.
        """
        sock = self._sock
        if sock is None:
            return
        try:
            sock.settimeout(None)      # block; close() breaks us out
            while not self._closed:
                msg = self._read_message()
                if msg is None:        # peer sent a close frame
                    self._rpc_rx.put(None)
                    self._wake_push(None)
                    return
                if msg:
                    self._enqueue(msg)
        except Exception as e:
            if not self._closed:
                self._io_error = True
                self._reader_err = str(e) or e.__class__.__name__
                self._rpc_rx.put(None)     # wake the consumer
                self._wake_push(None)

    def _read_message(self) -> Optional[str]:
        """Read one complete message (reader thread only).

        Returns ``None`` on a close frame. Ping/pong control frames are
        handled inline — pings get an immediate pong, which is what keeps
        the server's keepalive from reaping an idle connection — and
        never surface to the caller.
        """
        frags: list[bytes] = []
        total_len = 0
        started = False
        while True:
            h = self._read(2)
            fin = bool(h[0] & 0x80)
            opcode = h[0] & 0x0F
            masked = bool(h[1] & 0x80)
            ln = h[1] & 0x7F
            if ln == 126:
                ln = struct.unpack("!H", self._read(2))[0]
            elif ln == 127:
                ln = struct.unpack("!Q", self._read(8))[0]

            if opcode in (0x8, 0x9, 0xA):          # control frames (RFC 6455 §5.5)
                if not fin:
                    raise WSError("fragmented control frame")
                if ln > 125:
                    raise WSError(f"control frame too large: {ln}B")
                if opcode != 0x9 and ln > 0 and not masked:
                    pass                           # servers may send unmasked; fine
            if ln > MAX_FRAME_BYTES:
                raise WSError(f"frame too large: {ln} bytes")

            mask = self._read(4) if masked else None
            payload = self._read(ln) if ln else b""
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

            if opcode == 0x9:            # ping → pong (keepalive answer)
                try:
                    # Byte-EXACT echo. send() passes bytes through
                    # untouched; decoding to str first (the old
                    # latin-1 → utf-8 roundtrip) corrupted any payload
                    # byte >= 0x80, so the server saw a pong that didn't
                    # match its ping and closed with 1011 "keepalive
                    # ping timeout" — the source of the recurring
                    # ~50s disconnect storm.
                    self.send(payload, opcode=0xA)
                except Exception:
                    pass
                continue
            if opcode == 0xA:            # pong → record for liveness checks
                try:
                    self._pending_pongs.put_nowait(payload)
                except queue.Full:
                    pass
                continue
            if opcode == 0x8:            # close
                return None
            if opcode in (0x1, 0x2):
                started = True
            elif opcode == 0x0 and not started:
                raise WSError("continuation frame without start")

            total_len += ln
            if total_len > MAX_MESSAGE_BYTES:
                raise WSError(f"message too large: {total_len} bytes")
            frags.append(payload)
            if fin:
                break

        return b"".join(frags).decode("utf-8", "replace")

    # ── inbound classification ────────────────────────────────────────

    def _enqueue(self, msg: str) -> None:
        """Route one text message into its lane (reader thread only)."""
        if _looks_like_rpc(msg):
            self._rpc_rx.put(msg)      # replies are never dropped
        else:
            self._offer_push(msg)

    def _offer_push(self, msg: Optional[str]) -> None:
        """Add to the bounded push lane, dropping oldest when full."""
        with self._push_cv:
            if len(self._push) >= MAX_PUSH_QUEUE:
                del self._push[0]
            self._push.append(msg)
            self._push_cv.notify()

    def _wake_push(self, sentinel: Optional[str]) -> None:
        """Append a sentinel to the push lane without enforcing the cap,
        so a waiting recv() wakes immediately."""
        with self._push_cv:
            self._push.append(sentinel)
            self._push_cv.notify()

    def purge_pending(self) -> None:
        """Discard queued pre-call frames (push backlog and any replies
        belonging to older, abandoned calls)."""
        while True:
            try:
                self._rpc_rx.get_nowait()
            except queue.Empty:
                break
        with self._push_cv:
            self._push.clear()

    # ── framing ────────────────────────────────────────────────────────

    def _read(self, n: int) -> bytes:
        """Read exactly n bytes through the single shared buffer.

        Only the reader thread runs this once connected.
        """
        while len(self._buf) < n:
            if self._sock is None:
                raise WSError("not connected")
            data = self._sock.recv(65536)
            if not data:
                raise WSError("connection closed")
            self._buf += data
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def send(self, text: str, opcode: int = 0x1) -> None:
        if self._sock is None or self._closed:
            raise WSError("not connected")
        payload = text.encode("utf-8") if isinstance(text, str) else text
        if len(payload) > MAX_FRAME_BYTES:
            raise WSError(f"outgoing frame too large: {len(payload)} bytes")
        mask = secrets.token_bytes(4)
        n = len(payload)
        if n < 126:
            hdr = bytes([0x80 | opcode, 0x80 | n])
        elif n < 65536:
            hdr = bytes([0x80 | opcode, 0xFE]) + struct.pack("!H", n)
        else:
            hdr = bytes([0x80 | opcode, 0xFF]) + struct.pack("!Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self._sndlock:              # reader thread pings from here too
            self._sock.sendall(hdr + mask + masked)

    # ── liveness ───────────────────────────────────────────────────────

    def send_ping(self, token: bytes = b"pi") -> bool:
        """Send a WS ping carrying ``token``. False when unusable."""
        if self._sock is None or self._closed:
            return False
        try:
            self.send(token, opcode=0x9)
        except Exception:
            return False
        return True

    def await_pong(self, token: bytes = b"pi", timeout: float = 5.0) -> bool:
        """True once OUR ping's echo arrives within ``timeout``.

        Pongs for other pingers (uvicorn's own keepalive) are consumed
        until ours shows up, so concurrent heartbeats can't confuse the
        check.
        """
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                item = self._pending_pongs.get(timeout=remaining)
            except queue.Empty:
                return False
            if item == token:
                return True
            # someone else's pong — ignore, keep waiting

    # ── receive ────────────────────────────────────────────────────────

    def recv(self, timeout: float = 30.0) -> Optional[str]:
        """Return the next text message, or None when the peer closed.

        Raises ``socket.timeout`` if nothing arrives within ``timeout``.
        Control frames are consumed continuously by the reader thread;
        this waits first on RPC replies, then on the bounded push lane.

        A ``None`` pulled from either lane is a lifecycle sentinel (clean
        close, or the reader died) — it goes through ``_interpret``, so
        socket-level deaths surface as WSError instead of being mistaken
        for an empty lane and polled away.
        """
        if self._reader is None:
            raise WSError("not connected")
        if self._closed:
            raise WSError("not connected")
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout(
                    f"no message within {timeout}s"
                )
            got_rpc = True
            try:
                item = self._rpc_rx.get(timeout=min(remaining, 0.05))
            except queue.Empty:
                got_rpc = False
                item = None
            if got_rpc:
                return self._interpret(item)
            # RPC lane quiet — take from the bounded push lane.
            with self._push_cv:
                got_push = bool(self._push)
                item2 = self._push.pop(0) if got_push else None
                if got_push:
                    self._push_cv.notify()
            if got_push:
                return self._interpret(item2)

    def _interpret(self, item: Optional[str]) -> Optional[str]:
        if item is None:
            if self._io_error:
                # Socket-level death. Prefer the reader's actual reason
                # (frame guard, RST, ...) so callers can tell a protocol
                # violation from a plain lost connection; fall back to
                # the generic wording the gateway's retry predicate
                # matches on.
                detail = self._reader_err or "connection lost"
                raise WSError(f"read failed: {detail}")
            return None                  # clean close frame from the peer
        return item

    def close(self) -> None:
        self._closed = True
        if self._sock is not None:
            try:
                with self._sndlock:
                    self._sock.sendall(b"\x88\x80\x00\x00\x00\x00")
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
