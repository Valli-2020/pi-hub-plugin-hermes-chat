"""Minimal stdlib RFC 6455 WebSocket client for the Hermes gateway.

Stdlib only. Text frames, continuation frames, ping/pong, close.
All reads go through one buffer (``_read``) — mixing buffered header
reads with raw ``recv()`` payload reads corrupts the stream whenever TCP
coalesces frames.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import socket
import struct
import urllib.parse
from typing import Optional

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WSError(Exception):
    """Raised on WebSocket connection, handshake, or framing errors."""


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
        self._closed = False

    # ── handshake ──────────────────────────────────────────────────────

    def connect(self) -> None:
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        expect = base64.b64encode(
            hashlib.sha1((key + _GUID).encode()).digest()
        ).decode()

        self._sock = socket.create_connection(
            (self._host, self._port), timeout=self._timeout
        )
        self._sock.sendall(
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
            chunk = self._sock.recv(4096)
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
        self._buf = bytearray(rest)
        self._closed = False

    # ── framing ────────────────────────────────────────────────────────

    def _read(self, n: int) -> bytes:
        """Read exactly n bytes through the single shared buffer."""
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
        mask = secrets.token_bytes(4)
        n = len(payload)
        if n < 126:
            hdr = bytes([0x80 | opcode, 0x80 | n])
        elif n < 65536:
            hdr = bytes([0x80 | opcode, 0xFE]) + struct.pack("!H", n)
        else:
            hdr = bytes([0x80 | opcode, 0xFF]) + struct.pack("!Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(hdr + mask + masked)

    def recv(self, timeout: float = 30.0) -> Optional[str]:
        """Return the next text message, or None when the peer closed.

        Raises ``socket.timeout`` if nothing arrives within ``timeout``.
        """
        if self._sock is None:
            raise WSError("not connected")
        self._sock.settimeout(timeout)

        frags: list[bytes] = []
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
            mask = self._read(4) if masked else None
            payload = self._read(ln) if ln else b""
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

            if opcode == 0x9:            # ping → pong
                try:
                    self.send(payload.decode("latin-1"), opcode=0xA)
                except Exception:
                    pass
                continue
            if opcode == 0xA:            # pong
                continue
            if opcode == 0x8:            # close
                self._closed = True
                return None
            if opcode in (0x1, 0x2):
                started = True
            elif opcode == 0x0 and not started:
                raise WSError("continuation frame without start")

            frags.append(payload)
            if fin:
                break

        return b"".join(frags).decode("utf-8", "replace")

    def close(self) -> None:
        self._closed = True
        if self._sock is not None:
            try:
                self._sock.sendall(b"\x88\x80\x00\x00\x00\x00")
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
