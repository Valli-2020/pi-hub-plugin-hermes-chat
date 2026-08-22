"""Hermes gateway client — JSON-RPC over the dashboard WebSocket.

Protocol, verified against the running server on this Pi:

* Requests are JSON-RPC 2.0: ``{"jsonrpc","id","method","params"}``.
* Streaming/telemetry frames arrive WRAPPED as
  ``{"method":"event","params":{"type":<event>,"payload":{...}}}`` —
  the event name is ``params.type``, NOT the JSON-RPC ``method``.
* A turn's completion frame is ``message.complete`` with payload keys
  ``{text, usage, status, reasoning}``. ``text`` holds the full reply, so
  it is authoritative; accumulated ``message.delta`` text is the fallback.
* ``session.create`` returns ``{session_id, stored_session_id,
  message_count, messages, info}``.

One connection is shared by all Pi Hub users and calls are serialized
under a lock, so a long turn blocks other senders — acceptable for a
single-Pi dashboard and it keeps the agent's tool use sequential.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, Callable, Optional

from .auth import AuthError, HermesAuth
from .wsclient import WSConnection, WSError

# Frames that carry streamed assistant text.
_TEXT_DELTAS = ("message.delta",)
# Terminal frames for one prompt turn.
_DONE = ("message.complete", "turn.complete")


class HermesGateway:
    """Persistent WS to the local Hermes agent; serializes JSON-RPC calls."""

    def __init__(self, base_url: str, auth: HermesAuth):
        self._base = base_url.rstrip("/")
        self._auth = auth
        self._conn: Optional[WSConnection] = None
        self._lock = threading.Lock()
        self._rid = 0
        self._connected = False
        self._last_error: Optional[str] = None

    # ── connection ─────────────────────────────────────────────────────

    def _connect_locked(self) -> bool:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
        try:
            url = self._auth.ws_url("/api/ws")
            conn = WSConnection(url, timeout=20.0)
            conn.connect()
        except (AuthError, WSError, OSError) as e:
            self._last_error = str(e)
            self._connected = False
            return False
        self._conn = conn
        self._connected = True
        self._last_error = None
        # Drain the boot burst (gateway.ready, sessions.changed, ...).
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                if conn.recv(timeout=0.6) is None:
                    break
            except socket.timeout:
                break
            except Exception:
                break
        return True

    def connect(self) -> bool:
        with self._lock:
            return self._connect_locked()

    def is_connected(self) -> bool:
        return self._connected

    def last_error(self) -> Optional[str]:
        return self._last_error

    def ping(self) -> bool:
        """Send a WS ping to detect a dead connection. Thread-safe."""
        with self._lock:
            if self._conn is None or not self._connected:
                return False
            try:
                self._conn.send("pi", opcode=0x9)
                return True
            except Exception:
                self._connected = False
                self._last_error = "heartbeat failed"
                return False

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
            self._connected = False

    # ── RPC ────────────────────────────────────────────────────────────

    def _next_rid(self) -> str:
        self._rid += 1
        return f"ph{self._rid}"

    @staticmethod
    def _unwrap(msg: dict) -> tuple[str, dict]:
        """Return ``(event_type, payload)`` for a wrapped event frame."""
        params = msg.get("params")
        if not isinstance(params, dict):
            return "", {}
        etype = str(params.get("type") or "")
        payload = params.get("payload")
        if not isinstance(payload, dict):
            payload = {k: v for k, v in params.items()
                       if k not in ("type", "session_id")}
        return etype, payload

    def call(self, method: str, params: dict, timeout: float = 60.0,
             stream: bool = False,
             on_delta: Optional[Callable[[str], None]] = None) -> dict:
        """Send a request and wait for its result.

        With ``stream=True`` the call additionally accumulates assistant
        text until a terminal frame arrives (the shape ``prompt.submit``
        needs — its JSON-RPC ack returns immediately, long before the
        turn is done).

        If the connection turns out to be dead (server closed an idle
        socket — sends into a half-closed TCP connection can succeed),
        the call reconnects once and retries transparently.
        """
        res = self._call_once(method, params, timeout, stream, on_delta)
        if not res.get("ok"):
            stale = ("closed by server" in str(res.get("error"))
                     or "read failed" in str(res.get("error"))
                     or "not connected" in str(res.get("error")))
            if stale:
                # Retry once on a fresh connection. The plugin's send
                # handler passes no on_delta callback, so nothing that
                # already reached the user can be duplicated.
                res = self._call_once(method, params, timeout, stream,
                                      on_delta)
        return res

    def _call_once(self, method: str, params: dict, timeout: float,
                   stream: bool, on_delta: Optional[Callable[[str], None]]) -> dict:
        with self._lock:
            if not self._connected and not self._connect_locked():
                return {"ok": False, "error": f"not connected: {self._last_error}"}

            rid = self._next_rid()
            req = json.dumps({"jsonrpc": "2.0", "id": rid,
                              "method": method, "params": params})
            try:
                self._conn.send(req)                      # type: ignore[union-attr]
            except Exception:
                if not self._connect_locked():
                    return {"ok": False,
                            "error": f"send failed: {self._last_error}"}
                try:
                    self._conn.send(req)                  # type: ignore[union-attr]
                except Exception as e:
                    self._connected = False
                    return {"ok": False, "error": f"send failed: {e}"}

            parts: list[str] = []
            result: dict = {}
            got_ack = False
            usage: dict = {}
            deadline = time.time() + timeout

            while time.time() < deadline:
                try:
                    raw = self._conn.recv(                 # type: ignore[union-attr]
                        timeout=min(5.0, max(0.5, deadline - time.time()))
                    )
                except socket.timeout:
                    continue
                except Exception as e:
                    self._connected = False
                    if parts:
                        break
                    return {"ok": False, "error": f"read failed: {e}"}

                if raw is None:                            # server closed
                    self._connected = False
                    if parts:
                        break
                    return {"ok": False, "error": "connection closed by server"}

                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(msg, dict):
                    continue

                # Our JSON-RPC reply?
                if msg.get("id") == rid:
                    if msg.get("error"):
                        err = msg["error"]
                        detail = err.get("message") if isinstance(err, dict) else err
                        return {"ok": False, "error": str(detail)}
                    result = msg.get("result") or {}
                    got_ack = True
                    if not stream:
                        return {"ok": True, **result}
                    continue

                if msg.get("method") != "event":
                    continue

                etype, payload = self._unwrap(msg)
                if etype in _TEXT_DELTAS:
                    chunk = str(payload.get("text") or "")
                    if chunk:
                        parts.append(chunk)
                        if on_delta is not None:
                            try:
                                on_delta(chunk)
                            except Exception:
                                pass
                elif etype == "session.usage":
                    if isinstance(payload.get("usage"), dict):
                        usage = payload["usage"]
                    elif payload:
                        usage = payload
                elif etype in _DONE:
                    if isinstance(payload.get("usage"), dict):
                        usage = payload["usage"]
                    final = str(payload.get("text") or "")
                    return {
                        "ok": True,
                        **result,
                        "text": final or "".join(parts),
                        "usage": usage,
                        "status": payload.get("status") or "completed",
                    }
                elif etype in ("error", "agent.error"):
                    detail = payload.get("message") or payload.get("error")
                    if detail:
                        return {"ok": False, "error": str(detail)}

            if parts:
                return {"ok": True, **result, "text": "".join(parts),
                        "usage": usage, "status": "timeout"}
            if got_ack:
                return {"ok": True, **result, "text": "",
                        "status": "timeout",
                        "error": "no reply before timeout"}
            return {"ok": False, "error": f"timed out after {int(timeout)}s"}
