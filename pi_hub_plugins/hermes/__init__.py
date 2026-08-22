"""Pi Hub Hermes Chat plugin.

Adds a "Hermes" tab to the Pi Hub dashboard that chats with the Hermes
agent running locally on this Pi, over the dashboard's JSON-RPC
WebSocket (``/api/ws``). No A2A, no extra service.

Each Pi Hub user gets their own Hermes session, keyed by username, so
conversations don't bleed between accounts. One shared WebSocket carries
all of them and calls are serialized.

Auth: the dashboard binds 0.0.0.0 here, which puts it in gated mode, so
the plugin logs in with the credentials from ``~/.hermes/.env`` and mints
a single-use ``?ticket=`` per connection. See auth.py for the details.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from pi_hub.plugins.base import (
    ActionDef,
    Plugin,
    PluginContext,
    RouteDef,
    TabUIDef,
    thread_cancel,
)

from .auth import HermesAuth, read_env_credentials
from .gateway import HermesGateway

DEFAULT_URL = "http://127.0.0.1:9119"

_ICON = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'
    "</svg>"
)


class HermesPlugin(Plugin):
    name = "hermes"
    version = "0.1.0"
    description = "Chat with the local Hermes agent — per-user sessions"
    min_core_version = "7.7.0"
    capabilities: list[str] = []

    # ── lifecycle ──────────────────────────────────────────────────────

    def load(self, ctx: PluginContext) -> None:
        self.ctx = ctx
        cfg = ctx.get_config()
        cfg.setdefault("hermes_url", DEFAULT_URL)
        cfg.setdefault("username", "")
        cfg.setdefault("password", "")
        cfg.setdefault("timeout_seconds", 180)
        ctx.save_config()

        self._sessions: dict[str, str] = {}
        self._history: dict[str, list[dict]] = {}
        self._lock = threading.Lock()
        self._gw: Optional[HermesGateway] = None
        self._running = True

        ctx.run_task("connect", self._keeper)

    def unload(self) -> None:
        self._running = False
        if self._gw is not None:
            self._gw.close()
            self._gw = None

    # ── connection keeper ──────────────────────────────────────────────

    def _build_gateway(self) -> HermesGateway:
        cfg = self.ctx.get_config()
        url = str(cfg.get("hermes_url") or DEFAULT_URL)
        user = str(cfg.get("username") or "")
        pw = str(cfg.get("password") or "")
        if not user or not pw:
            env_user, env_pw = read_env_credentials()
            user = user or env_user
            pw = pw or env_pw
        return HermesGateway(url, HermesAuth(url, user, pw))

    def _keeper(self) -> None:
        """Keep one WS to Hermes alive, with backoff on failure."""
        cancel = thread_cancel()
        backoff = 2.0
        announced = False
        while self._running and not (cancel is not None and cancel.is_set()):
            gw = self._gw
            if gw is None or not gw.is_connected():
                try:
                    gw = self._build_gateway()
                    if gw.connect():
                        self._gw = gw
                        backoff = 2.0
                        if not announced:
                            self.ctx.toast("Hermes chat connected", "success")
                            announced = True
                        # Sessions from the dead connection are gone.
                        with self._lock:
                            self._sessions.clear()
                    else:
                        self._gw = gw            # keep it for last_error()
                except RuntimeError:
                    return                       # context died: unloaded
                except Exception:
                    pass
            if self._gw is None or not self._gw.is_connected():
                time.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
            else:
                # Heartbeat: the dashboard closes idle WS connections;
                # ping periodically so a dead socket is caught here
                # instead of on the next user message.
                if not self._gw.ping():
                    with self._lock:
                        self._sessions.clear()
                    self._gw = None
                    backoff = 2.0
                time.sleep(20.0)

    # ── session helpers ────────────────────────────────────────────────

    @staticmethod
    def _user_of(session: Any) -> str:
        if isinstance(session, dict):
            return str(session.get("user") or session.get("username") or "default")
        return "default"

    def _remember(self, user: str, prompt: str, reply: str) -> None:
        """Append one turn to this user's rolling transcript (last 40)."""
        stamp = time.strftime("%H:%M:%S")
        with self._lock:
            log = self._history.setdefault(user, [])
            log.append({"time": stamp, "who": "you",
                        "message": prompt[:300]})
            log.append({"time": stamp, "who": "hermes",
                        "message": (reply or "(empty reply)")[:300]})
            if len(log) > 40:
                del log[: len(log) - 40]

    def _session_for(self, user: str, create: bool = True) -> tuple[str, str]:
        """Return ``(session_id, error)`` for this Pi Hub user."""
        with self._lock:
            sid = self._sessions.get(user)
        if sid:
            return sid, ""
        if not create:
            return "", ""
        gw = self._gw
        if gw is None or not gw.is_connected():
            return "", "Hermes not connected"
        res = gw.call("session.create", {}, timeout=45.0)
        if not res.get("ok"):
            return "", str(res.get("error") or "session.create failed")
        sid = str(res.get("session_id") or "")
        if not sid:
            return "", "Hermes returned no session id"
        with self._lock:
            self._sessions[user] = sid
        return sid, ""

    # ── declarative surface ────────────────────────────────────────────

    def get_routes(self) -> list[RouteDef]:
        return [
            RouteDef("GET", "/health", self.health),
            RouteDef("POST", "/send", self.send),
            RouteDef("POST", "/new-session", self.new_session),
        ]

    def get_ui(self) -> list[Any]:
        return [
            TabUIDef(
                id="hermes",
                label="Hermes",
                icon_svg=_ICON,
                position=6,
                poll_endpoint="/api/plugin/hermes/health",
                actions=[
                    ActionDef(
                        "send",
                        "Send Message",
                        style="primary",
                        fields=[
                            {
                                "name": "text",
                                "label": "Message to Hermes",
                                "type": "text",
                                "placeholder": "Ask the agent something…",
                            }
                        ],
                    ),
                    ActionDef("new-session", "New Session", style="secondary"),
                ],
            )
        ]

    # ── route handlers ─────────────────────────────────────────────────

    def health(self, session: Any = None, body: Any = None,
               **_: Any) -> tuple[Any, int]:
        gw = self._gw
        online = bool(gw is not None and gw.is_connected())
        user = self._user_of(session)
        with self._lock:
            mine = self._sessions.get(user, "")
            total = len(self._sessions)
        out: dict[str, Any] = {
            "status": "online" if online else "offline",
            "hermes_url": str(self.ctx.get_config().get("hermes_url") or ""),
            "transport": "local websocket (/api/ws)",
            "my_session": mine or "none yet",
            "active_sessions": total,
        }
        with self._lock:
            convo = list(self._history.get(user, []))
        if convo:
            out["conversation"] = convo[-12:]
        else:
            out["conversation"] = []
        if not online:
            out["last_error"] = (
                gw.last_error() if gw is not None else "connecting…"
            ) or "connecting…"
        return out, 200

    def send(self, session: Any = None, body: Any = None,
             **_: Any) -> tuple[Any, int]:
        body = body if isinstance(body, dict) else {}
        text = str(body.get("text") or "").strip()
        if not text:
            return {"ok": False, "error": "empty message"}, 400

        gw = self._gw
        if gw is None or not gw.is_connected():
            err = (gw.last_error() if gw is not None else "") or "not connected"
            return {"ok": False, "error": f"Hermes offline: {err}"}, 503

        user = self._user_of(session)
        sid, err = self._session_for(user)
        if err:
            return {"ok": False, "error": err}, 503

        try:
            timeout = float(self.ctx.get_config().get("timeout_seconds") or 180)
        except (TypeError, ValueError):
            timeout = 180.0

        res = gw.call(
            "prompt.submit",
            {"session_id": sid, "text": text},
            timeout=timeout,
            stream=True,
        )
        if not res.get("ok"):
            return {"ok": False, "error": str(res.get("error") or "failed")}, 502

        reply = res.get("text") or ""
        self._remember(user, text, reply)
        usage = res.get("usage") or {}
        return {
            "ok": True,
            "text": res.get("text") or "",
            "session_id": sid,
            "status": res.get("status") or "complete",
            "tokens": {
                "input": usage.get("input"),
                "output": usage.get("output"),
                "total": usage.get("total"),
                "context_percent": usage.get("context_percent"),
                "model": usage.get("model"),
            },
        }, 200

    def new_session(self, session: Any = None, body: Any = None,
                    **_: Any) -> tuple[Any, int]:
        user = self._user_of(session)
        with self._lock:
            self._sessions.pop(user, None)
            self._history.pop(user, None)
        sid, err = self._session_for(user)
        if err:
            return {"ok": False, "error": err}, 503
        return {"ok": True, "message": "New Hermes session started",
                "session_id": sid}, 200

    def open_chat(self, session: Any = None, body: Any = None,
                  **_: Any) -> tuple[Any, int]:
        """Kept for API compatibility; the tab itself is the chat UI."""
        return {"ok": True, "message": "Use the Hermes tab to chat"}, 200


PLUGIN_CLASS = HermesPlugin
