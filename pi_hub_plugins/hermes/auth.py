"""Hermes dashboard auth: password login -> session cookie -> WS ticket.

The dashboard on this Pi binds 0.0.0.0, so it runs in *gated* mode:
``should_require_auth()`` is True for any non-loopback bind, and the
legacy ``?token=`` query param is only honoured on a loopback bind. The
working path (verified against the running server) is:

    POST /auth/password-login   {provider, username, password}  -> cookies
    POST /api/auth/ws-ticket    (with cookies)                  -> ticket
    GET  /api/ws?ticket=<t>                                     -> 101

Tickets are single-use with a ~30s TTL, so one is minted per connection.
Credentials come from ``~/.hermes/.env`` (mode 0600), the same file the
hermes-dashboard systemd unit loads via EnvironmentFile.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

ENV_PATH = os.path.expanduser("~/.hermes/.env")
USER_KEY = "HERMES_DASHBOARD_BASIC_AUTH_USERNAME"
PASS_KEY = "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"


class AuthError(Exception):
    """Raised when login or ticket minting fails."""


def read_env_credentials(path: str = "") -> tuple[str, str]:
    """Return ``(username, password)`` from the Hermes .env file.

    Returns empty strings when the file or keys are absent — callers then
    fall back to an unauthenticated (loopback) attempt.
    """
    target = path or ENV_PATH
    user = pw = ""
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key == USER_KEY:
                    user = val
                elif key == PASS_KEY:
                    pw = val
    except OSError:
        return "", ""
    return user, pw


class HermesAuth:
    """Holds a dashboard session and mints per-connection WS tickets."""

    def __init__(self, base_url: str, username: str = "", password: str = "",
                 timeout: float = 15.0):
        self.base = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar)
        )
        self._logged_in = False

    # ── internals ──────────────────────────────────────────────────────

    def _post(self, path: str, payload: Optional[dict] = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else b""
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method="POST"
        )
        with self._opener.open(req, timeout=self.timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
        try:
            return json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {}

    def _providers(self) -> list[str]:
        try:
            req = urllib.request.Request(self.base + "/api/auth/providers")
            with self._opener.open(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            return []
        out = []
        for p in data.get("providers", []) or []:
            if isinstance(p, dict) and p.get("supports_password") and p.get("name"):
                out.append(str(p["name"]))
        return out

    # ── public API ─────────────────────────────────────────────────────

    def auth_required(self) -> bool:
        """True when the dashboard rejects unauthenticated API calls."""
        try:
            req = urllib.request.Request(self.base + "/api/auth/me")
            with self._opener.open(req, timeout=self.timeout) as resp:
                json.loads(resp.read().decode("utf-8", "replace"))
            return False
        except urllib.error.HTTPError as e:
            return e.code in (401, 403)
        except Exception:
            return True

    def login(self) -> None:
        """Establish a session cookie. No-op when already logged in."""
        if self._logged_in:
            return
        if not self.username or not self.password:
            raise AuthError(
                f"no dashboard credentials — set {USER_KEY}/{PASS_KEY} in {ENV_PATH}"
            )
        providers = self._providers() or ["basic"]
        last = ""
        for provider in providers:
            try:
                res = self._post(
                    "/auth/password-login",
                    {
                        "provider": provider,
                        "username": self.username,
                        "password": self.password,
                    },
                )
            except urllib.error.HTTPError as e:
                last = f"{provider}: HTTP {e.code}"
                continue
            except Exception as e:                       # network-level
                raise AuthError(f"login failed: {e}") from e
            if res.get("ok"):
                self._logged_in = True
                return
            last = f"{provider}: {res.get('detail') or 'rejected'}"
        raise AuthError(f"login failed ({last or 'no password provider'})")

    def ws_ticket(self) -> str:
        """Mint a single-use WS ticket, logging in / re-logging as needed."""
        self.login()
        try:
            res = self._post("/api/auth/ws-ticket")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                # Session expired — drop it and retry once.
                self._logged_in = False
                self._jar.clear()
                self.login()
                res = self._post("/api/auth/ws-ticket")
            else:
                raise AuthError(f"ws-ticket failed: HTTP {e.code}") from e
        except Exception as e:
            raise AuthError(f"ws-ticket failed: {e}") from e
        ticket = str(res.get("ticket") or "")
        if not ticket:
            raise AuthError("ws-ticket response had no ticket")
        return ticket

    def ws_url(self, path: str = "/api/ws") -> str:
        """Build the ws:// URL with a freshly minted ticket, when needed."""
        scheme = "wss" if self.base.startswith("https://") else "ws"
        netloc = self.base.split("://", 1)[1]
        if self.auth_required():
            ticket = urllib.parse.quote(self.ws_ticket())
            return f"{scheme}://{netloc}{path}?ticket={ticket}"
        return f"{scheme}://{netloc}{path}"
