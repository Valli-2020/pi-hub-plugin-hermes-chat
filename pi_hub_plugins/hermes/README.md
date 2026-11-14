# pi-hub-plugin-hermes-chat

Chat with your Hermes agent from the Pi Hub dashboard — the agent runs
locally on the same Pi, reached over its dashboard WebSocket. No A2A, no
extra services.

> **Status: working.** Installed and verified live against Pi Hub core
> 7.7.0 and Hermes Agent's gated dashboard (2026-08-21).

## What you get

A "Hermes" tab in Pi Hub with a Send Message form, your own persistent
Hermes session, and a rolling transcript (40 entries by default). Each Pi Hub
user gets an isolated session — transcripts never cross accounts.

## How it connects

The plugin performs the same auth dance as the dashboard web UI:

1. `POST /auth/password-login` using the basic-auth credentials from
   Hermes' `.env` file (`HERMES_DASHBOARD_BASIC_AUTH_USERNAME` /
   `_PASSWORD`) → session cookie
2. `POST /api/auth/ws-ticket` → single-use ticket (~30 s TTL)
3. `GET /api/ws?ticket=…` → JSON-RPC 2.0 WebSocket

Streaming frames arrive wrapped as
`{"method":"event","params":{"type":…,"payload":…}}`; each turn ends
with a `message.complete` event carrying the full reply and token usage.
The dashboard closes idle sockets, so a keeper thread pings every 20 s by default
and any call hitting a dead connection reconnects once and retries.

## Install

Install from the Pi Hub plugin store (Settings -> Plugins), then enable it.
Requires:

- Pi Hub core 8.3.0 or newer
- A running Hermes dashboard (`hermes dashboard ...`) reachable at the
  configured URL (default `http://127.0.0.1:9119`)
- Basic-auth credentials, either in the plugin settings or in Hermes' `.env`

The plugin needs no Pi Hub capabilities.

## Configuration

All settings are in Settings -> Plugins -> Configure.

| Key | Type | Section | Default | Meaning |
|---|---|---|---|---|
| `hermes_url` | url | Connection | `http://127.0.0.1:9119` | Hermes dashboard address (reconnects on change) |
| `username` | text | Connection | empty | Dashboard username; empty = read from the `.env` file |
| `password` | password | Connection | empty | Dashboard password; empty = read from the `.env` file |
| `env_path` | text | Connection | `~/.hermes/.env` | File with `HERMES_DASHBOARD_BASIC_AUTH_USERNAME` / `_PASSWORD` |
| `timeout_seconds` | number | Chat | 180 | Wait for one reply (10-3600) |
| `tab_label` | text | Chat | `Hermes` | Sidebar tab name (after reload) |
| `history_limit` | number | Transcript | 40 | Entries kept per user (4-200) |
| `history_visible` | number | Transcript | 12 | Entries shown in the tab (2-100) |
| `history_chars` | number | Transcript | 300 | Max characters per entry (50-2000) |
| `heartbeat_seconds` | number | Connection health | 20 | Ping interval of the idle socket (5-120) |
| `reconnect_max_seconds` | number | Connection health | 60 | Max back-off between reconnects (5-600) |

## Layout

| File | Role |
|---|---|
| `wsclient.py` | stdlib RFC 6455 WebSocket client |
| `auth.py` | credential loading, login, ticket minting |
| `gateway.py` | persistent WS + serialized JSON-RPC calls |
| `__init__.py` | plugin routes, tab UI, per-user sessions |

## Notes

- Replies arrive complete rather than token-streamed; the tab renderer
  polls every 10 s, so true streaming would need core frontend changes.
- Chat lives in the tab itself because Pi Hub never serves plugin static
  files as `text/html` (anti-XSS by design).
