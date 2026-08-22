# pi-hub-plugin-hermes-chat

Chat with your Hermes agent from the Pi Hub dashboard — the agent runs
locally on the same Pi, reached over its dashboard WebSocket. No A2A, no
extra services.

> **Status: working.** Installed and verified live against Pi Hub core
> 7.7.0 and Hermes Agent's gated dashboard (2026-08-21).

## What you get

A "Hermes" tab in Pi Hub with a Send Message form, your own persistent
Hermes session, and a rolling transcript (last 40 entries). Each Pi Hub
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
The dashboard closes idle sockets, so a keeper thread pings every 20 s
and any call hitting a dead connection reconnects once and retries.

## Install

Copy `pi_hub_plugins/hermes/` into your Pi Hub's `pi_hub_plugins/`
directory and add `"hermes"` to `pi_hub_plugins/plugins.json`, then
restart Pi Hub. Requires:

- Pi Hub core ≥ 7.7.0
- A running Hermes dashboard (`hermes dashboard …`) reachable at the
  configured URL (default `http://127.0.0.1:9119`)
- Basic-auth credentials present in Hermes' `.env`

### Config (`config.json`)

```json
{
  "hermes_url": "http://127.0.0.1:9119",
  "username": "",
  "password": "",
  "timeout_seconds": 180
}
```

Leave `username`/`password` empty to read them from Hermes' `.env`.

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
