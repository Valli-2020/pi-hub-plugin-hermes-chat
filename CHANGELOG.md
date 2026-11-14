# Changelog

## 0.2.0

- Every setting is now in Settings -> Plugins -> Configure: Hermes URL, dashboard
  username and password (password field), path of the Hermes .env file, reply
  timeout, tab label, transcript length / visible entries / characters per entry,
  heartbeat interval and maximum reconnect delay.
- Changing the URL, credentials or .env path reconnects at once; the other
  settings apply live (the tab label after reload).
- `migrate_config` adds the new keys to existing 0.1.0 configs; the stored URL,
  username and password are kept.
- Added `pihub-plugin.json` (API v2, no capabilities, min core 8.3.0) and an MIT LICENSE.
- Removed the leftover `pi_hub_plugins/plugins.json` (the store never extracts it).
- Connection hardening from the field: reader thread keeps WebSocket pings answered, correlated ping/pong heartbeat, no blind re-send of a prompt on a slow server, frame size caps, TCP keepalive, always mint a fresh ticket on reconnect. Includes the hardening and WebSocket client tests.

## 0.1.0

- First version: Hermes tab with per-user sessions over the dashboard WebSocket.
