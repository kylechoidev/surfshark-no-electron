# Local Control & Web API Reference (`/api/v1/*`)

Surf Shark Ultra Lite exposes a single JSON API over two transports:
1. **Unix Domain Socket (`$XDG_RUNTIME_DIR/surfshark-ultralite/control.sock`):** Mode `0600`, pre-authenticated by OS filesystem permissions. Used by the `surfshark-lite` CLI.
2. **Loopback TCP (`http://127.0.0.1:8777`):** Protected by `Host`, `Origin`, `Sec-Fetch-Site`, `X-SSUL: 1` header on mutating methods, and `HttpOnly; SameSite=Strict` session cookies (`ssul_session`).

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Liveness check (`{"ok": true, "version": "2.0.0"}`) |
| `GET` | `/api/v1/status` | Full connection state, active cluster, auth summary, 7-state security verdict, and telemetry |
| `GET` | `/api/v1/events` | Server-Sent Events (SSE) stream (`state`, `telemetry`, `auth`, `settings`) |
| `POST` | `/api/v1/connect` | Connect or switch to `{"target": "fastest", "kind": null, "physical_only": false, "takeover": false}` |
| `POST` | `/api/v1/switch` | Fast `<100ms` in-place peer switch (`{"target": "sfo"}`) |
| `POST` | `/api/v1/disconnect` | Tear down active WireGuard tunnel (`{"takeover": false}`) |
| `POST` | `/api/v1/reconnect` | Reconnect to current or last cluster |
| `GET` | `/api/v1/servers` | Query catalog (`?q=`, `?country=`, `?kind=`, `?refresh=1`) |
| `POST` | `/api/v1/servers/probe` | Probe ICMP RTT (`{"scope": "nearest"}`) |
| `GET` | `/api/v1/ip` | Force immediate egress IP/Geo verification |
| `GET` | `/api/v1/auth` | Current authentication state and token/key expiry |
| `POST` | `/api/v1/auth/login` | Email/password login (`{"email": "...", "password": "..."}`) -> `200` or `202` (`otp_required`) |
| `POST` | `/api/v1/auth/otp` | 2FA verification (`{"challenge_id": "...", "code": "123456"}`) |
| `POST` | `/api/v1/auth/import-official` | Import tokens & WireGuard keys from `~/.config/Surfshark/` |
| `POST` | `/api/v1/auth/logout` | Revoke session token and wipe stored credentials |
| `GET` | `/api/v1/keys` | Inspect registered WireGuard public key metadata (never returns private key) |
| `POST` | `/api/v1/keys/rotate` | Revalidate or rotate WireGuard keypair |
| `GET` | `/api/v1/settings` | Read current `settings.json` |
| `PATCH` | `/api/v1/settings` | Apply JSON merge-patch to settings |
| `GET` | `/api/v1/logs` | Retrieve redacted ring-buffer logs (`?limit=200`) |
| `GET` | `/api/v1/doctor` | Run 7-point self-diagnostics |
| `POST` | `/api/v1/ui-ticket` | *(Unix socket only)* Mint a single-use 30s ticket for `/auth?t=<ticket>` |
