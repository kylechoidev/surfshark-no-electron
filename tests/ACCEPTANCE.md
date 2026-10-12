# Acceptance Test Checklist (§17.3)

| ID | Criterion | Verification Method | Status |
|----|-----------|---------------------|--------|
| A1 | Zero Electron / Zero Node runtime dependencies | `test_ast_imports.py` AST policy check | Verified |
| A2 | Pure-Python X25519 RFC 7748 test vectors + cross-backend parity | `test_x25519_and_keys.py` | Verified |
| A3 | Native Login + HTTP 423 `POST /v1/auth/activate` 2FA + single-flight 401 renew | `test_auth.py` | Verified |
| A4 | Official `~/.config/Surfshark/` credential & key migration | `test_credstore.py` | Verified |
| A5 | Resolver golden table (`sfo`, `uk`, `tokyo`, `frankfurt`, `fastest de`, ambiguity detection) | `test_catalog.py` | Verified |
| A6 | Policy routing rules (`30000..30021`, RFC1918 LAN bypass, IPv6 ULA guard, drift detection) | `test_routing.py` | Verified |
| A7 | 7-state security verdict evaluation & L0–L5 watchdog hysteresis | `test_telemetry_watchdog.py` | Verified |
| A8 | Web security matrix (`Host` 421, `Origin` 403, `Sec-Fetch-Site` 403, `X-SSUL` 403, `Content-Type` 415, single-use ticket) | `test_web_security.py` | Verified |
| A9 | `surfsharkd.sock` NDJSON-RPC fallback driver (no premature `SHUT_WR`) | `test_surfsharkd.py` | Verified |
