# Security Architecture & Threat Model

## 1. Local Loopback Hardening (`127.0.0.1:8777`)

Any service listening on `127.0.0.1` is reachable from untrusted websites open in the user's browser unless explicitly hardened against DNS rebinding and Cross-Site Request Forgery (CSRF). Surf Shark Ultra Lite enforces five independent layers on TCP requests:

1. **DNS Rebinding Defense (`Host` Whitelist):**
   Requests whose `Host` header is not in `{"127.0.0.1", "127.0.0.1:<port>", "localhost", "localhost:<port>"}` are rejected immediately with `421 Misdirected Request`.
2. **Fetch Metadata Defense (`Sec-Fetch-Site`):**
   Requests carrying `Sec-Fetch-Site: cross-site` or `same-site` are rejected with `403 Forbidden`.
3. **Origin Verification:**
   Any request carrying an `Origin` header not matching `http://127.0.0.1:<port>` or `http://localhost:<port>` is rejected with `403 Forbidden`.
4. **Custom Pre-Flight Header (`X-SSUL: 1`) & Strict JSON `Content-Type`:**
   All mutating methods (`POST`, `PATCH`, `PUT`, `DELETE`) require `X-SSUL: 1` (`403` if absent) and `Content-Type: application/json` (`415` if mismatched), forcing a CORS preflight that cross-origin pages cannot pass.
5. **Strict Content Security Policy (CSP):**
   Every response carries `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.

---

## 2. Credential & Key Storage Hygiene

- **Zero Plaintext Passwords at Rest:** User passwords are used once during `POST /v1/auth/login` and immediately discarded. Only the short-lived `token`, `renewToken`, and WireGuard keypair are persisted.
- **Strict `0700` / `0600` Permissions:** `~/.config/surfshark-ultralite/credentials.json` is written via atomic temp-file + `fchmod(0600)` + `fsync` + `os.replace` under an `flock` lockfile. If permissions are ever broadened (`st_mode & 0o077 != 0`), loading refuses with `CREDENTIALS_INSECURE`.
- **Automatic Log Redaction:** Every log handler attaches `RedactingFilter`, which scrubs JWTs (`eyJ...`), 44-character base64 WireGuard keys, passwords, OTP codes, and masks email addresses (`u***@domain`).

---

## 3. Fail-Closed Routing & IPv6 Leak Prevention

- **Policy Routing via Table `300000` (`fwmark 0x493e0`):** Unmarked traffic is routed into table `300000` at priority `30021`, while `suppress_prefixlength 0` at priority `30020` and explicit RFC 1918 rules (`30010`–`30014`) keep local LAN and loopback connections intact.
- **IPv6 Leak Guard:** Assigns ULA `fd7d:76ee:e68f:a993::2/128` with `AllowedIPs = ::/0` and matching IPv6 policy rules so dual-stack hosts never leak IPv6 traffic outside the tunnel.
