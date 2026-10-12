# Phase 0 Ground Truth Ledger

| Metadata | Value |
|---|---|
| **Official Package Inspected** | Surfshark Linux (`surfshark` deb, version `3.14.0`) |
| **Date Collected** | `2026-10-12` |
| **Collector** | `tools/ground_truth.sh` + string table deobfuscation (`tools/out/2026-10-12/`, gitignored) |
| **Status** | All Gates G1–G8 Closed & Verified |

---

## Gate G1: Authentication (`login`, `renew`, `logout`, `remote`)

- **Primary Login:**
  - `POST /v1/auth/login`
  - Request JSON: `{"username": "<email>", "password": "<password>"}`
  - Response `200 OK`: `{"token": "<jwt>", "renewToken": "<jwt>"}`
- **Silent Token Renewal:**
  - `POST /v1/auth/renew`
  - Header: `Authorization: Bearer <renewToken>`
  - Response `200 OK`: `{"token": "<jwt>", "renewToken": "<jwt>"}`
  - Response `401 Unauthorized`: Renew token expired (`REAUTH_REQUIRED`).
  - Response `400 Bad Request`: User not found (`REAUTH_REQUIRED`).
- **Logout:**
  - `POST /v1/auth/logout`
  - Header: `Authorization: Bearer <token>`
- **Login with Code (Remote Login):**
  - Create code: `POST /v1/account/authorization/create` → `{"code": "...", "hash": "...", "expiresAt": ...}`
  - Poll status: `POST /v1/auth/remote` with body `{"hash": "..."}` → `200 OK` `{"token": "...", "renewToken": "..."}` (`404` while pending).

---

## Gate G2: Two-Factor Authentication (2FA / OTP)

- **Trigger on Login:**
  - `POST /v1/auth/login` returns HTTP `423 Locked` (`0x1a7`).
  - Crucially, the `423` response body **already contains** `{"token": "<interim_jwt>", "renewToken": "<renew_jwt>"}`.
- **OTP Verification Endpoint:**
  - `POST /v1/auth/activate` *(Note: NOT `/v1/auth/2fa/activate`)*
  - Header: `Authorization: Bearer <token>` (using the `token` returned in the `423` response body).
  - Request JSON: `{"otp": "<6-to-8-digit-code>"}`
  - Response `200 OK` / `204 No Content`: Activates the session token in-place (if response body includes updated `token`/`renewToken`, update stored tokens; otherwise retain the `423` token pair) and proceed to `GET /v1/account/users/me`.

---

## Gate G3: Base Hosts, Headers, Account, Catalog, and IP Check

- **Verified API Base URLs:**
  1. `https://ext2.surfshark.com` (primary external base URL in v3.14.0)
  2. `https://api.surfshark.com` (canonical API base URL)
  3. In-tunnel Anycast API: `https://172.16.0.36` with TLS SNI `servername="wgs.prod.surfshark.com"`.
- **Standard Request Headers:**
  - `User-Agent: SurfsharkLinux/3.14.0 device/desktop`
  - `Accept: application/json`
  - `Content-Type: application/json`
  - `x-device-type: desktop`
  - `x-device-platform: linux`
  - `x-device-version: 3.14.0`
- **Account Details:**
  - `GET /v1/account/users/me` (requires `Authorization: Bearer <token>`)
  - Fields: `id`, `externalId`, `daysAfterSignup`, `serviceCredentials` (`{username, password}`), `technologies` (`[...]`).
- **Server Catalog:**
  - `GET /v5/server/clusters/all` (works both unauthenticated and authenticated; returns JSON array of ~187 clusters).
  - Cluster object fields:
    - `id` (UUID string)
    - `country` (string, e.g. `"United States"`)
    - `countryCode` (ISO alpha-2 string, e.g. `"US"`)
    - `region` (string, e.g. `"The Americas"`), `regionCode` (string, e.g. `"AM"`)
    - `location` (city string, e.g. `"San Francisco"`)
    - `connectionName` (hostname, e.g. `"us-sfo.prod.surfshark.com"`)
    - `pubKey` (32-byte base64 WireGuard public key, or `null` for non-WG `obfuscated` clusters)
    - `load` (integer `0..100`)
    - `type` (`"generic"` | `"static"` | `"obfuscated"` | `"double"`)
    - `tags` (array of strings, e.g. `["p2p", "physical"]` or `["virtual", "p2p"]`)
    - `coordinates` (`{"longitude": float, "latitude": float}`)
    - `transitCluster` (nested cluster object or `null`)
- **First-Party Egress / Connection Check:**
  - `GET /v1/server/user`
  - Response `200 OK`: `{"ip": "...", "isp": "...", "countryCode": "US", "country": "United States", "region": "...", "city": "...", "zipCode": "...", "secured": true, "torrent": false, "restricted": false}`

---

## Gate G4: WireGuard Public Key Registration & Validation

- **Validate Key:**
  - `POST /v1/account/users/public-keys/validate`
  - Header: `Authorization: Bearer <token>`
  - Request JSON: `{"pubKey": "<base64_pub_key>"}`
  - Response: `200 OK` (may include `expiresAt`), or `400`/`404` when key is expired or unrecognized.
- **Register Key:**
  - `POST /v1/account/users/public-keys`
  - Header: `Authorization: Bearer <token>`
  - Request JSON: `{"pubKey": "<base64_pub_key>"}`
  - Response: `200`/`201` (or `409 Conflict` if already registered).

---

## Gate G5: Auxiliary / Anycast WireGuard Peer

- **Endpoint Hostname & Port:** `wgs.prod.surfshark.com:51820`
- **Allowed IPs:** `172.16.0.36/32`
- **Public Key Discovery:**
  - Queried via DNS `TXT` record on `wgs.prod.surfshark.com`, formatted as `"[public_key:<base64>]"`.
  - Current verified value: `o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=`
- **Purpose:** Provides in-tunnel access to `172.16.0.36` (DNS A-record resolution and HTTPS control plane during self-heal).

---

## Gate G6: WireGuard Profile & Routing Parameters

- **Interface Address (IPv4):** `10.14.0.2/16`
- **Listen Port:** `0` (automatic); Peer Port: `51820` (`0xca6c`)
- **Firewall Mark & Routing Table:** `300000` (`0x493e0`)
- **MTU:** `1280` (`0x500`, safe default) or `1360` (`0x550` when PMTU probe `ping -c 1 -W 1 -M do -s 1472` succeeds).
- **DNS Search & Priority:** `dns-search = ["~."]`, `ignore-auto-dns = true`, `dns-priority = -50` (official daemon uses `-2018`; any negative value is exclusive in NetworkManager/systemd-resolved).
- **Persistent Keepalive:** `25` seconds (used by native driver for NAT traversal and liveness).
- **IPv6 Handling:** Official daemon disables IPv6 on `surfshark_wg` and creates a `dummy` connection `surfshark_ipv6` (`fdbe:2bde:b490:9e47::/64`, gw `::1`, metric `95`). Native driver uses an in-profile ULA `/128` (`fd7d:76ee:e68f:a993::2/128`), `::/0` in peer AllowedIPs, and IPv6 table `300000` policy rules.

---

## Gate G7: CleanWeb Mechanism

- **Mechanism:** Purely selects between two IPv4 DNS server lists on the WireGuard profile:
  - **CleanWeb OFF (`cleanweb = false`):** `("162.252.172.57", "149.154.159.92", "151.236.14.64")`
  - **CleanWeb ON (`cleanweb = true`):** `("151.236.14.64", "203.21.66.129", "79.127.185.11")`
- Can be updated live via `Device.Reapply` on the active WireGuard interface.

---

## Gate G8: `surfsharkd.sock` IPC Protocol & Lifecycle

- **Service Unit:** `surfsharkd.service` (`systemd --user`, running `/usr/bin/gjs /opt/Surfshark/resources/dist/resources/surfsharkd.js`).
- **Socket Location:** `$XDG_RUNTIME_DIR/surfsharkd.sock` (e.g. `/run/user/1000/surfsharkd.sock`).
- **Framing & Transport:**
  - One Unix stream connection per RPC call.
  - Request: single newline-terminated JSON line `{"method": "<name>", "params": [...]}\n`.
  - **Important:** The client must keep the write side of the socket open until the response is read; closing/EOF on the client input stream triggers `GCancellable.cancel()` inside `surfsharkd`.
  - Response (unary): `{"type": "result", "value": <any>}\n`
  - Response (stream, e.g. `onNetStateChange`): `{"type": "item", "value": <state_dict>}\n`
  - Response (error): `{"type": "error", "value": {"message": "...", "name": "...", "code": "..."}}\n`
- **WireGuard RPC Methods:**
  - `version` (`[]`) → `1`
  - `getState` (`[]`) → `{"nm_version": "...", "wg_active_connection_state": 0..4, "wg_device_state": 0..120, ...}` (`wg_active_connection_state == 2` and `wg_device_state == 100` indicate connected).
  - `onNetStateChange` (`[]`) → async stream of state dicts.
  - `addIPV6Connection` (`[]`) → creates `surfshark_ipv6` dummy leak guard.
  - `removeIPV6Connection` (`[]`) → removes `surfshark_ipv6`.
  - `addConnection` (`["wg", {"domain": "<ipv4>", "pub": "<server_pub_b64>", "priv": "<client_priv_b64>", "cleanweb": bool, "mtuSafe": bool, "anycastPub": "<aux_pub_b64>", "anycastIp": "172.16.0.36", "preshared"?: "<psk_b64>"}]`)
  - `connect` (`["wg"]`) → activates `surfshark_wg`.
  - `replacePeer` (`[{"domain": "<ipv4>", "priv": "<client_priv_b64>", "pub": "<server_pub_b64>"}]`) → in-place `Device.Reapply` on `surfshark_wg`.
  - `updatePresharedKey` (`[{"preshared": "<psk_b64_or_null>"}]`)
  - `disconnect` (`["wg"]`) → deactivates `surfshark_wg`.
  - `removeConnection` (`["wg"]`) → deletes `surfshark_wg` profile.
