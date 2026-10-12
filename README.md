# Surf Shark Ultra Lite for Linux (`v2.0.0`)

**Zero-Electron · Zero-Node · Native NetworkManager WireGuard Client for Surfshark on Linux**

Surf Shark Ultra Lite (`surfshark-lite`) replaces the ~500 MB official Electron + Node.js desktop client with a pure-Python 3.10+ daemon, full CLI, and local Web UI (~18 MB RSS, 0.0% idle CPU) that drives Linux kernel WireGuard directly through NetworkManager (`libnm`).

---

## Key Highlights

- **100% Standalone (No Official App Required):**
  - Native Email + Password login (`POST /v1/auth/login`), 2FA TOTP verification (`POST /v1/auth/activate`), single-flight JWT refresh (`POST /v1/auth/renew`), and automatic WireGuard Curve25519 key generation & registration (`POST /v1/account/users/public-keys`).
  - Optional 1-click migration (`surfshark-lite login --import-official`) from an existing `~/.config/Surfshark/` installation.
- **Native Kernel WireGuard via NetworkManager (`libnm`):**
  - Creates ephemeral, user-scoped WireGuard profiles on `surfshark_lite` (`10.14.0.2/16`, `fwmark 300000`, `table 300000`).
  - **Fail-Closed `<100ms` Peer Switching:** Uses `NM.Device.reapply_async` to swap WireGuard peers in-place without tearing down the interface or dropping policy routing rules.
  - **RFC 1918 LAN & Local Loopback Preservation:** Keeps `127.0.0.0/8` and local LAN traffic outside the VPN tunnel table while capturing unmarked WAN IPv4 & IPv6 traffic (`fd7d:76ee:e68f:a993::2/128` IPv6 leak guard).
  - **Dual-Driver Support:** Automatically uses native `libnm` (`python3-gi` + `gir1.2-nm-1.0`) or falls back to `surfsharkd.sock` if present.
- **7-State Security Verdict & L0–L5 Self-Healing Watchdog:**
  - Continuously verifies kernel policy rules, WireGuard handshake freshness, DNS configuration, and multi-provider egress IP/Geo quorum (`PROTECTED`, `HANDSHAKE_PENDING`, `ROUTING_DEGRADED`, `STALE_HANDSHAKE`, `LEAK_SUSPECTED`, `EXPOSED`, `UNVERIFIED`).
- **Hardened Local Web UI + Full CLI:**
  - Serves a zero-animation-loop dark Web UI on `127.0.0.1:8777` (protected by `Host`, `Origin`, `Sec-Fetch-Site`, `X-SSUL: 1`, strict CSP, and single-use launch tickets) and a `0600` Unix control socket at `$XDG_RUNTIME_DIR/surfshark-ultralite/control.sock`.

---

## Quick Start

### 1. System Dependencies (Debian / Ubuntu / Mint)

```bash
sudo apt install python3 python3-gi gir1.2-nm-1.0 iproute2
```

*(Optional: `python3-cryptography` or `wireguard-tools` for hardware-accelerated X25519 key derivation; a pure-Python RFC 7748 Curve25519 ladder with import-time self-test is built in.)*

### 2. Run Directly or Install

```bash
# Run directly from checkout:
./launch.sh doctor
./launch.sh ui

# Or install to ~/.local/bin + systemd user service + desktop launcher:
./install.sh
```

### 3. Authenticate & Connect

```bash
# Log in natively (supports 2FA TOTP):
surfshark-lite login

# Or import an existing session from ~/.config/Surfshark:
surfshark-lite login --import-official

# Connect to the fastest server, a city, or a country:
surfshark-lite connect fastest
surfshark-lite connect tokyo
surfshark-lite switch frankfurt

# Check status and security verdict:
surfshark-lite status
surfshark-lite ip

# Open the desktop app window:
surfshark-lite ui
```

---

## Documentation

- [Ground Truth Reverse-Engineering Report](docs/GROUND_TRUTH.md)
- [REST & Unix Socket API Reference](docs/API.md)
- [Security Architecture & Threat Model](docs/SECURITY.md)
- [Troubleshooting & Polkit Guide](docs/TROUBLESHOOTING.md)
- [Acceptance Checklist](tests/ACCEPTANCE.md)

---

## License

MIT License — see [LICENSE](LICENSE).
