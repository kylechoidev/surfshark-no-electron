# Troubleshooting & Diagnostics Guide

Run the built-in diagnostic suite first:

```bash
surfshark-lite doctor
```

---

## Common Issues & Remediations

### 1. `PERMISSION_DENIED`: NetworkManager Polkit Authorization Failed
When running over SSH, inside a headless session, or without an active Polkit desktop seat, NetworkManager may reject `settings.modify.own` or `network-control`.
- **Fix:** Install the Polkit rule once:
  ```bash
  ./install.sh --polkit
  ```

### 2. `DRIVER_UNAVAILABLE`: Missing `python3-gi` or `gir1.2-nm-1.0`
The native NetworkManager driver uses GObject Introspection (`libnm`).
- **Fix:**
  ```bash
  sudo apt install python3-gi gir1.2-nm-1.0
  ```

### 3. `CREDENTIALS_INSECURE`: Broad Permissions on `credentials.json`
Surf Shark Ultra Lite refuses to load `credentials.json` if group or world permissions are set.
- **Fix:**
  ```bash
  chmod 600 ~/.config/surfshark-ultralite/credentials.json
  chmod 700 ~/.config/surfshark-ultralite
  ```

### 4. `FOREIGN_TUNNEL_ACTIVE`: Another VPN Connection is Active
If the official Surfshark app or another WireGuard profile is currently active, `surfshark-lite connect` refuses to collide with it by default.
- **Fix:** Pass `--takeover` to cleanly deactivate the foreign tunnel first:
  ```bash
  surfshark-lite connect fastest --takeover
  ```
