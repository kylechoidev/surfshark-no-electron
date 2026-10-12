#!/usr/bin/env bash
# Phase 0 collector. Read-only. Never prints secrets (no `nmcli -s`, no `wg showconf`).
# Run with the official app installed and its tunnel UP.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="${SURFSHARK_APP_DIR:-/opt/Surfshark}"
OUT="${1:-$HERE/out/$(date +%F)}"
umask 077
mkdir -p "$OUT/asar"

find "$APP" -maxdepth 6 \( -name '*.asar' -o -name 'surfsharkd*' -o -name '*.service' \) -print > "$OUT/files.txt" 2>/dev/null || true
find /usr/lib/systemd/user /etc/systemd/user /usr/lib/systemd/system -maxdepth 1 -iname '*surf*' -print >> "$OUT/files.txt" 2>/dev/null || true

ASAR="$(grep -m1 '/app\.asar$' "$OUT/files.txt" || true)"
[ -n "$ASAR" ] && python3 -I "$HERE/asar_extract.py" "$ASAR" "$OUT/asar"
DAEMON="$(grep -m1 'surfsharkd[^/]*\.js$' "$OUT/files.txt" || true)"

# Endpoint and host inventory
grep -rhoaE '/v[0-9]+/[A-Za-z0-9_./{}$-]+' "$OUT/asar" ${DAEMON:+"$DAEMON"} 2>/dev/null | sort -u > "$OUT/endpoints.txt" || true
grep -rhoaE 'https://[a-z0-9.-]+\.[a-z]{2,}' "$OUT/asar" ${DAEMON:+"$DAEMON"} 2>/dev/null | sort -u > "$OUT/hosts.txt" || true

# Topic context (G1–G8)
for k in auth/login auth/renew 423 2fa otp mfa twoFactor captcha public-keys wireguard clusters \
         server/user cleanweb CleanWeb User-Agent surfsharkd.sock getState '"connect"' "'connect'" \
         updatePresharedKey replacePeer wgs.prod 172.16.0.36 10.14.0 persistentKeepalive keepalive \
         mtu fwmark 300000 surfshark_ipv6 162.252 dnsPriority; do
  safe="$(printf '%s' "$k" | tr -c 'A-Za-z0-9' '_')"
  python3 -I "$HERE/ctxgrep.py" "$k" 160 "$OUT/asar" ${DAEMON:+"$DAEMON"} > "$OUT/ctx_${safe}.txt" 2>/dev/null || true
done

# Live state (official tunnel UP)
nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active > "$OUT/nm_active.txt" || true
for uuid in $(nmcli -t -f UUID,TYPE connection show --active | awk -F: '$2=="wireguard"{print $1}'); do
  nmcli -f all connection show "$uuid" > "$OUT/nm_profile_${uuid}.txt" || true   # secrets show as <hidden>
done
ip -d link show > "$OUT/links.txt"
ip rule show > "$OUT/rules4.txt"
ip -6 rule show > "$OUT/rules6.txt"
ip route show table all | grep -E 'surfshark|300000' > "$OUT/routes4.txt" || true
ip -6 route show table all | grep -E 'surfshark|300000' > "$OUT/routes6.txt" || true
resolvectl status > "$OUT/resolved.txt" 2>&1 || true
ps -eo pid,ppid,user,etimes,rss,args | grep -iE 'surfshark|gjs' | grep -v grep > "$OUT/procs.txt" || true
systemctl --user list-units --all --no-pager 2>/dev/null | grep -i surf > "$OUT/user_units.txt" || true
ls -la "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" 2>/dev/null | grep -i surf > "$OUT/runtime.txt" || true
ls -la "$HOME/.config/Surfshark" > "$OUT/official_config_listing.txt" 2>&1 || true        # names only, never contents

echo "Collected into $OUT (mode 0700). Contains proprietary excerpts — never commit. Optional: sudo wg show surfshark_wg"
