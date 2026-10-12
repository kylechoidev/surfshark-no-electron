#!/usr/bin/env bash
# Surf Shark Ultra Lite for Linux — Uninstaller
set -euo pipefail

APP_SHARE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/surfshark-ultralite"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICON_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"

PURGE=0
for arg in "$@"; do
  case "$arg" in
    --purge)
      PURGE=1
      ;;
  esac
done

echo "==> Disconnecting active tunnel and stopping service..."
if [[ -x "${BIN_DIR}/surfshark-lite" ]]; then
  "${BIN_DIR}/surfshark-lite" disconnect >/dev/null 2>&1 || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now surfshark-ultralite.service >/dev/null 2>&1 || true
  systemctl --user daemon-reload >/dev/null 2>&1 || true
fi

rm -f "${BIN_DIR}/surfshark-lite"
rm -f "${SYSTEMD_USER_DIR}/surfshark-ultralite.service"
rm -f "${DESKTOP_DIR}/surfshark-ultralite.desktop"
rm -f "${ICON_DIR}/surfshark-ultralite.svg"
rm -rf "${APP_SHARE_DIR}"

if [[ "$PURGE" -eq 1 ]]; then
  echo "==> Purging configuration, credentials, cache, and state..."
  rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/surfshark-ultralite"
  rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/surfshark-ultralite"
  rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/surfshark-ultralite"
  rm -rf "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/surfshark-ultralite"
fi

echo "==> Surf Shark Ultra Lite uninstalled."
