#!/usr/bin/env bash
# Surf Shark Ultra Lite for Linux — User-space installer (Zero root required unless --polkit passed)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SHARE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/surfshark-ultralite"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICON_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"

INSTALL_POLKIT=0
NO_SERVICE=0

for arg in "$@"; do
  case "$arg" in
    --polkit)
      INSTALL_POLKIT=1
      ;;
    --no-service)
      NO_SERVICE=1
      ;;
    -h|--help)
      echo "Usage: ./install.sh [--polkit] [--no-service]"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

echo "==> Installing Surf Shark Ultra Lite to ${APP_SHARE_DIR}"
mkdir -p -m 0700 "${APP_SHARE_DIR}"
mkdir -p "${BIN_DIR}" "${SYSTEMD_USER_DIR}" "${DESKTOP_DIR}" "${ICON_DIR}"

rm -rf "${APP_SHARE_DIR}/src"
cp -R "${SCRIPT_DIR}/src" "${APP_SHARE_DIR}/src"

cat > "${BIN_DIR}/surfshark-lite" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APP_SRC="${XDG_DATA_HOME:-$HOME/.local/share}/surfshark-ultralite/src"
export PYTHONPATH="${APP_SRC}${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/python3 -m surfshark_lite "$@"
EOF
chmod 0755 "${BIN_DIR}/surfshark-lite"

cp "${SCRIPT_DIR}/packaging/systemd/surfshark-ultralite.service" "${SYSTEMD_USER_DIR}/surfshark-ultralite.service"
cp "${SCRIPT_DIR}/packaging/icons/surfshark-ultralite.svg" "${ICON_DIR}/surfshark-ultralite.svg"
sed "s|^Exec=surfshark-lite ui|Exec=${BIN_DIR}/surfshark-lite ui|g; s|^Exec=surfshark-lite |Exec=${BIN_DIR}/surfshark-lite |g; s|^Icon=surfshark-ultralite|Icon=${ICON_DIR}/surfshark-ultralite.svg|g" \
  "${SCRIPT_DIR}/packaging/desktop/surfshark-ultralite.desktop" > "${DESKTOP_DIR}/surfshark-ultralite.desktop"
chmod 0755 "${DESKTOP_DIR}/surfshark-ultralite.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "${DESKTOP_DIR}" >/dev/null 2>&1 || true
fi

if [[ "$INSTALL_POLKIT" -eq 1 ]]; then
  echo "==> Installing Polkit rule for user ${USER} (requires sudo)"
  TMP_RULE="$(mktemp)"
  sed "s/@USERNAME@/${USER}/g" "${SCRIPT_DIR}/packaging/polkit/50-surfshark-ultralite.rules.in" > "${TMP_RULE}"
  sudo install -m 0644 "${TMP_RULE}" /etc/polkit-1/rules.d/50-surfshark-ultralite.rules
  rm -f "${TMP_RULE}"
fi

if [[ "$NO_SERVICE" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl --user stop surfshark-ultralite.service >/dev/null 2>&1 || true
  pkill -f "python3 -m surfshark_lite daemon" >/dev/null 2>&1 || true
  systemctl --user daemon-reload || true
  systemctl --user enable --now surfshark-ultralite.service || true
fi

echo "==> Installation complete!"
echo "    CLI: ${BIN_DIR}/surfshark-lite"
echo "    Run: surfshark-lite doctor"
echo "    UI:  surfshark-lite ui"
