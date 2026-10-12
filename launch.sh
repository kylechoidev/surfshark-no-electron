#!/usr/bin/env bash
# Direct checkout launcher for Surf Shark Ultra Lite (no installation required)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}/src${PYTHONPATH:+:$PYTHONPATH}"

if [[ $# -eq 0 ]]; then
  exec /usr/bin/python3 -m surfshark_lite ui
else
  exec /usr/bin/python3 -m surfshark_lite "$@"
fi
