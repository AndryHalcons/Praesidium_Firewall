#!/bin/bash
set -euo pipefail

# Ejecuta un commit/apply inicial al final de la post-instalación.
# Runs an initial commit/apply at the end of post-installation.
COMMIT_APPLY="${PRAESIDIUM_COMMIT_APPLY:-/var/lib/praesidium/scripts/commits/commit_apply.py}"
COMMIT_USER="${PRAESIDIUM_INITIAL_COMMIT_USER:-initial_config}"
CONFIG_DIR="${PRAESIDIUM_CONFIG_DIR:-/var/lib/praesidium/candidate}"
CONFIG_RUNNING_DIR="${PRAESIDIUM_CONFIG_RUNNING_DIR:-/var/lib/praesidium/running}"

if [[ ! -f "$COMMIT_APPLY" ]]; then
    echo "No existe commit_apply.py: $COMMIT_APPLY" >&2
    exit 1
fi

# Usa una marca temporal compatible con commit_history.
# Use a timestamp compatible with commit_history.
COMMIT_DATE="$(date -u +%Y%m%d%H%M%S%3N)"
COMMIT_PAYLOAD="{\"commit\":{\"date\":\"${COMMIT_DATE}\",\"user\":\"${COMMIT_USER}\"}}"

python3 "$COMMIT_APPLY" "$COMMIT_PAYLOAD"

python3 -m json.tool "/var/lib/praesidium/commits/commit_history.json" >/dev/null
python3 -m json.tool "$CONFIG_RUNNING_DIR/interfaces.json" >/dev/null
