#!/bin/bash
set -euo pipefail

INTERFACES_JSON="${PRAESIDIUM_INTERFACES_JSON:-/var/lib/praesidium/candidate/interfaces.json}"
RUNNING_INTERFACES_JSON="${PRAESIDIUM_RUNNING_INTERFACES_JSON:-/var/lib/praesidium/running/interfaces.json}"

# Sincroniza el estado running inicial con las interfaces reales detectadas y normalizadas.
# Synchronizes the initial running state with the detected and normalized interfaces.
mkdir -p "$(dirname "$RUNNING_INTERFACES_JSON")"
cp "$INTERFACES_JSON" "$RUNNING_INTERFACES_JSON"
python3 -m json.tool "$RUNNING_INTERFACES_JSON" >/dev/null
