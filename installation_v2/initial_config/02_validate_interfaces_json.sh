#!/bin/bash
set -euo pipefail

INTERFACES_JSON="${PRAESIDIUM_INTERFACES_JSON:-/var/lib/praesidium/candidate/interfaces.json}"
ALL_INTERFACES_JSON="${PRAESIDIUM_ALL_INTERFACES_JSON:-/var/lib/praesidium/state/interfaces/all_interfaces_list.json}"
PHYSICAL_INTERFACES_JSON="${PRAESIDIUM_PHYSICAL_INTERFACES_JSON:-/var/lib/praesidium/state/interfaces/physical_interfaces_list.json}"

# Valida que los JSON críticos existen y son sintácticamente correctos.
# Validates that critical JSON files exist and are syntactically correct.
python3 -m json.tool "$INTERFACES_JSON" >/dev/null
python3 -m json.tool "$ALL_INTERFACES_JSON" >/dev/null
python3 -m json.tool "$PHYSICAL_INTERFACES_JSON" >/dev/null
