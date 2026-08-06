#!/bin/bash
set -euo pipefail

INTERFACES_CHECK="${PRAESIDIUM_INTERFACES_CHECK:-/var/lib/praesidium/scripts/checks/check_interfaces/main_interfaces_check.py}"

# Ejecuta el mismo refresco de interfaces que usa la WebGUI, pero durante instalación.
# Runs the same interface refresh used by the WebGUI, but during installation.
python3 "$INTERFACES_CHECK"
