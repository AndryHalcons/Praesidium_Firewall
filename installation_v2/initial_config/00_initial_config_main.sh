#!/bin/bash
set -euo pipefail

# Genera la configuración inicial dependiente del sistema real recién instalado.
# Generates the initial configuration that depends on the freshly installed real system.
echo "Generando configuración inicial del sistema... / Generating initial system configuration..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INITIAL_CONFIG_DIR="${SCRIPT_DIR}"

run_initial_config_step() {
    local label="$1"
    shift
    echo "== ${label} =="
    "$@"
}

run_initial_config_step "Refrescando interfaces / Refreshing interfaces" \
    bash "${INITIAL_CONFIG_DIR}/01_refresh_interfaces.sh"

run_initial_config_step "Validando JSON de interfaces / Validating interfaces JSON" \
    bash "${INITIAL_CONFIG_DIR}/02_validate_interfaces_json.sh"

run_initial_config_step "Generando bridges br / Generating br bridges" \
    python3 "${INITIAL_CONFIG_DIR}/03_generate_bridges.py"

run_initial_config_step "Sincronizando running / Syncing running" \
    bash "${INITIAL_CONFIG_DIR}/04_sync_running_interfaces.sh"

run_initial_config_step "Adaptando BPFilter de gestión / Adapting management BPFilter" \
    python3 "${INITIAL_CONFIG_DIR}/05_adapt_bpfilter_management.py"

run_initial_config_step "Commit inicial / Initial commit" \
    bash "${INITIAL_CONFIG_DIR}/99_commit_initial_config.sh"

run_initial_config_step "Ajustando permisos runtime de interfaces / Fixing interfaces runtime permissions" \
    bash -c '        chgrp -R praesidium /var/lib/praesidium/state/interfaces /var/lib/praesidium/candidate/interfaces.json /var/lib/praesidium/running/interfaces.json;         chmod 775 /var/lib/praesidium/state/interfaces;         find /var/lib/praesidium/state/interfaces -type f -name "*.json" -exec chmod 664 {} +;         chmod 664 /var/lib/praesidium/candidate/interfaces.json /var/lib/praesidium/running/interfaces.json    '

echo "Configuración inicial completada. / Initial configuration completed."
