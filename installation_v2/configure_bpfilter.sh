#!/bin/bash
set -euo pipefail

# Configura bpfilter como servicio systemd para que el instalador no quede bloqueado.
# Configure bpfilter as a systemd service so the installer does not block.

SERVICE_FILE="/etc/systemd/system/bpfilter.service"
BPFILTER_BIN="${BPFILTER_BIN:-/usr/local/bin/bpfilter}"
VERBOSE_LEVEL="${BPFILTER_VERBOSE_LEVEL:-debug}"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

# Verifica permisos y binario instalado.
# Verify privileges and installed binary.
check_prerequisites() {
    if [ "$EUID" -ne 0 ]; then
        fail "Este script debe ejecutarse como root. Usa: sudo ./configure_bpfilter.sh / This script must be run as root. Use: sudo ./configure_bpfilter.sh"
    fi

    [ -x "$BPFILTER_BIN" ] || fail "El binario bpfilter no existe o no es ejecutable en $BPFILTER_BIN. Ejecuta install_bpfilter.sh primero. / The bpfilter binary does not exist or is not executable at $BPFILTER_BIN. Run install_bpfilter.sh first."
}

# Prepara bpffs y directorios de runtime antes de arrancar el daemon.
# Prepare bpffs and runtime directories before starting the daemon.
prepare_runtime() {
    mkdir -p /sys/fs/bpf
    if ! mountpoint -q /sys/fs/bpf; then
        mount -t bpf bpf /sys/fs/bpf
    fi

    mkdir -p /sys/fs/bpf/bpfilter
    mkdir -p /run/bpfilter
}

# Escribe una unidad systemd persistente para bpfilter.
# Write a persistent systemd unit for bpfilter.
write_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=PraesidiumFirewall bpfilter daemon
Documentation=https://github.com/AndryHalcons/bpfilter
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStartPre=/bin/sh -c 'mkdir -p /sys/fs/bpf; mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; mkdir -p /sys/fs/bpf/bpfilter /run/bpfilter'
ExecStart=$BPFILTER_BIN --no-iptables --no-nftables --verbose=$VERBOSE_LEVEL
Restart=on-failure
RestartSec=3
RuntimeDirectory=bpfilter

[Install]
WantedBy=multi-user.target
EOF
}

# Recarga systemd, arranca el servicio y verifica que queda activo.
# Reload systemd, start the service and verify it remains active.
start_service() {
    systemctl daemon-reload
    systemctl reset-failed bpfilter.service 2>/dev/null || true
    systemctl enable bpfilter.service
    systemctl restart bpfilter.service
    systemctl is-active --quiet bpfilter.service
    systemctl --no-pager --full status bpfilter.service | sed -n '1,25p'
}

main() {
    check_prerequisites
    prepare_runtime
    write_service
    start_service
    echo "bpfilter configurado como servicio systemd. / bpfilter configured as a systemd service."
}

main "$@"
