#!/bin/bash
set -e

# Ruta al directorio donde están los archivos de configuración
# Path to the directory containing the configuration files
SOURCE_DIR="./configure_logs"

configure_nftables_logging() {
    # Nombres de los archivos de configuración
    # Configuration file names
    RSYSLOG_CONF="nftables_rsyslog.conf"
    NFTABLES_LOGROTATE_CONF="nftables_logrotate.conf"
    JOURNALD_CONF="praesidium_journald.conf"
    RSYSLOG_LOGROTATE_CONF="praesidium_rsyslog_logrotate.conf"

    # Destinos donde deben copiarse los archivos
    # Destination paths for system configuration
    RSYSLOG_DEST="/etc/rsyslog.d/$RSYSLOG_CONF"
    NFTABLES_LOGROTATE_DEST="/etc/logrotate.d/$NFTABLES_LOGROTATE_CONF"
    JOURNALD_DEST_DIR="/etc/systemd/journald.conf.d"
    JOURNALD_DEST="$JOURNALD_DEST_DIR/10-praesidium-limits.conf"
    RSYSLOG_LOGROTATE_DEST="/etc/logrotate.d/rsyslog"

    # Directorio de logs personalizado
    # Custom log directory
    LOG_DIR="/var/log/praesidium"

    echo "Copiando configuración de logs Praesidium... / Copying Praesidium log configuration..."
    sudo cp "$SOURCE_DIR/$RSYSLOG_CONF" "$RSYSLOG_DEST"
    sudo cp "$SOURCE_DIR/$NFTABLES_LOGROTATE_CONF" "$NFTABLES_LOGROTATE_DEST"

    echo "Aplicando límites de journald... / Applying journald limits..."
    sudo mkdir -p "$JOURNALD_DEST_DIR"
    sudo cp "$SOURCE_DIR/$JOURNALD_CONF" "$JOURNALD_DEST"
    sudo chmod 644 "$JOURNALD_DEST"

    echo "Aplicando rotación limitada de logs del sistema... / Applying bounded system log rotation..."
    if [ -f "$RSYSLOG_LOGROTATE_DEST" ] && [ ! -f "$RSYSLOG_LOGROTATE_DEST.praesidium.bak" ]; then
        sudo cp "$RSYSLOG_LOGROTATE_DEST" "$RSYSLOG_LOGROTATE_DEST.praesidium.bak"
    fi
    sudo cp "$SOURCE_DIR/$RSYSLOG_LOGROTATE_CONF" "$RSYSLOG_LOGROTATE_DEST"
    sudo chmod 644 "$RSYSLOG_LOGROTATE_DEST"

    echo " Creando directorio de logs en $LOG_DIR... / Creating log directory at $LOG_DIR..."
    sudo mkdir -p "$LOG_DIR"

    echo " Asignando permisos para rsyslog y logrotate... / Setting permissions for rsyslog and logrotate..."
    sudo chown syslog:adm "$LOG_DIR"
    sudo chmod 750 "$LOG_DIR"

    echo " Validando configuraciones logrotate... / Validating logrotate configurations..."
    sudo logrotate -d "$NFTABLES_LOGROTATE_DEST" >/dev/null
    sudo logrotate -d "$RSYSLOG_LOGROTATE_DEST" >/dev/null

    echo " Reiniciando servicios de logs... / Restarting log services..."
    sudo systemctl restart systemd-journald
    sudo journalctl --vacuum-size=100M >/dev/null || true
    sudo systemctl restart rsyslog

    echo " Todo listo. Logs de nftables: $LOG_DIR/nftables.log / All set. nftables logs: $LOG_DIR/nftables.log"
}

# Ejecutar la función principal
# Run the main function
configure_nftables_logging
