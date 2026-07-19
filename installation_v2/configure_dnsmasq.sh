#!/bin/bash
set -e

# Configura dnsmasq para que Praesidium lo use solo como servidor DHCP.
# Configure dnsmasq so Praesidium uses it only as a DHCP server.

# Verifica que el script se ejecute como root.
# Ensure the script is run as root.
if [ "$EUID" -ne 0 ]; then
    echo "Este script debe ejecutarse como root. Usa: sudo ./configure_dnsmasq.sh"
    echo "This script must be run as root. Use: sudo ./configure_dnsmasq.sh"
    exit 1
fi

# Comprueba que dnsmasq esté instalado antes de escribir la configuración.
# Check that dnsmasq is installed before writing the configuration.
if ! command -v dnsmasq >/dev/null 2>&1; then
    echo "dnsmasq no está instalado. Ejecuta system_requirements.sh primero."
    echo "dnsmasq is not installed. Run system_requirements.sh first."
    exit 1
fi

CONFIG_DIR="/etc/dnsmasq.d"
CONFIG_FILE="$CONFIG_DIR/praesidium-dhcp.conf"

# Crea una configuración base segura: DHCP sí, DNS no.
# Create a safe base configuration: DHCP yes, DNS no.
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_FILE" <<EOF
# PraesidiumFirewall dnsmasq base configuration.
# Configuración base de dnsmasq para PraesidiumFirewall.

# Praesidium uses dnsmasq only for DHCP. Do not listen on DNS port 53.
# Praesidium usa dnsmasq solo para DHCP. No escuchar en el puerto DNS 53.
port=0

# DHCP ranges and DHCP options are generated later by Praesidium commit/apply.
# Los rangos y opciones DHCP se generarán después mediante commit/apply de Praesidium.
EOF

# Valida la configuración completa que cargará el servicio del sistema.
# Validate the complete configuration that the system service will load.
dnsmasq --test

# Limpia fallos previos provocados por el arranque con la configuración por defecto.
# Clear previous failures caused by starting with the default configuration.
systemctl reset-failed dnsmasq 2>/dev/null || true
systemctl enable dnsmasq
systemctl restart dnsmasq

# Verifica que dnsmasq queda activo y sin ocupar el puerto DNS 53.
# Verify that dnsmasq remains active and does not occupy DNS port 53.
if command -v ss >/dev/null 2>&1 && ss -H -lntup 2>/dev/null | grep -Eq '(:53[[:space:]].*dnsmasq|dnsmasq.*:53)'; then
    echo "dnsmasq está escuchando en el puerto 53 y Praesidium solo debe usarlo para DHCP."
    echo "dnsmasq is listening on port 53 and Praesidium must use it only for DHCP."
    exit 1
fi

systemctl is-active --quiet dnsmasq

echo "dnsmasq configurado para DHCP sin DNS (port=0)."
echo "dnsmasq configured for DHCP without DNS (port=0)."
