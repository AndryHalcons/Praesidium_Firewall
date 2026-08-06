#!/bin/bash
set -e
# Enable permanent IP forwarding on Debian 13
# Activar reenvío de IP permanente en Debian 13

# Must be run as root
# Debe ejecutarse como root

CONFIG_FILE="/etc/sysctl.conf"

# --- IPv4 ---
# If the line exists, replace it with value 1; if not, add it
# Si la línea existe, reemplazar con valor 1; si no, añadirla
if grep -q "^net.ipv4.ip_forward" "$CONFIG_FILE"; then
    sed -i 's/^net\.ipv4\.ip_forward=.*/net.ipv4.ip_forward=1/' "$CONFIG_FILE"
else
    echo "net.ipv4.ip_forward=1" >> "$CONFIG_FILE"
fi

# --- IPv6 ---
# Same process for IPv6 forwarding
# Mismo proceso para el reenvío IPv6
if grep -q "^net.ipv6.conf.all.forwarding" "$CONFIG_FILE"; then
    sed -i 's/^net\.ipv6\.conf\.all\.forwarding=.*/net.ipv6.conf.all.forwarding=1/' "$CONFIG_FILE"
else
    echo "net.ipv6.conf.all.forwarding=1" >> "$CONFIG_FILE"
fi

# Apply the changes immediately
# Aplicar los cambios inmediatamente
sysctl -p

# Display status of IPv4 and IPv6 forwarding
# Mostrar estado del reenvío IPv4 e IPv6
echo "IPv4 forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
echo "IPv6 forwarding: $(cat /proc/sys/net/ipv6/conf/all/forwarding)"
echo "IP forwarding permanently enabled / Reenvío IP activado permanentemente"
