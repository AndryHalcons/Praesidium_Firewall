#!/bin/bash
set -e

# Desinstalando ifupdown / Uninstalling ifupdown
if dpkg -l | grep -q "^ii  ifupdown "; then
    apt remove -y ifupdown
    echo "ifupdown ha sido desinstalado correctamente. / ifupdown has been successfully uninstalled."
else
    echo "ifupdown no está instalado en este sistema. / ifupdown is not installed on this system."
fi

# Desinstalando UFW / Uninstalling UFW
if dpkg -l | grep -q "^ii  ufw "; then
    apt remove -y ufw
    echo "UFW ha sido desinstalado correctamente. / UFW has been successfully uninstalled."
else
    echo "UFW no está instalado en este sistema. / UFW is not installed on this system."
fi



# Desinstalando iptables / Uninstalling iptables
if dpkg -l | grep -q "^ii  iptables "; then
    apt remove -y iptables
    echo "iptables ha sido desinstalado correctamente. / iptables has been successfully uninstalled."
else
    echo "iptables no está instalado en este sistema. / iptables is not installed on this system."
fi

# Desinstalando nftables / Uninstalling nftables
#if dpkg -l | grep -q "^ii  nftables "; then
#    apt remove -y nftables
# echo " nftables ha sido desinstalado correctamente. / nftables has been successfully uninstalled."
#else
# echo " nftables no está instalado en este sistema. / nftables is not installed on this system."
#fi
