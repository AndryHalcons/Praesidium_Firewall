#!/usr/bin/env python3

import subprocess
import json
import os

# Este script genera un listado de interfaces físicas en formato JSON, será el que se use en los formularios de la GUI (incluido ifindex)
# This script generates a list of physical interfaces in JSON format; it will be used in the GUI forms (include ifindex)

#  Obtiene el índice de interfaz (ifindex) desde /sys/class/net/<interfaz>/ifindex
#  Gets the interface index (ifindex) from /sys/class/net/<interface>/ifindex
def get_ifindex(interface):
    path = f"/sys/class/net/{interface}/ifindex"
    try:
        with open(path) as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return None  # Si no existe, devuelve None
        # If it doesn't exist, return None

#  Extrae las interfaces físicas del sistema usando 'ip link show'
#  Extracts physical interfaces from the system using 'ip link show'
def get_physical_interfaces():
    #  Extrae las interfaces físicas del sistema usando 'ip link show'
    #  Extracts physical interfaces from the system using 'ip link show'
    result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    interfaces = []

    for line in lines:
        if ": " in line:
            # Extrae el nombre de la interfaz
            # Extracts the interface name
            name = line.split(": ")[1].split("@")[0].strip()
            # Filtra solo interfaces físicas válidas
            # Filters only valid physical interfaces
            if name.startswith(("en", "eth", "wl")):
                # Añade la interfaz con su ifindex
                # Adds the interface with its ifindex
                ifindex = get_ifindex(name)
                interfaces.append({
                    "name": name,
                    "ifindex": ifindex
                })
    return interfaces


#  Guarda el listado de interfaces en formato JSON
#  Saves the list of interfaces in JSON format
def save_interfaces_to_json(path, interfaces):
    os.makedirs(os.path.dirname(path), exist_ok=True)  # Crea el directorio si no existe
    # Creates the directory if it doesn't exist
    with open(path, "w") as f:
        json.dump({"physical_interfaces": interfaces}, f, indent=2)


def check_generate_physical_interfaces_list():
    output_path = "/var/lib/praesidium/state/interfaces/physical_interfaces_list.json"
    interfaces = get_physical_interfaces()
    save_interfaces_to_json(output_path, interfaces)


if __name__ == "__main__":
    check_generate_physical_interfaces_list()
