#!/usr/bin/env python3

import subprocess
import json
import os
import sys
from pathlib import Path

INTERFACE_HELPERS_DIR = Path(os.environ.get("PRAESIDIUM_INTERFACE_HELPERS_DIR", "/var/lib/praesidium/scripts/checks/check_interfaces"))
SOURCE_INTERFACE_HELPERS_DIR = Path(__file__).resolve().parents[1] / "checks" / "check_interfaces"
for helper_dir in (INTERFACE_HELPERS_DIR, SOURCE_INTERFACE_HELPERS_DIR):
    if helper_dir.exists() and str(helper_dir) not in sys.path:
        sys.path.insert(0, str(helper_dir))
from interface_uuid_helpers import ensure_interface_uuids, new_interface_entry

#Este script añade las interfaces FISICAS nuevas detectadas por el sistema al archivo interfaces
#This script adds newly detected physical interfaces from the system to the interfaces file.

# Ejecutar 'ip link show' y obtener nombres de interfaces físicas
# Run 'ip link show' and get physical interface names (excluding loopback)
def get_system_interfaces():
    result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    interfaces = []

    for line in lines:
        if ": " in line:
            name = line.split(": ")[1].split("@")[0].strip()
            if name.startswith(("en", "eth", "wl")):
                interfaces.append(name)
    return interfaces

#carga el json de interfaces de /var/lib/praesidium/candidate
#loads the interfaces json from /var/lib/praesidium/candidate
def load_iface_json_file(path):
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError:
        return {}

# Añade las interfaces que no existan al JSON de interfaces de /var/lib/praesidium/candidate
# Add non-existent interfaces to the interfaces JSON in /var/lib/praesidium/candidate
def iface_compare_and_write(system_ifaces, iface_json):
    # Aseguramos que la sección 'network' exista en el JSON
    # Ensure the 'network' section exists in the JSON
    if "network" not in iface_json:
        iface_json["network"] = {}

    # Lista de todas las subsecciones que deben existir
    # List of all required subsections
    required_sections = ["ethernets", "wifis", "bonds", "bridges", "vlans", "wireguard"]

    # Creamos cualquier subsección que falte
    # Create any missing subsection
    for section in required_sections:
        if section not in iface_json["network"]:
            iface_json["network"][section] = {}

    # Referencias directas a secciones relevantes
    # Direct references to relevant sections
    ethernets = iface_json["network"]["ethernets"]
    wifis = iface_json["network"]["wifis"]

    # Recorremos las interfaces físicas detectadas en el sistema
    # Iterate over physical interfaces detected on the system
    for iface in system_ifaces:
        # Si es una interfaz Ethernet y no está en el JSON, la añadimos vacía
        # If it's an Ethernet interface and not in the JSON, add it as empty
        if iface.startswith(("en", "eth")) and iface not in ethernets:
            ethernets[iface] = new_interface_entry(iface_json, "ethernets", iface)

        # Si es una interfaz Wi-Fi y no está en el JSON, la añadimos vacía
        # If it's a Wi-Fi interface and not in the JSON, add it as empty
        elif iface.startswith("wl") and iface not in wifis:
            wifis[iface] = new_interface_entry(iface_json, "wifis", iface)

    # Devolvemos el JSON actualizado con las nuevas interfaces añadidas
    # Return the updated JSON with newly added interfaces
    return ensure_interface_uuids(iface_json)


# Guarda el JSON actualizado en el archivo especificado
# Save the updated JSON to the specified file
def save_iface_json_file(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=4)
        return True  # Éxito / Success
    except Exception as e:
        print(f"Error al guardar el archivo: {e}")  # Error message
        return False  # Fallo / Failure


# Ejecutar el proceso completo directamente
# Execute the full process directly
def run_check_new_interfaces():
    #json path
    iface_json_path = "/var/lib/praesidium/candidate/interfaces.json"
    #get physical interfaces
    system_ifaces = get_system_interfaces()
    #load json
    iface_json = load_iface_json_file(iface_json_path)
    #write add ifaces on json
    json_output = iface_compare_and_write(system_ifaces,iface_json)
    #save json
    save_iface_json_file(iface_json_path, json_output)
