#!/usr/bin/env python3

import subprocess
import json
import os

# Este script genera un listado de TODAS las interfaces  en formato JSON, será el que se use en los formularios de la GUI
# This script generates a list of ALL interfaces in JSON format; it will be used in the GUI forms


def get_all_interfaces():
    result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    interfaces = []

    for line in lines:
        parts = line.split(": ")
        if len(parts) >= 2:
            name = parts[1].split("@")[0].strip()
            if name != "lo":  # Excluir loopback
                interfaces.append(name)
    return interfaces


def classify_interfaces(interfaces):
    return {
        "ethernets": [i for i in interfaces if i.startswith(("eth", "enp", "en"))],
        "bridge":    [i for i in interfaces if i.startswith("br")],
        "vlans":     [i for i in interfaces if i.startswith("vlan")],
        "bonds":     [i for i in interfaces if i.startswith("bond")],
        "wireguard": [i for i in interfaces if i.startswith("wg")],
        "wifis":     [i for i in interfaces if i.startswith(("wl", "ath"))],
    }

def save_interfaces_to_json(path, interfaces, categories):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = {"all_interfaces": interfaces}
    data.update(categories)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def check_generate_all_interfaces_list():
    output_path = "/var/lib/praesidium/state/interfaces/all_interfaces_list.json"
    interfaces = get_all_interfaces()
    categories = classify_interfaces(interfaces)
    save_interfaces_to_json(output_path, interfaces, categories)

check_generate_all_interfaces_list()

