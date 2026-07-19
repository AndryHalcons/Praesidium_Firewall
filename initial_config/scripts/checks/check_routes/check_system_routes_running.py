import subprocess
import json
import os
import re

#Este archivo extrae la tabla de rutas del sistema y genera el archivo routes.json que es el que se muestra en sistema->enrutamiento
#genera/actualiza el snapshot de rutas del sistema usado por Routing.
#This script extracts the system's routing table and refreshes the routes.json snapshot used by Routing.
ROUTES_FILE = "/var/lib/praesidium/state/routes/routes.json"

def run_command(cmd):
    try:
        return subprocess.check_output(cmd, text=True).strip().splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Error ejecutando {' '.join(cmd)}: {e}")
        return []

def parse_route_line(line, table="main", ip_version="ipv4"):
    parts = line.split()
    route = {
        "table": table,
        "ip_version": ip_version,
        "action": "add"
    }

    # Detectar destino
    route["destination"] = parts[0] if parts[0] != "default" else "default"

    # Detectar gateway
    if "via" in parts:
        route["gateway"] = parts[parts.index("via") + 1]

    # Interfaz
    if "dev" in parts:
        route["interface"] = parts[parts.index("dev") + 1]

    # Métrica
    if "metric" in parts:
        route["metric"] = int(parts[parts.index("metric") + 1])

    # Atributos adicionales
    for attr in ["proto", "scope", "src", "type"]:
        if attr in parts:
            route[attr] = parts[parts.index(attr) + 1]

    return route

def get_all_tables():
    lines = run_command(["ip", "route", "show", "table", "all"])
    tables = set()
    for line in lines:
        match = re.search(r"table (\S+)", line)
        if match:
            tables.add(match.group(1))
    return list(tables) or ["main"]

def get_routes():
    routes = []

    # IPv4 por tabla
    for table in get_all_tables():
        lines = run_command(["ip", "route", "show", "table", table])
        for line in lines:
            routes.append(parse_route_line(line, table=table, ip_version="ipv4"))

    # IPv6 por tabla
    for table in get_all_tables():
        lines = run_command(["ip", "-6", "route", "show", "table", table])
        for line in lines:
            routes.append(parse_route_line(line, table=table, ip_version="ipv6"))

    return routes

def get_rules():
    lines = run_command(["ip", "rule", "show"])
    rules = []
    for line in lines:
        parts = line.split()
        rule = {"action": "add"}
        for i, part in enumerate(parts):
            if part == "from":
                rule["from"] = parts[i + 1]
            elif part == "to":
                rule["to"] = parts[i + 1]
            elif part == "lookup":
                rule["table"] = parts[i + 1]
            elif part == "priority":
                rule["priority"] = int(parts[i + 1])
        rules.append(rule)
    return rules

def save_to_json(routes, rules, path):
    data = {
        "routes": routes,
        "rules": rules
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Rutas y reglas guardadas en {path}")

def generate_routes_file():
    routes = get_routes()
    rules = get_rules()
    save_to_json(routes, rules, ROUTES_FILE)

# Llamada principal
generate_routes_file()
