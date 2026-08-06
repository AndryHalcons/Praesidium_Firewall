import yaml
import shutil
import subprocess
import os
import json
import ast
from task_update_json import task_update_json





######################################################################################################
################################## PARSE JSON TO YML FORMAT ##########################################
######################################################################################################

# Inicializa la estructura base compatible con Netplan
# Initialize the base structure compatible with Netplan
def initial_yaml_format():
    return {
        "network": {
            "version": 2,
            "ethernets": {},
            "bonds": {},
            "bridges": {},
            "vlans": {},
            "wifis": {},
            "wireguard": {}
        }
    }

# Procesa las interfaces tipo bond y las añade al objeto Netplan  
# Processes bond-type interfaces and adds them to the Netplan object  
def parser_bonds(data, netplan):
    for name, config in data.items():
        # Normaliza entradas bond vacías heredadas como [] para evitar fallos al generar Netplan.
        # Normalize legacy empty bond entries stored as [] to avoid Netplan generation failures.
        if not isinstance(config, dict):
            config = {}
        bond = {}

        # Interfaces esclavas del bond  
        # Bond slave interfaces
        if config.get("interfaces"):
            bond["interfaces"] = [i.strip() for i in config["interfaces"].split(",") if i.strip()]

        # Configuración de DHCP  
        # DHCP configuration
        if config.get("dhcp4", "false").lower() == "true":
            bond["dhcp4"] = True
        if config.get("dhcp6", "false").lower() == "true":
            bond["dhcp6"] = True

        # Direcciones IP estáticas  
        # Static IP addresses
        if config.get("addresses"):
            bond["addresses"] = [a.strip() for a in config["addresses"].split(",") if a.strip()]

        # Las puertas de enlace gateway4/gateway6 están deprecated en Netplan.
        # The gateway4/gateway6 keys are deprecated in Netplan.
        # No se emiten aquí; si existen valores heredados, se migran a rutas default más abajo.
        # They are not emitted here; legacy values are migrated to default routes below.

        # MTU  
        # MTU
        if config.get("mtu"):
            try:
                bond["mtu"] = int(config["mtu"])
            except ValueError:
                pass

        # Dirección MAC  
        # MAC address
        if config.get("macaddress"):
            bond["macaddress"] = config["macaddress"]

        # Servidores DNS  
        # DNS servers
        nameservers = {}
        if config.get("nameservers.addresses"):
            ns = [ns.strip() for ns in config["nameservers.addresses"].split(",") if ns.strip()]
            if ns:
                nameservers["addresses"] = ns
        if config.get("nameservers.search"):
            search = [s.strip() for s in config["nameservers.search"].split(",") if s.strip()]
            if search:
                nameservers["search"] = search
        if nameservers:
            bond["nameservers"] = nameservers

        # Parámetros específicos del bond  
        # Bond-specific parameters
        parameters = {}
        integer_bond_parameters = {"mii-monitor-interval", "up-delay", "down-delay", "min-links"}
        for key, value in config.items():
            if key.startswith("parameters.") and value != "":
                param_name = key.split(".", 1)[1]
                if param_name in integer_bond_parameters:
                    try:
                        parameters[param_name] = int(value)
                    except (TypeError, ValueError):
                        pass
                else:
                    parameters[param_name] = value
        if parameters:
            bond["parameters"] = parameters

        # Campos adicionales  
        # Additional fields
        if config.get("optional", "false").lower() == "true":
            bond["optional"] = True
        if config.get("accept-ra", "false").lower() == "true":
            bond["accept-ra"] = True
        # Netplan espera ipv6-privacy como booleano; la WebGUI lo guarda como texto "true"/"false".
        # Netplan expects ipv6-privacy as a boolean; the WebGUI stores it as text "true"/"false".
        ipv6_privacy = str(config.get("ipv6-privacy", "")).lower()
        if ipv6_privacy in ["true", "enabled", "preferred"]:
            bond["ipv6-privacy"] = True
        elif ipv6_privacy in ["false", "disabled"]:
            bond["ipv6-privacy"] = False

        # Rutas  
        # Routes
        routes = []
        if config.get("routes.to") and config.get("routes.via"):
            route = {"to": config["routes.to"], "via": config["routes.via"]}
            if config.get("routes.metric"):
                try:
                    route["metric"] = int(config["routes.metric"])
                except ValueError:
                    pass
            routes.append(route)

        # Migra rutas heredadas guardadas como string/dict/list bajo "routes".
        # Migrate legacy routes stored as string/dict/list under "routes".
        if not routes and config.get("routes"):
            legacy_routes = config.get("routes")
            if isinstance(legacy_routes, str):
                try:
                    legacy_routes = ast.literal_eval(legacy_routes)
                except (ValueError, SyntaxError):
                    legacy_routes = None
            if isinstance(legacy_routes, dict) and legacy_routes.get("to") and legacy_routes.get("via"):
                routes.append({"to": legacy_routes["to"], "via": legacy_routes["via"]})
            elif isinstance(legacy_routes, list):
                for legacy_route in legacy_routes:
                    if isinstance(legacy_route, dict) and legacy_route.get("to") and legacy_route.get("via"):
                        routes.append({"to": legacy_route["to"], "via": legacy_route["via"]})

        # Migra valores heredados gateway4/gateway6 a rutas default para no emitir claves deprecated.
        # Migrate legacy gateway4/gateway6 values to default routes to avoid emitting deprecated keys.
        if not routes:
            if config.get("gateway4"):
                routes.append({"to": "default", "via": config["gateway4"]})
            if config.get("gateway6"):
                routes.append({"to": "default", "via": config["gateway6"]})
        if routes:
            bond["routes"] = routes

        # Overrides DHCPv4  
        # DHCPv4 overrides
        dhcp4_overrides = {}
        for key in ["use-dns", "use-routes", "send-hostname", "use-hostname"]:
            full_key = f"dhcp4-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp4_overrides[key] = True
        if config.get("dhcp4-overrides.hostname"):
            dhcp4_overrides["hostname"] = config["dhcp4-overrides.hostname"]
        if dhcp4_overrides:
            bond["dhcp4-overrides"] = dhcp4_overrides

        # Overrides DHCPv6  
        # DHCPv6 overrides
        dhcp6_overrides = {}
        for key in ["use-dns", "use-routes"]:
            full_key = f"dhcp6-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp6_overrides[key] = True
        if dhcp6_overrides:
            bond["dhcp6-overrides"] = dhcp6_overrides

        # Bonds son interfaces virtuales: match.* y set-name no son claves válidas aquí en Netplan.
        # Bonds are virtual interfaces: match.* and set-name are not valid Netplan keys here.

        # Añade la interfaz bond al bloque Netplan  
        # Add the bond interface to the Netplan block
        netplan["network"]["bonds"][name] = bond


# Procesa las interfaces tipo bridge y las añade al objeto Netplan  
# Processes bridge-type interfaces and adds them to the Netplan object  
def parser_bridges(data, netplan):
    for name, config in data.items():
        # Normaliza entradas bridge vacías heredadas como [] para evitar fallos al generar Netplan.
        # Normalize legacy empty bridge entries stored as [] to avoid Netplan generation failures.
        if not isinstance(config, dict):
            config = {}
        bridge = {}

        # Asigna las interfaces esclavas  
        # Assign slave interfaces
        if config.get("interfaces"):
            bridge["interfaces"] = [i.strip() for i in config["interfaces"].split(",") if i.strip()]

        # Configura DHCP  
        # Configure DHCP
        if config.get("dhcp4", "false").lower() == "true":
            bridge["dhcp4"] = True
        if config.get("dhcp6", "false").lower() == "true":
            bridge["dhcp6"] = True

        # Direcciones estáticas  
        # Static addresses
        if config.get("addresses"):
            bridge["addresses"] = [a.strip() for a in config["addresses"].split(",") if a.strip()]

        # Las puertas de enlace gateway4/gateway6 están deprecated en Netplan.
        # The gateway4/gateway6 keys are deprecated in Netplan.
        # No se emiten aquí; si existen valores heredados, se migran a rutas default más abajo.
        # They are not emitted here; legacy values are migrated to default routes below.

        # MTU  
        # MTU
        if config.get("mtu"):
            try:
                bridge["mtu"] = int(config["mtu"])
            except ValueError:
                pass

        # Dirección MAC  
        # MAC address
        if config.get("macaddress"):
            bridge["macaddress"] = config["macaddress"]

        # Servidores DNS  
        # DNS servers
        nameservers = {}
        if config.get("nameservers.addresses"):
            ns = [ns.strip() for ns in config["nameservers.addresses"].split(",") if ns.strip()]
            if ns:
                nameservers["addresses"] = ns
        if config.get("nameservers.search"):
            search = [s.strip() for s in config["nameservers.search"].split(",") if s.strip()]
            if search:
                nameservers["search"] = search
        if nameservers:
            bridge["nameservers"] = nameservers

        # Parámetros específicos del bridge  
        # Bridge-specific parameters
        parameters = {}
        integer_bridge_parameters = {"priority", "forward-delay", "hello-time", "max-age", "ageing-time"}
        for key, value in config.items():
            if key.startswith("parameters.") and value != "":
                param_name = key.split(".", 1)[1]
                if param_name == "stp":
                    parameters[param_name] = str(value).lower() == "true"
                elif param_name in integer_bridge_parameters:
                    try:
                        parameters[param_name] = int(value)
                    except (TypeError, ValueError):
                        pass
                else:
                    parameters[param_name] = value
        if parameters:
            bridge["parameters"] = parameters

        # Configura campos adicionales  
        # Configure additional fields
        if config.get("optional", "false").lower() == "true":
            bridge["optional"] = True
        if config.get("accept-ra", "false").lower() == "true":
            bridge["accept-ra"] = True
        # Netplan espera ipv6-privacy como booleano; la WebGUI lo guarda como texto "true"/"false".
        # Netplan expects ipv6-privacy as a boolean; the WebGUI stores it as text "true"/"false".
        ipv6_privacy = str(config.get("ipv6-privacy", "")).lower()
        if ipv6_privacy in ["true", "enabled", "preferred"]:
            bridge["ipv6-privacy"] = True
        elif ipv6_privacy in ["false", "disabled"]:
            bridge["ipv6-privacy"] = False

        # Configura rutas  
        # Configure routes
        routes = []
        if config.get("routes.to") and config.get("routes.via"):
            route = {"to": config["routes.to"], "via": config["routes.via"]}
            if config.get("routes.metric"):
                try:
                    route["metric"] = int(config["routes.metric"])
                except ValueError:
                    pass
            routes.append(route)

        # Migra rutas heredadas guardadas como string/dict bajo "routes".
        # Migrate legacy routes stored as string/dict under "routes".
        if not routes and config.get("routes"):
            legacy_routes = config.get("routes")
            if isinstance(legacy_routes, str):
                try:
                    legacy_routes = ast.literal_eval(legacy_routes)
                except (ValueError, SyntaxError):
                    legacy_routes = None
            if isinstance(legacy_routes, dict) and legacy_routes.get("to") and legacy_routes.get("via"):
                routes.append({"to": legacy_routes["to"], "via": legacy_routes["via"]})
            elif isinstance(legacy_routes, list):
                for legacy_route in legacy_routes:
                    if isinstance(legacy_route, dict) and legacy_route.get("to") and legacy_route.get("via"):
                        routes.append({"to": legacy_route["to"], "via": legacy_route["via"]})

        # Migra valores heredados gateway4/gateway6 a rutas default para no emitir claves deprecated.
        # Migrate legacy gateway4/gateway6 values to default routes to avoid emitting deprecated keys.
        if not routes:
            if config.get("gateway4"):
                routes.append({"to": "default", "via": config["gateway4"]})
            if config.get("gateway6"):
                routes.append({"to": "default", "via": config["gateway6"]})
        if routes:
            bridge["routes"] = routes

        # Configura overrides DHCPv4  
        # Configure DHCPv4 overrides
        dhcp4_overrides = {}
        for key in ["use-dns", "use-routes", "send-hostname", "use-hostname"]:
            full_key = f"dhcp4-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp4_overrides[key] = True
        if config.get("dhcp4-overrides.hostname"):
            dhcp4_overrides["hostname"] = config["dhcp4-overrides.hostname"]
        if dhcp4_overrides:
            bridge["dhcp4-overrides"] = dhcp4_overrides

        # Configura overrides DHCPv6  
        # Configure DHCPv6 overrides
        dhcp6_overrides = {}
        for key in ["use-dns", "use-routes"]:
            full_key = f"dhcp6-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp6_overrides[key] = True
        if dhcp6_overrides:
            bridge["dhcp6-overrides"] = dhcp6_overrides

        # Bridges son interfaces virtuales: match.* y set-name no son claves válidas aquí en Netplan.
        # Bridges are virtual interfaces: match.* and set-name are not valid Netplan keys here.

        # Añade la interfaz bridge al bloque Netplan  
        # Add the bridge interface to the Netplan block
        netplan["network"]["bridges"][name] = bridge

# Procesa las interfaces tipo ethernet y las añade al objeto Netplan  
# Processes ethernet-type interfaces and adds them to the Netplan object  
def parser_ethernets(data, netplan):
    for name, config in data.items():
        # Normaliza entradas ethernet vacías heredadas como [] para evitar fallos al generar Netplan.
        # Normalize legacy empty Ethernet entries stored as [] to avoid Netplan generation failures.
        if not isinstance(config, dict):
            config = {}
        ethernet = {}

        # Configura DHCP  
        # Configure DHCP
        if config.get("dhcp4", "false").lower() == "true":
            ethernet["dhcp4"] = True
        if config.get("dhcp6", "false").lower() == "true":
            ethernet["dhcp6"] = True

        # Direcciones estáticas  
        # Static addresses
        if config.get("addresses"):
            ethernet["addresses"] = [a.strip() for a in config["addresses"].split(",") if a.strip()]

        # Las puertas de enlace gateway4/gateway6 están deprecated en Netplan.
        # The gateway4/gateway6 keys are deprecated in Netplan.
        # No se emiten aquí; si existen valores heredados, se migran a rutas default más abajo.
        # They are not emitted here; legacy values are migrated to default routes below.

        # MTU  
        # MTU
        if config.get("mtu"):
            try:
                ethernet["mtu"] = int(config["mtu"])
            except ValueError:
                pass

        # Dirección MAC  
        # MAC address
        if config.get("macaddress"):
            ethernet["macaddress"] = config["macaddress"]

        # Servidores DNS  
        # DNS servers
        nameservers = {}
        if config.get("nameservers.addresses"):
            ns = [ns.strip() for ns in config["nameservers.addresses"].split(",") if ns.strip()]
            if ns:
                nameservers["addresses"] = ns
        if config.get("nameservers.search"):
            search = [s.strip() for s in config["nameservers.search"].split(",") if s.strip()]
            if search:
                nameservers["search"] = search
        if nameservers:
            ethernet["nameservers"] = nameservers

        # Configura campos adicionales  
        # Configure additional fields
        if config.get("optional", "false").lower() == "true":
            ethernet["optional"] = True
        if config.get("accept-ra", "false").lower() == "true":
            ethernet["accept-ra"] = True
        if config.get("wakeonlan", "false").lower() == "true":
            ethernet["wakeonlan"] = True
        # Netplan espera ipv6-privacy como booleano; la WebGUI lo guarda como texto "true"/"false".
        # Netplan expects ipv6-privacy as a boolean; the WebGUI stores it as text "true"/"false".
        ipv6_privacy = str(config.get("ipv6-privacy", "")).lower()
        if ipv6_privacy in ["true", "enabled", "preferred"]:
            ethernet["ipv6-privacy"] = True
        elif ipv6_privacy in ["false", "disabled"]:
            ethernet["ipv6-privacy"] = False

        # Configura rutas  
        # Configure routes
        routes = []
        if config.get("routes.to") and config.get("routes.via"):
            route = {"to": config["routes.to"], "via": config["routes.via"]}
            if config.get("routes.metric"):
                try:
                    route["metric"] = int(config["routes.metric"])
                except ValueError:
                    pass
            routes.append(route)

        # Migra rutas heredadas guardadas como string/dict/list bajo "routes".
        # Migrate legacy routes stored as string/dict/list under "routes".
        if not routes and config.get("routes"):
            legacy_routes = config.get("routes")
            if isinstance(legacy_routes, str):
                try:
                    legacy_routes = ast.literal_eval(legacy_routes)
                except (ValueError, SyntaxError):
                    legacy_routes = None
            if isinstance(legacy_routes, dict) and legacy_routes.get("to") and legacy_routes.get("via"):
                routes.append({"to": legacy_routes["to"], "via": legacy_routes["via"]})
            elif isinstance(legacy_routes, list):
                for legacy_route in legacy_routes:
                    if isinstance(legacy_route, dict) and legacy_route.get("to") and legacy_route.get("via"):
                        routes.append({"to": legacy_route["to"], "via": legacy_route["via"]})

        # Migra valores heredados gateway4/gateway6 a rutas default para no emitir claves deprecated.
        # Migrate legacy gateway4/gateway6 values to default routes to avoid emitting deprecated keys.
        if not routes:
            if config.get("gateway4"):
                routes.append({"to": "default", "via": config["gateway4"]})
            if config.get("gateway6"):
                routes.append({"to": "default", "via": config["gateway6"]})
        if routes:
            ethernet["routes"] = routes

        # Configura overrides DHCPv4  
        # Configure DHCPv4 overrides
        dhcp4_overrides = {}
        for key in ["use-dns", "use-routes", "send-hostname", "use-hostname"]:
            full_key = f"dhcp4-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp4_overrides[key] = True
        if config.get("dhcp4-overrides.hostname"):
            dhcp4_overrides["hostname"] = config["dhcp4-overrides.hostname"]
        if dhcp4_overrides:
            ethernet["dhcp4-overrides"] = dhcp4_overrides

        # Configura overrides DHCPv6  
        # Configure DHCPv6 overrides
        dhcp6_overrides = {}
        for key in ["use-dns", "use-routes"]:
            full_key = f"dhcp6-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp6_overrides[key] = True
        if dhcp6_overrides:
            ethernet["dhcp6-overrides"] = dhcp6_overrides

        # Configura bloque match  
        # Configure match block
        match = {}
        for key in ["name", "macaddress", "driver"]:
            full_key = f"match.{key}"
            if config.get(full_key):
                match[key] = config[full_key]
        if match:
            ethernet["match"] = match

        # Configura set-name  
        # Configure set-name
        if config.get("set-name"):
            ethernet["set-name"] = config["set-name"]

        # Añade la interfaz ethernet al bloque Netplan  
        # Add the ethernet interface to the Netplan block
        netplan["network"]["ethernets"][name] = ethernet


# Procesa las interfaces tipo wireguard y las añade al objeto Netplan  
# Processes wireguard-type interfaces and adds them to the Netplan object  
def parser_wireguard(data, netplan):
    for name, config in data.items():
        wg = {}

        # Direcciones IP asignadas  
        # Assigned IP addresses
        if config.get("addresses"):
            wg["addresses"] = [a.strip() for a in config["addresses"].split(",") if a.strip()]

        # Puerto de escucha  
        # Listening port
        if config.get("port"):
            try:
                wg["port"] = int(config["port"])
            except ValueError:
                pass

        # Clave privada  
        # Private key
        if config.get("key.private"):
            wg["private-key"] = config["key.private"]

        # Configuración de peers  
        # Peer configuration
        peers = {}
        if config.get("peers.keys.public"):
            peers["public-key"] = config["peers.keys.public"]
        if config.get("peers.allowed-ips"):
            peers["allowed-ips"] = [ip.strip() for ip in config["peers.allowed-ips"].split(",") if ip.strip()]
        if config.get("peers.keepalive"):
            try:
                peers["persistent-keepalive"] = int(config["peers.keepalive"])
            except ValueError:
                pass
        if config.get("peers.endpoint"):
            peers["endpoint"] = config["peers.endpoint"]
        if peers:
            wg["peers"] = [peers]

        # Rutas asociadas  
        # Associated routes
        routes = {}
        if config.get("routes.to"):
            routes["to"] = config["routes.to"]
        if config.get("routes.via"):
            routes["via"] = config["routes.via"]
        if config.get("routes.table"):
            routes["table"] = config["routes.table"]
        if routes:
            wg["routes"] = [routes]

        # Política de enrutamiento  
        # Routing policy
        policy = {}
        if config.get("routing-policy.from"):
            policy["from"] = config["routing-policy.from"]
        if config.get("routing-policy.table"):
            policy["table"] = config["routing-policy.table"]
        if policy:
            wg["routing-policy"] = policy

        # Marca de tráfico  
        # Traffic mark
        if config.get("mark"):
            wg["mark"] = config["mark"]

        # MTU  
        # MTU
        if config.get("mtu"):
            try:
                wg["mtu"] = int(config["mtu"])
            except ValueError:
                pass

        # set-name  
        # Set-name
        if config.get("set-name"):
            wg["set-name"] = config["set-name"]

        # Añade la interfaz wireguard al bloque Netplan  
        # Add the wireguard interface to the Netplan block
        netplan["network"]["wireguard"][name] = wg

# Procesa las interfaces tipo VLAN y las añade al objeto Netplan  
# Processes VLAN-type interfaces and adds them to the Netplan object  
def parser_vlans(data, netplan):
    for name, config in data.items():
        # Normaliza entradas VLAN vacías heredadas como [] para evitar fallos al generar Netplan.
        # Normalize legacy empty VLAN entries stored as [] to avoid Netplan generation failures.
        if not isinstance(config, dict):
            config = {}
        vlan = {}

        # ID de la VLAN  
        # VLAN ID
        if config.get("id"):
            try:
                vlan["id"] = int(config["id"])
            except ValueError:
                pass

        # Enlace físico al que se asocia la VLAN  
        # Physical link associated with the VLAN
        if config.get("link"):
            vlan["link"] = config["link"]

        # Configura DHCP  
        # Configure DHCP
        if config.get("dhcp4", "false").lower() == "true":
            vlan["dhcp4"] = True
        if config.get("dhcp6", "false").lower() == "true":
            vlan["dhcp6"] = True

        # Direcciones IP estáticas  
        # Static IP addresses
        if config.get("addresses"):
            vlan["addresses"] = [a.strip() for a in config["addresses"].split(",") if a.strip()]

        # Las puertas de enlace gateway4/gateway6 están deprecated en Netplan.
        # The gateway4/gateway6 keys are deprecated in Netplan.
        # No se emiten aquí; si existen valores heredados, se migran a rutas default más abajo.
        # They are not emitted here; legacy values are migrated to default routes below.

        # MTU  
        # MTU
        if config.get("mtu"):
            try:
                vlan["mtu"] = int(config["mtu"])
            except ValueError:
                pass

        # Dirección MAC  
        # MAC address
        if config.get("macaddress"):
            vlan["macaddress"] = config["macaddress"]

        # Servidores DNS  
        # DNS servers
        nameservers = {}
        if config.get("nameservers.addresses"):
            ns = [ns.strip() for ns in config["nameservers.addresses"].split(",") if ns.strip()]
            if ns:
                nameservers["addresses"] = ns
        if config.get("nameservers.search"):
            search = [s.strip() for s in config["nameservers.search"].split(",") if s.strip()]
            if search:
                nameservers["search"] = search
        if nameservers:
            vlan["nameservers"] = nameservers

        # Campos adicionales  
        # Additional fields
        if config.get("optional", "false").lower() == "true":
            vlan["optional"] = True
        if config.get("accept-ra", "false").lower() == "true":
            vlan["accept-ra"] = True
        # Netplan espera ipv6-privacy como booleano; la WebGUI lo guarda como texto "true"/"false".
        # Netplan expects ipv6-privacy as a boolean; the WebGUI stores it as text "true"/"false".
        # wakeonlan no se emite en VLANs porque Netplan solo lo acepta en interfaces físicas.
        # wakeonlan is not emitted for VLANs because Netplan only accepts it on physical interfaces.
        ipv6_privacy = str(config.get("ipv6-privacy", "")).lower()
        if ipv6_privacy in ["true", "enabled", "preferred"]:
            vlan["ipv6-privacy"] = True
        elif ipv6_privacy in ["false", "disabled"]:
            vlan["ipv6-privacy"] = False

        # Rutas  
        # Routes
        routes = []
        if config.get("routes.to") and config.get("routes.via"):
            route = {"to": config["routes.to"], "via": config["routes.via"]}
            if config.get("routes.metric"):
                try:
                    route["metric"] = int(config["routes.metric"])
                except ValueError:
                    pass
            routes.append(route)

        # Migra rutas heredadas guardadas como string/dict/list bajo "routes".
        # Migrate legacy routes stored as string/dict/list under "routes".
        if not routes and config.get("routes"):
            legacy_routes = config.get("routes")
            if isinstance(legacy_routes, str):
                try:
                    legacy_routes = ast.literal_eval(legacy_routes)
                except (ValueError, SyntaxError):
                    legacy_routes = None
            if isinstance(legacy_routes, dict) and legacy_routes.get("to") and legacy_routes.get("via"):
                routes.append({"to": legacy_routes["to"], "via": legacy_routes["via"]})
            elif isinstance(legacy_routes, list):
                for legacy_route in legacy_routes:
                    if isinstance(legacy_route, dict) and legacy_route.get("to") and legacy_route.get("via"):
                        routes.append({"to": legacy_route["to"], "via": legacy_route["via"]})

        # Migra valores heredados gateway4/gateway6 a rutas default para no emitir claves deprecated.
        # Migrate legacy gateway4/gateway6 values to default routes to avoid emitting deprecated keys.
        if not routes:
            if config.get("gateway4"):
                routes.append({"to": "default", "via": config["gateway4"]})
            if config.get("gateway6"):
                routes.append({"to": "default", "via": config["gateway6"]})
        if routes:
            vlan["routes"] = routes

        # Overrides DHCPv4  
        # DHCPv4 overrides
        dhcp4_overrides = {}
        for key in ["use-dns", "use-routes", "send-hostname", "use-hostname"]:
            full_key = f"dhcp4-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp4_overrides[key] = True
        if config.get("dhcp4-overrides.hostname"):
            dhcp4_overrides["hostname"] = config["dhcp4-overrides.hostname"]
        if dhcp4_overrides:
            vlan["dhcp4-overrides"] = dhcp4_overrides

        # Overrides DHCPv6  
        # DHCPv6 overrides
        dhcp6_overrides = {}
        for key in ["use-dns", "use-routes"]:
            full_key = f"dhcp6-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp6_overrides[key] = True
        if dhcp6_overrides:
            vlan["dhcp6-overrides"] = dhcp6_overrides

        # VLANs son interfaces virtuales: match.* y set-name no son claves válidas aquí en Netplan.
        # VLANs are virtual interfaces: match.* and set-name are not valid Netplan keys here.

        # Añade la interfaz VLAN al bloque Netplan  
        # Add the VLAN interface to the Netplan block
        netplan["network"]["vlans"][name] = vlan

# Procesa las interfaces tipo wifi y las añade al objeto Netplan  
# Processes wifi-type interfaces and adds them to the Netplan object  
def parser_wifis(data, netplan):
    for name, config in data.items():
        # Normaliza entradas Wi-Fi vacías heredadas como [] para evitar fallos al generar Netplan.
        # Normalize legacy empty Wi-Fi entries stored as [] to avoid Netplan generation failures.
        if not isinstance(config, dict):
            config = {}
        wifi = {}

        # Configura DHCP  
        # Configure DHCP  
        if config.get("dhcp4", "false").lower() == "true":
            wifi["dhcp4"] = True
        if config.get("dhcp6", "false").lower() == "true":
            wifi["dhcp6"] = True

        # Direcciones IP estáticas  
        # Static IP addresses  
        if config.get("addresses"):
            wifi["addresses"] = [a.strip() for a in config["addresses"].split(",") if a.strip()]

        # Las puertas de enlace gateway4/gateway6 están deprecated en Netplan.
        # The gateway4/gateway6 keys are deprecated in Netplan.
        # No se emiten aquí; si existen valores heredados, se migran a rutas default más abajo.
        # They are not emitted here; legacy values are migrated to default routes below.

        # MTU  
        # MTU  
        if config.get("mtu"):
            try:
                wifi["mtu"] = int(config["mtu"])
            except ValueError:
                pass

        # Dirección MAC  
        # MAC address  
        if config.get("macaddress"):
            wifi["macaddress"] = config["macaddress"]

        # Servidores DNS  
        # DNS servers  
        nameservers = {}
        if config.get("nameservers.addresses"):
            ns = [ns.strip() for ns in config["nameservers.addresses"].split(",") if ns.strip()]
            if ns:
                nameservers["addresses"] = ns
        if config.get("nameservers.search"):
            search = [s.strip() for s in config["nameservers.search"].split(",") if s.strip()]
            if search:
                nameservers["search"] = search
        if nameservers:
            wifi["nameservers"] = nameservers

        # Campos adicionales  
        # Additional fields
        if config.get("optional", "false").lower() == "true":
            wifi["optional"] = True
        if config.get("accept-ra", "false").lower() == "true":
            wifi["accept-ra"] = True
        if config.get("wakeonlan", "false").lower() == "true":
            wifi["wakeonlan"] = True
        # Netplan espera ipv6-privacy como booleano; la WebGUI lo guarda como texto "true"/"false".
        # Netplan expects ipv6-privacy as a boolean; the WebGUI stores it as text "true"/"false".
        ipv6_privacy = str(config.get("ipv6-privacy", "")).lower()
        if ipv6_privacy in ["true", "enabled", "preferred"]:
            wifi["ipv6-privacy"] = True
        elif ipv6_privacy in ["false", "disabled"]:
            wifi["ipv6-privacy"] = False

        # Rutas  
        # Routes
        routes = []
        if config.get("routes.to") and config.get("routes.via"):
            route = {"to": config["routes.to"], "via": config["routes.via"]}
            if config.get("routes.metric"):
                try:
                    route["metric"] = int(config["routes.metric"])
                except ValueError:
                    pass
            routes.append(route)

        # Migra rutas heredadas guardadas como string/dict/list bajo "routes".
        # Migrate legacy routes stored as string/dict/list under "routes".
        if not routes and config.get("routes"):
            legacy_routes = config.get("routes")
            if isinstance(legacy_routes, str):
                try:
                    legacy_routes = ast.literal_eval(legacy_routes)
                except (ValueError, SyntaxError):
                    legacy_routes = None
            if isinstance(legacy_routes, dict) and legacy_routes.get("to") and legacy_routes.get("via"):
                routes.append({"to": legacy_routes["to"], "via": legacy_routes["via"]})
            elif isinstance(legacy_routes, list):
                for legacy_route in legacy_routes:
                    if isinstance(legacy_route, dict) and legacy_route.get("to") and legacy_route.get("via"):
                        routes.append({"to": legacy_route["to"], "via": legacy_route["via"]})

        # Migra valores heredados gateway4/gateway6 a rutas default para no emitir claves deprecated.
        # Migrate legacy gateway4/gateway6 values to default routes to avoid emitting deprecated keys.
        if not routes:
            if config.get("gateway4"):
                routes.append({"to": "default", "via": config["gateway4"]})
            if config.get("gateway6"):
                routes.append({"to": "default", "via": config["gateway6"]})
        if routes:
            wifi["routes"] = routes

        # Overrides DHCPv4  
        # DHCPv4 overrides
        dhcp4_overrides = {}
        for key in ["use-dns", "use-routes", "send-hostname", "use-hostname"]:
            full_key = f"dhcp4-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp4_overrides[key] = True
        if config.get("dhcp4-overrides.hostname"):
            dhcp4_overrides["hostname"] = config["dhcp4-overrides.hostname"]
        if dhcp4_overrides:
            wifi["dhcp4-overrides"] = dhcp4_overrides

        # Overrides DHCPv6  
        # DHCPv6 overrides
        dhcp6_overrides = {}
        for key in ["use-dns", "use-routes"]:
            full_key = f"dhcp6-overrides.{key}"
            if config.get(full_key, "false").lower() == "true":
                dhcp6_overrides[key] = True
        if dhcp6_overrides:
            wifi["dhcp6-overrides"] = dhcp6_overrides

        # En Praesidium se usa el backend networkd; Netplan no acepta match.* en wifis con networkd.
        # Praesidium uses the networkd backend; Netplan does not accept match.* on wifis with networkd.
        # set-name depende de match.*, así que tampoco se emite para evitar YAML inválido.
        # set-name depends on match.*, so it is not emitted either to avoid invalid YAML.

        # Puntos de acceso WiFi  
        # WiFi access points  
        access_points = {}
        for key, value in config.items():
            if key.startswith("access-points.") and value:
                parts = key.split(".")
                if len(parts) == 3:
                    ssid, field = parts[1], parts[2]
                    if ssid not in access_points:
                        access_points[ssid] = {}
                    access_points[ssid][field] = value
        if access_points:
            wifi["access-points"] = access_points

        # Añade la interfaz wifi al bloque Netplan  
        # Add the wifi interface to the Netplan block  
        netplan["network"]["wifis"][name] = wifi



#Elimina las secciones vacías dentro del bloque 'network' del diccionario Netplan.
#Esto evita que Netplan rechace el archivo por definiciones incompletas.
#Useful for cleaning up empty blocks like 'wifis: {}' before saving the YAML file.
#This prevents Netplan from rejecting the file due to incomplete definitions.
def remove_empty_sections(netplan):
    # Recorre todas las claves dentro de 'network'
    # Iterate over all keys inside 'network'
    for section in list(netplan.get("network", {})):
        # Si la sección es un diccionario vacío, se elimina
        # If the section is an empty dictionary, delete it
        if isinstance(netplan["network"][section], dict) and not netplan["network"][section]:
            del netplan["network"][section]
    return netplan



# Convierte el JSON completo en estructura Netplan llamando a cada parser
# Converts the full JSON into Netplan structure by calling each parser
def convert(json_data):
    # Inicializa la estructura base de Netplan
    # Initialize Netplan base structure
    netplan = initial_yaml_format()

    # Procesa interfaces tipo bond si están bien formadas
    # Process bond interfaces if properly structured
    bonds_data = json_data.get("network", {}).get("bonds", {})
    if isinstance(bonds_data, dict):
        parser_bonds(bonds_data, netplan)

    # Procesa bridges si es un diccionario válido
    # Process bridges if it's a valid dictionary
    bridges_data = json_data.get("network", {}).get("bridges", {})
    if isinstance(bridges_data, dict):
        parser_bridges(bridges_data, netplan)

    # Procesa ethernets si están bien definidas
    # Process ethernets if properly defined
    ethernets_data = json_data.get("network", {}).get("ethernets", {})
    if isinstance(ethernets_data, dict):
        parser_ethernets(ethernets_data, netplan)

    # Procesa wireguard si hay configuración válida
    # Process wireguard if there's valid config
    wireguard_data = json_data.get("network", {}).get("wireguard", {})
    if isinstance(wireguard_data, dict):
        parser_wireguard(wireguard_data, netplan)

    # Procesa wifis solo si es un diccionario (evita errores con "None")
    # Process wifis only if it's a dictionary (avoids "None" errors)
    wifis_data = json_data.get("network", {}).get("wifis", {})
    if isinstance(wifis_data, dict):
        parser_wifis(wifis_data, netplan)

    # Procesa vlans si están bien formadas
    # Process vlans if properly structured
    vlans_data = json_data.get("network", {}).get("vlans", {})
    if isinstance(vlans_data, dict):
        parser_vlans(vlans_data, netplan)

    # limpiamos los diccionarios vacios
    # we clean the empty dictionaries
    netplan = remove_empty_sections(netplan)
    # Devuelve el objeto Netplan final
    # Return final Netplan object
    return netplan



#########################################################################################################
################################## CHECK YAML ###########################################################
#########################################################################################################

def check_yml_syntax(user, date, path):
    # Verifica si el archivo YAML tiene estructura compatible con Netplan  
    # Checks if the YAML file has a structure compatible with Netplan
    try:
        with open(path, 'r') as f:
            config = yaml.safe_load(f)

        return (
            isinstance(config, dict) and
            "network" in config and
            isinstance(config["network"], dict) and
            config["network"].get("version") == 2
        )
    except Exception:
        task_update_json(date, "gen_interfaz_yml_syntax", "fail")
        exit()


def validate_netplan_file(path):
    # Valida si un archivo YAML es aceptado por Netplan sin aplicarlo  
    # Validates whether a YAML file is accepted by Netplan without applying it
    try:
        netplan_dir = "/etc/netplan"
        backup_dir = "/etc/netplan_backup"
        os.makedirs(backup_dir, exist_ok=True)

        # Respaldamos todos los archivos .yaml actuales  
        # Backup all current .yaml files
        original_files = []
        for file in os.listdir(netplan_dir):
            if file.endswith(".yaml") or file.endswith(".yml"):
                src = os.path.join(netplan_dir, file)
                dst = os.path.join(backup_dir, file)
                shutil.copy2(src, dst)
                os.remove(src)
                original_files.append(file)

        # Copiamos el nuevo archivo temporalmente  
        # Copy the new file temporarily
        temp_path = os.path.join(netplan_dir, "temp_interfaces.yml")
        shutil.copy2(path, temp_path)

        # Ejecutamos netplan generate  
        # Run netplan generate
        result = subprocess.run(
            ["netplan", "--debug", "generate"],
            capture_output=True,
            text=True
        )

        # Eliminamos el archivo temporal  
        # Remove the temporary file
        os.remove(temp_path)

        # Restauramos los archivos originales SIEMPRE  
        # Always restore the original files
        for file in original_files:
            src = os.path.join(backup_dir, file)
            dst = os.path.join(netplan_dir, file)
            shutil.copy2(src, dst)

        # Eliminamos el directorio de respaldo  
        # Remove the backup directory
        shutil.rmtree(backup_dir)

        # Si hubo error, lo devolvemos  
        # Return error if validation failed
        if result.returncode != 0:
            return False, result.stderr.strip()

        # Si todo fue bien, devolvemos éxito  
        # Return success if validation passed
        return True, None

    except Exception as e:
        # En caso de excepción, devolvemos el error  
        # Return error if an exception occurs
        return False, str(e)

def verify_yaml(user, date, path):
    # Verifica sintaxis y compatibilidad con Netplan sin aplicar  
    # Verifies syntax and Netplan compatibility without applying
    syntax_ok = check_yml_syntax(user, date, path)
    is_valid, error_msg = validate_netplan_file(path)

    if not syntax_ok:
        task_update_json(date, "gen_interfaz_verify_yml", "fail")
        exit()

    if not is_valid:
        task_update_json(date, "gen_interfaz_verify_yml", "fail")
        exit()

    task_update_json(date, "gen_interfaz_verify_yml", "success")


#########################################################################################################
################################## main #################################################################
#########################################################################################################

# Punto de entrada principal del script
# Main entry point of the script
def gen_interface_config(user, date):
    json_path = "/var/lib/praesidium/running/interfaces.json"
    yaml_output = "/var/lib/praesidium/running/interfaces.yml"

    # Verifica si el archivo JSON existe
    # Check if the JSON file exists
    if not os.path.exists(json_path):
        task_update_json(date, "gen_interfaz_config_locate", "fail")
        return

    # Carga el contenido del archivo JSON
    # Load the content of the JSON file
    with open(json_path, "r") as f:
        json_data = json.load(f)

    # Convierte el JSON a formato Netplan
    # Convert the JSON to Netplan format
    netplan_data = convert(json_data)

    # Guarda el resultado en un archivo YAML
    # Save the result into a YAML file
    with open(yaml_output, "w") as f:
        yaml.dump(netplan_data, f, default_flow_style=False, sort_keys=False)

    task_update_json(date, "gen_interfaz_config", "success")

    #CHECK yml
    verify_yaml(user, date, yaml_output)
