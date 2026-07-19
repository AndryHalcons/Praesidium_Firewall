import os
import ipaddress
import json
import re
import importlib.util
from pathlib import Path
from task_update_json import task_update_json


# Carga los conversores auxiliares del módulo alias desde runtime o source.
# Loads Alias module auxiliary converters from runtime or source.
def _load_alias_aux_module(module_name: str):
    current_dir = Path(__file__).resolve().parent
    candidates = [current_dir / f"{module_name}.py"]

    # ES: En la estructura moderna, los auxiliares se despliegan junto a commit_task.
    # EN: In the modern structure, helpers are deployed next to commit_task.

    for candidate in candidates:
        if candidate.exists():
            spec = importlib.util.spec_from_file_location(module_name, candidate)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module

    raise FileNotFoundError(f"{module_name}.py not found")


# BPFilter recibe valores mixtos; sólo decide si el campo está vacío.
# BPFilter receives mixed values; it only decides whether the field is empty.
def _bpf_field_is_empty(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ''
    if isinstance(value, list):
        return len(value) == 0
    return False

###########################################################################
############################# hook & chain SECTION ########################
###########################################################################
# Verifica si el valor recibido como hook es uno de los tres tipos válidos: BF_HOOK_XDP, BF_HOOK_TC_INGRESS o BF_HOOK_TC_EGRESS.
# Si el hook es válido, lo devuelve en mayúsculas; en caso contrario, devuelve una cadena vacía.

# Verifies whether the provided hook value is one of the three valid types: BF_HOOK_XDP, BF_HOOK_TC_INGRESS, or BF_HOOK_TC_EGRESS.
# If the hook is valid, it returns it in uppercase; otherwise, it returns an empty string.

def verify_hook(hook):
    valid_hooks = {"BF_HOOK_XDP", "BF_HOOK_TC_INGRESS", "BF_HOOK_TC_EGRESS"}

    if not hook:
        return ""

    hook = hook.strip().upper()

    return hook if hook in valid_hooks else ""


# Verifica si el nombre de cadena (chain) recibido es válido para el hook especificado.
# Si la cadena es válida para el hook, se devuelve tal cual; en caso contrario, se devuelve una cadena vacía.

# Verifies whether the provided chain name is valid for the specified hook.
# If the chain is valid for the given hook, it returns the chain name; otherwise, it returns an empty string.

def verify_chain(hook, chain_name, interface):
    if not hook or not chain_name or not interface:
        result = ""
        return result

    hook_clean = hook.strip().lower()
    chain_clean = chain_name.strip()
    expected_chain = f"{interface}_{hook_clean}"

    if chain_clean != expected_chain:
        result = ""
        return result

    result = chain_clean
    return result





###########################################################################
############################# l3 & l4  SECTION ########################
###########################################################################

# Transforma el protocolo de capa 3 (ej. IPv4, IPv6) al formato bpfilter.
# Devuelve 'meta.l3_proto eq <valor>' si es válido, o cadena vacía si no lo es.
#
# Transforms layer 3 protocol (e.g., IPv4, IPv6) into bpfilter format.
# Returns 'meta.l3_proto eq <value>' if valid, or empty string if invalid.

def transform_l3_proto(locate, proto):
    if not proto:
        return ""

    proto = proto.strip().lower()
    valid_l3 = {"ipv4", "ipv6"}

    if proto in valid_l3:
        return f"{locate} eq {proto}"
    return ""

# Transforma el protocolo de capa 4 (ej. TCP, UDP, ICMP, ICMPv6) al formato bpfilter.
# Devuelve 'meta.l4_proto eq <valor>' si es válido, o cadena vacía si no lo es.
#
# Transforms layer 4 protocol (e.g., TCP, UDP, ICMP, ICMPv6) into bpfilter format.
# Returns 'meta.l4_proto eq <value>' if valid, or empty string if invalid.

def transform_l4_proto(locate, proto):
    if not proto:
        return ""

    proto = proto.strip().lower()
    valid_l4 = {"tcp", "udp", "icmp", "icmpv6"}

    if proto in valid_l4:
        return f"{locate} eq {proto}"
    return ""


###########################################################################
############################# INTERFACE  SECTION ##########################
###########################################################################
# // Recibe el nombre de una interfaz y devuelve su ifindex desde el archivo JSON del sistema
# // Receives an interface name and returns its ifindex from the system JSON file
def transform_iface(iface_name):
    if not iface_name:
        return ""

    path = "/var/lib/praesidium/state/interfaces/physical_interfaces_list.json"
    try:
        with open(path, "r") as f:
            data = json.load(f)
        interfaces = data.get("physical_interfaces", [])
        for iface in interfaces:
            if iface.get("name") == iface_name:
                return iface.get("ifindex", "")
    except Exception:
        pass  # Silencia errores de lectura

    return ""

###########################################################################
############################# IP SECTION ##################################
###########################################################################
# Procesa una entrada de direcciones IPv4 individuales.
# Si se recibe una lista o cadena separada por comas, valida cada IP.
# Devuelve el formato bpfilter con 'eq' para una sola IP o 'in {…}' para múltiples.
# Si ninguna IP es válida, devuelve cadena vacía.
#
# Processes input containing individual IPv4 addresses.
# If a list or comma-separated string is provided, each IP is validated.
# Returns bpfilter format: 'eq' for a single IP or 'in {…}' for multiple.
# Returns an empty string if no valid IPs are found.
"""
def transform_ip4(locate, source):

    # Si no hay fuente, devolvemos cadena vacía
    # If no source is provided, return empty string
    if not source:
        return ""

    # Si es una cadena con varias IPs separadas por coma, la convertimos en lista
    # If it's a comma-separated string of IPs, convert it to a list
    if isinstance(source, str) and "," in source:
        source = [ip.strip() for ip in source.split(",")]

    # Si es una lista de IPs, procesamos cada una
    # If it's a list of IPs, process each one
    if isinstance(source, list):
        valid_ips = []
        for ip in source:
            # Validamos que cada IP sea IPv4 válida
            # Validate that each IP is a valid IPv4 address
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                valid_ips.append(str(ip_obj))
            except ValueError:
                continue

        # Si hay IPs válidas, devolvemos formato bpfilter con 'in'
        # If valid IPs exist, return bpfilter format with 'in'
        if valid_ips:
            return f"({locate}) in {{ {'; '.join(valid_ips)} }}"
            #return f"{locate} in {{{','.join(valid_ips)}}}" old
            
        else:
            return ""

    # Si es una sola IP, validamos y devolvemos formato 'eq'
    # If it's a single IP, validate and return 'eq' format
    try:
        ip_obj = ipaddress.IPv4Address(source)
        return f"{locate} eq {ip_obj}"
    except ValueError:
        return ""
"""
def transform_ip4(locate, source):

    # Si no hay fuente, devolvemos cadena vacía
    # If no source is provided, return empty string
    if not source:
        return ""

    # Si es una cadena con varias IPs separadas por coma, la convertimos en lista
    # If it's a comma-separated string of IPs, convert it to a list
    if isinstance(source, str) and "," in source:
        source = [ip.strip() for ip in source.split(",")]

    # Si es una lista de IPs, procesamos cada una
    # If it's a list of IPs, process each one
    if isinstance(source, list):
        valid_ips = []
        for ip in source:
            # Si viene con /32, lo tratamos como IP individual
            # If it comes with /32, treat it as an individual IP
            if isinstance(ip, str) and "/32" in ip:
                ip = ip.split("/")[0]
            # Validamos que cada IP sea IPv4 válida
            # Validate that each IP is a valid IPv4 address
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                valid_ips.append(str(ip_obj))
            except ValueError:
                continue

        # Si hay IPs válidas, devolvemos formato bpfilter con 'in'
        # If valid IPs exist, return bpfilter format with 'in'
        if valid_ips:
            return f"({locate}) in {{ {'; '.join(valid_ips)} }}"
        else:
            return ""

    # Si es una sola IP, validamos y devolvemos formato 'eq'
    # If it's a single IP, validate and return 'eq' format
    try:
        if isinstance(source, str) and "/32" in source:
            source = source.split("/")[0]
        ip_obj = ipaddress.IPv4Address(source)
        return f"{locate} eq {ip_obj}"
    except ValueError:
        return ""

# Procesa una entrada de redes IPv4 con máscara.
# Ignora redes /32 (equivalentes a direcciones individuales).
# Devuelve 'eq' para una sola red válida o 'in {…}' para múltiples.
# Si no hay redes válidas, devuelve cadena vacía.
#
# Processes input containing IPv4 networks with masks.
# Skips /32 networks (treated as individual addresses).
# Returns 'eq' for a single valid network or 'in {…}' for multiple.
# Returns an empty string if no valid networks are found.

def transform_ip4_net(locate, source):
    # Si no hay fuente, devolvemos cadena vacía
    # If no source is provided, return empty string
    if not source:
        return ""

    # Si es una cadena con varias redes separadas por coma, la convertimos en lista
    # If it's a comma-separated string of networks, convert it to a list
    if isinstance(source, str) and "," in source:
        source = [ip.strip() for ip in source.split(",")]

    # Si es una lista de redes, procesamos cada una
    # If it's a list of networks, process each one
    if isinstance(source, list):
        valid_nets = []
        for net in source:
            # Validamos que cada red sea IPv4 válida con máscara
            # Validate that each network is a valid IPv4 with mask
            try:
                net_obj = ipaddress.IPv4Network(net, strict=False)
                # Ignoramos redes con máscara /32 (son direcciones individuales)
                # Skip networks with /32 mask (they're individual addresses)
                if net_obj.prefixlen != 32:
                    valid_nets.append(str(net_obj))
            except ValueError:
                continue

        # Si hay redes válidas, devolvemos formato bpfilter con 'in'
        # If valid networks exist, return bpfilter format with 'in'
        if valid_nets:
            return f"({locate}) in {{ {'; '.join(valid_nets)} }}"
            #return f"{locate} in {{{','.join(valid_nets)}}}" old
        else:
            return ""

    # Si es una sola red, validamos y devolvemos formato 'eq'
    # If it's a single network, validate and return 'eq' format
    try:
        net_obj = ipaddress.IPv4Network(source, strict=False)
        # Ignoramos si es /32
        # Skip if it's /32
        if net_obj.prefixlen != 32:
            return f"{locate} eq {net_obj}"
    except ValueError:
        pass

    return ""

# Procesa direcciones IPv6 individuales (sin máscara).
# Ignora entradas que contengan máscara (/).
# Devuelve 'eq' si hay una sola IP válida o 'in {…}' si hay varias.
# Si no hay direcciones válidas, devuelve cadena vacía.
#
# Processes individual IPv6 addresses (without masks).
# Skips entries containing a mask (/).
# Returns 'eq' for a single valid IP or 'in {…}' for multiple.
# Returns an empty string if no valid addresses are found.
"""
def transform_ip6(locate, source):
    # Si no hay fuente, devolvemos cadena vacía
    # If no source is provided, return empty string
    if not source:
        return ""

    # Convertimos en lista si es una cadena separada por comas
    # Convert to list if it's a comma-separated string
    if isinstance(source, str):
        source = [ip.strip() for ip in source.split(",")]

    # Procesamos cada entrada y filtramos solo direcciones IPv6 válidas (sin máscara)
    # Process each entry and keep only valid IPv6 addresses (no mask)
    valid_ips = []
    for ip in source:
        # Ignoramos si contiene máscara -> es una red
        # Skip if it contains a mask -> it's a network
        if "/" in ip:
            continue
        try:
            ip_obj = ipaddress.IPv6Address(ip)
            valid_ips.append(str(ip_obj))
        except ValueError:
            continue

    # Devolvemos el formato adecuado según cantidad
    # Return appropriate format based on count
    if not valid_ips:
        return ""
    elif len(valid_ips) == 1:
        return f"{locate} eq {valid_ips[0]}"
    else:
        return f"({locate}) in {{ {'; '.join(valid_ips)} }}"
        #return f"{locate} in {{{','.join(valid_ips)}}}" old
"""

def transform_ip6(locate, source):
    # Si no hay fuente, devolvemos cadena vacía
    # If no source is provided, return empty string
    if not source:
        return ""

    # Convertimos en lista si es una cadena separada por comas
    # Convert to list if it's a comma-separated string
    if isinstance(source, str):
        source = [ip.strip() for ip in source.split(",")]

    # Procesamos cada entrada y filtramos solo direcciones IPv6 válidas (sin máscara o /128)
    # Process each entry and keep only valid IPv6 addresses (no mask or /128)
    valid_ips = []
    for ip in source:
        # Si contiene máscara, solo aceptamos /128 -> es una IP individual
        # If it contains a mask, only accept /128 -> it's an individual IP
        if "/" in ip:
            try:
                net_obj = ipaddress.IPv6Network(ip, strict=False)
                if net_obj.prefixlen == 128:
                    valid_ips.append(str(net_obj.network_address))
            except ValueError:
                continue
        else:
            try:
                ip_obj = ipaddress.IPv6Address(ip)
                valid_ips.append(str(ip_obj))
            except ValueError:
                continue

    # Devolvemos el formato adecuado según cantidad
    # Return appropriate format based on count
    if not valid_ips:
        return ""
    elif len(valid_ips) == 1:
        return f"{locate} eq {valid_ips[0]}"
    else:
        return f"({locate}) in {{ {'; '.join(valid_ips)} }}"
        #return f"{locate} in {{{','.join(valid_ips)}}}" old

# Procesa redes IPv6 con máscara.
# Ignora redes /128 (equivalentes a direcciones individuales).
# Devuelve 'eq' para una sola red válida o 'in {…}' para múltiples.
# Si no hay redes válidas, devuelve cadena vacía.
#
# Processes IPv6 networks with masks.
# Skips /128 networks (treated as individual addresses).
# Returns 'eq' for a single valid network or 'in {…}' for multiple.
# Returns an empty string if no valid networks are found.

def transform_ip6_net(locate, source):
    # Si no hay fuente, devolvemos cadena vacía
    # If no source is provided, return empty string
    if not source:
        return ""

    # Si es una cadena con varias redes separadas por coma, la convertimos en lista
    # If it's a comma-separated string of networks, convert it to a list
    if isinstance(source, str) and "," in source:
        source = [ip.strip() for ip in source.split(",")]

    # Si es una lista de redes, procesamos cada una
    # If it's a list of networks, process each one
    if isinstance(source, list):
        valid_nets = []
        for net in source:
            # Validamos que cada red sea IPv6 válida con máscara
            # Validate that each network is a valid IPv6 with mask
            try:
                net_obj = ipaddress.IPv6Network(net, strict=False)
                # Ignoramos redes con máscara /128 (son direcciones individuales)
                # Skip networks with /128 mask (they're individual addresses)
                if net_obj.prefixlen != 128:
                    valid_nets.append(str(net_obj))
            except ValueError:
                continue

        # Si hay redes válidas, devolvemos formato bpfilter con 'in'
        # If valid networks exist, return bpfilter format with 'in'
        if valid_nets:
            return f"({locate}) in {{ {'; '.join(valid_nets)} }}"
            #return f"{locate} in {{{','.join(valid_nets)}}}" old
        else:
            return ""

    # Si es una sola red, validamos y devolvemos formato 'eq'
    # If it's a single network, validate and return 'eq' format
    try:
        net_obj = ipaddress.IPv6Network(source, strict=False)
        if net_obj.prefixlen != 128:
            return f"{locate} eq {net_obj}"
    except ValueError:
        pass

    return ""


######################################################################################################
################################## PORT SECTION #####################################################
######################################################################################################

# Procesa los campos de puertos TCP si el protocolo de capa 4 es TCP.
# Acepta puertos individuales o rangos (ej. "80", "1000-2000"), en cadena o lista.
# Devuelve el formato bpfilter correspondiente: 'eq', 'in {…}' o 'range …'.
# Si el protocolo no es TCP o los valores son inválidos, devuelve cadena vacía.
#
# Processes TCP port fields if the layer 4 protocol is TCP.
# Accepts individual ports or ranges (e.g., "80", "1000-2000"), as string or list.
# Returns the appropriate bpfilter format: 'eq', 'in {…}', or 'range …'.
# If the protocol is not TCP or values are invalid, returns an empty string.

def transform_tcp_port(l4_proto, locate, source):
    # Si no hay fuente o el protocolo no es TCP, devolvemos cadena vacía
    if not source or l4_proto.lower() != "tcp":
        return ""

    # Si es una cadena con varias entradas separadas por coma, la convertimos en lista
    if isinstance(source, str) and "," in source:
        source = [p.strip() for p in source.split(",")]

    # Si es una lista, procesamos cada entrada
    if isinstance(source, list):
        valid_ports = []
        valid_ranges = []
        for item in source:
            # Si es un rango tipo "1000-2000"
            if "-" in item:
                try:
                    start, end = map(int, item.split("-"))
                    if 0 <= start <= 65535 and 0 <= end <= 65535 and start < end:
                        valid_ranges.append(f"{start}-{end}")
                except ValueError:
                    continue
            else:
                # Si es un puerto individual
                try:
                    port = int(item)
                    if 0 <= port <= 65535:
                        valid_ports.append(str(port))
                except ValueError:
                    continue

        # Construimos la salida según lo que haya
        output = []
        if valid_ports:
            output.append(f"{locate} in {{{','.join(valid_ports)}}}")
        if valid_ranges:
            for r in valid_ranges:
                output.append(f"{locate} range {r}")

        return " and ".join(output) if output else ""

    # Si es una sola entrada
    if isinstance(source, str):
        # Rango tipo "1000-2000"
        if "-" in source:
            try:
                start, end = map(int, source.split("-"))
                if 0 <= start <= 65535 and 0 <= end <= 65535 and start < end:
                    return f"{locate} range {start}-{end}"
            except ValueError:
                return ""
        else:
            # Puerto individual
            try:
                port = int(source)
                if 0 <= port <= 65535:
                    return f"{locate} eq {port}"
            except ValueError:
                return ""

    return ""


# Procesa los flags TCP si el protocolo de capa 4 es TCP.
# Acepta una cadena separada por comas con flags válidos (ej. "syn,ack").
# Devuelve el formato bpfilter con 'eq' o 'eq {…}' según la cantidad de flags válidos.
# Si el protocolo no es TCP o no hay flags válidos, devuelve cadena vacía.
#
# Processes TCP flags if the layer 4 protocol is TCP.
# Accepts a comma-separated string of valid flags (e.g., "syn,ack").
# Returns bpfilter format using 'eq' or 'eq {…}' depending on the number of valid flags.
# If the protocol is not TCP or no valid flags are found, returns an empty string.

def transform_tcp_port_flags(l4_proto, locate, source):
    # Si no hay fuente o el protocolo no es TCP, devolvemos cadena vacía
    if not source or l4_proto.lower() != "tcp":
        return ""

    # Lista de flags válidos (case-insensitive)
    valid_flags_set = {"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}

    # Convertimos la fuente en lista si es cadena
    if isinstance(source, str):
        source = [flag.strip().lower() for flag in source.split(",")]

    # Filtramos solo los flags válidos
    valid_flags = [flag for flag in source if flag in valid_flags_set]

    # Devolvemos el formato adecuado
    if not valid_flags:
        return ""
    elif len(valid_flags) == 1:
        return f"{locate} eq {valid_flags[0]}"
    else:
        return f"{locate} eq {{{','.join(valid_flags)}}}"


# Procesa los campos de puertos UDP si el protocolo de capa 4 es UDP.
# Acepta puertos individuales o rangos (ej. "53", "1000-2000"), en cadena o lista.
# Devuelve el formato bpfilter correspondiente: 'eq', 'in {…}' o 'range …'.
# Si el protocolo no es UDP o los valores son inválidos, devuelve cadena vacía.
#
# Processes UDP port fields if the layer 4 protocol is UDP.
# Accepts individual ports or ranges (e.g., "53", "1000-2000"), as string or list.
# Returns the appropriate bpfilter format: 'eq', 'in {…}', or 'range …'.
# If the protocol is not UDP or values are invalid, returns an empty string.

def transform_udp_port(l4_proto, locate, source):
    # Validamos que el protocolo sea UDP y que haya fuente
    if not source or l4_proto.lower() != "udp":
        return ""

    # Si es una cadena con varias entradas separadas por coma, la convertimos en lista
    if isinstance(source, str) and "," in source:
        source = [p.strip() for p in source.split(",")]

    # Si es una lista, procesamos cada entrada
    if isinstance(source, list):
        valid_ports = []
        valid_ranges = []
        for item in source:
            # Si es un rango tipo "1000-2000"
            if "-" in item:
                try:
                    start, end = map(int, item.split("-"))
                    if 0 <= start <= 65535 and 0 <= end <= 65535 and start < end:
                        valid_ranges.append(f"{start}-{end}")
                except ValueError:
                    continue
            else:
                # Si es un puerto individual
                try:
                    port = int(item)
                    if 0 <= port <= 65535:
                        valid_ports.append(str(port))
                except ValueError:
                    continue

        # Construimos la salida según lo que haya
        output = []
        if valid_ports:
            output.append(f"{locate} in {{{','.join(valid_ports)}}}")
        if valid_ranges:
            for r in valid_ranges:
                output.append(f"{locate} range {r}")

        return " and ".join(output) if output else ""

    # Si es una sola entrada
    if isinstance(source, str):
        # Rango tipo "1000-2000"
        if "-" in source:
            try:
                start, end = map(int, source.split("-"))
                if 0 <= start <= 65535 and 0 <= end <= 65535 and start < end:
                    return f"{locate} range {start}-{end}"
            except ValueError:
                return ""
        else:
            # Puerto individual
            try:
                port = int(source)
                if 0 <= port <= 65535:
                    return f"{locate} eq {port}"
            except ValueError:
                return ""

    return ""



######################################################################################################
################################## ICMP SECTION #####################################################
######################################################################################################

# Procesa el campo ICMP type si el protocolo de capa 4 es ICMP.
# Acepta valores decimales, hexadecimales (ej. "0x08") o nombres simbólicos (ej. "echo-reply").
# Devuelve el formato bpfilter 'eq' con el valor correspondiente.
# Si el protocolo no es ICMP o el valor es inválido, devuelve cadena vacía.
#
# Processes the ICMP type field if the layer 4 protocol is ICMP.
# Accepts decimal values, hexadecimal (e.g., "0x08"), or symbolic names (e.g., "echo-reply").
# Returns bpfilter 'eq' format with the corresponding value.
# If the protocol is not ICMP or the value is invalid, returns an empty string.

def transform_icmp_type(l4_proto, locate, source):
    # Solo procesamos si el protocolo es ICMP
    if not source or l4_proto.lower() != "icmp":
        return ""

    # Normalizamos y limpiamos
    if isinstance(source, str):
        source = source.strip().lower()

    # Si es hexadecimal (ej. "0x08")
    try:
        if source.startswith("0x"):
            value = int(source, 16)
            return f"{locate} eq {value}"
        else:
            # Si es decimal
            value = int(source)
            return f"{locate} eq {value}"
    except ValueError:
        # Si no es número, asumimos que es nombre (ej. "echo-reply")
        return f"{locate} eq {source}"

    return ""


# Procesa el campo ICMP code si el protocolo de capa 4 es ICMP.
# Acepta valores decimales o hexadecimales (ej. "0x05").
# Devuelve el formato bpfilter 'eq' con el valor correspondiente.
# Si el protocolo no es ICMP o el valor es inválido, devuelve cadena vacía.
#
# Processes the ICMP code field if the layer 4 protocol is ICMP.
# Accepts decimal or hexadecimal values (e.g., "0x05").
# Returns bpfilter 'eq' format with the corresponding value.
# If the protocol is not ICMP or the value is invalid, returns an empty string.

def transform_icmp_code(l4_proto, locate, source):
    # Solo procesamos si el protocolo es ICMP
    if not source or l4_proto.lower() != "icmp":
        return ""

    # Normalizamos y limpiamos
    if isinstance(source, str):
        source = source.strip().lower()

    try:
        if source.startswith("0x"):
            value = int(source, 16)
        else:
            value = int(source)
        return f"{locate} eq {value}"
    except ValueError:
        return ""


# Procesa el campo ICMPv6 type si el protocolo de capa 4 es ICMPv6.
# Acepta valores decimales, hexadecimales o nombres simbólicos.
# Devuelve el formato bpfilter 'eq' con el valor correspondiente.
# Si el protocolo no es ICMPv6 o el valor es inválido, devuelve cadena vacía.
#
# Processes the ICMPv6 type field if the layer 4 protocol is ICMPv6.
# Accepts decimal values, hexadecimal, or symbolic names.
# Returns bpfilter 'eq' format with the corresponding value.
# If the protocol is not ICMPv6 or the value is invalid, returns an empty string.

def transform_icmpv6_type(l4_proto, locate, source):
    # Solo procesamos si el protocolo es ICMPv6
    if not source or l4_proto.lower() != "icmpv6":
        return ""

    if isinstance(source, str):
        source = source.strip().lower()

    try:
        if source.startswith("0x"):
            value = int(source, 16)
            return f"{locate} eq {value}"
        else:
            value = int(source)
            return f"{locate} eq {value}"
    except ValueError:
        return f"{locate} eq {source}"


# Procesa el campo ICMPv6 code si el protocolo de capa 4 es ICMPv6.
# Acepta valores decimales o hexadecimales.
# Devuelve el formato bpfilter 'eq' con el valor correspondiente.
# Si el protocolo no es ICMPv6 o el valor es inválido, devuelve cadena vacía.
#
# Processes the ICMPv6 code field if the layer 4 protocol is ICMPv6.
# Accepts decimal or hexadecimal values.
# Returns bpfilter 'eq' format with the corresponding value.
# If the protocol is not ICMPv6 or the value is invalid, returns an empty string.

def transform_icmpv6_code(l4_proto, locate, source):
    # Solo procesamos si el protocolo es ICMPv6
    if not source or l4_proto.lower() != "icmpv6":
        return ""

    if isinstance(source, str):
        source = source.strip().lower()

    try:
        if source.startswith("0x"):
            value = int(source, 16)
        else:
            value = int(source)
        return f"{locate} eq {value}"
    except ValueError:
        return ""


######################################################################################################
################################## Probability SECTION ###############################################
######################################################################################################
# Convierte el valor de probabilidad recibido en formato bpfilter.
# Acepta valores enteros entre 0 y 100, con o sin símbolo de porcentaje.
# Si el valor es inválido o está vacío, se asigna automáticamente "100%".
#
# Converts the received probability value into bpfilter format.
# Accepts integer values between 0 and 100, with or without a percent symbol.
# If the value is invalid or missing, it automatically assigns "100%".

def transform_probability(locate, source):
    # Si no hay fuente, devolvemos 100%
    if not source:
        return f"{locate} eq 100%"

    # Normalizamos y limpiamos
    if isinstance(source, str):
        source = source.strip().replace("%", "")

    try:
        value = int(source)
        if 0 <= value <= 100:
            return f"{locate} eq {value}%"
    except ValueError:
        pass

    # Si no es válido, devolvemos 100%
    return f"{locate} eq 100%"


######################################################################################################
################################## Action SECTION ###############################################
######################################################################################################
# Verifica y transforma el valor de acción recibido.
# Acepta "accept" o "drop" sin distinguir mayúsculas/minúsculas.
# Devuelve "ACCEPT" o "DROP" en mayúsculas según corresponda.
# Si el valor está vacío o no es válido, devuelve "ACCEPT" por defecto.
#
# Validates and transforms the received action value.
# Accepts "accept" or "drop" regardless of case sensitivity.
# Returns "ACCEPT" or "DROP" in uppercase accordingly.
# If the value is empty or invalid, defaults to returning "ACCEPT".

def transform_action(action):
    if not action:
        return "ACCEPT"

    action = action.strip().lower()

    if action == "accept":
        return "ACCEPT"
    elif action == "drop":
        return "DROP"

    return "ACCEPT"







##########################################################################################################
############################################## Alias Translate ###########################################
##########################################################################################################
# //////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////// PORTS VALIDATION SECTION ///////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////

# elimina puertos de los campos puerto si el protocolo de la regla es icmp
# Remove ports from the port fields if the rule protocol is icmp
def validation_icmp_no_ports(rule: dict) -> dict:
    protocol = rule.get('l4_protocol', '').lower()

    if protocol in ['icmp', 'icmpv6']:
        fields_to_clear = [
            'sport',
            'dport',
        ]

        for field in fields_to_clear:
            if field in rule:
                rule[field] = ''

    return rule

def convert_alias_port_group_to_network_port(value, date):
    if _bpf_field_is_empty(value):
        return ''

    try:
        aux_ports = _load_alias_aux_module('aux_convert_alias_to_ports')
        ports = aux_ports.convert_ports(value)
    except Exception:
        task_update_json(date, "bpfilter_convert_alias_port_aux_invalid", "fail")
        exit()

    if not ports:
        task_update_json(date, "bpfilter_convert_alias_port_not_exist", "fail")
        exit()

    # Se devuelve CSV porque los transformadores bpfilter actuales consumen strings separadas por comas.
    # Return CSV because current bpfilter transformers consume comma-separated strings.
    return ','.join(ports)


# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////// IPV4 & IPV6 VALIDATION SECTION ///////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

def convert_alias_group_to_Network_ips(value, date):
    if _bpf_field_is_empty(value):
        return ''

    try:
        aux_ips = _load_alias_aux_module('aux_convert_alias_to_ips')
        result = aux_ips.convert_ip_field(value)
    except Exception:
        task_update_json(date, "bpfilter_convert_alias_ip_aux_invalid", "fail")
        exit()

    if not isinstance(result, dict):
        task_update_json(date, "bpfilter_convert_alias_or_group_invalid", "fail")
        exit()

    # BPFilter puede generar IPv4 e IPv6; se devuelve una lista CSV única compatible con transform_ip4/ip6.
    # BPFilter may generate IPv4 and IPv6; return one CSV list compatible with transform_ip4/ip6.
    ips = list(result.get('ipv4', [])) + list(result.get('ipv6', []))
    if not ips:
        task_update_json(date, "bpfilter_convert_alias_or_group_invalid", "fail")
        exit()

    return ','.join(ips)

# Convierte alias en objetos de red reales usando funciones auxiliares
# Converts aliases into real network objects using helper functions
def Main_convert_alias_object_to_network_object(rule: dict, date):
    # Campos relacionados con puertos
    # Port-related fields
    port_fields = ['sport', 'dport']

    for field in port_fields:
        if field in rule:
            # Llama a la función de conversión de puertos
            # Call the port conversion function
            rule[field] = convert_alias_port_group_to_network_port(rule[field], date)

    # Campos relacionados con direcciones IP
    # IP-related fields
    ip_fields = ['source', 'destination']

    for field in ip_fields:
        if field in rule:
            # Llama a la función de conversión de grupos IP
            # Call the IP group conversion function
            rule[field] = convert_alias_group_to_Network_ips(rule[field], date)

    return rule



def separate_rules(rule):
    # Extraemos los campos relevantes de la regla original
    # Extract relevant fields from the original rule
    ip4_saddr = rule.get("ip4_saddr")  # IP origen individual
    ip4_snet = rule.get("ip4_snet")    # Red origen
    ip4_daddr = rule.get("ip4_daddr")  # IP destino individual
    ip4_dnet = rule.get("ip4_dnet")    # Red destino

    # Si no hay mezcla de IPs y redes en origen o destino, no hay conflicto
    # If there's no mix of IPs and networks in source or destination, no conflict
    if not (ip4_saddr and ip4_snet) and not (ip4_daddr and ip4_dnet):
        return [rule]  # Se devuelve la regla tal cual
                      # Return the rule as-is

    subrules = []  # Lista para almacenar las subreglas generadas
                   # List to store generated subrules

    # Combinación 1: IP origen + IP destino
    # Combination 1: Source IP + Destination IP
    if ip4_saddr and ip4_daddr:
        r1 = rule.copy()
        r1["ip4_snet"] = ""  # Se elimina la red origen
        r1["ip4_dnet"] = ""  # Se elimina la red destino
        subrules.append(r1)

    # Combinación 2: IP origen + Red destino
    # Combination 2: Source IP + Destination Network
    if ip4_saddr and ip4_dnet:
        r2 = rule.copy()
        r2["ip4_snet"] = ""  # Se elimina la red origen
        r2["ip4_daddr"] = ""  # Se elimina la IP destino
        subrules.append(r2)

    # Combinación 3: Red origen + IP destino
    # Combination 3: Source Network + Destination IP
    if ip4_snet and ip4_daddr:
        r3 = rule.copy()
        r3["ip4_saddr"] = ""  # Se elimina la IP origen
        r3["ip4_dnet"] = ""   # Se elimina la red destino
        subrules.append(r3)

    # Combinación 4: Red origen + Red destino
    # Combination 4: Source Network + Destination Network
    if ip4_snet and ip4_dnet:
        r4 = rule.copy()
        r4["ip4_saddr"] = ""  # Se elimina la IP origen
        r4["ip4_daddr"] = ""  # Se elimina la IP destino
        subrules.append(r4)

    # Se devuelve la lista de subreglas compatibles con bpfilter
    # Return the list of bpfilter-compatible subrules
    return subrules
