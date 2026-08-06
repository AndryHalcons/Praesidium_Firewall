import json
import subprocess
import os
import convert_bpfilter
from collections import defaultdict
from task_update_json import task_update_json

# Carga el contenido de un archivo JSON desde la ruta especificada.
# Devuelve el contenido como diccionario si la lectura es exitosa.
# Si ocurre algún error, devuelve un diccionario vacío.
#
# Loads the contents of a JSON file from the specified path.
# Returns the content as a dictionary if reading is successful.
# If an error occurs, returns an empty dictionary.

def load_json_as_array():
    path = "/var/lib/praesidium/candidate/rules_bpfilter_human_viewer.json"
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data
    except Exception:
        return {}



##########################################################################################################
############################################## Transform fields to bpf ###################################
##########################################################################################################

# Extrae y transforma los campos relevantes de una regla plana para adaptarlos al formato bpfilter.
# Aplica validaciones y conversiones específicas según el protocolo, tipo de dirección, puertos, flags, etc.
# Devuelve un diccionario con todos los campos normalizados y listos para ser procesados por el motor de reglas.
#
# Extracts and transforms relevant fields from a flat rule to adapt them to bpfilter format.
# Applies validations and specific conversions based on protocol, address type, ports, flags, etc.
# Returns a dictionary with all normalized fields ready to be processed by the rule engine.

def saniticed_bpfilter_format(rule):
    hook = convert_bpfilter.verify_hook(rule.get("hook"))
    chain = convert_bpfilter.verify_chain(rule.get("hook"),rule.get("chain"),rule.get("interface"))
    iface = convert_bpfilter.transform_iface(rule.get("interface"))
    l3_proto_data = rule.get("l3_protocol") #used for others transform
    l4_proto_data = rule.get("l4_protocol") #used for others transform
    l3_proto = convert_bpfilter.transform_l3_proto("meta.l3_proto", rule.get("l3_protocol")) #transform for output
    l4_proto = convert_bpfilter.transform_l4_proto("meta.l4_proto", rule.get("l4_protocol")) #transform for output

    # IPv4
    ip4_saddr = convert_bpfilter.transform_ip4("ip4.saddr", rule.get("source"))
    ip4_daddr = convert_bpfilter.transform_ip4("ip4.daddr", rule.get("destination"))
    ip4_snet = convert_bpfilter.transform_ip4_net("ip4.snet", rule.get("source"))
    ip4_dnet = convert_bpfilter.transform_ip4_net("ip4.dnet", rule.get("destination"))
    ip4_proto = ""
    # IPv6
    ip6_saddr = convert_bpfilter.transform_ip6("ip6.saddr", rule.get("source"))
    ip6_daddr = convert_bpfilter.transform_ip6("ip6.daddr", rule.get("destination"))
    ip6_snet =  convert_bpfilter.transform_ip6_net("ip6.snet", rule.get("source"))
    ip6_dnet =  convert_bpfilter.transform_ip6_net("ip6.dnet", rule.get("destination"))
    ip6_nexthdr = rule.get("ipv6_next_header")

    # TCP
    tcp_sport = convert_bpfilter.transform_tcp_port(l4_proto_data,"meta.sport", rule.get("sport"))
    tcp_dport = convert_bpfilter.transform_tcp_port(l4_proto_data,"meta.dport", rule.get("dport"))
    tcp_flags = convert_bpfilter.transform_tcp_port_flags(l4_proto_data, "tcp.flags", rule.get("tcp_flags"))

    # UDP
    udp_sport = convert_bpfilter.transform_udp_port(l4_proto_data,"meta.sport", rule.get("sport"))
    udp_dport = convert_bpfilter.transform_udp_port(l4_proto_data,"meta.dport", rule.get("dport"))

    # ICMP
    icmp_type =  convert_bpfilter.transform_icmp_type(l4_proto_data,"icmp.type",rule.get("icmp_type"))
    icmp_code =  convert_bpfilter.transform_icmp_code(l4_proto_data,"icmp.code",rule.get("icmp_code"))

    # ICMPv6
    icmpv6_type = convert_bpfilter.transform_icmpv6_type(l4_proto_data,"icmp.type",rule.get("icmpv6_type"))
    icmpv6_code = convert_bpfilter.transform_icmpv6_code(l4_proto_data,"icmp.code",rule.get("icmpv6_code"))

    # Meta
    probability = convert_bpfilter.transform_probability("meta.probability", rule.get("probability"))

    # Action
    action = convert_bpfilter.transform_action(rule.get("action"))
    return {
        "hook" : hook,
        "chain" : chain,
        "interface": iface,
        "l3_protocol": l3_proto,
        "l4_protocol": l4_proto,
        "ip4_saddr": ip4_saddr,
        "ip4_snet": ip4_snet,
        "ip4_daddr": ip4_daddr,
        "ip4_dnet": ip4_dnet,
        "ip4_proto": ip4_proto,
        "ip6_saddr": ip6_saddr,
        "ip6_snet": ip6_snet,
        "ip6_daddr": ip6_daddr,
        "ip6_dnet": ip6_dnet,
        "ip6_nexthdr": ip6_nexthdr,
        "tcp_sport": tcp_sport,
        "tcp_dport": tcp_dport,
        "tcp_flags": tcp_flags,
        "udp_sport": udp_sport,
        "udp_dport": udp_dport,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "icmpv6_type": icmpv6_type,
        "icmpv6_code": icmpv6_code,
        "probability": probability,
        "action": action
    }




##########################################################################################################
############################################## constructor ###############################################
##########################################################################################################

# Genera un archivo de texto en formato bpfilter a partir de una lista de reglas procesadas.
# Agrupa las reglas por cadena (chain) y construye la estructura completa con encabezados, condiciones y contadores.
# El resultado se guarda en la ruta especificada como archivo plano.
#
# Generates a bpfilter-formatted text file from a list of processed rules.
# Groups rules by chain and builds the full structure including headers, conditions, and counters.
# The result is saved to the specified path as a plain text file.



def gen_bpf_txt_formt(user, date, allRules, outputPath):
    # Agrupa las reglas por nombre de cadena (chain)
    # Group rules by chain name
    chains = defaultdict(list)
    for rule in allRules:
        chain_name = rule.get("chain", "")
        if chain_name:
            chains[chain_name].append(rule)

    # Lista para almacenar las líneas del archivo de salida
    # List to store output file lines
    output_lines = []

    for chain, rules in chains.items():
        # Obtiene el hook de la primera regla del grupo (por defecto BF_HOOK_XDP)
        # Get hook from the first rule in the group (default BF_HOOK_XDP)
        hook = rules[0].get("hook", "BF_HOOK_XDP")

        # Obtiene la acción de la primera regla (por defecto ACCEPT)
        # Get action from the first rule (default ACCEPT)
        action = rules[0].get("action", "ACCEPT")

        # Obtiene la interfaz de la primera regla
        # Get interface from the first rule
        iface = rules[0].get("interface", "")

        # Construye el encabezado de la cadena con ifindex si hay interfaz
        # Build chain header with ifindex if interface is present
        if iface:
            output_lines.append(f"chain {chain} {hook}{{ifindex={iface}}} {"ACCEPT"}")
        else:
            output_lines.append(f"chain {chain} {hook}{{}} {action}")

        # Añade las reglas individuales dentro de la cadena
        # Add individual rules inside the chain
        for rule in rules:
            # Separar la regla si contiene combinaciones no válidas
            # Split the rule if it contains invalid combinations
            subrules = convert_bpfilter.separate_rules(rule)

            for subrule in subrules:
                output_lines.append("    rule")
                for key, value in subrule.items():
                    # Omite campos ya usados en el encabezado
                    # Skip fields already used in the header
                    if key in {"chain", "hook", "action", "interface"}:
                        continue
                    # Añade parámetros de la regla si tienen valor
                    # Add rule parameters if they have a value
                    if value:
                        output_lines.append(f"        {value}")
                # Añade contador y acción final
                # Add counter and final action
                output_lines.append("        counter")
                output_lines.append(f"        {subrule.get('action', 'ACCEPT')}")

    try:
        # Escribe el contenido en el archivo de salida
        # Write the content to the output file
        with open(outputPath, "w") as f:
            f.write("\n".join(output_lines))

        # Marca la tarea como exitosa
        # Mark the task as successful
        task_update_json(date, "convert_bpfilter_json_txt", "success")
    except Exception as e:
        # Marca la tarea como fallida si ocurre un error
        # Mark the task as failed if an error occurs
        task_update_json(date, "convert_bpfilter_json_txt", "fail")



##########################################################################################################
############################################## validate rules ###############################################
##########################################################################################################
def validate_bpfilter_policy(rule: dict, date):
    rule = convert_bpfilter.validation_icmp_no_ports(rule)
    rule = convert_bpfilter.Main_convert_alias_object_to_network_object(rule, date)
    return rule

# Carga las reglas desde el archivo JSON en formato humano, las transforma al formato interno bpfilter
# mediante la función saniticed_bpfilter_format(), y luego genera el archivo de texto final con gen_bpf_txt_formt().
#
# Loads rules from the human-readable JSON file, transforms them into internal bpfilter format
# using saniticed_bpfilter_format(), and then generates the final text file via gen_bpf_txt_formt().



def gen_bpfilter_policies(user, date):
    inputPath = "/var/lib/praesidium/running/rules_bpfilter_human_viewer.json"
    outputPath = "/var/lib/praesidium/running/bpfilter_machine_format.txt"

    try:
        with open(inputPath, "r") as f:
            data = json.load(f)
            task_update_json(date, "open_bpfilter_json", "success")
    except Exception as e:
        task_update_json(date, "open_bpfilter_json", "fail")
        return

    allRules = []

    for entry in data.get("bpfilter", []):
        rule = entry.get("rule", {})

        # Solo procesar si 'enable' es exactamente "true"
        # Only process if 'enable' is exactly "true"
        if rule.get("enable") != "true":
            continue

        rule = validate_bpfilter_policy(rule, date)
        formatted_rule = saniticed_bpfilter_format(rule)
        allRules.append(formatted_rule)

    try:
        gen_bpf_txt_formt(user, date, allRules, outputPath)
        task_update_json(date, "convert_bpfilter_json", "success")
    except Exception as e:
        task_update_json(date, "convert_bpfilter_json", "fail")
        return

