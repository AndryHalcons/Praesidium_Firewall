import os
import json
import re
import importlib.util
from pathlib import Path
from task_update_json import task_update_json

# ES: Carga los auxiliares de alias desde runtime o desde el repo durante pruebas.
# EN: Loads alias helpers from runtime or from the repo during tests.
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


# ES: nftables recibe valores mixtos; sólo decide si el campo está vacío.
# EN: nftables receives mixed values; it only decides whether the field is empty.
def _nft_field_is_empty(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ''
    if isinstance(value, list):
        return len(value) == 0
    return False
def import_policy_nft_json():
    json_path = "/var/lib/praesidium/running/rules_nftables_human_viewer.json"

    if not os.path.exists(json_path):
        return False

    with open(json_path, 'r', encoding='utf-8') as f:
        raw = f.read()

    try:
        alias_json_data = json.loads(raw)
    except json.JSONDecodeError:
        return False

    return alias_json_data

FORM_NFT_CONFIG = {'select': {'action': ['accept', 'drop', 'reject', 'queue'],
            'meta.iifname': [''],
            'meta.oifname': [''],
            'ip.protocol': ['tcp', 'udp', 'tcp, udp', 'icmp', 'icmpv6'],
            'ct.state': ['',
                         'new',
                         'related',
                         'established',
                         'established, related',
                         'new, related',
                         'new, established',
                         'new, related, established']},
 'checkbox': {'ip.saddr.op': {'checked': '!=', 'unchecked': '=='},
              'ip.daddr.op': {'checked': '!=', 'unchecked': '=='},
              'sport.op': {'checked': '!=', 'unchecked': '=='},
              'dport.op': {'checked': '!=', 'unchecked': '=='},
              'log': {'checked': 'true', 'unchecked': 'false'},
              'enable': {'checked': 'true', 'unchecked': 'false'},
              'masquerade': {'checked': 'true', 'unchecked': 'false'}},
 'not_editable': {'family': ['inet'],
                  'table': ['filter', 'nat'],
                  'chain': ['FORWARDING', 'PREROUTING', 'POSTROUTING', 'input', 'output'],
                  'id': ['1-10000']},
 'object_multiselect': {'ip.saddr': [],
                        'ip.daddr': [],
                        'sport': [],
                        'dport': [],
                        'dnat.addr': [],
                        'dnat.port': [],
                        'snat.addr': [],
                        'redirect': []}}

# devuelve la configuración de formulario nftables embebida para no depender del backend legacy.
# returns embedded nftables form configuration to avoid depending on the legacy backend.
def import_forms_nft_json():
    return json.loads(json.dumps(FORM_NFT_CONFIG))

# importa la lista de interfaces en array 
# imports the list of interfaces into array
def import_all_interfaces(date):
    path = '/var/lib/praesidium/state/interfaces/all_interfaces_list.json'

    if not os.path.exists(path):
        task_update_json(date, "nftables_convert_interfaces_file_invalid", "fail")
        return []

    with open(path, 'r', encoding='utf-8') as f:
        raw = f.read()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        task_update_json(date, "nftables_convert_interfaces_file_invalid", "fail")
        return []

    return data.get('all_interfaces', [])

# //////////////////////////////////////////////////////////////////////////////////////////////////////
# ////////////////////////////////    form field review        /////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////

# revisa los campos que contienen formularios
# check the fields that contain forms
def validation_form_field_review(rule, date):
    form_config = import_forms_nft_json()
    if not form_config:
        #print(json.dumps({"error": "No se pudo cargar la configuración del formulario interfaces"}))
        task_update_json(date, "nftables_convert_load_interfaces_json", "fail")
        exit()

    interfaces = import_all_interfaces(date)
    if 'meta.iifname' in form_config.get('select', {}):
        form_config['select']['meta.iifname'] += interfaces
    if 'meta.oifname' in form_config.get('select', {}):
        form_config['select']['meta.oifname'] += interfaces

    if 'select' in form_config:
        for key, valid_values in form_config['select'].items():
            if key in rule:
                value = rule[key]
                if str(value).strip() == '':
                    continue
                if value not in valid_values:
                    #print(json.dumps({"error": f"value in validation_form_field_review_select '{value}' not found"}))
                    task_update_json(date, "nftables_convert_select_field", "fail")
                    exit()

    if 'checkbox' in form_config:
        for key, options in form_config['checkbox'].items():
            if key in rule:
                value = rule[key]
                if str(value).strip() == '':
                    continue
                if value != options.get("checked") and value != options.get("unchecked"):
                    #print(json.dumps({"error": f"alias port validation_form_field_review_checkbox '{value}' not found"}))
                    task_update_json(date, "nftables_convert_checkbox", "fail")
                    exit()

    if 'not_editable' in form_config:
        for key, valid_values in form_config['not_editable'].items():
            if key == 'id':
                continue
            if key in rule:
                value = rule[key]
                if str(value).strip() == '':
                    continue
                if value not in valid_values:
                    #print(json.dumps({"error": f"alias port validation_form_field_review_not_editable '{value}' not found"}))
                    task_update_json(date, "nftables_convert_not_editable", "fail")
                    exit()

# genera la entrada log compatible con nftables si es true, si es false borra "log" de la regla
# Generates the nftables-compatible log entry if true, if false deletes "log" from the rule
def log_format_nft(rule: dict) -> dict:
    if 'log' in rule:
        if rule['log'] == 'true':
            id_ = rule.get('id', '')
            chain = rule.get('chain', '')
            action = rule.get('action', '')
            rule['log'] = f"nftables {id_} {chain} {action}"
        elif rule['log'] == 'false':
            rule.pop('log', None)
    return rule


# //////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////// ID and name section     /////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////

# Genera un ID único buscando el primer número no usado en los comentarios
# Generates a unique ID by finding the first unused number in rule comments
def get_id_from_policy() -> str:
    data = import_policy_nft_json()
    if not data or 'nftables' not in data or not isinstance(data['nftables'], list):
        return "1"  # fallback si no se puede leer el archivo

    used_ids = []

    for entry in data['nftables']:
        if 'rule' in entry and 'id' in entry['rule']:
            try:
                used_ids.append(int(entry['rule']['id']))
            except ValueError:
                # Si el id no es numérico, lo ignoramos
                continue

    # Busca el primer ID libre empezando desde 1
    id_ = 1
    while id_ in used_ids:
        id_ += 1

    return str(id_)


# convierte el campo name y el campo id en partes del campo comment de nftables
# si no hay id por que la regla por ejemplo es nueva, se llama a get_id_from_policy() que devuelve un id único
# makes the name field and id field parts of the nftables comment field
# if there is no id because the rule is new, for example, get_id_from_policy() is called which returns a unique id
def comment_convert_id_name(rule: dict) -> dict:
    # Si no hay id, se genera automáticamente
    # If 'id' is missing, generate it automatically
    id_ = rule.get('id', '').strip() or get_id_from_policy()

    # El name puede estar vacío, pero debe incluirse
    # 'name' can be empty, but must be included
    name = rule.get('name', '').strip()

    # Construye el campo comment con ambas claves
    # Builds the 'comment' field with both keys
    rule['comment'] = f"id='{id_}',name='{name}'"

    return rule




# //////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////// PORTS VALIDATION SECTION ///////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////

# elimina puertos de los campos puerto si el protocolo de la regla es icmp
# Remove ports from the port fields if the rule protocol is icmp
def validation_icmp_no_ports(rule: dict) -> dict:
    protocol = rule.get('ip.protocol', '').lower()

    if protocol in ['icmp', 'icmpv6']:
        fields_to_clear = [
            'sport.op',
            'sport',
            'dport.op',
            'dport',
            'redirect',
            'dnat.port'
        ]

        for field in fields_to_clear:
            if field in rule:
                rule[field] = ''

    return rule
def convert_alias_port_group_to_network_port(value, date):
    if _nft_field_is_empty(value):
        return ''

    try:
        aux_ports = _load_alias_aux_module('aux_convert_alias_to_ports')
        ports = aux_ports.convert_ports(value)
    except Exception:
        task_update_json(date, "nftables_convert_alias_port_aux_invalid", "fail")
        exit()

    if not ports:
        task_update_json(date, "nftables_convert_alias_port_not_exist", "fail")
        exit()

    # ES: Se devuelve CSV porque el formateador nftables actual consume strings separadas por comas.
    # EN: Return CSV because the current nftables formatter consumes comma-separated strings.
    return ','.join(ports)
def convert_alias_group_to_Network_ips(value, date):
    if _nft_field_is_empty(value):
        return ''

    try:
        aux_ips = _load_alias_aux_module('aux_convert_alias_to_ips')
        result = aux_ips.convert_ip_field(value)
    except Exception:
        task_update_json(date, "nftables_convert_alias_ip_aux_invalid", "fail")
        exit()

    ips = result.get('ipv4', []) if isinstance(result, dict) else []
    if not ips:
        task_update_json(date, "nftables_convert_alias_or_group_invalid", "fail")
        exit()

    # ES: Se devuelve CSV porque el formateador nftables actual consume strings separadas por comas.
    # EN: Return CSV because the current nftables formatter consumes comma-separated strings.
    return ','.join(ips)


# Convierte alias en objetos de red reales usando funciones auxiliares
# Converts aliases into real network objects using helper functions
def Main_convert_alias_object_to_network_object(rule: dict, date):
    # si masquerade está activado borramos la configuracion del campo snat para que no se procese
    # If masquerade is enabled, clear snat.addr to avoid conflict with dynamic NAT
    if str(rule.get('masquerade', '')).lower() == 'true':
        rule['snat.addr'] = ''
    # Campos relacionados con puertos
    # Port-related fields
    port_fields = ['sport', 'dport', 'dnat.port', 'redirect']

    for field in port_fields:
        if field in rule:
            # Llama a la función de conversión de puertos
            # Call the port conversion function
            rule[field] = convert_alias_port_group_to_network_port(rule[field], date)

    # Campos relacionados con direcciones IP
    # IP-related fields
    ip_fields = ['ip.daddr', 'ip.saddr', 'dnat.addr', 'snat.addr']

    for field in ip_fields:
        if field in rule:
            # Llama a la función de conversión de grupos IP
            # Call the IP group conversion function
            rule[field] = convert_alias_group_to_Network_ips(rule[field], date)

    return rule


# ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////// Assign position if empty /////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

# Asigna la posición 1 si no viene definida o está vacía
# Assigns position 1 if not defined or empty
def assign_position(rule: dict) -> dict:
    # Verifica si el campo 'position' está ausente o vacío
    # Checks if the 'position' field is missing or empty
    if 'position' not in rule or str(rule['position']).strip() == '':
        # Asigna la posición 1 por defecto
        # Assigns default position 1
        rule['position'] = 1

    # Devuelve la regla modificada
    # Returns the modified rule
    return rule



# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////// Saniticed to nftables json format /////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

# Función para convertir la regla al formato de nftables
# Function to convert the rule to nftables format
# Genera la estructura base de una regla nftables
# Generates the base structure of an nftables rule
def saniticed_nftables_policy(rule):
    #print(rule)
    return {
        "rule": {
            "family": rule.get("family", ""),
            "table": rule.get("table", ""),
            "chain": rule.get("chain", ""),
            "position": rule.get("position", ""),
            "id": rule.get("id", ""),
            "name": rule.get("name", ""),
            "expr": build_expr(rule, rule.get("comment", "")),
            "comment": rule.get("comment", "")
        }
    }
    


# genera la estructura de expr en nftables
# generate the structure of expr in nftables
def build_expr(rule, comment):
    expr = []

    for field in ["snat.addr", "dnat.addr"]:
        if rule.get(field):
            rule[field] = re.sub(r"/(32|128)$", "", str(rule[field]))

    if rule.get("ip.protocol"):
        protocols = [str(p).strip() for p in str(rule["ip.protocol"]).split(",")]
        expr.append({
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": "ip", "field": "protocol"}},
                "right": protocols[0] if len(protocols) == 1 else {"set": protocols}
            }
        })

    if rule.get("ip.saddr"):
        set_ = []
        for cidr in str(rule["ip.saddr"]).split(","):
            if "/" in cidr:
                addr, length = cidr.strip().split("/")
                if str(length).isdigit():
                    set_.append({"prefix": {"addr": addr, "len": int(length)}})
        if set_:
            expr.append({
                "match": {
                    "op": rule.get("ip.saddr.op", "=="),
                    "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                    "right": {"set": set_}
                }
            })

    if rule.get("ip.daddr"):
        set_ = []
        for cidr in str(rule["ip.daddr"]).split(","):
            if "/" in cidr:
                addr, length = cidr.strip().split("/")
                if str(length).isdigit():
                    set_.append({"prefix": {"addr": addr, "len": int(length)}})
        if set_:
            expr.append({
                "match": {
                    "op": rule.get("ip.daddr.op", "=="),
                    "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                    "right": {"set": set_}
                }
            })

    for port_type in ["sport", "dport"]:
        if rule.get(port_type):
            ports = [str(p).strip() for p in str(rule[port_type]).split(",")]
            items = []
            for p in ports:
                if re.match(r"^\d+-\d+$", p):
                    start, end = p.split("-")
                    if str(start).isdigit() and str(end).isdigit():
                        items.append({"range": [int(start), int(end)]})
                elif str(p).isdigit():
                    items.append(int(p))
            if items:
                right = items[0] if len(items) == 1 else {"set": items}
                proto_raw = str(rule.get("ip.protocol", "")).strip()
                is_tcp_udp = proto_raw == "tcp, udp"
                has_snat = bool(str(rule.get("snat.addr", "")).strip())
                has_dnat = bool(str(rule.get("dnat.addr", "")).strip())
                has_both_ports = bool(str(rule.get("sport", "")).strip()) and bool(str(rule.get("dport", "")).strip())
                proto = "th" if is_tcp_udp and (has_snat or has_dnat or has_both_ports) else proto_raw
                expr.append({
                    "match": {
                        "op": rule.get(f"{port_type}.op", "=="),
                        "left": {"payload": {"protocol": proto, "field": port_type}},
                        "right": right
                    }
                })

    if rule.get("meta.iifname"):
        expr.append({
            "match": {
                "op": "==",
                "left": {"meta": {"key": "iifname"}},
                "right": rule["meta.iifname"]
            }
        })

    if rule.get("meta.oifname"):
        expr.append({
            "match": {
                "op": "==",
                "left": {"meta": {"key": "oifname"}},
                "right": rule["meta.oifname"]
            }
        })

    if rule.get("ct.state"):
        states = [str(s).strip() for s in str(rule["ct.state"]).split(",") if str(s).strip()]
        if states:
            expr.append({
                "match": {
                    "op": "==",
                    "left": {"ct": {"key": "state"}},
                    "right": {"set": states}
                }
            })

    if "packets" in rule or "bytes" in rule:
        packets = str(rule.get("packets", "0")).strip()
        bytes_ = str(rule.get("bytes", "0")).strip()
        expr.append({
            "counter": {
                "packets": int(packets) if packets.isdigit() else 0,
                "bytes": int(bytes_) if bytes_.isdigit() else 0
            }
        })

    if rule.get("log"):
        expr.append({
            "log": {
                "prefix": str(rule["log"]) + " ",
                "flags": "all",
                "level": "info"
            }
        })
    
    # If masquerade is enabled, add masquerade action
    if str(rule.get("masquerade", "")).lower() == "true":
        expr.append({"masquerade": None})


    if rule.get("snat.addr"):
        snat = {"addr": rule["snat.addr"]}
        port = str(rule.get("snat.port", "")).strip()
        if port.isdigit():
            snat["port"] = int(port)
        expr.append({"snat": snat})

    if rule.get("dnat.addr"):
        dnat = {"addr": rule["dnat.addr"]}
        port = str(rule.get("dnat.port", "")).strip()
        if port.isdigit():
            dnat["port"] = int(port)
        expr.append({"dnat": dnat})
    elif rule.get("dnat.port"):
        port = str(rule["dnat.port"]).strip()
        if port.isdigit():
            expr.append({"dnat": {"port": int(port)}})

    if rule.get("redirect"):
        port = str(rule["redirect"]).strip()
        if port.isdigit():
            expr.append({"redirect": {"port": int(port)}})

    
    if rule.get("action"):
        expr.append({rule["action"]: None})

    return expr


# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////// write and order policy /////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

# Reasigna la posición de una regla según su familia, tabla y cadena
# Reassigns the position of a rule based on its family, table, and chain
def reassign_position(rule: dict) -> dict:
    # Carga el JSON que contiene todas las reglas actuales
    # Loads the JSON containing all current rules
    json_data = import_policy_nft_json()

    # Si no se puede cargar o no contiene reglas, se devuelve la regla tal cual
    # If loading fails or there are no rules, return the rule as-is
    if not json_data or "nftables" not in json_data:
        return rule

    # Extrae los valores clave para identificar el grupo de reglas
    # Extracts key values to identify the rule group
    family = rule["family"]
    table = rule["table"]
    chain = rule["chain"]

    # Verifica si la posición viene definida o está vacía
    # Checks whether the position is defined or empty
    incoming_position = int(rule["position"]) if rule.get("position") not in [None, ""] else None

    # Si no viene posición, se asigna la posición 1
    # If no position is provided, assign position 1
    if incoming_position is None:
        rule["position"] = 1
        incoming_position = 1

        # Desplaza hacia adelante (+1) todas las reglas que coincidan en familia, tabla y cadena
        # Shift forward (+1) all rules that match family, table, and chain
        for entry in json_data["nftables"]:
            r = entry.get("rule")
            if r and all(k in r for k in ["family", "table", "chain", "position"]):
                if r["family"] == family and r["table"] == table and r["chain"] == chain:
                    r["position"] = int(r["position"]) + 1
    else:
        # Si ya viene una posición, se respeta
        # If a position is already provided, it is respected

        # Desplaza hacia adelante (+1) todas las reglas con posición igual o superior
        # Shift forward (+1) all rules with equal or higher position
        for entry in json_data["nftables"]:
            r = entry.get("rule")
            if r and all(k in r for k in ["family", "table", "chain", "position"]):
                if r["family"] == family and r["table"] == table and r["chain"] == chain:
                    if int(r["position"]) >= incoming_position:
                        r["position"] = int(r["position"]) + 1

    # Devuelve la regla con la posición ajustada
    # Returns the rule with the adjusted position
    return rule


# Inserta o actualiza una regla en el JSON de reglas
# Inserts or updates a rule in the rules JSON
def update_or_insert_nft_rule(rule: dict, rules_json: dict) -> dict:
    id_ = int(rule.get("id", 0))
    if not id_:
        return rules_json

    for index, entry in enumerate(rules_json.get("nftables", [])):
        existing_rule = entry.get("rule")
        if not existing_rule:
            continue
        existing_id = int(existing_rule.get("id", 0))
        if existing_id == id_:
            rules_json["nftables"][index]["rule"] = rule
            rules_json = reorder_policies(rules_json)
            return rules_json

    # Inserta como nueva
    # Insert as new
    rules_json.setdefault("nftables", []).append({"rule": rule})
    rules_json = reorder_policies(rules_json)
    return rules_json


# Ordena las reglas por posición
# Sorts rules by position
def reorder_policies(rules_json: dict) -> dict:
    # Extraer solo las reglas
    # Extract only rules
    rules = [entry for entry in rules_json.get("nftables", []) if "rule" in entry]

    # Ordenar solo las reglas por position
    # Sort rules by position
    rules.sort(key=lambda r: int(r["rule"].get("position", float("inf"))))

    # Reconstruir el array original, reemplazando solo las reglas
    # Rebuild the original array, replacing only the rules
    rule_index = 0
    for i, entry in enumerate(rules_json.get("nftables", [])):
        if "rule" in entry:
            rules_json["nftables"][i] = rules[rule_index]
            rule_index += 1

    return rules_json
