"""
ES: Generador de configuración dnsmasq para el módulo DHCP.
    Lee /var/lib/praesidium/running/dhcp.json, convierte ámbitos y reservas al
    formato de texto dnsmasq, verifica la sintaxis con dnsmasq --test y escribe
    /var/lib/praesidium/running/dnsmasq/praesidium-dhcp.conf.
EN: dnsmasq configuration generator for the DHCP module.
    Reads /var/lib/praesidium/running/dhcp.json, converts scopes and reservations
    to dnsmasq text format, verifies syntax with dnsmasq --test and writes
    /var/lib/praesidium/running/dnsmasq/praesidium-dhcp.conf.
"""
import importlib.util
import ipaddress
import json
import os
import subprocess
from pathlib import Path
from task_update_json import task_update_json

DHCP_JSON = Path('/var/lib/praesidium/running/dhcp.json')
OUTPUT_DIR = Path('/var/lib/praesidium/running/dnsmasq')
OUTPUT_FILE = OUTPUT_DIR / 'praesidium-dhcp.conf'


# ES: Carga el conversor Alias IP centralizado ubicado junto a las tareas de commit.
# EN: Loads the centralized Alias IP converter located beside commit tasks.
def _load_alias_ip_aux():
    helper = Path(__file__).resolve().parent / 'aux_convert_alias_to_ips.py'
    spec = importlib.util.spec_from_file_location('aux_convert_alias_to_ips', helper)
    if spec is None or spec.loader is None:
        raise ImportError(f'cannot load {helper}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ALIAS_IP_AUX = _load_alias_ip_aux()


# ES: Marca una subtarea como fallida y lanza error controlado.
# EN: Mark a subtask as failed and raise a controlled error.
def _fail(date, task):
    task_update_json(date, task, 'fail')
    raise SystemExit(1)


# ES: Carga y valida la estructura base de dhcp.json en config_running.
# EN: Load and validate the base dhcp.json structure in config_running.
def _load_json(date):
    if not DHCP_JSON.exists():
        _fail(date, 'dhcp_json_exist')
    try:
        data = json.loads(DHCP_JSON.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        _fail(date, 'dhcp_json_format')
    if not isinstance(data, dict) or not isinstance(data.get('dhcp'), list):
        _fail(date, 'dhcp_json_format')
    if not isinstance(data.get('dhcp_reservation', []), list):
        _fail(date, 'dhcp_json_format')
    data.setdefault('dhcp_reservation', [])
    task_update_json(date, 'dhcp_json_exist', 'success')
    task_update_json(date, 'dhcp_json_format', 'success')
    return data


# ES: Valida campos IPv4; rechaza texto, listas, CIDR e IPv6.
# EN: Validate IPv4 fields; reject text, lists, CIDR and IPv6.
def _ipv4(value, field, required=True):
    if value is None or value == '' or value == []:
        if required:
            raise ValueError(f'{field} is required')
        return ''
    try:
        value = _ALIAS_IP_AUX.convert_single_ipv4_address(value)
        ip = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError(f'{field} must be one valid IPv4 address or Alias Address; IPv6 and CIDR are not supported in DHCPv4') from exc
    if not _is_unicast_ipv4(ip):
        raise ValueError(f'{field} must be a usable unicast IPv4 address')
    return value


# ES: Comprueba que una IPv4 sea utilizable como dirección de host DHCP.
# EN: Check that an IPv4 address is usable as a DHCP host address.
def _is_unicast_ipv4(ip):
    return not (
        ip.is_unspecified or ip.is_loopback or ip.is_link_local or
        ip.is_multicast or ip.is_reserved or ip == ipaddress.IPv4Address('255.255.255.255')
    )


# ES: Valida máscara IPv4 contigua.
# EN: Validate contiguous IPv4 netmask.
def _netmask(value):
    value = str(value or '').strip()
    if not value:
        raise ValueError('netmask is required')
    try:
        ipaddress.IPv4Address(value)
        ipaddress.IPv4Network(f'0.0.0.0/{value}')
    except ValueError as exc:
        raise ValueError('netmask must be a valid contiguous IPv4 netmask') from exc
    return value
# ES: Valida lease_time antes de escribirlo en dnsmasq.
# EN: Validate lease_time before writing it to dnsmasq.
def _lease(value):
    value = str(value or '').strip() or '12h'
    import re
    if not re.match(r'^[1-9][0-9]*[mhdw]$', value):
        raise ValueError('lease_time must look like 30m, 12h, 7d or 1w')
    return value


# ES: Valida MAC de reserva: formato, no cero, no broadcast y unicast.
# EN: Validate reservation MAC: format, not zero, not broadcast and unicast.
def _mac(value):
    import re
    value = str(value or '').strip().upper()
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', value):
        raise ValueError('mac must look like AA:BB:CC:DD:EE:FF')
    if value in ('00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'):
        raise ValueError('mac cannot be zero or broadcast')
    if int(value[:2], 16) & 1:
        raise ValueError('mac must be unicast')
    return value


# ES: Valida hostname opcional de reserva como nombre DNS simple.
# EN: Validate optional reservation hostname as a simple DNS name.
def _hostname(value):
    import re
    value = str(value or '').strip()
    if not value:
        return ''
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9-]{0,62}$', value):
        raise ValueError('hostname must be a simple DNS label')
    return value


# ES: Calcula red y broadcast de un ámbito.
# EN: Calculate network and broadcast for a scope.
def _network(gateway, netmask):
    return ipaddress.IPv4Network(f'{gateway}/{netmask}', strict=False)


# ES: Comprueba si una IP pertenece a la red del ámbito.
# EN: Check whether an IP belongs to the scope network.
def _network_contains(ip, gateway, netmask):
    return ipaddress.IPv4Address(ip) in _network(gateway, netmask)


# ES: Detecta direcciones no asignables: red o broadcast.
# EN: Detect non-assignable addresses: network or broadcast.
def _is_network_or_broadcast(ip, gateway, netmask):
    network = _network(gateway, netmask)
    candidate = ipaddress.IPv4Address(ip)
    return candidate == network.network_address or candidate == network.broadcast_address


# ES: Comprueba si una IP está dentro del rango dinámico.
# EN: Check whether an IP is inside the dynamic range.
def _range_contains(ip, start, end):
    candidate = int(ipaddress.IPv4Address(ip))
    return int(ipaddress.IPv4Address(start)) <= candidate <= int(ipaddress.IPv4Address(end))


# ES: Verifica que la interfaz exista en Linux antes de generar dnsmasq.
# EN: Verify that the interface exists in Linux before generating dnsmasq.
def _interface_exists(name):
    sys_path = Path('/sys/class/net') / name
    return name != 'lo' and sys_path.is_dir() and (sys_path / 'ifindex').exists()


# ES: Convierte rango start/end a enteros para comparar solapes.
# EN: Convert start/end range to integers for overlap checks.
def _range_tuple(rule):
    return (int(ipaddress.IPv4Address(rule['range_start'])), int(ipaddress.IPv4Address(rule['range_end'])))


# ES: Detecta solape entre dos rangos DHCP.
# EN: Detect overlap between two DHCP ranges.
def _overlap(a, b):
    a1, a2 = _range_tuple(a)
    b1, b2 = _range_tuple(b)
    return a1 <= b2 and b1 <= a2


# ES: Valida ámbitos server/relay antes de renderizar la configuración.
# EN: Validate server/relay scopes before rendering the configuration.
def _validate_rules(date, entries):
    normalized = []
    active_by_interface = {}
    for entry in entries:
        rule = entry.get('rule') if isinstance(entry, dict) else None
        if not isinstance(rule, dict):
            _fail(date, 'dhcp_validate_model')
        item = {
            'id': str(rule.get('id', '')).strip(),
            'enable': str(rule.get('enable', 'true')).strip().lower(),
            'mode': str(rule.get('mode', 'server')).strip().lower(),
            'interface': str(rule.get('interface', '')).strip(),
            'range_start': '', 'range_end': '', 'lease_time': '', 'gateway': '', 'netmask': '',
            'dns_primary': '', 'dns_secondary': '', 'ntp_server': '',
            'relay_local_ip': '', 'relay_dest_server': ''
        }
        if item['enable'] not in ('true', 'false') or item['mode'] not in ('server', 'relay') or not item['interface']:
            _fail(date, 'dhcp_validate_model')
        if not _interface_exists(item['interface']):
            _fail(date, 'dhcp_validate_model')
        if item['enable'] != 'true':
            normalized.append(item)
            continue
        try:
            if item['mode'] == 'server':
                if str(rule.get('relay_local_ip', '')).strip() or str(rule.get('relay_dest_server', '')).strip():
                    raise ValueError('server entries cannot contain relay fields')
                item['range_start'] = _ipv4(rule.get('range_start'), 'range_start')
                item['range_end'] = _ipv4(rule.get('range_end'), 'range_end')
                item['gateway'] = _ipv4(rule.get('gateway'), 'gateway')
                item['netmask'] = _netmask(rule.get('netmask'))
                item['lease_time'] = _lease(rule.get('lease_time'))
                item['dns_primary'] = _ipv4(rule.get('dns_primary'), 'dns_primary', False)
                item['dns_secondary'] = _ipv4(rule.get('dns_secondary'), 'dns_secondary', False)
                item['ntp_server'] = _ipv4(rule.get('ntp_server'), 'ntp_server', False)
                if _network(item['gateway'], item['netmask']).prefixlen > 30:
                    raise ValueError('netmask does not leave enough usable addresses for a DHCP scope')
                if int(ipaddress.IPv4Address(item['range_start'])) > int(ipaddress.IPv4Address(item['range_end'])):
                    raise ValueError('range_start cannot be greater than range_end')
                for field in ('gateway', 'range_start', 'range_end'):
                    if not _network_contains(item[field], item['gateway'], item['netmask']):
                        raise ValueError(f'{field} must be inside gateway/netmask network')
                    if _is_network_or_broadcast(item[field], item['gateway'], item['netmask']):
                        raise ValueError(f'{field} cannot be network or broadcast address')
                if _range_contains(item['gateway'], item['range_start'], item['range_end']):
                    raise ValueError('gateway cannot be inside the DHCP client pool')
                for field in ('dns_primary', 'dns_secondary', 'ntp_server'):
                    if item[field] and _is_network_or_broadcast(item[field], item['gateway'], item['netmask']):
                        raise ValueError(f'{field} cannot be network or broadcast address')
            else:
                forbidden = ['range_start','range_end','gateway','netmask','dns_primary','dns_secondary','ntp_server']
                if any(str(rule.get(k, '')).strip() for k in forbidden):
                    raise ValueError('relay entries cannot contain server scope fields')
                item['relay_local_ip'] = _ipv4(rule.get('relay_local_ip'), 'relay_local_ip')
                item['relay_dest_server'] = _ipv4(rule.get('relay_dest_server'), 'relay_dest_server')
                if item['relay_local_ip'] == item['relay_dest_server']:
                    raise ValueError('relay_local_ip and relay_dest_server cannot be equal')
        except ValueError:
            _fail(date, 'dhcp_validate_model')

        iface_items = active_by_interface.setdefault(item['interface'], [])
        for other in iface_items:
            if other['mode'] != item['mode']:
                _fail(date, 'dhcp_validate_model')
            if item['mode'] == 'relay':
                _fail(date, 'dhcp_validate_model')
            if item['mode'] == 'server' and _overlap(item, other):
                _fail(date, 'dhcp_validate_model')
        iface_items.append(item)
        normalized.append(item)
    task_update_json(date, 'dhcp_validate_model', 'success')
    return normalized


# ES: Busca el ámbito server compatible con una reserva por interfaz y red.
# EN: Find the server scope compatible with a reservation by interface and network.
def _scope_for_reservation(reservation, scopes):
    for scope in scopes:
        if scope.get('enable') != 'true' or scope.get('mode') != 'server':
            continue
        if scope.get('interface') != reservation['interface']:
            continue
        if _network_contains(reservation['ip'], scope['gateway'], scope['netmask']):
            return scope
    return None


# ES: Valida reservas MAC/IP y sus duplicados antes de renderizar.
# EN: Validate MAC/IP reservations and duplicates before rendering.
def _validate_reservations(date, entries, scopes):
    normalized = []
    active_mac = set()
    active_ip_iface = set()
    active_hostname = set()
    for entry in entries:
        rule = entry.get('rule') if isinstance(entry, dict) else None
        if not isinstance(rule, dict):
            _fail(date, 'dhcp_validate_model')
        item = {
            'id': str(rule.get('id', '')).strip(),
            'enable': str(rule.get('enable', 'true')).strip().lower(),
            'interface': str(rule.get('interface', '')).strip(),
            'mac': '',
            'ip': '',
            'hostname': '',
            'lease_time': '',
        }
        if item['enable'] not in ('true', 'false') or not item['interface']:
            _fail(date, 'dhcp_validate_model')
        if not _interface_exists(item['interface']):
            _fail(date, 'dhcp_validate_model')
        try:
            item['mac'] = _mac(rule.get('mac'))
            item['ip'] = _ipv4(rule.get('ip'), 'ip')
            item['hostname'] = _hostname(rule.get('hostname'))
            item['lease_time'] = _lease(rule.get('lease_time'))
            if item['enable'] == 'true':
                scope = _scope_for_reservation(item, scopes)
                if scope is None:
                    raise ValueError('reservation must belong to an active DHCP server scope on the same interface')
                if _is_network_or_broadcast(item['ip'], scope['gateway'], scope['netmask']):
                    raise ValueError('reservation IP cannot be network or broadcast')
                if item['ip'] == scope['gateway']:
                    raise ValueError('reservation IP cannot be gateway')
                if item['mac'] in active_mac:
                    raise ValueError('duplicated reservation mac')
                key = (item['interface'], item['ip'])
                if key in active_ip_iface:
                    raise ValueError('duplicated reservation ip on interface')
                if item['hostname']:
                    hkey = item['hostname'].lower()
                    if hkey in active_hostname:
                        raise ValueError('duplicated reservation hostname')
                    active_hostname.add(hkey)
                active_mac.add(item['mac'])
                active_ip_iface.add(key)
        except ValueError:
            _fail(date, 'dhcp_validate_model')
        normalized.append(item)
    return normalized

# ES: Renderiza dnsmasq con tags estrictos por interfaz; reservas nunca globales.
# EN: Render dnsmasq with strict per-interface tags; reservations are never global.
def _render_dnsmasq(rules, reservations=None):
    reservations = reservations or []
    lines = [
        '# Generated by PraesidiumFirewall. Do not edit manually.',
        '# Generado por PraesidiumFirewall. No editar manualmente.',
        'bind-interfaces',
        'except-interface=lo',
    ]
    # ES: Primero se escriben interfaces/rangos/opciones para crear las tags.
    # EN: First write interfaces/ranges/options to create the tags.
    for rule in rules:
        if rule['enable'] != 'true':
            continue
        iface = rule['interface']
        lines.append('')
        lines.append(f'# DHCP rule {rule["id"]} on {iface}')
        if rule['mode'] == 'server':
            lines.append(f'interface={iface}')
            lines.append(f'dhcp-range=set:{iface},{rule["range_start"]},{rule["range_end"]},{rule["netmask"]},{rule["lease_time"]}')
            lines.append(f'dhcp-option=tag:{iface},option:router,{rule["gateway"]}')
            dns = [x for x in [rule['dns_primary'], rule['dns_secondary']] if x]
            if dns:
                lines.append(f'dhcp-option=tag:{iface},option:dns-server,{",".join(dns)}')
            if rule['ntp_server']:
                lines.append(f'dhcp-option=tag:{iface},option:ntp-server,{rule["ntp_server"]}')
        else:
            lines.append(f'dhcp-relay={rule["relay_local_ip"]},{rule["relay_dest_server"]},{iface}')
    # ES: Después se escriben reservas siempre con tag:<interface>.
    # EN: Then write reservations always with tag:<interface>.
    for reservation in reservations:
        if reservation['enable'] != 'true':
            continue
        parts = [f'tag:{reservation["interface"]}', reservation['mac']]
        if reservation['hostname']:
            parts.append(reservation['hostname'])
        parts.append(reservation['ip'])
        if reservation['lease_time']:
            parts.append(reservation['lease_time'])
        lines.append('')
        lines.append(f'# DHCP reservation {reservation["id"]} on {reservation["interface"]}')
        lines.append('dhcp-host=' + ','.join(parts))
    lines.append('')
    return '\n'.join(lines)


# ES: Verifica sintaxis dnsmasq antes de aceptar la configuración generada.
# EN: Verify dnsmasq syntax before accepting the generated configuration.
def verify_dnsmasq_config(date, conf_file=OUTPUT_FILE):
    try:
        subprocess.run(['sudo', 'dnsmasq', '--test', f'--conf-file={conf_file}'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        task_update_json(date, 'verify_dnsmasq_config', 'success')
    except subprocess.CalledProcessError:
        task_update_json(date, 'verify_dnsmasq_config', 'fail')
        raise SystemExit(1)


# ES: Entrada llamada por la fase generate_config del commit Praesidium.
# EN: Entry point called by Praesidium commit generate_config phase.
def gen_dhcp_config(user, date):
    data = _load_json(date)
    rules = _validate_rules(date, data['dhcp'])
    reservations = _validate_reservations(date, data.get('dhcp_reservation', []), rules)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(_render_dnsmasq(rules, reservations), encoding='utf-8')
    task_update_json(date, 'dhcp_convert_dnsmasq', 'success')
    verify_dnsmasq_config(date, OUTPUT_FILE)
