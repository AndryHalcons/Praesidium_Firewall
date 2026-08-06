# Generador WireGuard: valida el running JSON y crea configs wg-quick en staging.
# WireGuard generator: validates the running JSON and creates wg-quick staging configs.
# Este archivo no aplica servicios; solo prepara archivos y manifest seguros para apply.
# This file does not apply services; it only prepares safe files and manifest for apply.

import ipaddress
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from task_update_json import task_update_json

# Reutiliza directamente la lógica Alias instalada de FastAPI, sin HTTP.
# Directly reuses installed FastAPI Alias logic, without HTTP.
FASTAPI_APP = Path('/opt/praesidium/fastapi/app')
FASTAPI_VENV = Path('/opt/praesidium/fastapi/.venv')
FASTAPI_SITE_PACKAGES = next(iter(FASTAPI_VENV.glob('lib/python*/site-packages')), None)
for import_path in (FASTAPI_APP, FASTAPI_SITE_PACKAGES):
    if import_path is not None and str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from modules.alias_ip.service import deep_translate_alias as deep_translate_ip_alias
from modules.alias_ip.service import deep_translate_sanitized_alias as deep_translate_sanitized_ip_alias
from modules.alias_services.service import deep_translate_sanitized_alias as deep_translate_sanitized_service_alias

WIREGUARD_JSON = Path('/var/lib/praesidium/running/wireguard.json')
OUTPUT_DIR = Path('/var/lib/praesidium/running/wireguard')
GENERATED_DIR = OUTPUT_DIR / 'generated'
MANIFEST = OUTPUT_DIR / 'manifest.json'

KEY_RE = re.compile(r'^[A-Za-z0-9+/]{43}=$')
IFACE_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
ENDPOINT_RE = re.compile(r'^(\[[0-9A-Fa-f:.]+\]|[^:\s]+):(\d{1,5})$')
EXPECTED_SECTIONS = {'site_to_site', 'remote_access', 'remote_clients'}


# Registra un fallo del proceso WireGuard en el historial del commit y detiene el commit.
# Records a WireGuard process failure in the commit history and stops the commit.
def _fail(date, task):
    task_update_json(date, task, 'fail')
    raise SystemExit(1)


# Registra un paso WireGuard correcto en el historial del commit.
# Records a successful WireGuard step in the commit history.
def _success(date, task):
    task_update_json(date, task, 'success')


# Normaliza secciones vacías del JSON para tratarlas siempre como diccionarios.
# Normalizes empty JSON sections so they are always handled as dictionaries.
def _as_dict(value):
    if value in ({}, [], None):
        return {}
    if not isinstance(value, dict):
        raise ValueError('section must be an object')
    return value


# Carga y comprueba la estructura base de /var/lib/praesidium/running/wireguard.json.
# Loads and checks the base structure of /var/lib/praesidium/running/wireguard.json.
def _load_json(date):
    # Fase 1: comprobar que existe el running JSON que viene del commit candidate->running.
    # Phase 1: check that the running JSON produced by candidate->running exists.
    if not WIREGUARD_JSON.exists():
        _fail(date, 'wireguard_json_exist')

    # Fase 2: parsear JSON y convertir cualquier error en fallo registrado del commit.
    # Phase 2: parse JSON and convert any error into a recorded commit failure.
    try:
        data = json.loads(WIREGUARD_JSON.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        _fail(date, 'wireguard_json_format')
    if not isinstance(data, dict) or not EXPECTED_SECTIONS.issubset(data.keys()):
        _fail(date, 'wireguard_json_format')
    # Fase 3: normalizar secciones vacías para que validadores y renderizadores usen dicts.
    # Phase 3: normalize empty sections so validators and renderers use dictionaries.
    try:
        normalized = {
            'site_to_site': _as_dict(data.get('site_to_site')),
            'remote_access': _as_dict(data.get('remote_access')),
            'remote_clients': _as_dict(data.get('remote_clients')),
        }
    except ValueError:
        _fail(date, 'wireguard_json_format')
    _success(date, 'wireguard_json_exist')
    _success(date, 'wireguard_json_format')
    return normalized


# Convierte cadenas true/false del candidate en booleanos reales para el generador.
# Converts candidate true/false strings into real booleans for the generator.
def _bool(value, field):
    value = str(value or '').strip().lower()
    if value not in ('true', 'false'):
        raise ValueError(f'{field} must be true or false')
    return value == 'true'


# Verifica campos obligatorios antes de generar una configuración activa.
# Checks required fields before generating an active configuration.
def _required(rule, fields):
    for field in fields:
        if str(rule.get(field, '')).strip() == '':
            raise ValueError(f'{field} is required')


# Valida nombres lógicos usados como claves dentro de wireguard.json.
# Validates logical names used as keys inside wireguard.json.
def _name(value, field='name'):
    value = str(value or '').strip()
    if not re.match(r'^[A-Za-z0-9_.-]{1,64}$', value):
        raise ValueError(f'{field} has invalid characters')
    return value


# Valida nombres de interfaz Linux antes de crear archivos wg-quick.
# Validates Linux interface names before creating wg-quick files.
def _iface(value):
    value = str(value or '').strip()
    if not IFACE_RE.match(value):
        raise ValueError('interface name is invalid')
    return value


# Valida puertos TCP/UDP dentro del rango permitido por el sistema.
# Validates TCP/UDP ports inside the range allowed by the system.
def _port(value):
    value = str(value or '').strip()
    if not value.isdigit() or not (1 <= int(value) <= 65535):
        raise ValueError('port out of range')
    return int(value)


# Valida enteros acotados como MTU o PersistentKeepalive.
# Validates bounded integers such as MTU or PersistentKeepalive.
def _int_range(value, field, minimum, maximum, default=None):
    value = str(value or '').strip()
    if value == '' and default is not None:
        return default
    if not value.isdigit() or not (minimum <= int(value) <= maximum):
        raise ValueError(f'{field} out of range')
    return int(value)


# Valida el formato base64 esperado para claves WireGuard.
# Validates the expected base64 format for WireGuard keys.
def _key(value, field):
    value = str(value or '').strip()
    if not KEY_RE.match(value):
        raise ValueError(f'{field} is not a valid WireGuard key')
    return value


# Divide campos separados por comas eliminando espacios y valores vacíos.
# Splits comma-separated fields while removing spaces and empty values.
def _csv(value):
    return [x.strip() for x in str(value or '').split(',') if x.strip()]


# Convierte listas CIDR en objetos ip_interface para direcciones con máscara.
# Converts CIDR lists into ip_interface objects for addresses with prefix length.
def _cidrs(value, field, required=False):
    items = _csv(value)
    if required and not items:
        raise ValueError(f'{field} is required')
    nets = []
    for item in items:
        try:
            nets.append(ipaddress.ip_interface(item))
        except ValueError as exc:
            raise ValueError(f'{field} contains invalid CIDR') from exc
    return nets


# Convierte listas de redes en objetos ip_network para validar solapes.
# Converts network lists into ip_network objects to validate overlaps.
def _networks(value, field, required=False):
    items = _csv(value)
    if required and not items:
        raise ValueError(f'{field} is required')
    nets = []
    for item in items:
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(f'{field} contains invalid network') from exc
    return nets


# Valida listas simples de direcciones IP, usadas por ejemplo en DNS.
# Validates simple IP address lists, used for example by DNS.
def _ips(value, field):
    ips = []
    for item in _csv(value):
        try:
            ips.append(ipaddress.ip_address(item))
        except ValueError as exc:
            raise ValueError(f'{field} contains invalid IP') from exc
    return ips


# Valida endpoints remotos en formato host:puerto o [IPv6]:puerto.
# Validates remote endpoints in host:port or [IPv6]:port format.
def _endpoint(value):
    value = str(value or '').strip()
    match = ENDPOINT_RE.match(value)
    if not match:
        raise ValueError('endpoint must be host:port')
    host, port = match.groups()
    _port(port)
    if host.startswith('[') and host.endswith(']'):
        ipaddress.IPv6Address(host[1:-1])
    elif not re.match(r'^[A-Za-z0-9.-]+$', host):
        raise ValueError('endpoint host is invalid')
    return value


# Comprueba si dos grupos de redes se solapan entre sí.
# Checks whether two groups of networks overlap with each other.
def _overlap(left, right):
    return any(a.version == b.version and a.overlaps(b) for a in left for b in right)


# Evita que dos túneles activos usen la misma interfaz o puerto de escucha.
# Prevents two active tunnels from using the same interface or listen port.
def _validate_unique_listener(seen_interfaces, seen_ports, name, iface, port):
    if iface in seen_interfaces:
        raise ValueError(f'duplicate WireGuard interface {iface}')
    if port in seen_ports:
        raise ValueError(f'duplicate WireGuard listen_port {port}')
    seen_interfaces[iface] = name
    seen_ports[port] = name


# Extrae items mixtos conservando objetos Alias y literales.
# Extracts mixed items while preserving Alias objects and literals.
def _mixed_site_items(value):
    if value in (None, ''):
        return []
    if isinstance(value, list):
        return [item for item in value if item not in (None, '')]
    if isinstance(value, dict):
        return [value]
    return [item.strip() for item in str(value).split(',') if item.strip()]


# ES: Identifica UUIDs Alias persistidos como string u objeto; los literales pasan intactos.
# EN: Identifies persisted Alias UUIDs represented as strings or objects; literals pass through unchanged.
def _alias_uuid(item):
    if isinstance(item, dict):
        value = str(item.get('UUID') or '').strip()
    elif isinstance(item, str):
        value = item.strip()
    else:
        return ''
    if re.fullmatch(r'(?:aliasad|aliagroup|aliaser|aliassergroup)-[A-Za-z0-9_.:-]+', value):
        return value
    return ''


# Resuelve un único IP/CIDR de túnel conservando la dirección host.
# Resolves one tunnel IP/CIDR while preserving the host address.
def _resolve_site_tunnel(value):
    resolved = []
    for item in _mixed_site_items(value):
        uuid = _alias_uuid(item)
        if uuid:
            payload = deep_translate_ip_alias(uuid)
            resolved.extend(payload.get('deep_content') or [])
        else:
            resolved.append(str(item).strip())
    if len(resolved) != 1:
        raise ValueError('site_to_site tunnel alias must resolve to exactly one value')
    return resolved[0]


# Resuelve redes Alias/grupos mediante la función sanitizada de FastAPI.
# Resolves Alias networks/groups through FastAPI's sanitized function.
def _resolve_site_networks(value):
    resolved = []
    for item in _mixed_site_items(value):
        uuid = _alias_uuid(item)
        if uuid:
            payload = deep_translate_sanitized_ip_alias(uuid)
            resolved.extend(payload.get('deep_content_sanitized') or [])
        else:
            resolved.append(str(item).strip())
    return ','.join(str(item).strip() for item in resolved if str(item).strip())


# Resuelve el alias de listen_port a exactamente un puerto final.
# Resolves the listen_port Alias into exactly one final port.
def _resolve_site_port(value):
    resolved = []
    for item in _mixed_site_items(value):
        uuid = _alias_uuid(item)
        if uuid:
            payload = deep_translate_sanitized_service_alias(uuid)
            resolved.extend(payload.get('deep_content_sanitized') or [])
        else:
            resolved.append(str(item).strip())
    if len(resolved) != 1:
        raise ValueError('listen_port alias must resolve to exactly one value')
    return str(resolved[0]).strip()


# Resuelve hosts IP Alias conservando valores finales para DNS/public_endpoint.
# Resolves Alias IP hosts while preserving final values for DNS/public_endpoint.
def _resolve_ip_hosts(value):
    resolved = []
    for item in _mixed_site_items(value):
        uuid = _alias_uuid(item)
        if uuid:
            payload = deep_translate_ip_alias(uuid)
            resolved.extend(payload.get('deep_content') or [])
        else:
            resolved.append(str(item).strip())
    return [str(item).strip() for item in resolved if str(item).strip()]


# Traduce exclusivamente campos Alias técnicos de site_to_site.
# Translates only technical Alias fields belonging to site_to_site.
def _resolve_site_to_site_aliases(rule):
    resolved = dict(rule)
    if _mixed_site_items(resolved.get('local_tunnel_ip')):
        resolved['local_tunnel_ip'] = _resolve_site_tunnel(resolved['local_tunnel_ip'])
    if _mixed_site_items(resolved.get('remote_tunnel_ip')):
        resolved['remote_tunnel_ip'] = _resolve_site_tunnel(resolved['remote_tunnel_ip'])
    if _mixed_site_items(resolved.get('local_networks')):
        resolved['local_networks'] = _resolve_site_networks(resolved['local_networks'])
    if _mixed_site_items(resolved.get('remote_networks')):
        resolved['remote_networks'] = _resolve_site_networks(resolved['remote_networks'])
    if _mixed_site_items(resolved.get('listen_port')):
        resolved['listen_port'] = _resolve_site_port(resolved['listen_port'])
    return resolved


# Valida una entrada sede-a-sede antes de renderizar su archivo .conf.
# Validates a site-to-site entry before rendering its .conf file.
def _validate_site_to_site(name, rule, seen_interfaces, seen_ports):
    rule = _resolve_site_to_site_aliases(rule)
    # Fase 1: validar nombre y estado para saber si esta entrada generará interfaz.
    # Phase 1: validate name and state to know whether this entry will generate an interface.
    _name(name)
    enabled = _bool(rule.get('enabled', 'false'), 'enabled')
    if enabled:
        _required(rule, ['interface', 'local_tunnel_ip', 'remote_tunnel_ip', 'local_networks', 'remote_networks', 'listen_port', 'remote_endpoint', 'private_key', 'remote_public_key'])
    iface = _iface(rule.get('interface')) if str(rule.get('interface', '')).strip() else ''
    port = _port(rule.get('listen_port')) if str(rule.get('listen_port', '')).strip() else None
    if iface and port is not None:
        _validate_unique_listener(seen_interfaces, seen_ports, name, iface, port)
    local_tunnel = _cidrs(rule.get('local_tunnel_ip'), 'local_tunnel_ip')
    remote_tunnel = _cidrs(rule.get('remote_tunnel_ip'), 'remote_tunnel_ip')
    if local_tunnel and remote_tunnel:
        if len(local_tunnel) != 1 or len(remote_tunnel) != 1:
            raise ValueError('site_to_site tunnel must have one local and one remote tunnel IP')
        if local_tunnel[0].version != remote_tunnel[0].version or local_tunnel[0].network != remote_tunnel[0].network:
            raise ValueError('site_to_site tunnel IPs must belong to the same network')
    local_networks = _networks(rule.get('local_networks'), 'local_networks')
    remote_networks = _networks(rule.get('remote_networks'), 'remote_networks')
    if local_networks and remote_networks and _overlap(local_networks, remote_networks):
        raise ValueError('site_to_site local and remote networks overlap')
    if str(rule.get('remote_endpoint', '')).strip():
        _endpoint(rule.get('remote_endpoint'))
    if str(rule.get('private_key', '')).strip():
        _key(rule.get('private_key'), 'private_key')
    if str(rule.get('remote_public_key', '')).strip():
        _key(rule.get('remote_public_key'), 'remote_public_key')
    if str(rule.get('keepalive', '')).strip():
        _int_range(rule.get('keepalive'), 'keepalive', 0, 65535)
    mtu = _int_range(rule.get('mtu'), 'mtu', 576, 9000, None) if str(rule.get('mtu', '')).strip() else None
    return {'name': name, 'enabled': enabled, 'rule': rule, 'interface': iface, 'port': port, 'mtu': mtu}


# Traduce campos Alias técnicos de remote_access reutilizando FastAPI.
# Translates remote_access technical Alias fields by reusing FastAPI.
def _resolve_remote_access_aliases(rule):
    resolved = dict(rule)
    if _mixed_site_items(resolved.get('server_vpn_ip')):
        resolved['server_vpn_ip'] = _resolve_site_tunnel(resolved['server_vpn_ip'])
    for field in ('vpn_network', 'internal_networks'):
        if _mixed_site_items(resolved.get(field)):
            resolved[field] = _resolve_site_networks(resolved[field])
    if _mixed_site_items(resolved.get('listen_port')):
        resolved['listen_port'] = _resolve_site_port(resolved['listen_port'])
    if _mixed_site_items(resolved.get('dns')):
        dns_values = _resolve_ip_hosts(resolved['dns'])
        resolved['dns'] = ','.join(str(ipaddress.ip_interface(value).ip) if '/' in value else value for value in dns_values)
    if _mixed_site_items(resolved.get('public_endpoint')):
        endpoint_values = _resolve_ip_hosts(resolved['public_endpoint'])
        if len(endpoint_values) != 1:
            raise ValueError('public_endpoint alias must resolve to exactly one value')
        endpoint = endpoint_values[0]
        try:
            endpoint = str(ipaddress.ip_interface(endpoint).ip) if '/' in endpoint else str(ipaddress.ip_address(endpoint))
        except ValueError:
            pass
        resolved['public_endpoint'] = endpoint
    return resolved


# Valida un servidor de acceso remoto y su red VPN asociada.
# Validates a remote-access server and its associated VPN network.
def _validate_remote_access(name, rule, seen_interfaces, seen_ports):
    rule = _resolve_remote_access_aliases(rule)
    # Fase 1: validar nombre/estado del servidor de acceso remoto.
    # Phase 1: validate the remote-access server name/state.
    _name(name)
    enabled = _bool(rule.get('enabled', 'false'), 'enabled')
    if enabled:
        _required(rule, ['interface', 'server_vpn_ip', 'vpn_network', 'listen_port', 'internal_networks', 'private_key'])
    iface = _iface(rule.get('interface')) if str(rule.get('interface', '')).strip() else ''
    port = _port(rule.get('listen_port')) if str(rule.get('listen_port', '')).strip() else None
    if iface and port is not None:
        _validate_unique_listener(seen_interfaces, seen_ports, name, iface, port)
    server_ips = _cidrs(rule.get('server_vpn_ip'), 'server_vpn_ip')
    vpn_networks = _networks(rule.get('vpn_network'), 'vpn_network')
    if server_ips:
        if len(server_ips) != 1:
            raise ValueError('remote_access server must have one VPN IP')
        if vpn_networks and not any(server_ips[0].ip.version == net.version and server_ips[0].ip in net for net in vpn_networks):
            raise ValueError('server_vpn_ip must belong to vpn_network')
    internal_networks = _networks(rule.get('internal_networks'), 'internal_networks')
    if vpn_networks and internal_networks and _overlap(vpn_networks, internal_networks):
        raise ValueError('vpn_network overlaps internal_networks')
    if str(rule.get('dns', '')).strip():
        _ips(rule.get('dns'), 'dns')
    if str(rule.get('private_key', '')).strip():
        _key(rule.get('private_key'), 'private_key')
    mtu = _int_range(rule.get('mtu'), 'mtu', 576, 9000, None) if str(rule.get('mtu', '')).strip() else None
    return {'name': name, 'enabled': enabled, 'rule': rule, 'interface': iface, 'port': port, 'mtu': mtu, 'vpn_networks': vpn_networks}


# Valida un cliente remoto y su relación con un servidor VPN existente.
# Validates a remote client and its relation to an existing VPN server.
def _validate_remote_client(name, rule, servers, seen_client_ips, seen_client_keys):
    # Fase 1: validar nombre/estado y localizar el servidor VPN referenciado.
    # Phase 1: validate name/state and locate the referenced VPN server.
    _name(name)
    enabled = _bool(rule.get('enabled', 'false'), 'enabled')
    if enabled:
        _required(rule, ['vpn', 'client_vpn_ip', 'client_public_key', 'allowed_ips'])
    vpn = str(rule.get('vpn', '')).strip()
    if vpn:
        _name(vpn, 'vpn')
        if vpn not in servers:
            raise ValueError('remote client references missing VPN server')
    client_ips = _cidrs(rule.get('client_vpn_ip'), 'client_vpn_ip')
    if client_ips:
        if len(client_ips) != 1:
            raise ValueError('remote client must have one VPN IP')
        raw_ip = str(client_ips[0])
        if raw_ip in seen_client_ips:
            raise ValueError('duplicate remote client VPN IP')
        seen_client_ips.add(raw_ip)
        if vpn and servers[vpn]['vpn_networks'] and not any(client_ips[0].ip.version == net.version and client_ips[0].ip in net for net in servers[vpn]['vpn_networks']):
            raise ValueError('client_vpn_ip must belong to selected server vpn_network')
    if str(rule.get('client_private_key', '')).strip():
        _key(rule.get('client_private_key'), 'client_private_key')
    if str(rule.get('client_public_key', '')).strip():
        key = _key(rule.get('client_public_key'), 'client_public_key')
        if key in seen_client_keys:
            raise ValueError('duplicate client public key')
        seen_client_keys.add(key)
    _networks(rule.get('allowed_ips'), 'allowed_ips')
    if str(rule.get('keepalive', '')).strip():
        _int_range(rule.get('keepalive'), 'keepalive', 0, 65535)
    return {'name': name, 'enabled': enabled, 'rule': rule, 'vpn': vpn}


# Valida el modelo completo de WireGuard y cruza relaciones entre secciones.
# Validates the full WireGuard model and cross-checks relations between sections.
def _validate_model(date, data):
    try:
        seen_interfaces = {}
        seen_ports = {}
        site_to_site = {
            name: _validate_site_to_site(name, rule, seen_interfaces, seen_ports)
            for name, rule in data['site_to_site'].items()
        }
        remote_access = {
            name: _validate_remote_access(name, rule, seen_interfaces, seen_ports)
            for name, rule in data['remote_access'].items()
        }
        seen_client_ips = set()
        seen_client_keys = set()
        remote_clients = {
            name: _validate_remote_client(name, rule, remote_access, seen_client_ips, seen_client_keys)
            for name, rule in data['remote_clients'].items()
        }
    except Exception:
        _fail(date, 'wireguard_validate_model')
    _success(date, 'wireguard_validate_model')
    return site_to_site, remote_access, remote_clients


# Formatea listas separadas por comas para escribir directivas wg-quick.
# Formats comma-separated lists to write wg-quick directives.
def _line_csv(value):
    return ', '.join(_csv(value))


# Renderiza una configuración wg-quick para un túnel sede-a-sede.
# Renders a wg-quick configuration for a site-to-site tunnel.
def _render_site_to_site(item):
    r = item['rule']
    lines = [
        '# Managed by PraesidiumFirewall. Do not edit manually.',
        '# Gestionado por PraesidiumFirewall. No editar manualmente.',
        f'# Scenario: site_to_site; name: {item["name"]}',
        '[Interface]',
        f'Address = {_line_csv(r.get("local_tunnel_ip"))}',
        f'ListenPort = {item["port"]}',
        f'PrivateKey = {r["private_key"]}',
    ]
    if item['mtu']:
        lines.append(f'MTU = {item["mtu"]}')
    lines.extend(['', '[Peer]', f'PublicKey = {r["remote_public_key"]}'])
    allowed = _csv(r.get('remote_tunnel_ip')) + _csv(r.get('remote_networks'))
    lines.append(f'AllowedIPs = {", ".join(allowed)}')
    if str(r.get('remote_endpoint', '')).strip():
        lines.append(f'Endpoint = {r["remote_endpoint"]}')
    if str(r.get('keepalive', '')).strip():
        lines.append(f'PersistentKeepalive = {r["keepalive"]}')
    lines.append('')
    return '\n'.join(lines)


# Renderiza una configuración wg-quick de servidor con sus peers cliente.
# Renders a wg-quick server configuration with its client peers.
def _render_remote_access(server, clients):
    r = server['rule']
    lines = [
        '# Managed by PraesidiumFirewall. Do not edit manually.',
        '# Gestionado por PraesidiumFirewall. No editar manualmente.',
        f'# Scenario: remote_access; name: {server["name"]}',
        '[Interface]',
        f'Address = {_line_csv(r.get("server_vpn_ip"))}',
        f'ListenPort = {server["port"]}',
        f'PrivateKey = {r["private_key"]}',
    ]
    if server['mtu']:
        lines.append(f'MTU = {server["mtu"]}')
    for client in clients:
        cr = client['rule']
        lines.extend(['', '[Peer]', f'# Client: {client["name"]}', f'PublicKey = {cr["client_public_key"]}', f'AllowedIPs = {_line_csv(cr.get("client_vpn_ip"))}'])
        if str(cr.get('keepalive', '')).strip():
            lines.append(f'PersistentKeepalive = {cr["keepalive"]}')
    lines.append('')
    return '\n'.join(lines)


# Verifica la sintaxis de un archivo WireGuard generado antes del apply.
# Verifies the syntax of a generated WireGuard file before apply.
def _verify_generated_config(date, conf_path):
    try:
        subprocess.run(['wg-quick', 'strip', str(conf_path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        task_update_json(date, f'wireguard_verify_{conf_path.stem}', 'success')
    except subprocess.CalledProcessError:
        task_update_json(date, f'wireguard_verify_{conf_path.stem}', 'fail')
        raise SystemExit(1)


# Genera los archivos staging y el manifest consumido por el apply.
# Generates staging files and the manifest consumed by the apply step.
def _generate(date, site_to_site, remote_access, remote_clients):
    # Limpiar la salida anterior para que no queden túneles obsoletos en staging.
    # Clean previous output so stale tunnels are not kept in staging.
    if GENERATED_DIR.exists():
        shutil.rmtree(GENERATED_DIR)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {'managed_interfaces': []}

    # Generar una configuración por cada túnel sede-a-sede activo.
    # Generate one configuration for each active site-to-site tunnel.
    for item in site_to_site.values():
        if not item['enabled']:
            continue
        conf = GENERATED_DIR / f'{item["interface"]}.conf'
        conf.write_text(_render_site_to_site(item), encoding='utf-8')
        conf.chmod(0o600)
        _verify_generated_config(date, conf)
        manifest['managed_interfaces'].append({'name': item['interface'], 'source': str(conf), 'scenario': 'site_to_site'})

    # Generar una configuración por cada servidor de acceso remoto activo.
    # Generate one configuration for each active remote-access server.
    for server in remote_access.values():
        if not server['enabled']:
            continue
        clients = [c for c in remote_clients.values() if c['enabled'] and c['vpn'] == server['name']]
        conf = GENERATED_DIR / f'{server["interface"]}.conf'
        conf.write_text(_render_remote_access(server, clients), encoding='utf-8')
        conf.chmod(0o600)
        _verify_generated_config(date, conf)
        manifest['managed_interfaces'].append({'name': server['interface'], 'source': str(conf), 'scenario': 'remote_access'})

    # Guardar el manifest que luego usará el apply para saber qué interfaces gestionar.
    # Save the manifest later used by apply to know which interfaces to manage.
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    _success(date, 'wireguard_generate_config')


# Punto de entrada del commit para validar y generar configuración WireGuard.
# Commit entry point to validate and generate WireGuard configuration.
def gen_wireguard_config(user, date):
    # Cargar el running JSON ya promovido por el commit.
    # Load the running JSON already promoted by the commit.
    data = _load_json(date)

    # Validar relaciones entre túneles, servidores y clientes antes de generar nada.
    # Validate relations between tunnels, servers and clients before generating anything.
    site_to_site, remote_access, remote_clients = _validate_model(date, data)

    # Generar archivos staging y manifest solo si todo el modelo es correcto.
    # Generate staging files and manifest only if the whole model is correct.
    _generate(date, site_to_site, remote_access, remote_clients)
