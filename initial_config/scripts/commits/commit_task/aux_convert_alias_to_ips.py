#!/usr/bin/env python3
"""
ES: Convierte objetos alias/grupos/literales de Praesidium a valores finales normalizados.
EN: Converts Praesidium alias/group/literal objects into normalized final values.

ES: Este helper backend lee la fuente runtime de alias.
EN: This backend helper reads the runtime alias source.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterable

ALIAS_RUNTIME_PATH = Path('/var/lib/praesidium/running/alias_ip.json')
PORT_RE = re.compile(r'^(\d+)(?:-(\d+))?$')


# ES: Carga alias IP runtime; el commit trabaja contra running.
# EN: Loads runtime IP aliases; commit works against running.
def load_alias_data(path: Path = ALIAS_RUNTIME_PATH) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


# ES: Devuelve valores de una sección compatible con lista antigua y mapa UUID nuevo.
# EN: Returns section values compatible with old lists and new UUID maps.
def alias_entries(alias_data: dict[str, Any], section: str) -> list[dict[str, Any]]:
    raw = alias_data.get(section, {})
    if isinstance(raw, dict):
        values = raw.values()
    elif isinstance(raw, list):
        values = raw
    else:
        return []
    return [entry for entry in values if isinstance(entry, dict)]


# ES: Busca alias sólo por UUID dentro de las secciones indicadas.
# EN: Finds an alias only by UUID inside the requested sections.
def find_alias(alias_data: dict[str, Any], reference: Any, sections: Iterable[str]) -> tuple[str, dict[str, Any]] | None:
    uuid = ''
    if isinstance(reference, dict):
        uuid = str(reference.get('UUID') or '').strip()
    elif isinstance(reference, str):
        uuid = reference.strip()
    else:
        return None

    if not uuid:
        return None

    for section in sections:
        for entry in alias_entries(alias_data, section):
            entry_uuid = str(entry.get('UUID') or '').strip()
            if entry_uuid and entry_uuid == uuid:
                return section, entry
    return None


# ES: Normaliza un campo mixto a una lista plana de items sin perder objetos.
# EN: Normalizes a mixed field into a flat item list without losing objects.
def mixed_items(value: Any) -> list[Any]:
    if value is None or value == '':
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        items: list[Any] = []
        for item in value:
            if item is None or item == '':
                continue
            if isinstance(item, str) and ',' in item:
                items.extend(part.strip() for part in item.split(',') if part.strip())
            else:
                items.append(item)
        return items
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []
        return [part.strip() for part in value.split(',') if part.strip()]
    return [value]


# ES: Detecta familia IP de un literal IP/CIDR.
# EN: Detects IP family from an IP/CIDR literal.
def identify_ip_family(value: str) -> int | None:
    try:
        return ipaddress.ip_network(value.strip(), strict=False).version
    except ValueError:
        return None


# ES: Añade una red/IP a la familia solicitada, validando formato.
# EN: Adds a network/IP to the requested family, validating format.
def append_network_literal(value: str, family: int, networks: list[ipaddress._BaseNetwork]) -> None:
    network = ipaddress.ip_network(value.strip(), strict=False)
    if network.version != family:
        return
    networks.append(network)


# ES: Resuelve recursivamente alias/grupos/literales IP a redes ipaddress.
# EN: Recursively resolves IP aliases/groups/literals into ipaddress networks.
def resolve_ip_item(item: Any, family: int, alias_data: dict[str, Any], seen: set[str] | None = None) -> list[ipaddress._BaseNetwork]:
    seen = seen or set()
    networks: list[ipaddress._BaseNetwork] = []

    if isinstance(item, str):
        item = item.strip()
        if not item:
            return []
        literal_family = identify_ip_family(item)
        if literal_family is not None:
            append_network_literal(item, family, networks)
            return networks

    resolved = find_alias(alias_data, item, ('alias_address', 'alias_addr_group'))
    if resolved is None:
        if isinstance(item, dict) and isinstance(item.get('content'), list):
            # ES: Si llega un objeto completo no presente en alias_ip.json, usamos su content directo.
            # EN: If a full object not present in alias_ip.json arrives, use its direct content.
            for child in mixed_items(item.get('content', [])):
                networks.extend(resolve_ip_item(child, family, alias_data, set(seen)))
            return networks
        return networks

    section, entry = resolved
    uuid = str(entry.get('UUID') or '')
    if uuid:
        if uuid in seen:
            return networks
        seen.add(uuid)

    # ES: Alias simple: su content debe contener literales IP/CIDR.
    # EN: Simple alias: its content must contain IP/CIDR literals.
    if section == 'alias_address':
        for child in mixed_items(entry.get('content', [])):
            if isinstance(child, str) and identify_ip_family(child) == family:
                append_network_literal(child, family, networks)
        return networks

    # ES: Grupo: su content puede contener UUID/name de alias o literales directos.
    # EN: Group: its content may contain alias UUID/name or direct literals.
    for child in mixed_items(entry.get('content', [])):
        networks.extend(resolve_ip_item(child, family, alias_data, set(seen)))
    return networks


# ES: Colapsa duplicados y subredes contenidas en redes mayores.
# EN: Collapses duplicates and subnets contained in broader networks.
def collapse_networks(networks: list[ipaddress._BaseNetwork]) -> list[str]:
    collapsed = ipaddress.collapse_addresses(networks)
    return [str(network) for network in collapsed]


# ES: Convierte entrada mixta a IPv4 finales limpias.
# EN: Converts mixed input into clean final IPv4 values.
def convert_ipv4(value: Any, alias_data: dict[str, Any] | None = None) -> list[str]:
    alias_data = alias_data if alias_data is not None else load_alias_data()
    networks: list[ipaddress._BaseNetwork] = []
    for item in mixed_items(value):
        networks.extend(resolve_ip_item(item, 4, alias_data))
    return collapse_networks(networks)


# ES: Convierte entrada mixta a IPv6 finales limpias.
# EN: Converts mixed input into clean final IPv6 values.
def convert_ipv6(value: Any, alias_data: dict[str, Any] | None = None) -> list[str]:
    alias_data = alias_data if alias_data is not None else load_alias_data()
    networks: list[ipaddress._BaseNetwork] = []
    for item in mixed_items(value):
        networks.extend(resolve_ip_item(item, 6, alias_data))
    return collapse_networks(networks)


# ES: Valida y normaliza puerto/rango manteniendo el formato final.
# EN: Validates and normalizes a port/range keeping final format.
def normalize_port_literal(value: str) -> str | None:
    value = value.strip()
    match = PORT_RE.fullmatch(value)
    if not match:
        return None
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    if start < 0 or end > 65535 or start > end:
        return None
    return str(start) if start == end else f'{start}-{end}'


# ES: Resuelve recursivamente alias/grupos/literales de puerto.
# EN: Recursively resolves port aliases/groups/literals.
def resolve_port_item(item: Any, alias_data: dict[str, Any], seen: set[str] | None = None) -> list[str]:
    seen = seen or set()
    ports: list[str] = []

    if isinstance(item, str):
        literal = normalize_port_literal(item)
        if literal is not None:
            return [literal]

    resolved = find_alias(alias_data, item, ('alias_service', 'alias_service_group'))
    if resolved is None:
        if isinstance(item, dict) and isinstance(item.get('content'), list):
            # ES: Si llega un objeto completo no presente en alias_ip.json, usamos su content directo.
            # EN: If a full object not present in alias_ip.json arrives, use its direct content.
            for child in mixed_items(item.get('content', [])):
                ports.extend(resolve_port_item(child, alias_data, set(seen)))
            return ports
        return ports

    section, entry = resolved
    uuid = str(entry.get('UUID') or '')
    if uuid:
        if uuid in seen:
            return ports
        seen.add(uuid)

    for child in mixed_items(entry.get('content', [])):
        if section == 'alias_service':
            if isinstance(child, str):
                literal = normalize_port_literal(child)
                if literal is not None:
                    ports.append(literal)
        else:
            ports.extend(resolve_port_item(child, alias_data, set(seen)))
    return ports


# ES: Convierte entrada mixta a puertos finales sin duplicados.
# EN: Converts mixed input into final deduplicated ports.
def convert_ports(value: Any, alias_data: dict[str, Any] | None = None) -> list[str]:
    alias_data = alias_data if alias_data is not None else load_alias_data()
    seen: set[str] = set()
    result: list[str] = []
    for item in mixed_items(value):
        for port in resolve_port_item(item, alias_data):
            if port not in seen:
                seen.add(port)
                result.append(port)
    return result


# ES: Convierte un campo mixto IP devolviendo IPv4 e IPv6 separadas.
# EN: Converts a mixed IP field returning IPv4 and IPv6 separately.
def convert_ip_field(value: Any, alias_data: dict[str, Any] | None = None) -> dict[str, list[str]]:
    alias_data = alias_data if alias_data is not None else load_alias_data()
    return {
        'ipv4': convert_ipv4(value, alias_data),
        'ipv6': convert_ipv6(value, alias_data),
    }


# ES: Convierte un literal/objeto/UUID a una única dirección IPv4 host.
#     No modifica convert_ipv4: añade el contrato estricto requerido por módulos
#     que no admiten listas, grupos, redes CIDR ni IPv6.
# EN: Converts a literal/object/UUID into exactly one IPv4 host address.
#     It does not modify convert_ipv4: this adds the strict contract required by
#     modules that do not accept lists, groups, CIDR networks, or IPv6.
def convert_single_ipv4_address(value: Any, alias_data: dict[str, Any] | None = None) -> str:
    alias_data = alias_data if alias_data is not None else load_alias_data()
    items = mixed_items(value)
    if len(items) != 1:
        raise ValueError('exactly one IPv4 address or Alias Address is required')

    networks = resolve_ip_item(items[0], 4, alias_data)
    if not networks:
        raise ValueError('IPv4 address or Alias Address cannot be resolved')

    hosts: set[str] = set()
    for network in networks:
        if network.version != 4 or network.prefixlen != 32:
            raise ValueError('CIDR networks and IPv6 are not accepted; one IPv4 host is required')
        hosts.add(str(network.network_address))

    if len(hosts) != 1:
        raise ValueError('Alias Address must resolve to exactly one IPv4 host')
    return next(iter(hosts))


if __name__ == '__main__':
    import sys

    raw = sys.stdin.read().strip()
    payload = json.loads(raw) if raw else []
    print(json.dumps(convert_ip_field(payload), ensure_ascii=False))
