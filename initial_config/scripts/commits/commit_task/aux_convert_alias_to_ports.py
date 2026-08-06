#!/usr/bin/env python3
"""
ES: Convierte alias/grupos/literales de puertos Praesidium a puertos/rangos finales limpios.
EN: Converts Praesidium port aliases/groups/literals into clean final ports/ranges.

ES: Este helper backend lee la fuente runtime de alias.
EN: This backend helper reads the runtime alias source.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

ALIAS_RUNTIME_PATH = Path('/var/lib/praesidium/running/alias_services.json')
PORT_RE = re.compile(r'^(\d+)(?:-(\d+))?$')


# ES: Carga alias de servicios runtime; el commit trabaja contra running.
# EN: Loads runtime service aliases; commit works against running.
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


# ES: Convierte puerto/rango a intervalo numérico validado.
# EN: Converts a port/range into a validated numeric interval.
def port_interval(value: str) -> tuple[int, int] | None:
    value = value.strip()
    match = PORT_RE.fullmatch(value)
    if not match:
        return None
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    if start < 0 or end > 65535 or start > end:
        return None
    return start, end


# ES: Formatea intervalo a puerto o rango.
# EN: Formats an interval as a port or range.
def format_interval(interval: tuple[int, int]) -> str:
    start, end = interval
    return str(start) if start == end else f'{start}-{end}'


# ES: Resuelve recursivamente alias/grupos/literales de puerto a intervalos.
# EN: Recursively resolves port aliases/groups/literals into intervals.
def resolve_port_item(item: Any, alias_data: dict[str, Any], seen: set[str] | None = None) -> list[tuple[int, int]]:
    seen = seen or set()
    intervals: list[tuple[int, int]] = []

    if isinstance(item, str):
        literal = port_interval(item)
        if literal is not None:
            return [literal]

    resolved = find_alias(alias_data, item, ('alias_service', 'alias_service_group'))
    if resolved is None:
        if isinstance(item, dict) and isinstance(item.get('content'), list):
            # ES: Objeto completo no encontrado en alias_services.json: se procesa su content directo.
            # EN: Full object not found in alias_services.json: process its direct content.
            for child in mixed_items(item.get('content', [])):
                intervals.extend(resolve_port_item(child, alias_data, set(seen)))
            return intervals
        return intervals

    section, entry = resolved
    uuid = str(entry.get('UUID') or '')
    if uuid:
        if uuid in seen:
            return intervals
        seen.add(uuid)

    # ES: Alias simple: su content contiene puertos/rangos literales.
    # EN: Simple alias: its content contains literal ports/ranges.
    if section == 'alias_service':
        for child in mixed_items(entry.get('content', [])):
            if isinstance(child, str):
                literal = port_interval(child)
                if literal is not None:
                    intervals.append(literal)
        return intervals

    # ES: Grupo: su content puede contener UUID/name de servicios o literales directos.
    # EN: Group: its content may contain service UUID/name or direct literals.
    for child in mixed_items(entry.get('content', [])):
        intervals.extend(resolve_port_item(child, alias_data, set(seen)))
    return intervals


# ES: Une duplicados, rangos solapados y puertos contenidos en rangos mayores.
# EN: Merges duplicates, overlapping ranges and ports contained in broader ranges.
def collapse_port_intervals(intervals: list[tuple[int, int]]) -> list[str]:
    if not intervals:
        return []
    ordered = sorted(intervals, key=lambda item: (item[0], item[1]))
    collapsed: list[tuple[int, int]] = []

    for start, end in ordered:
        if not collapsed:
            collapsed.append((start, end))
            continue
        prev_start, prev_end = collapsed[-1]
        if start <= prev_end + 1:
            # ES: Solapado/contiguo: se conserva el rango más amplio.
            # EN: Overlapping/contiguous: keep the broader range.
            collapsed[-1] = (prev_start, max(prev_end, end))
        else:
            collapsed.append((start, end))

    return [format_interval(interval) for interval in collapsed]


# ES: Convierte entrada mixta a puertos/rangos finales limpios.
# EN: Converts mixed input into clean final ports/ranges.
def convert_ports(value: Any, alias_data: dict[str, Any] | None = None) -> list[str]:
    alias_data = alias_data if alias_data is not None else load_alias_data()
    intervals: list[tuple[int, int]] = []
    for item in mixed_items(value):
        intervals.extend(resolve_port_item(item, alias_data))
    return collapse_port_intervals(intervals)


if __name__ == '__main__':
    import sys

    raw = sys.stdin.read().strip()
    payload = json.loads(raw) if raw else []
    print(json.dumps({'ports': convert_ports(payload)}, ensure_ascii=False))
