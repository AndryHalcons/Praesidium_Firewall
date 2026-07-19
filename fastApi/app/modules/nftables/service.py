"""Lógica de negocio FastAPI para Nftables."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid
from modules.alias_ip.domain import find_entry_reference as find_ip_reference, mixed_reference_items, resolve_deep_content, validate_mixed_ip_references
from modules.alias_services.domain import validate_mixed_service_references
from modules.nftables import repository

DEFAULT_CHAIN_TOKENS = {
    "FORWARDING": "forwarding",
    "PREROUTING": "prerouting",
    "POSTROUTING": "postrouting",
    "input": "input",
    "output": "output",
}
SELECT_VALUES = {
    "action": ["accept", "drop", "reject", "queue"],
    "meta.iifname": [""],
    "meta.oifname": [""],
    "ip.protocol": ["tcp", "udp", "tcp, udp", "icmp", "icmpv6"],
    "ct.state": ["", "new", "related", "established", "established, related", "new, related", "new, established", "new, related, established"],
}
CHECKBOX_VALUES = {
    "ip.saddr.op": ["!=", "=="],
    "ip.daddr.op": ["!=", "=="],
    "sport.op": ["!=", "=="],
    "dport.op": ["!=", "=="],
    "log": ["true", "false"],
    "enable": ["true", "false"],
    "masquerade": ["true", "false"],
}
SANITIZED_KEYS = (
    "family", "table", "chain", "id", "position", "action", "enable", "name", "ip.protocol",
    "ip.saddr.op", "ip.saddr", "sport.op", "sport", "ip.daddr.op", "ip.daddr", "dport.op", "dport",
    "meta.iifname", "meta.oifname", "ct.state", "packets", "bytes", "log", "snat.addr", "masquerade",
    "snat.port", "dnat.addr", "dnat.port", "redirect",
)
IP_FIELDS = ("ip.daddr", "ip.saddr", "dnat.addr", "snat.addr")
PORT_FIELDS = ("sport", "dport", "dnat.port", "redirect")
NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
ALLOWED_CHAIN_TYPES = {"filter", "nat", "route"}
ALLOWED_CHAIN_HOOKS = {"", "input", "output", "forward", "prerouting", "postrouting", "ingress"}
ALLOWED_POLICIES = {"", "accept", "drop"}


# ES: Lanza errores API con forma estable status/error_code.
# EN: Raise API errors with stable status/error_code shape.
def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    raise HTTPException(status_code=status_code, detail={"status": "error", "error_code": code})


# ES: Extrae tablas declaradas desde nftables_tables_chains.json.
# EN: Extract declared tables from nftables_tables_chains.json.
def declared_tables() -> list[dict[str, Any]]:
    data = repository.read_tables_chains()
    tables: list[dict[str, Any]] = []
    for item in data.get("nftables", []):
        table = item.get("table") if isinstance(item, dict) else None
        if isinstance(table, dict) and table.get("name"):
            tables.append(table)
    return tables


# ES: Extrae cadenas declaradas desde nftables_tables_chains.json.
# EN: Extract declared chains from nftables_tables_chains.json.
def declared_chains() -> list[dict[str, Any]]:
    data = repository.read_tables_chains()
    chains: list[dict[str, Any]] = []
    for item in data.get("nftables", []):
        chain = item.get("chain") if isinstance(item, dict) else None
        if isinstance(chain, dict) and chain.get("table") and chain.get("name"):
            chains.append(chain)
    return chains


# ES: Devuelve las combinaciones table/chain disponibles para que el usuario no adivine valores.
# EN: Return available table/chain combinations so users do not guess values.
def available_chains() -> list[dict[str, str]]:
    return [
        {
            "table": str(chain.get("table", "")),
            "chain": str(chain.get("name", "")),
            "token": DEFAULT_CHAIN_TOKENS.get(str(chain.get("name", "")), str(chain.get("name", ""))),
            "family": str(chain.get("family", "")),
            "hook": str(chain.get("hook", "")),
        }
        for chain in declared_chains()
    ]


# ES: Valida que table y chain existan como combinación declarada en candidate.
# EN: Validate table and chain exist as a declared candidate combination.
def validate_table_chain(table: str, chain: str) -> dict[str, str]:
    clean_table = str(table).strip()
    clean_chain = str(chain).strip()
    if not clean_table or not clean_chain:
        fail("NFTABLES_TABLE_CHAIN_REQUIRED")
    table_exists = any(str(item.get("name", "")) == clean_table for item in declared_tables())
    if not table_exists:
        fail("NFTABLES_TABLE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    for item in declared_chains():
        if str(item.get("table", "")) == clean_table and str(item.get("name", "")) == clean_chain:
            return {"family": str(item.get("family", "inet")), "table": clean_table, "chain": clean_chain}
    fail("NFTABLES_CHAIN_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    raise AssertionError("unreachable")


# ES: Valida forma básica del candidate nftables.
# EN: Validate basic shape of the nftables candidate.
def validate_config_shape(config: dict[str, Any]) -> None:
    if not isinstance(config, dict) or not isinstance(config.get("nftables"), list):
        fail("NFTABLES_CANDIDATE_CONFIG_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
    for entry in config["nftables"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("rule"), dict):
            fail("NFTABLES_RULE_ENTRY_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)


# ES: Lee candidate tras validar estructura.
# EN: Read candidate after validating shape.
def read_candidate_config() -> dict[str, Any]:
    config = repository.read_config()
    validate_config_shape(config)
    return config


# ES: Lista reglas de una cadena canonical.
# EN: List rules for one canonical chain.
def list_rules_for_chain(table: str, chain: str) -> list[dict[str, Any]]:
    target = validate_table_chain(table, chain)
    config = read_candidate_config()
    return [
        entry["rule"] for entry in config["nftables"]
        if entry.get("rule", {}).get("table") == target["table"] and entry.get("rule", {}).get("chain") == target["chain"]
    ]


# ES: Aplica family/table/chain desde la cadena de URL, no desde payload.
# EN: Apply family/table/chain from URL chain, not from payload.
def apply_family(table: str, chain: str, rule: dict[str, Any]) -> dict[str, Any]:
    definition = validate_table_chain(table, chain)
    rule["family"] = definition["family"]
    rule["table"] = definition["table"]
    rule["chain"] = definition["chain"]
    return rule


# ES: Limpia puertos si el protocolo ICMP los hace incompatibles.
# EN: Clear ports when ICMP protocol makes them incompatible.
def validation_icmp_no_ports(rule: dict[str, Any]) -> dict[str, Any]:
    protocol = str(rule.get("ip.protocol", "")).strip().lower()
    if protocol in ("icmp", "icmpv6"):
        for field in ("sport.op", "sport", "dport.op", "dport", "dnat.port", "redirect"):
            if field in rule:
                rule[field] = ""
    return rule


# ES: Valida IPs/puertos mixtos delegando en alias_ip/alias_services.
# EN: Validate mixed IP/port fields by delegating to alias_ip/alias_services.
def validate_alias_fields(rule: dict[str, Any]) -> None:
    if str(rule.get("masquerade", "")).strip().lower() == "true":
        rule["snat.addr"] = ""
    alias_ip = repository.read_alias_ip()
    alias_services = repository.read_alias_services()
    for field in PORT_FIELDS:
        if field in rule:
            try:
                validate_mixed_service_references(alias_services, rule[field], allow_groups=True, allow_multiple=True)
            except HTTPException as exc:
                if isinstance(exc.detail, str):
                    fail("INVALID_PORT_OR_ALIAS")
                raise
    for field in IP_FIELDS:
        if field in rule:
            try:
                validate_mixed_ip_references(alias_ip, rule[field], allow_groups=True, allow_multiple=True)
            except HTTPException as exc:
                if isinstance(exc.detail, str):
                    fail("INVALID_IP_OR_ALIAS")
                raise


# ES: Asigna o normaliza id global de regla nftables.
# EN: Assign or normalize the global nftables rule id.
def normalize_id(rule: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    candidate = rule.get("id")
    if isinstance(candidate, str):
        candidate = candidate.strip()
    if candidate in (None, ""):
        rule["id"] = next_id(config)
        return rule
    if isinstance(candidate, int) and candidate > 0:
        rule["id"] = str(candidate)
        return rule
    if isinstance(candidate, str) and candidate.isdigit() and int(candidate) > 0:
        rule["id"] = str(int(candidate))
        return rule
    rule["id"] = next_id(config)
    return rule


# ES: Valida id positivo de regla.
# EN: Validate positive rule id.
def validate_rule_id(rule_id: Any) -> str:
    clean = str(rule_id).strip()
    if not clean.isdigit() or int(clean) <= 0:
        fail("NFTABLES_ID_INVALID")
    return str(int(clean))


# ES: Comprueba si existe regla por table/chain/id.
# EN: Check if a rule exists by table/chain/id.
def rule_exists(config: dict[str, Any], table: str, chain: str, rule_id: str) -> bool:
    clean_id = validate_rule_id(rule_id)
    return any(
        isinstance(entry, dict)
        and isinstance(entry.get("rule"), dict)
        and str(entry["rule"].get("table", "")) == table
        and str(entry["rule"].get("chain", "")) == chain
        and str(entry["rule"].get("id", "")) == clean_id
        for entry in config.get("nftables", [])
    )


# ES: Calcula el primer id positivo libre.
# EN: Calculate first free positive id.
def next_id(config: dict[str, Any]) -> str:
    used: set[int] = set()
    for entry in config.get("nftables", []):
        try:
            value = int(str(entry.get("rule", {}).get("id", "")))
        except ValueError:
            continue
        if value > 0:
            used.add(value)
    candidate = 1
    while candidate in used:
        candidate += 1
    return str(candidate)


# ES: Valida selects, checkboxes y campos no editables del formulario legacy.
# EN: Validate legacy-form selects, checkboxes and not-editable fields.
def validate_form_fields(rule: dict[str, Any]) -> None:
    selects = {key: list(values) for key, values in SELECT_VALUES.items()}
    interfaces = repository.read_all_interfaces()
    selects["meta.iifname"] = [*selects["meta.iifname"], *interfaces]
    selects["meta.oifname"] = [*selects["meta.oifname"], *interfaces]
    for key, valid_values in selects.items():
        if key in rule:
            value = str(rule[key]).strip()
            if value and value not in valid_values:
                fail("INVALID_SELECT_VALUE")
    for key, valid_values in CHECKBOX_VALUES.items():
        if key in rule:
            value = str(rule[key]).strip()
            if value and value not in valid_values:
                fail("INVALID_CHECKBOX_VALUE")
    if str(rule.get("family", "")) != "inet":
        fail("INVALID_NOT_EDITABLE_VALUE")
    validate_table_chain(str(rule.get("table", "")), str(rule.get("chain", "")))


# ES: Extrae literales IP profundos desde literals, UUIDs u objetos alias completos.
# EN: Extract deep IP literals from literals, UUIDs or complete alias objects.
def collect_ip_literals(value: Any, alias_data: dict[str, Any]) -> list[str]:
    literals: list[str] = []
    for item in mixed_reference_items(value):
        if isinstance(item, str):
            clean = item.strip()
            if detect_ip_version(clean) in ("IPv4", "IPv6"):
                literals.append(clean)
                continue
        section, entry = find_ip_reference(alias_data, item)
        if section and entry:
            for deep_value in resolve_deep_content(alias_data, section, entry):
                if detect_ip_version(str(deep_value)) in ("IPv4", "IPv6"):
                    literals.append(str(deep_value))
        elif isinstance(item, dict):
            for child in mixed_reference_items(item.get("content", [])):
                if isinstance(child, str) and detect_ip_version(child) in ("IPv4", "IPv6"):
                    literals.append(child)
    return literals


# ES: Detecta versión IP de un literal.
# EN: Detect IP version for one literal.
def detect_ip_version(value: str) -> str:
    text = str(value).strip()
    if not text:
        return "Desconocido"
    ip_text = text.split("/", 1)[0]
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return "Desconocido"
    return "IPv4" if ip.version == 4 else "IPv6"


# ES: Rechaza mezcla IPv4/IPv6 en campos IP de la misma regla.
# EN: Reject IPv4/IPv6 mix inside one rule's IP fields.
def ensure_single_ip_version(rule: dict[str, Any]) -> None:
    alias_data = repository.read_alias_ip()
    versions: list[str] = []
    for field in IP_FIELDS:
        for literal in collect_ip_literals(rule.get(field, ""), alias_data):
            version = detect_ip_version(literal)
            if version in ("IPv4", "IPv6"):
                versions.append(version)
    if len(set(versions)) > 1:
        fail("NFTABLES_MIXED_IP_VERSIONS")


# ES: Limpia operadores de puerto sin puerto asociado; el operador no tiene significado por sí solo.
# EN: Clear port operators without an associated port; the operator has no standalone meaning.
def normalize_empty_port_operators(rule: dict[str, Any]) -> dict[str, Any]:
    if not mixed_reference_items(rule.get("sport", "")):
        rule["sport.op"] = ""
    if not mixed_reference_items(rule.get("dport", "")):
        rule["dport.op"] = ""
    return rule


# ES: Valida compatibilidad de protocolo, puertos y NAT.
# EN: Validate protocol, port and NAT compatibility.
def validate_nft_rule_protocols(rule: dict[str, Any]) -> None:
    ip_protocol = str(rule.get("ip.protocol", "")).strip().lower()
    table = str(rule.get("table", "")).strip()
    sport = bool(mixed_reference_items(rule.get("sport", "")))
    sport_op = str(rule.get("sport.op", "")).strip()
    dport = bool(mixed_reference_items(rule.get("dport", "")))
    dport_op = str(rule.get("dport.op", "")).strip()
    snat_addr = bool(mixed_reference_items(rule.get("snat.addr", "")))
    dnat_addr = bool(mixed_reference_items(rule.get("dnat.addr", "")))
    dnat_port = bool(mixed_reference_items(rule.get("dnat.port", "")))
    redirect = bool(mixed_reference_items(rule.get("redirect", "")))
    ip_saddr = bool(mixed_reference_items(rule.get("ip.saddr", "")))
    ip_saddr_op = str(rule.get("ip.saddr.op", "")).strip()
    ip_daddr = bool(mixed_reference_items(rule.get("ip.daddr", "")))
    ip_daddr_op = str(rule.get("ip.daddr.op", "")).strip()
    ct_state = str(rule.get("ct.state", "")).strip()
    masquerade = str(rule.get("masquerade", "")).strip().lower() == "true"

    if not sport and sport_op:
        fail("NFTABLES_SPORT_OP_WITHOUT_SPORT")
    if not dport and dport_op:
        fail("NFTABLES_DPORT_OP_WITHOUT_DPORT")
    if snat_addr and dnat_addr:
        fail("NFTABLES_SNAT_DNAT_CONFLICT")
    if not ip_saddr and ip_saddr_op:
        fail("NFTABLES_SADDR_OP_WITHOUT_SADDR")
    if not ip_daddr and ip_daddr_op:
        fail("NFTABLES_DADDR_OP_WITHOUT_DADDR")
    if "udp" in ip_protocol and ct_state:
        fail("NFTABLES_CT_STATE_WITH_UDP")
    if ip_protocol == "tcp, udp" and ct_state:
        fail("NFTABLES_CT_STATE_WITH_TCP_UDP")
    if ip_protocol in ("icmp", "icmpv6") and (dnat_port or sport or dport or redirect):
        fail("NFTABLES_ICMP_WITH_PORT_FIELDS")
    if "icmp" in ip_protocol and "icmpv6" not in ip_protocol and (sport or sport_op or dport or dport_op or dnat_port or redirect):
        fail("NFTABLES_ICMP_WITH_PORT_FIELDS")
    if "icmpv6" in ip_protocol and (sport or sport_op or dport or dport_op or dnat_port or redirect):
        fail("NFTABLES_ICMPV6_WITH_PORT_FIELDS")
    ensure_single_ip_version(rule)
    if table == "nat" and not (snat_addr or dnat_addr or masquerade or dnat_port or redirect):
        fail("NFTABLES_NAT_TARGET_REQUIRED")
    if redirect and (dnat_addr or dnat_port):
        fail("NFTABLES_REDIRECT_WITH_DNAT")
    if masquerade and snat_addr:
        fail("NFTABLES_MASQUERADE_WITH_SNAT")


# ES: Asigna posición por defecto y normaliza a entero positivo.
# EN: Assign default position and normalize to positive integer.
def assign_position(rule: dict[str, Any]) -> dict[str, Any]:
    candidate = rule.get("position")
    if candidate is None or str(candidate).strip() == "":
        rule["position"] = 1
        return rule
    if isinstance(candidate, int):
        rule["position"] = candidate if candidate > 0 else 1
        return rule
    text = str(candidate).strip()
    rule["position"] = int(text) if text.isdigit() and int(text) > 0 else 1
    return rule


# ES: Sanea al formato estable del JSON rules_nftables_human_viewer.
# EN: Sanitize to the stable rules_nftables_human_viewer JSON format.
def sanitize_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {key: rule.get(key, "") for key in SANITIZED_KEYS}


# ES: Recoge UUIDs internos existentes.
# EN: Collect existing internal UUIDs.
def existing_rule_uuids(config: dict[str, Any]) -> set[str]:
    return {str(entry.get("rule", {}).get("UUID")) for entry in config.get("nftables", []) if entry.get("rule", {}).get("UUID")}


# ES: Inserta UUID junto a id para legibilidad compatible.
# EN: Insert UUID next to id for compatible readability.
def set_internal_uuid(rule: dict[str, Any], uuid: str) -> dict[str, Any]:
    ordered: dict[str, Any] = {}
    inserted = False
    for key, value in rule.items():
        if key == "UUID":
            continue
        ordered[key] = value
        if key == "id":
            ordered["UUID"] = uuid
            inserted = True
    if not inserted:
        ordered["UUID"] = uuid
    return ordered


# ES: Inserta o actualiza por id preservando UUID interno.
# EN: Insert or update by id preserving internal UUID.
def update_or_insert_rule(rule: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(int(str(rule.get("id", "0")))) if str(rule.get("id", "")).isdigit() else ""
    if not rule_id:
        return config
    rule.pop("UUID", None)
    for index, entry in enumerate(config["nftables"]):
        existing = entry.get("rule", {})
        try:
            existing_id = str(int(str(existing.get("id", "0"))))
        except ValueError:
            existing_id = ""
        if existing_id == rule_id:
            uuid = str(existing.get("UUID", "")) or generate_unique_internal_uuid("nft", rule_id, existing_rule_uuids(config))
            config["nftables"][index]["rule"] = set_internal_uuid(rule, uuid)
            return config
    uuid = generate_unique_internal_uuid("nft", rule_id, existing_rule_uuids(config))
    config["nftables"].append({"rule": set_internal_uuid(rule, uuid)})
    return config


# ES: Reordena posiciones dentro del bloque family/table/chain.
# EN: Reorder positions inside the family/table/chain block.
def reorder_position(config: dict[str, Any], rule_id: str, position: Any, family: str, table: str, chain: str) -> dict[str, Any]:
    target_pos = int(position)
    block: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    for entry in config["nftables"]:
        rule = entry["rule"]
        try:
            rule["position"] = int(rule.get("position", 1))
        except (TypeError, ValueError):
            rule["position"] = 1
        if rule.get("family") == family and rule.get("table") == table and rule.get("chain") == chain:
            block.append(entry)
        else:
            others.append(entry)
    target_index = None
    for index, entry in enumerate(block):
        if str(entry["rule"].get("id")) == str(rule_id):
            target_index = index
            break
    if target_index is None:
        return config
    for index, entry in enumerate(block):
        if index == target_index:
            entry["rule"]["position"] = target_pos
        elif int(entry["rule"].get("position", 1)) >= target_pos:
            entry["rule"]["position"] = int(entry["rule"].get("position", 1)) + 1
    block.sort(key=lambda entry: int(entry["rule"].get("position", 1)))
    for index, entry in enumerate(block, start=1):
        entry["rule"]["position"] = index
    config["nftables"] = [*others, *block]
    return config


# ES: Ejecuta el pipeline legacy de validación/saneado.
# EN: Execute the legacy validation/sanitization pipeline.
def validate_and_prepare_rule(table: str, chain: str, rule: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(rule, dict):
        fail("NFTABLES_RULE_INVALID")
    rule = apply_family(table, chain, dict(rule))
    rule = validation_icmp_no_ports(rule)
    validate_alias_fields(rule)
    rule = normalize_empty_port_operators(rule)
    rule = normalize_id(rule, config)
    validate_form_fields(rule)
    validate_nft_rule_protocols(rule)
    rule = assign_position(rule)
    return sanitize_rule(rule)


# ES: Crea o actualiza una regla nftables candidate.
# EN: Create or update a candidate nftables rule.
def upsert_rule(table: str, chain: str, rule: dict[str, Any]) -> dict[str, Any]:
    target = validate_table_chain(table, chain)
    with repository.config_lock():
        config = read_candidate_config()
        sanitized = validate_and_prepare_rule(target["table"], target["chain"], rule, config)
        config = update_or_insert_rule(sanitized, config)
        config = reorder_position(config, sanitized["id"], sanitized["position"], sanitized["family"], sanitized["table"], sanitized["chain"])
        repository.write_config(config)
    return {"success": True, "action": "update", "table": sanitized["table"], "chain": sanitized["chain"], "id": str(sanitized["id"])}


# ES: Actualiza solo una regla existente; PATCH no crea reglas nuevas.
# EN: Update only an existing rule; PATCH does not create new rules.
def update_existing_rule(table: str, chain: str, rule_id: str, rule: dict[str, Any]) -> dict[str, Any]:
    target = validate_table_chain(table, chain)
    clean_id = validate_rule_id(rule_id)
    with repository.config_lock():
        config = read_candidate_config()
        if not rule_exists(config, target["table"], target["chain"], clean_id):
            fail("NFTABLES_RULE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        body = dict(rule)
        body["id"] = clean_id
        sanitized = validate_and_prepare_rule(target["table"], target["chain"], body, config)
        config = update_or_insert_rule(sanitized, config)
        config = reorder_position(config, sanitized["id"], sanitized["position"], sanitized["family"], sanitized["table"], sanitized["chain"])
        repository.write_config(config)
    return {"success": True, "action": "update", "table": sanitized["table"], "chain": sanitized["chain"], "id": str(sanitized["id"])}


# ES: Borra una regla por cadena e id.
# EN: Delete one rule by chain and id.
def delete_rule(table: str, chain: str, rule_id: str) -> dict[str, Any]:
    target = validate_table_chain(table, chain)
    rule_id = validate_rule_id(rule_id)
    with repository.config_lock():
        config = read_candidate_config()
        original_count = len(config["nftables"])
        config["nftables"] = [
            entry for entry in config["nftables"]
            if not (str(entry.get("rule", {}).get("id", "")) == str(rule_id) and entry.get("rule", {}).get("table") == target["table"] and entry.get("rule", {}).get("chain") == target["chain"])
        ]
        if len(config["nftables"]) == original_count:
            fail("NFTABLES_RULE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        repository.write_config(config)
    return {"success": True, "action": "delete", "table": target["table"], "chain": target["chain"], "id": str(rule_id)}


# ES: Valida forma básica del candidate nftables_tables_chains.
# EN: Validate basic shape of nftables_tables_chains candidate.
def validate_tables_chains_shape(config: dict[str, Any]) -> None:
    if not isinstance(config, dict) or not isinstance(config.get("nftables"), list):
        fail("NFTABLES_TABLES_CHAINS_CONFIG_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
    for entry in config["nftables"]:
        if not isinstance(entry, dict):
            fail("NFTABLES_TABLES_CHAINS_ENTRY_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
        allowed = {key for key in ("metainfo", "table", "chain") if key in entry}
        if len(allowed) != 1:
            fail("NFTABLES_TABLES_CHAINS_ENTRY_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
        if "table" in entry and not isinstance(entry["table"], dict):
            fail("NFTABLES_TABLE_ENTRY_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
        if "chain" in entry and not isinstance(entry["chain"], dict):
            fail("NFTABLES_CHAIN_ENTRY_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)


# ES: Lee candidate de tablas/cadenas tras validar estructura.
# EN: Read tables/chains candidate after validating shape.
def read_tables_chains_config() -> dict[str, Any]:
    config = repository.read_tables_chains()
    validate_tables_chains_shape(config)
    return config


# ES: Lista tablas declaradas preservando orden.
# EN: List declared tables preserving order.
def list_tables() -> list[dict[str, Any]]:
    return [dict(item["table"]) for item in read_tables_chains_config().get("nftables", []) if isinstance(item, dict) and isinstance(item.get("table"), dict)]


# ES: Lista chains de una tabla declarada.
# EN: List chains for one declared table.
def list_table_chains(table: str) -> list[dict[str, Any]]:
    clean_table = validate_table_exists(table)["name"]
    return [dict(item["chain"]) for item in read_tables_chains_config().get("nftables", []) if isinstance(item, dict) and isinstance(item.get("chain"), dict) and str(item["chain"].get("table", "")) == clean_table]


# ES: Obtiene una tabla por nombre.
# EN: Get one table by name.
def get_table(table: str) -> dict[str, Any]:
    clean = validate_name(table, "NFTABLES_TABLE_NAME_INVALID")
    for item in list_tables():
        if str(item.get("name", "")) == clean:
            return item
    fail("NFTABLES_TABLE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    raise AssertionError("unreachable")


# ES: Obtiene una chain por table/name.
# EN: Get one chain by table/name.
def get_chain(table: str, chain: str) -> dict[str, Any]:
    clean_table = validate_table_exists(table)["name"]
    clean_chain = validate_name(chain, "NFTABLES_CHAIN_NAME_INVALID")
    for item in list_table_chains(clean_table):
        if str(item.get("name", "")) == clean_chain:
            return item
    fail("NFTABLES_CHAIN_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    raise AssertionError("unreachable")


# ES: Valida nombre seguro para table/chain.
# EN: Validate safe table/chain name.
def validate_name(value: Any, code: str) -> str:
    clean = str(value).strip()
    if not clean or not NAME_RE.fullmatch(clean):
        fail(code)
    return clean


# ES: Normaliza family obligatoria inet.
# EN: Normalize required inet family.
def normalize_inet_family(value: Any) -> str:
    family = "inet" if value in (None, "") else str(value).strip()
    if family != "inet":
        fail("NFTABLES_FAMILY_MUST_BE_INET")
    return "inet"


# ES: Valida tabla existente por nombre.
# EN: Validate existing table by name.
def validate_table_exists(table: str) -> dict[str, Any]:
    clean = validate_name(table, "NFTABLES_TABLE_NAME_INVALID")
    for item in list_tables():
        if str(item.get("name", "")) == clean:
            return item
    fail("NFTABLES_TABLE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    raise AssertionError("unreachable")


# ES: Calcula siguiente handle libre dentro de tables/chains.
# EN: Calculate next free handle inside tables/chains.
def next_tables_chains_handle(config: dict[str, Any]) -> int:
    used: set[int] = set()
    for entry in config.get("nftables", []):
        obj = entry.get("table") if isinstance(entry, dict) and isinstance(entry.get("table"), dict) else entry.get("chain") if isinstance(entry, dict) and isinstance(entry.get("chain"), dict) else None
        if not isinstance(obj, dict):
            continue
        try:
            handle = int(obj.get("handle", 0))
        except (TypeError, ValueError):
            continue
        if handle > 0:
            used.add(handle)
    candidate = 1
    while candidate in used:
        candidate += 1
    return candidate


# ES: Normaliza handle opcional.
# EN: Normalize optional handle.
def normalize_handle(value: Any, config: dict[str, Any]) -> int:
    if value in (None, ""):
        return next_tables_chains_handle(config)
    if isinstance(value, int) and value > 0:
        return value
    text = str(value).strip()
    if text.isdigit() and int(text) > 0:
        return int(text)
    fail("NFTABLES_HANDLE_INVALID")
    raise AssertionError("unreachable")


# ES: Normaliza entero prio.
# EN: Normalize integer prio.
def normalize_prio(value: Any) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text)
    except ValueError:
        fail("NFTABLES_CHAIN_PRIO_INVALID")
    raise AssertionError("unreachable")


# ES: Verifica si una tabla tiene chains declaradas.
# EN: Check if a table has declared chains.
def table_has_chains(config: dict[str, Any], table: str) -> bool:
    return any(isinstance(entry, dict) and isinstance(entry.get("chain"), dict) and str(entry["chain"].get("table", "")) == table for entry in config.get("nftables", []))


# ES: Verifica si una chain tiene reglas declaradas.
# EN: Check if a chain has declared rules.
def chain_has_rules(table: str, chain: str) -> bool:
    config = read_candidate_config()
    return any(isinstance(entry, dict) and isinstance(entry.get("rule"), dict) and str(entry["rule"].get("table", "")) == table and str(entry["rule"].get("chain", "")) == chain for entry in config.get("nftables", []))


# ES: Normaliza payload de tabla, siempre family inet.
# EN: Normalize table payload, always family inet.
def normalize_table_payload(payload: dict[str, Any], config: dict[str, Any], current_name: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        fail("NFTABLES_TABLE_PAYLOAD_INVALID")
    name = validate_name(payload.get("name", current_name or ""), "NFTABLES_TABLE_NAME_INVALID")
    family = normalize_inet_family(payload.get("family", "inet"))
    handle = normalize_handle(payload.get("handle"), config)
    return {"family": family, "name": name, "handle": handle}


# ES: Normaliza payload de chain, siempre family inet.
# EN: Normalize chain payload, always family inet.
def normalize_chain_payload(table: str, payload: dict[str, Any], config: dict[str, Any], current_name: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        fail("NFTABLES_CHAIN_PAYLOAD_INVALID")
    clean_table = validate_table_exists(table)["name"]
    name = validate_name(payload.get("name", current_name or ""), "NFTABLES_CHAIN_NAME_INVALID")
    family = normalize_inet_family(payload.get("family", "inet"))
    chain_type = str(payload.get("type", "filter")).strip() or "filter"
    if chain_type not in ALLOWED_CHAIN_TYPES:
        fail("NFTABLES_CHAIN_TYPE_INVALID")
    hook = str(payload.get("hook", "")).strip()
    if hook not in ALLOWED_CHAIN_HOOKS:
        fail("NFTABLES_CHAIN_HOOK_INVALID")
    policy = str(payload.get("policy", "accept")).strip() or "accept"
    if policy not in ALLOWED_POLICIES:
        fail("NFTABLES_CHAIN_POLICY_INVALID")
    handle = normalize_handle(payload.get("handle"), config)
    prio = normalize_prio(payload.get("prio", 0))
    return {"family": family, "table": clean_table, "name": name, "handle": handle, "type": chain_type, "hook": hook, "prio": prio, "policy": policy}


# ES: Crea tabla en nftables_tables_chains.json.
# EN: Create table in nftables_tables_chains.json.
def create_table(payload: dict[str, Any]) -> dict[str, Any]:
    with repository.tables_chains_lock():
        config = read_tables_chains_config()
        table = normalize_table_payload(payload, config)
        if any(str(item.get("name", "")) == table["name"] for item in list_tables()):
            fail("NFTABLES_TABLE_ALREADY_EXISTS", status.HTTP_409_CONFLICT)
        config["nftables"].append({"table": table})
        repository.write_tables_chains(config)
    return {"success": True, "action": "create", "table": table["name"]}


# ES: Edita tabla; renombrar se bloquea si tiene chains.
# EN: Update table; rename is blocked when it has chains.
def update_table(table_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    clean_name = validate_table_exists(table_name)["name"]
    with repository.tables_chains_lock():
        config = read_tables_chains_config()
        new_table = normalize_table_payload(payload, config, current_name=clean_name)
        if new_table["name"] != clean_name:
            if table_has_chains(config, clean_name):
                fail("NFTABLES_TABLE_RENAME_HAS_CHAINS", status.HTTP_409_CONFLICT)
            if any(isinstance(entry, dict) and isinstance(entry.get("table"), dict) and str(entry["table"].get("name", "")) == new_table["name"] for entry in config["nftables"]):
                fail("NFTABLES_TABLE_ALREADY_EXISTS", status.HTTP_409_CONFLICT)
        found = False
        for entry in config["nftables"]:
            if isinstance(entry.get("table"), dict) and str(entry["table"].get("name", "")) == clean_name:
                entry["table"] = new_table
                found = True
                break
        if not found:
            fail("NFTABLES_TABLE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        repository.write_tables_chains(config)
    return {"success": True, "action": "update", "table": new_table["name"]}


# ES: Borra tabla si no tiene chains.
# EN: Delete table if it has no chains.
def delete_table(table_name: str) -> dict[str, Any]:
    clean_name = validate_table_exists(table_name)["name"]
    with repository.tables_chains_lock():
        config = read_tables_chains_config()
        if table_has_chains(config, clean_name):
            fail("NFTABLES_TABLE_HAS_CHAINS", status.HTTP_409_CONFLICT)
        original = len(config["nftables"])
        config["nftables"] = [entry for entry in config["nftables"] if not (isinstance(entry, dict) and isinstance(entry.get("table"), dict) and str(entry["table"].get("name", "")) == clean_name)]
        if len(config["nftables"]) == original:
            fail("NFTABLES_TABLE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        repository.write_tables_chains(config)
    return {"success": True, "action": "delete", "table": clean_name}


# ES: Crea chain en nftables_tables_chains.json.
# EN: Create chain in nftables_tables_chains.json.
def create_chain(table: str, payload: dict[str, Any]) -> dict[str, Any]:
    clean_table = validate_table_exists(table)["name"]
    with repository.tables_chains_lock():
        config = read_tables_chains_config()
        chain = normalize_chain_payload(clean_table, payload, config)
        if any(isinstance(entry, dict) and isinstance(entry.get("chain"), dict) and str(entry["chain"].get("table", "")) == clean_table and str(entry["chain"].get("name", "")) == chain["name"] for entry in config["nftables"]):
            fail("NFTABLES_CHAIN_ALREADY_EXISTS", status.HTTP_409_CONFLICT)
        config["nftables"].append({"chain": chain})
        repository.write_tables_chains(config)
    return {"success": True, "action": "create", "table": clean_table, "chain": chain["name"]}


# ES: Edita chain; renombrar se bloquea si tiene reglas.
# EN: Update chain; rename is blocked when it has rules.
def update_chain(table: str, chain_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    clean_table = validate_table_exists(table)["name"]
    clean_chain = get_chain(clean_table, chain_name)["name"]
    with repository.tables_chains_lock():
        config = read_tables_chains_config()
        new_chain = normalize_chain_payload(clean_table, payload, config, current_name=clean_chain)
        if new_chain["name"] != clean_chain:
            if chain_has_rules(clean_table, clean_chain):
                fail("NFTABLES_CHAIN_RENAME_HAS_RULES", status.HTTP_409_CONFLICT)
            if any(isinstance(entry, dict) and isinstance(entry.get("chain"), dict) and str(entry["chain"].get("table", "")) == clean_table and str(entry["chain"].get("name", "")) == new_chain["name"] for entry in config["nftables"]):
                fail("NFTABLES_CHAIN_ALREADY_EXISTS", status.HTTP_409_CONFLICT)
        found = False
        for entry in config["nftables"]:
            if isinstance(entry.get("chain"), dict) and str(entry["chain"].get("table", "")) == clean_table and str(entry["chain"].get("name", "")) == clean_chain:
                entry["chain"] = new_chain
                found = True
                break
        if not found:
            fail("NFTABLES_CHAIN_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        repository.write_tables_chains(config)
    return {"success": True, "action": "update", "table": clean_table, "chain": new_chain["name"]}


# ES: Borra chain si no tiene reglas.
# EN: Delete chain if it has no rules.
def delete_chain(table: str, chain_name: str) -> dict[str, Any]:
    clean_table = validate_table_exists(table)["name"]
    clean_chain = get_chain(clean_table, chain_name)["name"]
    if chain_has_rules(clean_table, clean_chain):
        fail("NFTABLES_CHAIN_HAS_RULES", status.HTTP_409_CONFLICT)
    with repository.tables_chains_lock():
        config = read_tables_chains_config()
        original = len(config["nftables"])
        config["nftables"] = [entry for entry in config["nftables"] if not (isinstance(entry, dict) and isinstance(entry.get("chain"), dict) and str(entry["chain"].get("table", "")) == clean_table and str(entry["chain"].get("name", "")) == clean_chain)]
        if len(config["nftables"]) == original:
            fail("NFTABLES_CHAIN_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        repository.write_tables_chains(config)
    return {"success": True, "action": "delete", "table": clean_table, "chain": clean_chain}
