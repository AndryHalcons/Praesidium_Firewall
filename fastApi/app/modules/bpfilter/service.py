"""Lógica de negocio FastAPI para BPFilter."""

from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid
from modules.alias_ip.domain import mixed_reference_items as ip_mixed_reference_items, validate_final_value as validate_ip_final_value, validate_mixed_ip_references
from modules.alias_services.domain import validate_mixed_service_references
from modules.bpfilter import repository

ALLOWED_HOOKS = ("BF_HOOK_XDP", "BF_HOOK_TC_INGRESS", "BF_HOOK_TC_EGRESS")
HOOK_ALIASES = {
    "xdp": "BF_HOOK_XDP",
    "tc-ingress": "BF_HOOK_TC_INGRESS",
    "tc_INGRESS": "BF_HOOK_TC_INGRESS",
    "tc_ingress": "BF_HOOK_TC_INGRESS",
    "ingress": "BF_HOOK_TC_INGRESS",
    "tc-egress": "BF_HOOK_TC_EGRESS",
    "tc_egress": "BF_HOOK_TC_EGRESS",
    "egress": "BF_HOOK_TC_EGRESS",
    "BF_HOOK_XDP": "BF_HOOK_XDP",
    "BF_HOOK_TC_INGRESS": "BF_HOOK_TC_INGRESS",
    "BF_HOOK_TC_EGRESS": "BF_HOOK_TC_EGRESS",
}
SELECT_VALUES = {
    "action": ["DROP"],
    "l3_protocol": ["", "IPv4", "IPv6", "MPLS", "IPX", "ARP"],
    "interface": [""],
    "l4_protocol": ["TCP", "UDP", "ICMP", "ICMPv6", "SCTP", "DCCP"],
    "ipv6_next_header": ["", "TCP", "UDP", "ICMP", "ICMPv6", "SCTP", "DCCP", "Hop-by-Hop", "Routing", "Fragment", "AH", "ESP", "Destination"],
    "tcp_flags": ["", "fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"],
    "icmp_type": ["", "echo-reply", "destination-unreachable", "source-quench", "redirect", "echo-request", "router-advertisement", "router-solicitation", "time-exceeded", "parameter-problem", "timestamp-request", "timestamp-reply", "address-mask-request", "address-mask-reply"],
    "icmp_code": ["", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"],
    "icmpv6_type": ["", "echo-request", "echo-reply", "destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem", "router-solicitation", "router-advertisement", "neighbor-solicitation", "neighbor-advertisement", "redirect", "multicast-listener-query", "multicast-listener-report", "multicast-listener-done"],
    "icmpv6_code": ["", "0", "1", "2", "3", "4"],
}
CHECKBOX_VALUES = {"log": ["true", "false"], "enable": ["true", "false"]}
SANITIZED_KEYS = ("id", "hook", "chain", "position", "action", "enable", "name", "interface", "l3_protocol", "l4_protocol", "source", "sport", "destination", "dport", "tcp_flags", "ipv6_next_header", "icmp_type", "icmp_code", "icmpv6_type", "icmpv6_code", "probability")


def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    raise HTTPException(status_code=status_code, detail={"status": "error", "error_code": code})


def normalize_hook(value: str) -> str:
    hook = HOOK_ALIASES.get(str(value).strip())
    if hook not in ALLOWED_HOOKS:
        fail("BPFILTER_HOOK_NOT_ALLOWED")
    return hook




def available_hooks() -> list[dict[str, str]]:
    return [
        {"hook": "xdp", "value": "BF_HOOK_XDP"},
        {"hook": "tc-ingress", "value": "BF_HOOK_TC_INGRESS"},
        {"hook": "tc-egress", "value": "BF_HOOK_TC_EGRESS"},
    ]

def validate_config_shape(config: dict[str, Any]) -> None:
    if not isinstance(config, dict) or not isinstance(config.get("bpfilter"), list):
        fail("BPFILTER_CANDIDATE_CONFIG_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
    for entry in config["bpfilter"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("rule"), dict):
            fail("BPFILTER_RULE_ENTRY_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)


def read_candidate_config() -> dict[str, Any]:
    config = repository.read_config()
    validate_config_shape(config)
    return config


def list_rules_for_hook(hook: str) -> list[dict[str, Any]]:
    hook = normalize_hook(hook)
    config = read_candidate_config()
    return [entry["rule"] for entry in config["bpfilter"] if entry.get("rule", {}).get("hook") == hook]


def mixed_items(value: Any) -> list[Any]:
    return ip_mixed_reference_items(value)


def validate_alias_fields(rule: dict[str, Any]) -> None:
    alias_services = repository.read_alias_services()
    alias_ip = repository.read_alias_ip()
    for field in ("sport", "dport"):
        if field in rule:
            try:
                validate_mixed_service_references(alias_services, rule[field], allow_groups=True, allow_multiple=True)
            except HTTPException as exc:
                if isinstance(exc.detail, str):
                    fail("INVALID_PORT_OR_ALIAS")
                raise
    for field in ("source", "destination"):
        if field in rule:
            try:
                validate_mixed_ip_references(alias_ip, rule[field], allow_groups=True, allow_multiple=True)
            except HTTPException as exc:
                if isinstance(exc.detail, str):
                    fail("INVALID_IP_OR_ALIAS")
                raise


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


def extract_ip_literals(entry: Any) -> list[str]:
    if isinstance(entry, str):
        return [item.strip() for item in entry.split(",") if item.strip()]
    if isinstance(entry, dict):
        out: list[str] = []
        for item in mixed_items(entry.get("content", [])):
            if isinstance(item, str) and detect_ip_version(item) in ("IPv4", "IPv6"):
                out.append(item.strip())
        return out
    return []


def contains_single_ip_version(source: Any, destination: Any) -> bool:
    versions: list[str] = []
    for entry in [*mixed_items(source), *mixed_items(destination)]:
        for literal in extract_ip_literals(entry):
            version = detect_ip_version(literal)
            if version in ("IPv4", "IPv6"):
                versions.append(version)
    return len(set(versions)) <= 1


def validate_form_fields(rule: dict[str, Any]) -> None:
    selects = {key: list(values) for key, values in SELECT_VALUES.items()}
    selects["interface"] = [*selects["interface"], *repository.read_physical_interfaces()]
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
    if "hook" in rule and str(rule["hook"]).strip() not in ALLOWED_HOOKS:
        fail("INVALID_NOT_EDITABLE_VALUE")


def gen_chain_name(rule: dict[str, Any]) -> dict[str, Any]:
    if not str(rule.get("interface", "")).strip():
        fail("BPFILTER_INTERFACE_REQUIRED")
    if not str(rule.get("hook", "")).strip():
        fail("BPFILTER_HOOK_REQUIRED")
    rule["chain"] = f"{rule['interface']}_{str(rule['hook']).lower()}"
    return rule


def next_id(config: dict[str, Any]) -> str:
    used = set()
    for entry in config.get("bpfilter", []):
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


def validate_protocols(rule: dict[str, Any]) -> None:
    l3 = rule.get("l3_protocol", "")
    l4 = rule.get("l4_protocol", "")
    ip6 = rule.get("ipv6_next_header", "")
    tcp_flags = rule.get("tcp_flags", "")
    icmp_type = rule.get("icmp_type", "")
    icmp_code = rule.get("icmp_code", "")
    icmpv6_type = rule.get("icmpv6_type", "")
    icmpv6_code = rule.get("icmpv6_code", "")
    if not contains_single_ip_version(rule.get("source", ""), rule.get("destination", "")):
        fail("BPFILTER_MIXED_IP_VERSIONS")
    if l3 == "":
        fail("BPFILTER_L3_PROTOCOL_REQUIRED")
    if l3 in ("MPLS", "IPX", "ARP") and any([l4, ip6, tcp_flags, icmp_type, icmp_code, icmpv6_type, icmpv6_code]):
        fail("BPFILTER_L3_EXTRA_FIELDS_NOT_ALLOWED")
    if l3 == "IPv4" and ip6:
        fail("BPFILTER_IPV6_NEXT_HEADER_WITH_IPV4")
    if l3 == "IPv4" and (icmpv6_type or icmpv6_code):
        fail("BPFILTER_ICMPV6_WITH_IPV4")
    if l3 == "IPv6" and (icmp_type or icmp_code):
        fail("BPFILTER_ICMP_WITH_IPV6")
    if l3 != "IPv6" and ip6:
        fail("BPFILTER_IPV6_NEXT_HEADER_REQUIRES_IPV6")
    if l4 == "TCP" and (icmp_type or icmp_code or icmpv6_type or icmpv6_code):
        fail("BPFILTER_TCP_WITH_ICMP_FIELDS")
    if l4 == "UDP":
        if icmp_type or icmp_code or icmpv6_type or icmpv6_code:
            fail("BPFILTER_UDP_WITH_ICMP_FIELDS")
        if tcp_flags:
            fail("BPFILTER_TCP_FLAGS_WITH_UDP")
    if l4 == "ICMP":
        if icmpv6_type or icmpv6_code:
            fail("BPFILTER_ICMP_WITH_ICMPV6_FIELDS")
        if tcp_flags:
            fail("BPFILTER_TCP_FLAGS_WITH_ICMP")
    if l4 == "ICMPv6":
        if icmp_type or icmp_code:
            fail("BPFILTER_ICMPV6_WITH_ICMP_FIELDS")
        if tcp_flags:
            fail("BPFILTER_TCP_FLAGS_WITH_ICMPV6")
    if tcp_flags and l4 != "TCP":
        fail("BPFILTER_TCP_FLAGS_REQUIRES_TCP")
    if ip6 == "TCP" and (icmp_type or icmp_code or icmpv6_type or icmpv6_code):
        fail("BPFILTER_IPV6_NEXT_TCP_WITH_ICMP_FIELDS")
    if ip6 == "UDP" and (icmp_type or icmp_code or icmpv6_type or icmpv6_code or tcp_flags):
        fail("BPFILTER_IPV6_NEXT_UDP_WITH_EXTRA_FIELDS")
    if ip6 == "ICMP" and (icmpv6_type or icmpv6_code or tcp_flags):
        fail("BPFILTER_IPV6_NEXT_ICMP_WITH_EXTRA_FIELDS")
    if ip6 == "ICMPv6" and (icmp_type or icmp_code or tcp_flags):
        fail("BPFILTER_IPV6_NEXT_ICMPV6_WITH_EXTRA_FIELDS")
    if ip6 in ("Hop-by-Hop", "Routing", "Fragment", "AH", "ESP", "Destination") and any([l4, tcp_flags, icmp_type, icmp_code, icmpv6_type, icmpv6_code]):
        fail("BPFILTER_IPV6_NEXT_HEADER_EXTRA_FIELDS_NOT_ALLOWED")


def sanitize_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {key: rule.get(key, "") for key in SANITIZED_KEYS}


def existing_rule_uuids(config: dict[str, Any]) -> set[str]:
    return {str(entry.get("rule", {}).get("UUID")) for entry in config.get("bpfilter", []) if entry.get("rule", {}).get("UUID")}


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


def update_or_insert_rule(rule: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(int(str(rule.get("id", "0")))) if str(rule.get("id", "")).isdigit() else ""
    if not rule_id:
        return config
    rule.pop("UUID", None)
    for index, entry in enumerate(config["bpfilter"]):
        existing = entry.get("rule", {})
        try:
            existing_id = str(int(str(existing.get("id", "0"))))
        except ValueError:
            existing_id = ""
        if existing_id == rule_id:
            uuid = str(existing.get("UUID", "")) or generate_unique_internal_uuid("bpf", rule_id, existing_rule_uuids(config))
            config["bpfilter"][index]["rule"] = set_internal_uuid(rule, uuid)
            return config
    uuid = generate_unique_internal_uuid("bpf", rule_id, existing_rule_uuids(config))
    config["bpfilter"].append({"rule": set_internal_uuid(rule, uuid)})
    return config


def family(rule: dict[str, Any]) -> str:
    hook = str(rule.get("hook", ""))
    chain = str(rule.get("chain", "")).strip()
    return f"{hook}_{chain}" if chain else hook


def reorder_position(config: dict[str, Any], rule_id: str, position: Any, hook: str, chain: str) -> dict[str, Any]:
    target_pos = int(position)
    target_family = f"{hook}_{chain.strip()}" if chain.strip() else hook
    block: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    for entry in config["bpfilter"]:
        rule = entry["rule"]
        try:
            rule["position"] = int(rule.get("position", 1))
        except (TypeError, ValueError):
            rule["position"] = 1
        (block if family(rule) == target_family else others).append(entry)
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
    config["bpfilter"] = [*others, *block]
    return config


def validate_and_prepare_rule(hook: str, rule: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(rule, dict):
        fail("BPFILTER_RULE_INVALID")
    rule = dict(rule)
    rule["hook"] = normalize_hook(hook)
    rule = gen_chain_name(rule)
    # Mantiene la lógica de validación/saneado de la WebGUI.
    validate_alias_fields(rule)
    rule = normalize_id(rule, config)
    validate_form_fields(rule)
    rule = assign_position(rule)
    sanitized = sanitize_rule(rule)
    validate_protocols(sanitized)
    return sanitized


def upsert_rule(hook: str, rule: dict[str, Any]) -> dict[str, Any]:
    hook = normalize_hook(hook)
    with repository.config_lock():
        config = read_candidate_config()
        sanitized = validate_and_prepare_rule(hook, rule, config)
        config = update_or_insert_rule(sanitized, config)
        config = reorder_position(config, sanitized["id"], sanitized["position"], sanitized["hook"], sanitized["chain"])
        repository.write_config(config)
    return {"success": True, "action": "update", "hook": hook, "id": str(sanitized["id"])}


def delete_rule(hook: str, rule_id: str) -> dict[str, Any]:
    hook = normalize_hook(hook)
    if not str(rule_id).isdigit() or int(str(rule_id)) <= 0:
        fail("BPFILTER_ID_INVALID")
    with repository.config_lock():
        config = read_candidate_config()
        original_count = len(config["bpfilter"])
        config["bpfilter"] = [entry for entry in config["bpfilter"] if not (str(entry.get("rule", {}).get("id", "")) == str(rule_id) and entry.get("rule", {}).get("hook") == hook)]
        if len(config["bpfilter"]) == original_count:
            fail("BPFILTER_RULE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        repository.write_config(config)
    return {"success": True, "action": "delete", "hook": hook, "id": str(rule_id)}
