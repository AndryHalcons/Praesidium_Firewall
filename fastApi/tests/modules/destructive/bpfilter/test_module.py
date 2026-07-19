"""Tests destructivos del módulo bpfilter FastAPI."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from common.runner import call, require

BPFILTER = Path("/var/lib/praesidium/candidate/rules_bpfilter_human_viewer.json")
ALIAS_IP = Path("/var/lib/praesidium/candidate/alias_ip.json")
ALIAS_SERVICES = Path("/var/lib/praesidium/candidate/alias_services.json")
BPFILTER_BACKUP = Path("/tmp/praesidium_bpfilter_before_destructive_test.json")
ALIAS_IP_BACKUP = Path("/tmp/praesidium_bpfilter_alias_ip_before_destructive_test.json")
ALIAS_SERVICES_BACKUP = Path("/tmp/praesidium_bpfilter_alias_services_before_destructive_test.json")


def _backup() -> None:
    # ES: Guarda los tres candidates tocados por esta batería.
    # EN: Save the three candidates touched by this suite.
    shutil.copy2(BPFILTER, BPFILTER_BACKUP)
    shutil.copy2(ALIAS_IP, ALIAS_IP_BACKUP)
    shutil.copy2(ALIAS_SERVICES, ALIAS_SERVICES_BACKUP)


def _restore(ctx) -> None:
    # ES: Restaura candidate para que la batería no deje reglas/alias temporales.
    # EN: Restore candidate so the suite leaves no temporary rules/aliases.
    shutil.copy2(BPFILTER_BACKUP, BPFILTER)
    shutil.copy2(ALIAS_IP_BACKUP, ALIAS_IP)
    shutil.copy2(ALIAS_SERVICES_BACKUP, ALIAS_SERVICES)
    for path in (BPFILTER, ALIAS_IP, ALIAS_SERVICES):
        path.chmod(0o664)
    ctx.log("RESTORE bpfilter/alias candidates applied")


def _detail(payload: Any) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        return json.dumps(detail, ensure_ascii=False, sort_keys=True) if isinstance(detail, dict) else str(detail)
    return str(payload)


def _expect_role(ctx, status: int, admin_expected: int, viewer_expected: int, label: str) -> None:
    expected = admin_expected if ctx.identity.role == "admin" else viewer_expected
    require(ctx, status == expected, f"{label} returned expected {expected}", f"{label} returned {status}, expected {expected}")


def _create_alias_fixtures(ctx) -> dict[str, Any]:
    # ES: Crea alias temporales IP/service y grupos para validar campos mixtos.
    # EN: Create temporary IP/service aliases and groups to validate mixed fields.
    status, ip_alias = call(ctx, "create bpfilter ip alias", "POST", "/api/v1/alias-ip/addresses", {"name": "tmp_bpf_ip", "content": ["10.250.0.1"]})
    require(ctx, status == 201, "ip alias created", f"ip alias create failed {status}: {_detail(ip_alias)}")
    ip_uuid = ip_alias.get("UUID")

    status, ip_group_literal = call(ctx, "create bpfilter literal ip group", "POST", "/api/v1/alias-ip/address-groups", {"name": "tmp_bpf_ip_group_lit", "content": ["10.250.1.0/24"]})
    require(ctx, status == 201, "literal ip group created", f"literal ip group create failed {status}: {_detail(ip_group_literal)}")

    status, ip_group_alias = call(ctx, "create bpfilter alias ip group", "POST", "/api/v1/alias-ip/address-groups", {"name": "tmp_bpf_ip_group_alias", "content": [ip_uuid]})
    require(ctx, status == 201, "alias ip group created", f"alias ip group create failed {status}: {_detail(ip_group_alias)}")

    status, service_alias = call(ctx, "create bpfilter service alias", "POST", "/api/v1/alias-services/services", {"name": "tmp_bpf_svc", "content": ["8443"]})
    require(ctx, status == 201, "service alias created", f"service alias create failed {status}: {_detail(service_alias)}")
    service_uuid = service_alias.get("UUID")

    status, service_group_literal = call(ctx, "create bpfilter literal service group", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_bpf_svc_group_lit", "content": ["9000-9002"]})
    require(ctx, status == 201, "literal service group created", f"literal service group create failed {status}: {_detail(service_group_literal)}")

    status, service_group_alias = call(ctx, "create bpfilter alias service group", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_bpf_svc_group_alias", "content": [service_uuid]})
    require(ctx, status == 201, "alias service group created", f"alias service group create failed {status}: {_detail(service_group_alias)}")

    return {
        "ip_alias": ip_alias,
        "ip_group": ip_group_literal,
        "ip_group_literal": ip_group_literal,
        "ip_group_alias": ip_group_alias,
        "service_alias": service_alias,
        "service_group": service_group_literal,
        "service_group_literal": service_group_literal,
        "service_group_alias": service_group_alias,
    }


def _valid_rule(fixtures: dict[str, Any]) -> dict[str, Any]:
    # ES: Regla con IPs/puertos literales, alias simples, grupos y objetos completos.
    # EN: Rule with literal IPs/ports, simple aliases, groups and full objects.
    return {
        "interface": "ens19",
        "action": "DROP",
        "enable": "true",
        "name": "tmp_bpf_rule",
        "l3_protocol": "IPv4",
        "l4_protocol": "TCP",
        "source": ["10.10.10.10", fixtures["ip_alias"].get("UUID"), fixtures["ip_group_alias"]],
        "destination": ["8.8.8.8", fixtures["ip_group_literal"].get("UUID")],
        "sport": ["443", fixtures["service_alias"].get("UUID"), fixtures["service_group_alias"]],
        "dport": ["80", "8080-8081", fixtures["service_group_literal"].get("UUID")],
        "position": "1",
    }


def _matrix_rule(fixtures: dict[str, Any], field: str, value: Any, name: str) -> dict[str, Any]:
    # ES: Construye una regla mínima para probar una combinación concreta de campo mixto.
    # EN: Build a minimal rule to test one concrete mixed-field combination.
    rule = {
        "interface": "ens19",
        "action": "DROP",
        "enable": "true",
        "name": name[:29],
        "l3_protocol": "IPv4",
        "l4_protocol": "TCP",
        "source": "10.100.0.1",
        "destination": "10.100.0.2",
        "sport": "1234",
        "dport": "4321",
        "position": "1",
    }
    rule[field] = value
    return rule


def _create_and_delete_matrix_rule(ctx, fixtures: dict[str, Any], field: str, label: str, value: Any) -> None:
    # ES: Crea y borra la regla para probar que la combinación se acepta y no deja basura.
    # EN: Create and delete the rule to prove the combination is accepted and leaves no junk.
    safe_label = label.replace(" ", "_").replace("-", "_")
    rule = _matrix_rule(fixtures, field, value, f"tmp_bpf_{field}_{safe_label}")
    status, created = call(ctx, f"matrix {field} {label}", "POST", "/api/v1/bpfilter/xdp", {"rule": rule})
    require(ctx, status == 200 and created.get("success") is True, f"matrix {field} {label} accepted", f"matrix {field} {label} failed {status}: {_detail(created)}")
    rule_id = str(created.get("id"))
    status, deleted = call(ctx, f"delete matrix {field} {label}", "DELETE", f"/api/v1/bpfilter/xdp/{rule_id}")
    require(ctx, status == 200 and deleted.get("action") == "delete", f"matrix {field} {label} deleted", f"matrix {field} {label} delete failed {status}: {_detail(deleted)}")


def _exercise_ip_matrix(ctx, fixtures: dict[str, Any]) -> None:
    # ES: Matriz completa exigida para campos IP source/destination.
    # EN: Full required matrix for source/destination IP fields.
    alias_uuid = fixtures["ip_alias"].get("UUID")
    group_literal_uuid = fixtures["ip_group_literal"].get("UUID")
    group_alias_uuid = fixtures["ip_group_alias"].get("UUID")
    cases = [
        ("01_hardcoded_ip", "10.110.0.1"),
        ("02_alias_addr", alias_uuid),
        ("03_alias_addr_group", group_literal_uuid),
        ("04_ip_plus_alias_addr", ["10.110.0.2", alias_uuid]),
        ("05_ip_plus_alias_addr_group", ["10.110.0.3", group_literal_uuid]),
        ("06_ip_plus_alias_addr_plus_group", ["10.110.0.4", alias_uuid, group_literal_uuid]),
        ("07_alias_addr_group_with_alias_addr", group_alias_uuid),
    ]
    for field in ("source", "destination"):
        for label, value in cases:
            _create_and_delete_matrix_rule(ctx, fixtures, field, label, value)


def _exercise_service_matrix(ctx, fixtures: dict[str, Any]) -> None:
    # ES: Matriz completa exigida para campos puerto sport/dport.
    # EN: Full required matrix for sport/dport service fields.
    alias_uuid = fixtures["service_alias"].get("UUID")
    group_literal_uuid = fixtures["service_group_literal"].get("UUID")
    group_alias_uuid = fixtures["service_group_alias"].get("UUID")
    cases = [
        ("01_hardcoded_port_or_range", "443"),
        ("01b_hardcoded_range", "8080-8081"),
        ("02_alias_service", alias_uuid),
        ("03_alias_service_group", group_literal_uuid),
        ("04_port_or_range_plus_alias_service", ["8444", alias_uuid]),
        ("05_port_or_range_plus_alias_service_group", ["8445", group_literal_uuid]),
        ("06_port_or_range_plus_alias_service_plus_group", ["8446", alias_uuid, group_literal_uuid]),
        ("07_alias_service_group_with_alias_service", group_alias_uuid),
    ]
    for field in ("sport", "dport"):
        for label, value in cases:
            _create_and_delete_matrix_rule(ctx, fixtures, field, label, value)


def run(ctx) -> None:
    ctx.log("=== BPFILTER DESTRUCTIVE ===")
    _backup()
    try:
        status, payload = call(ctx, "viewer/admin create contract", "POST", "/api/v1/bpfilter/xdp", {"rule": {"interface": "ens19", "action": "DROP", "enable": "true", "l3_protocol": "IPv4", "l4_protocol": "TCP", "destination": "8.8.8.8"}})
        _expect_role(ctx, status, 200, 403, "bpfilter create contract")
        if ctx.identity.role != "admin":
            return

        _restore(ctx)
        fixtures = _create_alias_fixtures(ctx)

        status, created = call(ctx, "create mixed alias bpfilter rule", "POST", "/api/v1/bpfilter/xdp", {"rule": _valid_rule(fixtures)})
        require(ctx, status == 200 and created.get("success") is True, "mixed alias bpfilter rule created", f"mixed alias rule failed {status}: {_detail(created)}")
        rule_id = str(created.get("id"))

        status, listed = call(ctx, "list xdp after create", "GET", "/api/v1/bpfilter/xdp")
        require(ctx, status == 200 and any(str(rule.get("id")) == rule_id for rule in listed.get("rules", [])), "created rule appears in hook list", "created rule missing from hook list")

        _exercise_ip_matrix(ctx, fixtures)
        _exercise_service_matrix(ctx, fixtures)

        invalid_cases = [
            ("invalid source literal", {"source": "999.999.999.999"}, 422),
            ("invalid destination alias", {"destination": "aliasad-missing"}, 422),
            ("invalid sport literal", {"sport": "70000"}, 422),
            ("invalid dport alias", {"dport": "aliaser-missing"}, 422),
            ("wrong IP object name", {"source": {"UUID": fixtures["ip_alias"].get("UUID"), "name": "wrong-name"}}, 422),
            ("wrong service object name", {"dport": {"UUID": fixtures["service_alias"].get("UUID"), "name": "wrong-name"}}, 422),
        ]
        for label, override, expected_status in invalid_cases:
            body = _valid_rule(fixtures)
            body.update(override)
            status, payload = call(ctx, label, "POST", "/api/v1/bpfilter/xdp", {"rule": body})
            require(ctx, status == expected_status, f"{label} rejected with {expected_status}", f"{label} returned {status}: {_detail(payload)}")

        patch_body = _valid_rule(fixtures)
        patch_body["enable"] = "false"
        status, patched = call(ctx, "patch mixed alias bpfilter rule", "PATCH", f"/api/v1/bpfilter/xdp/{rule_id}", {"rule": patch_body})
        require(ctx, status == 200 and patched.get("id") == rule_id, "mixed alias bpfilter rule patched", f"patch mixed alias rule failed {status}: {_detail(patched)}")

        status, deleted = call(ctx, "delete mixed alias bpfilter rule", "DELETE", f"/api/v1/bpfilter/xdp/{rule_id}")
        require(ctx, status == 200 and deleted.get("action") == "delete", "mixed alias bpfilter rule deleted", f"delete mixed alias rule failed {status}: {_detail(deleted)}")
    finally:
        _restore(ctx)
