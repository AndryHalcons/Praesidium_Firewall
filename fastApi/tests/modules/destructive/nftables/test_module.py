"""Tests destructivos del módulo nftables FastAPI."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from common.runner import call, require

NFTABLES = Path("/var/lib/praesidium/candidate/rules_nftables_human_viewer.json")
TABLES_CHAINS = Path("/var/lib/praesidium/candidate/nftables_tables_chains.json")
ALIAS_IP = Path("/var/lib/praesidium/candidate/alias_ip.json")
ALIAS_SERVICES = Path("/var/lib/praesidium/candidate/alias_services.json")
NFTABLES_BACKUP = Path("/tmp/praesidium_nftables_before_destructive_test.json")
TABLES_CHAINS_BACKUP = Path("/tmp/praesidium_nftables_tables_chains_before_destructive_test.json")
ALIAS_IP_BACKUP = Path("/tmp/praesidium_nftables_alias_ip_before_destructive_test.json")
ALIAS_SERVICES_BACKUP = Path("/tmp/praesidium_nftables_alias_services_before_destructive_test.json")


def _backup() -> None:
    # ES: Guarda los candidates tocados por esta batería.
    # EN: Save candidates touched by this suite.
    shutil.copy2(NFTABLES, NFTABLES_BACKUP)
    shutil.copy2(TABLES_CHAINS, TABLES_CHAINS_BACKUP)
    shutil.copy2(ALIAS_IP, ALIAS_IP_BACKUP)
    shutil.copy2(ALIAS_SERVICES, ALIAS_SERVICES_BACKUP)


def _restore(ctx) -> None:
    # ES: Restaura candidate para no dejar reglas ni alias temporales.
    # EN: Restore candidate to leave no temporary rules or aliases.
    shutil.copy2(NFTABLES_BACKUP, NFTABLES)
    shutil.copy2(TABLES_CHAINS_BACKUP, TABLES_CHAINS)
    shutil.copy2(ALIAS_IP_BACKUP, ALIAS_IP)
    shutil.copy2(ALIAS_SERVICES_BACKUP, ALIAS_SERVICES)
    for path in (NFTABLES, TABLES_CHAINS, ALIAS_IP, ALIAS_SERVICES):
        path.chmod(0o664)
    ctx.log("RESTORE nftables/alias candidates applied")


def _detail(payload: Any) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        return json.dumps(detail, ensure_ascii=False, sort_keys=True) if isinstance(detail, dict) else str(detail)
    return str(payload)


def _expect_role(ctx, status: int, admin_expected: int, viewer_expected: int, label: str) -> None:
    expected = admin_expected if ctx.identity.role == "admin" else viewer_expected
    require(ctx, status == expected, f"{label} returned expected {expected}", f"{label} returned {status}, expected {expected}")


def _negative_label(label: str, expected_status: int) -> str:
    return f"negative-{label}" if expected_status >= 400 and not label.startswith("negative-") else label


def _expect_status(ctx, label: str, method: str, path: str, body: Any | None, expected: int) -> Any:
    # ES: Ejecuta un caso negativo/positivo puntual y valida código HTTP exacto.
    # EN: Execute one focused negative/positive case and validate exact HTTP status.
    label = _negative_label(label, expected)
    status, payload = call(ctx, label, method, path, body)
    require(ctx, status == expected, f"{label} returned {expected}", f"{label} returned {status}, expected {expected}: {_detail(payload)}")
    return payload


CHAIN_ROUTES = {
    "forwarding": ("filter", "FORWARDING"),
    "input": ("filter", "input"),
    "output": ("filter", "output"),
    "prerouting": ("nat", "PREROUTING"),
    "postrouting": ("nat", "POSTROUTING"),
}


def _route(chain: str) -> str:
    # ES: Convierte token de prueba a ruta table/chain real.
    # EN: Convert test token to real table/chain route.
    table_name, chain_name = CHAIN_ROUTES[chain]
    return f"/api/v1/nftables/{table_name}/{chain_name}"



def _exercise_table_chain_crud(ctx) -> None:
    # ES: Prueba CRUD real sobre nftables_tables_chains.json con restore final.
    # EN: Exercise real CRUD on nftables_tables_chains.json with final restore.
    status, payload = call(ctx, "negative-create table non inet rejected", "POST", "/api/v1/nftables/tables", {"table": {"name": "tmp_nft_bad_family", "family": "ip"}})
    require(ctx, status == 422, "non-inet table rejected", f"non-inet table returned {status}: {_detail(payload)}")

    _expect_status(ctx, "create table payload malformed", "POST", "/api/v1/nftables/tables", {"table": "not-a-dict"}, 422)
    _expect_status(ctx, "create table missing name", "POST", "/api/v1/nftables/tables", {"table": {"family": "inet"}}, 422)
    _expect_status(ctx, "create table invalid name", "POST", "/api/v1/nftables/tables", {"table": {"name": "bad name", "family": "inet"}}, 422)
    _expect_status(ctx, "create table invalid handle text", "POST", "/api/v1/nftables/tables", {"table": {"name": "tmp_nft_bad_handle", "family": "inet", "handle": "x"}}, 422)
    _expect_status(ctx, "create table invalid handle zero", "POST", "/api/v1/nftables/tables", {"table": {"name": "tmp_nft_bad_handle_zero", "family": "inet", "handle": 0}}, 422)
    _expect_status(ctx, "delete missing table", "DELETE", "/api/v1/nftables/tables/notreal", None, 404)

    status, payload = call(ctx, "create tmp table", "POST", "/api/v1/nftables/tables", {"table": {"name": "tmp_nft_table", "family": "inet"}})
    require(ctx, status == 200 and payload.get("table") == "tmp_nft_table", "table created", f"table create failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "get tmp table", "GET", "/api/v1/nftables/tables/tmp_nft_table")
    require(ctx, status == 200 and payload.get("table", {}).get("family") == "inet", "table read after create", f"table read failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-duplicate table rejected", "POST", "/api/v1/nftables/tables", {"table": {"name": "tmp_nft_table", "family": "inet"}})
    require(ctx, status == 409, "duplicate table rejected", f"duplicate table returned {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-table patch not allowed", "PATCH", "/api/v1/nftables/tables/tmp_nft_table", {"table": {"handle": 90}})
    require(ctx, status == 405, "table patch endpoint not allowed", f"table patch returned {status}: {_detail(payload)}")

    _expect_status(ctx, "create chain payload malformed", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": "not-a-dict"}, 422)
    _expect_status(ctx, "create chain missing name", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"family": "inet"}}, 422)
    _expect_status(ctx, "create chain invalid name", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"name": "bad name", "family": "inet"}}, 422)
    _expect_status(ctx, "create chain non inet", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"name": "TMP_NFT_BAD_FAMILY", "family": "ip"}}, 422)
    _expect_status(ctx, "create chain invalid handle", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"name": "TMP_NFT_BAD_HANDLE", "handle": "x"}}, 422)
    _expect_status(ctx, "create chain invalid type", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"name": "TMP_NFT_BAD_TYPE", "type": "bad"}}, 422)
    _expect_status(ctx, "create chain invalid hook", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"name": "TMP_NFT_BAD_HOOK", "hook": "bad"}}, 422)
    _expect_status(ctx, "create chain invalid policy", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"name": "TMP_NFT_BAD_POLICY", "policy": "queue"}}, 422)
    _expect_status(ctx, "create chain invalid prio", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"name": "TMP_NFT_BAD_PRIO", "prio": "x"}}, 422)
    _expect_status(ctx, "delete missing chain", "DELETE", "/api/v1/nftables/tables/tmp_nft_table/chains/notreal", None, 404)

    status, payload = call(ctx, "create tmp chain", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"name": "TMP_NFT_CHAIN", "family": "inet", "type": "filter", "hook": "", "prio": 0, "policy": "accept"}})
    require(ctx, status == 200 and payload.get("chain") == "TMP_NFT_CHAIN", "chain created", f"chain create failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "get tmp chain", "GET", "/api/v1/nftables/tables/tmp_nft_table/chains/TMP_NFT_CHAIN")
    require(ctx, status == 200 and payload.get("chain", {}).get("family") == "inet", "chain read after create", f"chain read failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-duplicate chain rejected", "POST", "/api/v1/nftables/tables/tmp_nft_table/chains", {"chain": {"name": "TMP_NFT_CHAIN", "family": "inet"}})
    require(ctx, status == 409, "duplicate chain rejected", f"duplicate chain returned {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-table delete blocked with chain", "DELETE", "/api/v1/nftables/tables/tmp_nft_table")
    require(ctx, status == 409, "table delete blocked when chains exist", f"table delete with chain returned {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-chain patch not allowed", "PATCH", "/api/v1/nftables/tables/tmp_nft_table/chains/TMP_NFT_CHAIN", {"chain": {"policy": "drop"}})
    require(ctx, status == 405, "chain patch endpoint not allowed", f"chain patch returned {status}: {_detail(payload)}")

    status, payload = call(ctx, "create rule in tmp chain", "POST", "/api/v1/nftables/tmp_nft_table/TMP_NFT_CHAIN", {"rule": {"action": "accept", "enable": "true", "ip.protocol": "tcp", "dport": "443", "dport.op": "==", "name": "tmp_nft_chain_rule"}})
    require(ctx, status == 200, "rule can use created table/chain", f"rule on created chain failed {status}: {_detail(payload)}")
    rule_id = str(payload.get("id"))

    status, payload = call(ctx, "negative-chain delete blocked with rule", "DELETE", "/api/v1/nftables/tables/tmp_nft_table/chains/TMP_NFT_CHAIN")
    require(ctx, status == 409, "chain delete blocked when rules exist", f"chain delete with rule returned {status}: {_detail(payload)}")

    status, payload = call(ctx, "delete tmp rule", "DELETE", f"/api/v1/nftables/tmp_nft_table/TMP_NFT_CHAIN/{rule_id}")
    require(ctx, status == 200, "temporary table-chain rule deleted", f"tmp rule delete failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "delete tmp chain", "DELETE", "/api/v1/nftables/tables/tmp_nft_table/chains/TMP_NFT_CHAIN")
    require(ctx, status == 200, "chain deleted", f"chain delete failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "delete tmp table", "DELETE", "/api/v1/nftables/tables/tmp_nft_table")
    require(ctx, status == 200, "table deleted", f"table delete failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "create chain missing table", "POST", "/api/v1/nftables/tables/notreal/chains", {"chain": {"name": "TMP_NFT_FAIL"}})
    require(ctx, status == 404, "chain create missing table rejected", f"chain missing table returned {status}: {_detail(payload)}")


def _create_alias_fixtures(ctx) -> dict[str, Any]:
    # ES: Crea alias temporales IP/service y grupos para campos mixtos nftables.
    # EN: Create temporary IP/service aliases and groups for nftables mixed fields.
    status, ip_alias = call(ctx, "create nft ip alias", "POST", "/api/v1/alias-ip/addresses", {"name": "tmp_nft_ip", "content": ["10.251.0.1"]})
    require(ctx, status == 201, "nft ip alias created", f"nft ip alias create failed {status}: {_detail(ip_alias)}")
    ip_uuid = ip_alias.get("UUID")
    status, ip_group_literal = call(ctx, "create nft literal ip group", "POST", "/api/v1/alias-ip/address-groups", {"name": "tmp_nft_ip_group_lit", "content": ["10.251.1.0/24"]})
    require(ctx, status == 201, "nft literal ip group created", f"nft literal ip group create failed {status}: {_detail(ip_group_literal)}")
    status, ip_group_alias = call(ctx, "create nft alias ip group", "POST", "/api/v1/alias-ip/address-groups", {"name": "tmp_nft_ip_group_alias", "content": [ip_uuid]})
    require(ctx, status == 201, "nft alias ip group created", f"nft alias ip group create failed {status}: {_detail(ip_group_alias)}")

    status, service_alias = call(ctx, "create nft service alias", "POST", "/api/v1/alias-services/services", {"name": "tmp_nft_svc", "content": ["8443"]})
    require(ctx, status == 201, "nft service alias created", f"nft service alias create failed {status}: {_detail(service_alias)}")
    service_uuid = service_alias.get("UUID")
    status, service_group_literal = call(ctx, "create nft literal service group", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_nft_svc_group_lit", "content": ["9000-9002"]})
    require(ctx, status == 201, "nft literal service group created", f"nft literal service group create failed {status}: {_detail(service_group_literal)}")
    status, service_group_alias = call(ctx, "create nft alias service group", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_nft_svc_group_alias", "content": [service_uuid]})
    require(ctx, status == 201, "nft alias service group created", f"nft alias service group create failed {status}: {_detail(service_group_alias)}")

    return {
        "ip_alias": ip_alias,
        "ip_group_literal": ip_group_literal,
        "ip_group_alias": ip_group_alias,
        "service_alias": service_alias,
        "service_group_literal": service_group_literal,
        "service_group_alias": service_group_alias,
    }


def _base_rule(chain: str, name: str) -> dict[str, Any]:
    # ES: Construye regla mínima válida según tipo de cadena.
    # EN: Build a minimal valid rule depending on chain type.
    common = {"enable": "true", "name": name[:29], "ip.protocol": "tcp", "position": "1", "log": "false"}
    if chain in ("forwarding", "input", "output"):
        common.update({"action": "accept", "dport": "443", "dport.op": "=="})
    elif chain == "prerouting":
        common.update({"dnat.addr": "10.50.0.10", "dnat.port": "443"})
    elif chain == "postrouting":
        common.update({"masquerade": "true"})
    return common


def _create_and_delete(ctx, chain: str, rule: dict[str, Any], label: str, expected_status: int = 200) -> str:
    # ES: Crea y borra una regla si se espera éxito.
    # EN: Create and delete a rule when success is expected.
    label = _negative_label(label, expected_status)
    status, created = call(ctx, label, "POST", f"{_route(chain)}", {"rule": rule})
    require(ctx, status == expected_status, f"{label} returned {expected_status}", f"{label} returned {status}: {_detail(created)}")
    if expected_status != 200:
        return ""
    rule_id = str(created.get("id"))
    status, listed = call(ctx, f"list after {label}", "GET", f"{_route(chain)}")
    require(ctx, status == 200 and any(str(rule.get("id")) == rule_id for rule in listed.get("rules", [])), f"{label} appears in list", f"{label} missing from list")
    status, deleted = call(ctx, f"delete {label}", "DELETE", f"{_route(chain)}/{rule_id}")
    require(ctx, status == 200 and deleted.get("action") == "delete", f"{label} deleted", f"{label} delete failed {status}: {_detail(deleted)}")
    return rule_id


def _matrix_rule(chain: str, field: str, value: Any, name: str) -> dict[str, Any]:
    rule = _base_rule(chain, name)
    rule[field] = value
    if chain == "prerouting" and field == "redirect":
        rule.pop("dnat.addr", None)
        rule.pop("dnat.port", None)
    if chain == "postrouting" and field == "snat.addr":
        rule["masquerade"] = "false"
    return rule


def _exercise_ip_matrix(ctx, fixtures: dict[str, Any]) -> None:
    alias_uuid = fixtures["ip_alias"].get("UUID")
    group_literal_uuid = fixtures["ip_group_literal"].get("UUID")
    group_alias_uuid = fixtures["ip_group_alias"].get("UUID")
    cases = [
        ("01_hardcoded_ip", "10.120.0.1"),
        ("02_alias_addr", alias_uuid),
        ("03_alias_addr_group", group_literal_uuid),
        ("04_ip_plus_alias_addr", ["10.120.0.2", alias_uuid]),
        ("05_ip_plus_alias_addr_group", ["10.120.0.3", group_literal_uuid]),
        ("06_ip_plus_alias_addr_plus_group", ["10.120.0.4", alias_uuid, group_literal_uuid]),
        ("07_alias_addr_group_with_alias_addr", group_alias_uuid),
    ]
    field_context = {
        "ip.saddr": "forwarding",
        "ip.daddr": "forwarding",
        "dnat.addr": "prerouting",
        "snat.addr": "postrouting",
    }
    for field, chain in field_context.items():
        for label, value in cases:
            _create_and_delete(ctx, chain, _matrix_rule(chain, field, value, f"tmp_nft_{field}_{label}"), f"matrix {field} {label}")


def _exercise_service_matrix(ctx, fixtures: dict[str, Any]) -> None:
    alias_uuid = fixtures["service_alias"].get("UUID")
    group_literal_uuid = fixtures["service_group_literal"].get("UUID")
    group_alias_uuid = fixtures["service_group_alias"].get("UUID")
    cases = [
        ("01_hardcoded_port", "443"),
        ("01b_hardcoded_range", "8080-8081"),
        ("02_alias_service", alias_uuid),
        ("03_alias_service_group", group_literal_uuid),
        ("04_port_plus_alias_service", ["8444", alias_uuid]),
        ("05_port_plus_alias_service_group", ["8445", group_literal_uuid]),
        ("06_port_plus_alias_service_plus_group", ["8446", alias_uuid, group_literal_uuid]),
        ("07_alias_service_group_with_alias_service", group_alias_uuid),
    ]
    field_context = {
        "sport": "forwarding",
        "dport": "forwarding",
        "dnat.port": "prerouting",
        "redirect": "prerouting",
    }
    for field, chain in field_context.items():
        for label, value in cases:
            _create_and_delete(ctx, chain, _matrix_rule(chain, field, value, f"tmp_nft_{field}_{label}"), f"matrix {field} {label}")


def run(ctx) -> None:
    ctx.log("=== NFTABLES DESTRUCTIVE ===")
    _backup()
    try:
        status, payload = call(ctx, "viewer/admin create contract", "POST", "/api/v1/nftables/filter/FORWARDING", {"rule": _base_rule("forwarding", "tmp_nft_contract")})
        _expect_role(ctx, status, 200, 403, "nftables create contract")
        if ctx.identity.role != "admin":
            return

        _restore(ctx)
        fixtures = _create_alias_fixtures(ctx)

        for chain in ("forwarding", "input", "output", "prerouting", "postrouting"):
            _create_and_delete(ctx, chain, _base_rule(chain, f"tmp_nft_{chain}"), f"create basic {chain}")

        status, payload = call(ctx, "negative-invalid table chain", "POST", "/api/v1/nftables/filter/PREROUTING", {"rule": _base_rule("prerouting", "tmp_nft_bad_chain")})
        require(ctx, status == 404, "invalid table/chain rejected", f"invalid table/chain returned {status}: {_detail(payload)}")

        _expect_status(ctx, "post malformed rule payload", "POST", "/api/v1/nftables/filter/FORWARDING", {"rule": "not-a-dict"}, 422)
        _expect_status(ctx, "patch malformed rule payload", "PATCH", "/api/v1/nftables/filter/FORWARDING/5", {"rule": "not-a-dict"}, 422)
        _expect_status(ctx, "delete invalid rule id text", "DELETE", "/api/v1/nftables/filter/FORWARDING/notanid", None, 422)
        _expect_status(ctx, "delete invalid rule id zero", "DELETE", "/api/v1/nftables/filter/FORWARDING/0", None, 422)
        _expect_status(ctx, "delete missing rule", "DELETE", "/api/v1/nftables/filter/FORWARDING/999999", None, 404)
        _expect_status(ctx, "patch invalid rule id text", "PATCH", "/api/v1/nftables/filter/FORWARDING/notanid", {"rule": _base_rule("forwarding", "tmp_nft_patch_bad_id")}, 422)
        _expect_status(ctx, "patch missing rule", "PATCH", "/api/v1/nftables/filter/FORWARDING/999999", {"rule": _base_rule("forwarding", "tmp_nft_patch_missing")}, 404)

        _exercise_ip_matrix(ctx, fixtures)
        _exercise_service_matrix(ctx, fixtures)

        invalid_cases = [
            ("invalid interface iif", "forwarding", {**_base_rule("forwarding", "tmp_nft_bad_iif"), "meta.iifname": "no_such_iface"}, 422),
            ("invalid action", "forwarding", {**_base_rule("forwarding", "tmp_nft_bad_action"), "action": "allow"}, 422),
            ("invalid ip literal", "forwarding", {**_base_rule("forwarding", "tmp_nft_bad_ip"), "ip.saddr": "999.999.999.999"}, 422),
            ("invalid port literal", "forwarding", {**_base_rule("forwarding", "tmp_nft_bad_port"), "dport": "70000"}, 422),
            ("udp with ct state", "forwarding", {**_base_rule("forwarding", "tmp_nft_udp_ct"), "ip.protocol": "udp", "ct.state": "new"}, 422),
            ("nat without target", "prerouting", {"enable": "true", "name": "tmp_nft_nat_empty", "ip.protocol": "tcp"}, 422),
            ("redirect with dnat", "prerouting", {**_base_rule("prerouting", "tmp_nft_redirect_dnat"), "redirect": "8443"}, 422),
            ("masquerade with snat", "postrouting", {**_base_rule("postrouting", "tmp_nft_masq_snat"), "snat.addr": "10.1.1.1"}, 200),
            ("invalid enable checkbox", "forwarding", {**_base_rule("forwarding", "tmp_nft_bad_enable"), "enable": "maybe"}, 422),
            ("invalid log checkbox", "forwarding", {**_base_rule("forwarding", "tmp_nft_bad_log"), "log": "maybe"}, 422),
            ("invalid dport op checkbox", "forwarding", {**_base_rule("forwarding", "tmp_nft_bad_dport_op"), "dport.op": "bad"}, 422),
            ("invalid ct state select", "forwarding", {**_base_rule("forwarding", "tmp_nft_bad_ct"), "ct.state": "invalid"}, 422),
            ("saddr op without saddr", "forwarding", {**_base_rule("forwarding", "tmp_nft_saddr_op"), "ip.saddr.op": "!="}, 422),
            ("daddr op without daddr", "forwarding", {**_base_rule("forwarding", "tmp_nft_daddr_op"), "ip.daddr.op": "!="}, 422),
            ("sport op without sport", "forwarding", {**_base_rule("forwarding", "tmp_nft_sport_op"), "sport.op": "=="}, 422),
            ("dport op without dport", "forwarding", {**_base_rule("forwarding", "tmp_nft_dport_op"), "dport": "", "dport.op": "=="}, 422),
            ("snat dnat conflict", "postrouting", {**_base_rule("postrouting", "tmp_nft_snat_dnat"), "masquerade": "false", "snat.addr": "10.1.1.1", "dnat.addr": "10.2.2.2"}, 422),
            ("mixed ipv4 ipv6", "forwarding", {**_base_rule("forwarding", "tmp_nft_mixed_ip"), "ip.saddr": ["10.1.1.1", "2001:db8::1"]}, 422),
            ("tcp udp with ct state", "forwarding", {**_base_rule("forwarding", "tmp_nft_tcp_udp_ct"), "ip.protocol": "tcp, udp", "ct.state": "new"}, 422),
        ]
        for label, chain, rule, expected in invalid_cases:
            _create_and_delete(ctx, chain, rule, label, expected)

        icmp_rule = {"action": "accept", "enable": "true", "name": "tmp_nft_icmp_clear", "ip.protocol": "icmp", "dport": "443", "sport": "1234", "dport.op": "==", "sport.op": "=="}
        status, created = call(ctx, "icmp clears ports", "POST", "/api/v1/nftables/filter/FORWARDING", {"rule": icmp_rule})
        require(ctx, status == 200, f"icmp rule accepted after clearing ports", f"icmp rule failed {status}: {_detail(created)}")
        rule_id = str(created.get("id"))
        status, listed = call(ctx, "list icmp cleared rule", "GET", "/api/v1/nftables/filter/FORWARDING")
        found = next((rule for rule in listed.get("rules", []) if str(rule.get("id")) == rule_id), {})
        require(ctx, found.get("dport") == "" and found.get("sport") == "" and found.get("dport.op") == "" and found.get("sport.op") == "", "icmp ports cleared before save", f"icmp ports not cleared {found}")
    finally:
        _restore(ctx)
