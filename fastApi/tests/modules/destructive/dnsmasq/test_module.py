"""Tests destructivos de dnsmasq/DHCP. / Destructive dnsmasq/DHCP tests."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from common.runner import call, require

BASE = "/api/v1/dnsmasq"
DHCP = Path("/var/lib/praesidium/candidate/dhcp.json")
ALIAS_IP = Path("/var/lib/praesidium/candidate/alias_ip.json")
INTERFACES = Path("/var/lib/praesidium/candidate/interfaces.json")
DHCP_BACKUP = Path("/tmp/praesidium_dnsmasq_dhcp_before_destructive_test.json")
ALIAS_BACKUP = Path("/tmp/praesidium_dnsmasq_alias_ip_before_destructive_test.json")

ALIAS_FIXTURES = {
    "gateway": ("aliasad-901-19700101000000000-0001", "tmp_dnsmasq_gateway", "10.250.0.1"),
    "range_start": ("aliasad-902-19700101000000000-0002", "tmp_dnsmasq_range_start", "10.250.0.50"),
    "range_end": ("aliasad-903-19700101000000000-0003", "tmp_dnsmasq_range_end", "10.250.0.60"),
    "dns_primary": ("aliasad-904-19700101000000000-0004", "tmp_dnsmasq_dns_primary", "1.1.1.1"),
    "ntp_server": ("aliasad-905-19700101000000000-0005", "tmp_dnsmasq_ntp", "10.250.0.2"),
    "relay_local_ip": ("aliasad-906-19700101000000000-0006", "tmp_dnsmasq_relay_local", "192.168.250.1"),
    "relay_dest_server": ("aliasad-907-19700101000000000-0007", "tmp_dnsmasq_relay_dest", "192.168.250.2"),
    "reservation_ip": ("aliasad-908-19700101000000000-0008", "tmp_dnsmasq_reservation_ip", "10.250.0.10"),
}
GROUP_UUID = "aliagroup-901-19700101000000000-0009"


def _backup() -> None:
    shutil.copy2(DHCP, DHCP_BACKUP)
    shutil.copy2(ALIAS_IP, ALIAS_BACKUP)


def _restore(ctx) -> None:
    shutil.copy2(DHCP_BACKUP, DHCP)
    shutil.copy2(ALIAS_BACKUP, ALIAS_IP)
    ctx.log("RESTORE dhcp.json and alias_ip.json applied")


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=4), encoding="utf-8")
    path.chmod(0o664)


def _reset_dhcp() -> None:
    _write(DHCP, {"dhcp": [], "dhcp_reservation": []})


def _install_alias_fixtures() -> dict[str, dict[str, Any]]:
    data = _read(ALIAS_IP)
    data.setdefault("alias_address", {})
    data.setdefault("alias_addr_group", {})
    objects: dict[str, dict[str, Any]] = {}
    for idx, (key, (uuid, name, ip)) in enumerate(ALIAS_FIXTURES.items(), start=901):
        obj = {"id": idx, "UUID": uuid, "name": name, "content": [ip]}
        data["alias_address"][uuid] = obj
        objects[key] = dict(obj)
    data["alias_addr_group"][GROUP_UUID] = {"id": 901, "UUID": GROUP_UUID, "name": "tmp_dnsmasq_group", "content": [objects["gateway"]["UUID"], objects["range_start"]["UUID"]]}
    _write(ALIAS_IP, data)
    return objects


def _first_candidate_interface() -> str:
    data = _read(INTERFACES)
    network = data.get("network", {}) if isinstance(data, dict) else {}
    for section in ["ethernets", "bridges", "vlans", "wifis"]:
        block = network.get(section, {})
        if isinstance(block, dict) and block:
            return sorted(block.keys())[0]
    raise RuntimeError("no candidate interface in ethernets/bridges/vlans/wifis")


def _scope_server(interface: str, rule_id: str | None = None) -> dict[str, Any]:
    rule = {
        "name": f"scope-{rule_id or 'auto'}",
        "enable": "true",
        "mode": "server",
        "interface": interface,
        "range_start": "10.250.0.100",
        "range_end": "10.250.0.150",
        "lease_time": "12h",
        "gateway": "10.250.0.1",
        "netmask": "255.255.255.0",
        "dns_primary": "1.1.1.1",
        "dns_secondary": "8.8.8.8",
        "ntp_server": "10.250.0.2",
    }
    if rule_id is not None:
        rule["id"] = rule_id
    return rule


def _scope_server_alias(interface: str, aliases: dict[str, dict[str, Any]], rule_id: str | None = None) -> dict[str, Any]:
    rule = _scope_server(interface, rule_id)
    rule.update({
        "range_start": aliases["range_start"],
        "range_end": aliases["range_end"],
        "gateway": aliases["gateway"],
        "dns_primary": aliases["dns_primary"],
        "ntp_server": aliases["ntp_server"],
    })
    return rule


def _scope_relay(interface: str, aliases: dict[str, dict[str, Any]], rule_id: str | None = None) -> dict[str, Any]:
    rule = {
        "name": f"relay-{rule_id or 'auto'}",
        "enable": "true",
        "mode": "relay",
        "interface": interface,
        "relay_local_ip": aliases["relay_local_ip"],
        "relay_dest_server": aliases["relay_dest_server"],
    }
    if rule_id is not None:
        rule["id"] = rule_id
    return rule


def _reservation(interface: str, aliases: dict[str, dict[str, Any]], rule_id: str | None = None, mac: str = "02:AA:BB:CC:DD:10", hostname: str = "host10") -> dict[str, Any]:
    rule = {
        "name": f"reservation-{hostname}",
        "enable": "true",
        "interface": interface,
        "mac": mac,
        "ip": aliases["reservation_ip"],
        "hostname": hostname,
        "lease_time": "12h",
    }
    if rule_id is not None:
        rule["id"] = rule_id
    return rule


def _status_ok(status: int) -> bool:
    return 200 <= status <= 299


def _detail(payload) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code") or detail)
        return str(detail)
    return str(payload)


def _expect(ctx, label: str, method: str, path: str, body: dict[str, Any] | None, expected: int) -> Any:
    status, payload = call(ctx, label, method, path, body)
    require(ctx, status == expected, f"{label} returned {expected}", f"{label} returned {status}, expected {expected}: {_detail(payload)}")
    return payload


def _create_scope(ctx, rule: dict[str, Any], expected: int = 200) -> Any:
    return _expect(ctx, "create scope", "POST", f"{BASE}/scopes", {"rule": rule}, expected)


def _patch_scope(ctx, rule_id: str, rule: dict[str, Any], expected: int = 200) -> Any:
    return _expect(ctx, f"patch scope {rule_id}", "PATCH", f"{BASE}/scopes/{rule_id}", {"rule": rule}, expected)


def _delete_scope(ctx, rule_id: str, expected: int = 200) -> Any:
    return _expect(ctx, f"delete scope {rule_id}", "DELETE", f"{BASE}/scopes/{rule_id}", None, expected)


def _create_reservation(ctx, rule: dict[str, Any], expected: int = 200) -> Any:
    return _expect(ctx, "create reservation", "POST", f"{BASE}/reservations", {"rule": rule}, expected)


def _patch_reservation(ctx, rule_id: str, rule: dict[str, Any], expected: int = 200) -> Any:
    return _expect(ctx, f"patch reservation {rule_id}", "PATCH", f"{BASE}/reservations/{rule_id}", {"rule": rule}, expected)


def _delete_reservation(ctx, rule_id: str, expected: int = 200) -> Any:
    return _expect(ctx, f"delete reservation {rule_id}", "DELETE", f"{BASE}/reservations/{rule_id}", None, expected)


def _exercise_viewer_forbidden(ctx, interface: str, aliases: dict[str, dict[str, Any]]) -> None:
    for label, method, path, body in [
        ("viewer create scope", "POST", f"{BASE}/scopes", {"rule": _scope_server(interface)}),
        ("viewer patch scope", "PATCH", f"{BASE}/scopes/1", {"rule": _scope_server(interface, "1")}),
        ("viewer delete scope", "DELETE", f"{BASE}/scopes/1", None),
        ("viewer create reservation", "POST", f"{BASE}/reservations", {"rule": _reservation(interface, aliases)}),
        ("viewer patch reservation", "PATCH", f"{BASE}/reservations/1", {"rule": _reservation(interface, aliases, "1")}),
        ("viewer delete reservation", "DELETE", f"{BASE}/reservations/1", None),
    ]:
        _expect(ctx, f"negative-{label}", method, path, body, 403)


def _exercise_scope_negative_matrix(ctx, interface: str, aliases: dict[str, dict[str, Any]]) -> None:
    base = _scope_server(interface)
    group_obj = {"UUID": GROUP_UUID, "name": "tmp_dnsmasq_group", "content": [aliases["gateway"]["UUID"]]}
    bad_service_obj = {"UUID": "aliaser-901-19700101000000000-0001", "name": "tmp_service", "content": ["53"]}
    cases: list[tuple[str, dict[str, Any]]] = [
        ("payload not object", []),
        ("enable invalid", {**base, "enable": "banana"}),
        ("mode invalid", {**base, "mode": "both"}),
        ("interface missing", {k: v for k, v in base.items() if k != "interface"}),
        ("interface sys only lo", {**base, "interface": "lo"}),
        ("interface not candidate", {**base, "interface": "notreal0"}),
        ("server with relay local", {**base, "relay_local_ip": "192.168.1.2"}),
        ("server with relay dest", {**base, "relay_dest_server": "192.168.1.3"}),
        ("range start missing enabled", {**base, "range_start": ""}),
        ("range end missing enabled", {**base, "range_end": ""}),
        ("gateway missing enabled", {**base, "gateway": ""}),
        ("netmask missing enabled", {**base, "netmask": ""}),
        ("ipv6 range start", {**base, "range_start": "2001:db8::1"}),
        ("cidr range start", {**base, "range_start": "10.250.0.50/24"}),
        ("text gateway", {**base, "gateway": "not-an-ip"}),
        ("list gateway", {**base, "gateway": ["10.250.0.1", "10.250.0.2"]}),
        ("alias group gateway", {**base, "gateway": group_obj}),
        ("service object dns", {**base, "dns_primary": bad_service_obj}),
        ("zero ip", {**base, "gateway": "0.0.0.1"}),
        ("loopback ip", {**base, "gateway": "127.0.0.1"}),
        ("link local ip", {**base, "gateway": "169.254.1.1"}),
        ("multicast ip", {**base, "gateway": "224.0.0.1"}),
        ("reserved ip", {**base, "gateway": "240.0.0.1"}),
        ("broadcast ip", {**base, "gateway": "255.255.255.255"}),
        ("netmask not contiguous", {**base, "netmask": "255.0.255.0"}),
        ("netmask too small pool", {**base, "netmask": "255.255.255.254"}),
        ("range reversed", {**base, "range_start": "10.250.0.151", "range_end": "10.250.0.150"}),
        ("range outside network", {**base, "range_start": "10.251.0.10"}),
        ("gateway network address", {**base, "gateway": "10.250.0.0"}),
        ("gateway broadcast address", {**base, "gateway": "10.250.0.255"}),
        ("range start network address", {**base, "range_start": "10.250.0.0"}),
        ("range end broadcast address", {**base, "range_end": "10.250.0.255"}),
        ("gateway inside range", {**base, "gateway": "10.250.0.120"}),
        ("dns primary broadcast", {**base, "dns_primary": "10.250.0.255"}),
        ("lease zero", {**base, "lease_time": "0h"}),
        ("lease bad unit", {**base, "lease_time": "12x"}),
        ("relay with server range", {"name": "negative-relay", "enable": "true", "mode": "relay", "interface": interface, "relay_local_ip": "192.168.1.1", "relay_dest_server": "192.168.1.2", "range_start": "10.0.0.10"}),
        ("relay equal ips", {"name": "negative-relay", "enable": "true", "mode": "relay", "interface": interface, "relay_local_ip": "192.168.1.1", "relay_dest_server": "192.168.1.1"}),
        ("relay missing local", {"name": "negative-relay", "enable": "true", "mode": "relay", "interface": interface, "relay_dest_server": "192.168.1.2"}),
        ("relay missing dest", {"name": "negative-relay", "enable": "true", "mode": "relay", "interface": interface, "relay_local_ip": "192.168.1.1"}),
    ]
    for label, rule in cases:
        _expect(ctx, f"negative-scope {label}", "POST", f"{BASE}/scopes", {"rule": rule}, 422)


def _exercise_reservation_negative_matrix(ctx, interface: str, aliases: dict[str, dict[str, Any]]) -> None:
    base = _reservation(interface, aliases)
    group_obj = {"UUID": GROUP_UUID, "name": "tmp_dnsmasq_group", "content": [aliases["reservation_ip"]["UUID"]]}
    bad_cases: list[tuple[str, dict[str, Any]]] = [
        ("payload not object", []),
        ("enable invalid", {**base, "enable": "maybe"}),
        ("interface missing", {k: v for k, v in base.items() if k != "interface"}),
        ("interface sys only lo", {**base, "interface": "lo"}),
        ("interface not candidate", {**base, "interface": "notreal0"}),
        ("mac text", {**base, "mac": "not-a-mac"}),
        ("mac broadcast", {**base, "mac": "FF:FF:FF:FF:FF:FF"}),
        ("mac zero", {**base, "mac": "00:00:00:00:00:00"}),
        ("mac multicast", {**base, "mac": "03:11:22:33:44:55"}),
        ("ip invalid", {**base, "ip": "999.999.999.999"}),
        ("ip ipv6", {**base, "ip": "2001:db8::10"}),
        ("ip cidr", {**base, "ip": "10.250.0.10/24"}),
        ("ip list", {**base, "ip": ["10.250.0.10", "10.250.0.11"]}),
        ("ip alias group", {**base, "ip": group_obj}),
        ("hostname starts hyphen", {**base, "hostname": "-bad"}),
        ("hostname contains dot", {**base, "hostname": "host.example"}),
        ("hostname too long", {**base, "hostname": "a" * 64}),
        ("lease bad", {**base, "lease_time": "99z"}),
        ("ip outside active scope", {**base, "mac": "02:AA:BB:CC:DD:20", "ip": "10.251.0.10", "hostname": "outside"}),
        ("ip is gateway", {**base, "mac": "02:AA:BB:CC:DD:21", "ip": aliases["gateway"], "hostname": "gateway"}),
        ("ip network address", {**base, "mac": "02:AA:BB:CC:DD:22", "ip": "10.250.0.0", "hostname": "network"}),
        ("ip broadcast address", {**base, "mac": "02:AA:BB:CC:DD:23", "ip": "10.250.0.255", "hostname": "broadcast"}),
    ]
    for label, rule in bad_cases:
        _expect(ctx, f"negative-reservation {label}", "POST", f"{BASE}/reservations", {"rule": rule}, 422)


def _exercise_candidate_shape_errors(ctx) -> None:
    original = _read(DHCP)
    cases = [
        ("empty object", {}, 500),
        ("missing scopes", {"dhcp_reservation": []}, 500),
        ("scopes not list", {"dhcp": {}, "dhcp_reservation": []}, 500),
        ("reservations not list", {"dhcp": [], "dhcp_reservation": {}}, 500),
        ("scope entry no rule", {"dhcp": [{}], "dhcp_reservation": []}, 500),
        ("scope rule not object", {"dhcp": [{"rule": []}], "dhcp_reservation": []}, 500),
    ]
    for label, data, expected in cases:
        _write(DHCP, data)
        _expect(ctx, f"negative-candidate shape {label}", "GET", BASE, None, expected)
        _write(DHCP, original)


def run(ctx) -> None:
    ctx.log("=== DNSMASQ DESTRUCTIVE ===")
    _backup()
    try:
        aliases = _install_alias_fixtures()
        interface = _first_candidate_interface()
        ctx.log(f"CHECK using candidate interface={interface}")

        if ctx.identity.role != "admin":
            _exercise_viewer_forbidden(ctx, interface, aliases)
            return

        _reset_dhcp()
        status, payload = call(ctx, "list empty dnsmasq config", "GET", BASE)
        require(ctx, status == 200, "empty dnsmasq config readable", f"empty dnsmasq config failed {status}: {_detail(payload)}")

        # ES: Scope principal con Alias; candidate debe guardar UUID y API debe mostrar name.
        # EN: Main Alias-backed scope; candidate must store UUID and API must show name.
        scope_rule = _scope_server_alias(interface, aliases)
        for field in ("range_start", "range_end", "gateway", "dns_primary", "dns_secondary", "ntp_server"):
            scope_rule[field] = [scope_rule[field]]
        scope_rule["name"] = "scope-main"
        scope_rule["id"] = "999"
        scope_rule["UUID"] = "tampered-scope"
        created = _create_scope(ctx, scope_rule)
        scope_uuid = str(created.get("uuid"))
        data = _read(DHCP)
        stored_scope = data["dhcp"][0]["rule"]
        require(ctx, stored_scope.get("id") == "1", "scope uses smallest free id", f"scope id is {stored_scope.get('id')}")
        require(ctx, scope_uuid.startswith("scopes-1-"), "scope UUID uses scopes prefix and id", f"bad scope UUID {scope_uuid}")
        require(ctx, stored_scope.get("UUID") == scope_uuid, "scope UUID stored", "scope UUID mismatch")
        require(ctx, stored_scope.get("name") == "scope-main", "scope name stored", "scope name missing")
        for field in ("range_start", "range_end", "gateway", "dns_primary", "ntp_server"):
            require(ctx, stored_scope.get(field) == aliases[field]["UUID"], f"scope {field} stores Alias UUID", f"scope {field} did not store UUID")

        visible = _expect(ctx, "get scope by UUID", "GET", f"{BASE}/scopes/{scope_uuid}", None, 200)["rule"]
        require(ctx, visible.get("gateway") == aliases["gateway"]["name"], "scope API displays Alias name", "scope API did not display Alias name")
        _expect(ctx, "negative-get scope by numeric id", "GET", f"{BASE}/scopes/1", None, 404)

        patched = _scope_server(interface)
        patched.update({"name": "scope-main-edited", "lease_time": "30m", "id": "77", "UUID": "tampered"})
        _patch_scope(ctx, scope_uuid, patched)
        data = _read(DHCP)
        stored_scope = data["dhcp"][0]["rule"]
        require(ctx, stored_scope.get("id") == "1", "scope id immutable on patch", "scope id changed")
        require(ctx, stored_scope.get("UUID") == scope_uuid, "scope UUID immutable on patch", "scope UUID changed")
        require(ctx, stored_scope.get("name") == "scope-main-edited", "scope name editable", "scope name not updated")

        duplicate_name = _scope_server(interface)
        duplicate_name.update({"name": "scope-main-edited", "enable": "false"})
        _expect(ctx, "negative-duplicate scope name", "POST", f"{BASE}/scopes", {"rule": duplicate_name}, 409)

        disabled = _scope_server(interface)
        disabled.update({"name": "scope-disabled", "enable": "false"})
        second = _create_scope(ctx, disabled)
        second_uuid = str(second.get("uuid"))
        require(ctx, str(second.get("id")) == "2", "second scope uses id 2", "second scope id is not 2")
        _delete_scope(ctx, second_uuid)
        disabled["name"] = "scope-reused"
        reused = _create_scope(ctx, disabled)
        reused_uuid = str(reused.get("uuid"))
        require(ctx, str(reused.get("id")) == "2", "scope reuses smallest free id", "scope did not reuse id 2")
        _delete_scope(ctx, reused_uuid)

        _exercise_scope_negative_matrix(ctx, interface, aliases)

        # ES: Reserva vinculada al scope; identidad y Alias siguen el mismo patrón.
        # EN: Reservation linked to the scope; identity and Alias follow the same pattern.
        reservation_rule = _reservation(interface, aliases)
        reservation_rule["ip"] = [reservation_rule["ip"]]
        reservation_rule.update({"name": "reservation-main", "id": "999", "UUID": "tampered-reservation"})
        reservation = _create_reservation(ctx, reservation_rule)
        reservation_uuid = str(reservation.get("uuid"))
        data = _read(DHCP)
        stored_reservation = data["dhcp_reservation"][0]["rule"]
        require(ctx, stored_reservation.get("id") == "1", "reservation uses smallest free id", "reservation id is not 1")
        require(ctx, reservation_uuid.startswith("dhcpres-1-"), "reservation UUID uses dhcpres prefix and id", f"bad reservation UUID {reservation_uuid}")
        require(ctx, stored_reservation.get("ip") == aliases["reservation_ip"]["UUID"], "reservation stores Alias UUID", "reservation did not store Alias UUID")
        visible_res = _expect(ctx, "get reservation by UUID", "GET", f"{BASE}/reservations/{reservation_uuid}", None, 200)["rule"]
        require(ctx, visible_res.get("ip") == aliases["reservation_ip"]["name"], "reservation API displays Alias name", "reservation API did not display Alias name")
        _expect(ctx, "negative-get reservation by numeric id", "GET", f"{BASE}/reservations/1", None, 404)

        patch_res = _reservation(interface, aliases, None, "02:AA:BB:CC:DD:11", "host11")
        patch_res.update({"name": "reservation-main-edited", "ip": "10.250.0.11", "id": "88", "UUID": "tampered"})
        _patch_reservation(ctx, reservation_uuid, patch_res)
        data = _read(DHCP)
        stored_reservation = data["dhcp_reservation"][0]["rule"]
        require(ctx, stored_reservation.get("id") == "1", "reservation id immutable on patch", "reservation id changed")
        require(ctx, stored_reservation.get("UUID") == reservation_uuid, "reservation UUID immutable on patch", "reservation UUID changed")
        require(ctx, stored_reservation.get("name") == "reservation-main-edited", "reservation name editable", "reservation name not updated")

        duplicate_name_res = _reservation(interface, aliases, None, "02:AA:BB:CC:DD:12", "host12")
        duplicate_name_res.update({"name": "reservation-main-edited", "enable": "false", "ip": "10.250.0.12"})
        _expect(ctx, "negative-duplicate reservation name", "POST", f"{BASE}/reservations", {"rule": duplicate_name_res}, 409)

        _exercise_reservation_negative_matrix(ctx, interface, aliases)
        _patch_reservation(ctx, "missing-reservation-uuid", patch_res, 404)
        _delete_reservation(ctx, "missing-reservation-uuid", 404)
        _delete_reservation(ctx, reservation_uuid)
        _delete_scope(ctx, scope_uuid)

        _exercise_candidate_shape_errors(ctx)
        text = DHCP.read_text(encoding="utf-8")
        require(ctx, "tmp_dnsmasq_" not in text, "no tmp_dnsmasq marker persisted in dhcp candidate", "tmp_dnsmasq marker leaked to dhcp candidate")
    finally:
        _restore(ctx)
