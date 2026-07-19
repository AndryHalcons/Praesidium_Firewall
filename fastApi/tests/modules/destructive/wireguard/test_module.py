"""Tests destructivos de WireGuard. / Destructive WireGuard tests."""
from __future__ import annotations

import io
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from common.runner import BASE_URL, call, require

BASE = "/api/v1/wireguard"
WIREGUARD = Path("/var/lib/praesidium/candidate/wireguard.json")
ALIAS_IP = Path("/var/lib/praesidium/candidate/alias_ip.json")
ALIAS_SERVICES = Path("/var/lib/praesidium/candidate/alias_services.json")
BACKUP = Path("/tmp/praesidium_wireguard_before_destructive_test.json")
ALIAS_IP_BACKUP = Path("/tmp/praesidium_alias_ip_before_wireguard_test.json")
ALIAS_SERVICES_BACKUP = Path("/tmp/praesidium_alias_services_before_wireguard_test.json")


def _backup() -> None:
    shutil.copy2(WIREGUARD, BACKUP)
    shutil.copy2(ALIAS_IP, ALIAS_IP_BACKUP)
    shutil.copy2(ALIAS_SERVICES, ALIAS_SERVICES_BACKUP)


def _restore(ctx) -> None:
    shutil.copy2(BACKUP, WIREGUARD)
    shutil.copy2(ALIAS_IP_BACKUP, ALIAS_IP)
    shutil.copy2(ALIAS_SERVICES_BACKUP, ALIAS_SERVICES)
    ctx.log("RESTORE wireguard/alias_ip/alias_services candidates applied")


def _write(data: Any) -> None:
    WIREGUARD.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    WIREGUARD.chmod(0o664)


def _reset() -> None:
    _write({"site_to_site": {}, "remote_access": {}, "remote_clients": {}})


def _keypair() -> dict[str, str]:
    private = subprocess.run(["wg", "genkey"], text=True, capture_output=True, timeout=10, check=True).stdout.strip()
    public = subprocess.run(["wg", "pubkey"], input=private, text=True, capture_output=True, timeout=10, check=True).stdout.strip()
    return {"private": private, "public": public}


def _raw_get(path: str, token: str) -> tuple[int, bytes, str]:
    req = urllib.request.Request(BASE_URL + path, headers={"Authorization": f"Bearer {token}"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read(), resp.headers.get("content-type", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("content-type", "")


def _raw_download(path: str, token: str) -> tuple[int, bytes, dict[str, str]]:
    """Descarga binaria conservando cabeceras para validar nombres y no-cache."""
    req = urllib.request.Request(BASE_URL + path, headers={"Authorization": f"Bearer {token}"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read(), {key.lower(): value for key, value in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), {key.lower(): value for key, value in exc.headers.items()}


def _ra_rule(name: str = "wg-ra-test", port: str = "51820", private_key: str | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "enabled": "true",
        "interface": "wgtest0",
        "server_vpn_ip": "10.60.0.1/24",
        "vpn_network": "10.60.0.0/24",
        "listen_port": port,
        "public_endpoint": "vpn.example.test",
        "internal_networks": "192.168.0.0/16",
        "dns": "1.1.1.1,8.8.8.8",
        "private_key": private_key or _keypair()["private"],
        "mtu": "1420",
    }


def _client_rule(name: str = "wg-client-test", vpn: str = "wg-ra-test", ip: str = "10.60.0.10/32") -> dict[str, Any]:
    return {
        "name": name,
        "enabled": "true",
        "vpn": vpn,
        "client_vpn_ip": ip,
        "client_private_key": "",
        "client_public_key": "",
        "allowed_ips": "0.0.0.0/0",
        "keepalive": "25",
    }


def _s2s_rule(name: str = "wg-s2s-test", port: str = "51821") -> dict[str, Any]:
    remote = _keypair()["public"]
    return {
        "name": name,
        "enabled": "true",
        "interface": "wgs2s0",
        "local_tunnel_ip": "172.31.10.1/30",
        "remote_tunnel_ip": "172.31.10.2/30",
        "local_networks": "10.10.0.0/16",
        "remote_networks": "10.20.0.0/16",
        "listen_port": port,
        "remote_endpoint": "203.0.113.10:51820",
        "private_key": _keypair()["private"],
        "remote_public_key": remote,
        "keepalive": "25",
        "mtu": "1420",
    }


def _expect_role(ctx, status: int, admin_expected: int, viewer_expected: int, label: str) -> None:
    expected = admin_expected if ctx.identity.role == "admin" else viewer_expected
    require(ctx, status == expected, f"{label} returned expected {expected}", f"{label} returned {status}, expected {expected}")


def _admin(ctx) -> bool:
    return ctx.identity.role == "admin"


def _alias_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("aliases", "items"):
        if isinstance(payload.get(key), list):
            return [row for row in payload[key] if isinstance(row, dict)]
    return []


def _create_alias(ctx, path: str, name: str, content: list[str]) -> dict[str, Any]:
    status, payload = call(ctx, f"helper create {name}", "POST", path, {"name": name, "content": content})
    require(ctx, status in {200, 201} and isinstance(payload, dict) and payload.get("UUID"), f"alias {name} created", f"alias {name} create failed {status}")
    return payload


def _run_site_to_site_identity_alias_tests(ctx) -> None:
    stamp = str(int(time.time()))

    # Identity contract: smallest free ID, centralized UUID, user-visible editable name.
    created: list[dict[str, Any]] = []
    for label in ("alpha", "beta", "gamma"):
        status, payload = call(ctx, f"create site identity {label}", "POST", f"{BASE}/site-to-site", {"rule": {"name": f"wg-{label}-{stamp}", "enabled": "false"}})
        require(ctx, status == 200, f"site identity {label} created", f"site identity {label} create returned {status}")
        created.append(payload)
    require(ctx, [item.get("id") for item in created] == ["1", "2", "3"], "site IDs allocated 1,2,3", f"unexpected site IDs: {[item.get('id') for item in created]}")
    require(ctx, all(str(item.get("UUID", "")).startswith(f"wgsite-{item.get('id')}-") for item in created), "site UUIDs use wgsite prefix and ID", "site UUID prefix/ID mismatch")

    first = created[0]
    status, payload = call(ctx, "get site by UUID", "GET", f"{BASE}/site-to-site/{first['UUID']}")
    entry = payload.get("entry", {}) if isinstance(payload, dict) else {}
    require(ctx, status == 200 and entry.get("id") == "1" and entry.get("UUID") == first["UUID"] and entry.get("name") == first["name"], "site GET by UUID returns identity", f"site GET by UUID failed {status}")
    status, _ = call(ctx, "negative-get site by name", "GET", f"{BASE}/site-to-site/{first['name']}")
    require(ctx, status == 404, "site GET by name rejected", f"site GET by name returned {status}")

    edited_name = f"wg-alpha-edited-{stamp}"
    status, payload = call(ctx, "patch site by UUID", "PATCH", f"{BASE}/site-to-site/{first['UUID']}", {"rule": {"name": edited_name}})
    require(ctx, status == 200 and payload.get("id") == "1" and payload.get("UUID") == first["UUID"] and payload.get("name") == edited_name, "site PATCH preserves id/UUID and edits name", f"site PATCH identity failed {status}")
    status, _ = call(ctx, "negative-duplicate site name", "POST", f"{BASE}/site-to-site", {"rule": {"name": edited_name, "enabled": "false"}})
    require(ctx, status == 409, "duplicate site name rejected", f"duplicate site name returned {status}")

    second = created[1]
    status, _ = call(ctx, "delete site by UUID for ID reuse", "DELETE", f"{BASE}/site-to-site/{second['UUID']}")
    require(ctx, status == 200, "site delete by UUID succeeded", f"site delete by UUID returned {status}")
    status, replacement = call(ctx, "create site reuses smallest ID", "POST", f"{BASE}/site-to-site", {"rule": {"name": f"wg-delta-{stamp}", "enabled": "false"}})
    require(ctx, status == 200 and replacement.get("id") == "2" and str(replacement.get("UUID", "")).startswith("wgsite-2-"), "site reuses smallest free ID 2", f"site ID reuse failed {status}: {replacement}")

    for item in (first, created[2], replacement):
        status, _ = call(ctx, f"cleanup identity {item['UUID']}", "DELETE", f"{BASE}/site-to-site/{item['UUID']}")
        require(ctx, status == 200, f"identity {item['UUID']} deleted", f"identity cleanup failed {status}")

    # Alias fixtures: single tunnel nets, network groups, one service port, and invalid range/host fixtures.
    aliases: dict[str, dict[str, Any]] = {}
    for key, value in {
        "local_tunnel": "172.31.10.1/30",
        "remote_tunnel": "172.31.10.2/30",
        "local_network": "10.10.0.0/16",
        "remote_network": "10.20.0.0/16",
        "overlap_network": "10.10.1.0/24",
        "host_only": "192.0.2.10/32",
    }.items():
        aliases[key] = _create_alias(ctx, "/api/v1/alias-ip/addresses", f"wg-{key}-{stamp}", [value])
    aliases["local_group"] = _create_alias(ctx, "/api/v1/alias-ip/address-groups", f"wg-local-group-{stamp}", [aliases["local_network"]["UUID"]])
    aliases["remote_group"] = _create_alias(ctx, "/api/v1/alias-ip/address-groups", f"wg-remote-group-{stamp}", [aliases["remote_network"]["UUID"]])
    services = {
        "port": _create_alias(ctx, "/api/v1/alias-services/services", f"wg-port-{stamp}", ["51821"]),
        "range": _create_alias(ctx, "/api/v1/alias-services/services", f"wg-range-{stamp}", ["51821-51822"]),
        "port2": _create_alias(ctx, "/api/v1/alias-services/services", f"wg-port2-{stamp}", ["51822"]),
    }

    keypair = _keypair()
    valid_rule = {
        "name": f"wg-alias-valid-{stamp}", "enabled": "true", "interface": "wgs2stest",
        "local_tunnel_ip": [aliases["local_tunnel"]], "remote_tunnel_ip": [aliases["remote_tunnel"]],
        "local_networks": [aliases["local_group"], "10.51.0.0/16"], "remote_networks": [aliases["remote_group"]],
        "listen_port": [services["port"]], "remote_endpoint": "203.0.113.10:51820",
        "private_key": keypair["private"], "remote_public_key": _keypair()["public"], "keepalive": "25", "mtu": "1420",
    }
    status, valid = call(ctx, "create alias-backed site", "POST", f"{BASE}/site-to-site", {"rule": valid_rule})
    require(ctx, status == 200 and valid.get("UUID"), "alias-backed site created", f"alias-backed site create returned {status}")
    status, payload = call(ctx, "read alias-backed site", "GET", f"{BASE}/site-to-site/{valid['UUID']}")
    entry = payload.get("entry", {}) if isinstance(payload, dict) else {}
    require(ctx, status == 200 and entry.get("local_tunnel_ip") == [aliases["local_tunnel"]["name"]], "site API shows tunnel alias name", f"site tunnel alias not visible by name: {entry.get('local_tunnel_ip')}")
    require(ctx, entry.get("local_networks") == [aliases["local_group"]["name"], "10.51.0.0/16"], "site API shows alias name and preserves literal", f"site visible mixed values invalid: {entry.get('local_networks')}")
    require(ctx, entry.get("listen_port") == [services["port"]["name"]], "site API shows service alias name", f"site service alias not visible by name: {entry.get('listen_port')}")
    stored = json.loads(WIREGUARD.read_text())["site_to_site"][valid["UUID"]]
    require(ctx, stored.get("local_tunnel_ip") == [aliases["local_tunnel"]["UUID"]], "site storage uses tunnel alias UUID", f"site tunnel storage invalid: {stored.get('local_tunnel_ip')}")
    require(ctx, stored.get("local_networks") == [aliases["local_group"]["UUID"], "10.51.0.0/16"], "site storage uses alias UUID and preserves literal", f"site mixed storage invalid: {stored.get('local_networks')}")
    require(ctx, stored.get("listen_port") == [services["port"]["UUID"]], "site storage uses service alias UUID", f"site service storage invalid: {stored.get('listen_port')}")
    require(ctx, aliases["local_tunnel"]["name"] not in stored.get("local_tunnel_ip", []) and services["port"]["name"] not in stored.get("listen_port", []), "site storage contains no alias names", "site storage leaked alias names")

    protected_name = f"wg-protected-{stamp}"
    status, payload = call(ctx, "patch site cannot alter id UUID", "PATCH", f"{BASE}/site-to-site/{valid['UUID']}", {"rule": {"id": "999", "UUID": "wgsite-999-19700101000000000-0000", "name": protected_name}})
    require(ctx, status == 200 and payload.get("id") == valid.get("id") and payload.get("UUID") == valid.get("UUID") and payload.get("name") == protected_name, "site PATCH protects id/UUID", f"site PATCH identity protection failed {status}")
    for label, method, body in [
        ("GET", "GET", None),
        ("PATCH", "PATCH", {"rule": {"name": protected_name}}),
        ("DELETE", "DELETE", None),
    ]:
        status, _ = call(ctx, f"negative-site {label} by name", method, f"{BASE}/site-to-site/{protected_name}", body)
        require(ctx, status == 404, f"site {label} by name rejected", f"site {label} by name returned {status}")

    duplicate_interface = {**valid_rule, "name": f"bad-duplicate-interface-{stamp}", "listen_port": [services["port2"]]}
    status, _ = call(ctx, "negative-site duplicate interface", "POST", f"{BASE}/site-to-site", {"rule": duplicate_interface})
    require(ctx, status == 409, "duplicate site interface rejected", f"duplicate site interface returned {status}")
    duplicate_port = {**valid_rule, "name": f"bad-duplicate-port-{stamp}", "interface": "wgs2stest2"}
    status, _ = call(ctx, "negative-site duplicate port", "POST", f"{BASE}/site-to-site", {"rule": duplicate_port})
    require(ctx, status == 409, "duplicate site listen port rejected", f"duplicate site listen port returned {status}")

    status, _ = call(ctx, "delete alias-backed site by UUID", "DELETE", f"{BASE}/site-to-site/{valid['UUID']}")
    require(ctx, status == 200, "alias-backed site deleted", f"alias-backed site delete returned {status}")

    literal_rule = _s2s_rule(name=f"wg-literal-{stamp}", port="51823")
    status, literal = call(ctx, "create literal IPv4 site", "POST", f"{BASE}/site-to-site", {"rule": literal_rule})
    require(ctx, status == 200 and literal.get("UUID"), "literal IPv4 site created", f"literal IPv4 site create returned {status}")
    status, _ = call(ctx, "delete literal IPv4 site", "DELETE", f"{BASE}/site-to-site/{literal['UUID']}")
    require(ctx, status == 200, "literal IPv4 site deleted", f"literal IPv4 site delete returned {status}")

    ipv6_rule = {
        **_s2s_rule(name=f"wg-ipv6-{stamp}", port="51824"),
        "interface": "wgs2sv6", "local_tunnel_ip": "2001:db8:100::/127", "remote_tunnel_ip": "2001:db8:100::1/127",
        "local_networks": "2001:db8:10::/64", "remote_networks": "2001:db8:20::/64", "remote_endpoint": "[2001:db8::10]:51820",
    }
    status, ipv6 = call(ctx, "create literal IPv6 site", "POST", f"{BASE}/site-to-site", {"rule": ipv6_rule})
    require(ctx, status == 200 and ipv6.get("UUID"), "literal IPv6 site created", f"literal IPv6 site create returned {status}")
    status, _ = call(ctx, "delete literal IPv6 site", "DELETE", f"{BASE}/site-to-site/{ipv6['UUID']}")
    require(ctx, status == 200, "literal IPv6 site deleted", f"literal IPv6 site delete returned {status}")

    invalid_rules = [
        ("site tunnel without CIDR", {**valid_rule, "name": f"bad-no-cidr-{stamp}", "local_tunnel_ip": "172.31.10.1"}, 422),
        ("site tunnel host alias", {**valid_rule, "name": f"bad-host-{stamp}", "local_tunnel_ip": [aliases["host_only"]]}, 422),
        ("site tunnel group", {**valid_rule, "name": f"bad-tunnel-group-{stamp}", "local_tunnel_ip": [aliases["local_group"]]}, 422),
        ("site service range alias", {**valid_rule, "name": f"bad-range-{stamp}", "listen_port": [services["range"]]}, 422),
        ("site multiple service values", {**valid_rule, "name": f"bad-multi-port-{stamp}", "listen_port": [services["port"], services["port2"]]}, 422),
        ("site hostname endpoint", {**valid_rule, "name": f"bad-hostname-{stamp}", "remote_endpoint": "vpn.example.test:51820"}, 422),
        ("site CIDR endpoint", {**valid_rule, "name": f"bad-cidr-endpoint-{stamp}", "remote_endpoint": "203.0.113.10/32:51820"}, 422),
        ("site oversized endpoint port", {**valid_rule, "name": f"bad-endpoint-port-{stamp}", "remote_endpoint": "203.0.113.10:500000"}, 422),
        ("site duplicate tunnel IP", {**valid_rule, "name": f"bad-duplicate-tunnel-{stamp}", "remote_tunnel_ip": [aliases["local_tunnel"]]}, 422),
        ("site tunnel network mismatch", {**valid_rule, "name": f"bad-network-mismatch-{stamp}", "remote_tunnel_ip": "172.31.11.2/30"}, 422),
        ("site tunnel family mismatch", {**valid_rule, "name": f"bad-family-mismatch-{stamp}", "remote_tunnel_ip": "2001:db8::1/127"}, 422),
        ("site local/remote overlap", {**valid_rule, "name": f"bad-overlap-{stamp}", "remote_networks": [aliases["overlap_network"]]}, 422),
    ]
    for label, rule, expected in invalid_rules:
        status, _ = call(ctx, f"negative-{label}", "POST", f"{BASE}/site-to-site", {"rule": rule})
        require(ctx, status == expected, f"{label} rejected", f"{label} returned {status}, expected {expected}")


def _run_remote_access_identity_validation_tests(ctx) -> None:
    """Cubre identidad, aliases y validación del servidor WireGuard."""
    stamp = str(int(time.time()))
    created: list[dict[str, Any]] = []
    for label in ("alpha", "beta", "gamma"):
        status, payload = call(ctx, f"create server identity {label}", "POST", f"{BASE}/remote-access", {"rule": {"name": f"wg-server-{label}-{stamp}", "enabled": "false"}})
        require(ctx, status == 200, f"server identity {label} created", f"server identity {label} returned {status}")
        created.append(payload)
    require(ctx, [item.get("id") for item in created] == ["1", "2", "3"], "server IDs allocated 1,2,3", f"unexpected server IDs: {[item.get('id') for item in created]}")
    require(ctx, all(str(item.get("UUID", "")).startswith(f"wgserv-{item.get('id')}-") for item in created), "server UUIDs use wgserv prefix and ID", "server UUID prefix/ID mismatch")

    first = created[0]
    status, payload = call(ctx, "get server by UUID", "GET", f"{BASE}/remote-access/{first['UUID']}")
    entry = payload.get("entry", {}) if isinstance(payload, dict) else {}
    require(ctx, status == 200 and entry.get("id") == "1" and entry.get("UUID") == first["UUID"] and entry.get("name") == first["name"], "server GET by UUID returns identity", f"server GET failed {status}")
    for method, body in (("GET", None), ("PATCH", {"rule": {"name": first["name"]}}), ("DELETE", None)):
        status, _ = call(ctx, f"negative-server {method} by name", method, f"{BASE}/remote-access/{first['name']}", body)
        require(ctx, status == 404, f"server {method} by name rejected", f"server {method} by name returned {status}")

    edited_name = f"wg-server-alpha-edited-{stamp}"
    status, payload = call(ctx, "patch server protects identity", "PATCH", f"{BASE}/remote-access/{first['UUID']}", {"rule": {"id": "999", "UUID": "evil", "name": edited_name}})
    require(ctx, status == 200 and payload.get("id") == "1" and payload.get("UUID") == first["UUID"] and payload.get("name") == edited_name, "server PATCH protects id/UUID and edits name", f"server PATCH identity failed {status}")
    status, _ = call(ctx, "negative-duplicate server name", "POST", f"{BASE}/remote-access", {"rule": {"name": edited_name, "enabled": "false"}})
    require(ctx, status == 409, "duplicate server name rejected", f"duplicate server name returned {status}")

    second = created[1]
    status, _ = call(ctx, "delete server UUID for ID reuse", "DELETE", f"{BASE}/remote-access/{second['UUID']}")
    require(ctx, status == 200, "server delete by UUID succeeded", f"server delete returned {status}")
    status, replacement = call(ctx, "create server reuses smallest ID", "POST", f"{BASE}/remote-access", {"rule": {"name": f"wg-server-delta-{stamp}", "enabled": "false"}})
    require(ctx, status == 200 and replacement.get("id") == "2" and str(replacement.get("UUID", "")).startswith("wgserv-2-"), "server reuses smallest free ID 2", f"server ID reuse failed {status}: {replacement}")
    for item in (first, created[2], replacement):
        status, _ = call(ctx, f"cleanup server identity {item['UUID']}", "DELETE", f"{BASE}/remote-access/{item['UUID']}")
        require(ctx, status == 200, "server identity cleanup succeeded", f"server identity cleanup returned {status}")

    aliases: dict[str, dict[str, Any]] = {}
    for key, value in {
        "server_ip": "10.60.0.1/24", "vpn_net": "10.60.0.0/24", "internal": "192.168.0.0/16",
        "dns": "1.1.1.1/32", "endpoint": "203.0.113.10/32", "ipv6_endpoint": "2001:db8::10/128",
    }.items():
        aliases[key] = _create_alias(ctx, "/api/v1/alias-ip/addresses", f"ra-{key[:6]}-{stamp}", [value])
    aliases["vpn_group"] = _create_alias(ctx, "/api/v1/alias-ip/address-groups", f"ra-vpng-{stamp}", [aliases["vpn_net"]["UUID"]])
    aliases["internal_group"] = _create_alias(ctx, "/api/v1/alias-ip/address-groups", f"ra-intg-{stamp}", [aliases["internal"]["UUID"]])
    aliases["endpoint_group"] = _create_alias(ctx, "/api/v1/alias-ip/address-groups", f"ra-endg-{stamp}", [aliases["endpoint"]["UUID"]])
    services = {
        "port": _create_alias(ctx, "/api/v1/alias-services/services", f"ra-port-{stamp}", ["51920"]),
        "port2": _create_alias(ctx, "/api/v1/alias-services/services", f"ra-port2-{stamp}", ["51921"]),
        "range": _create_alias(ctx, "/api/v1/alias-services/services", f"ra-range-{stamp}", ["51920-51921"]),
    }
    valid_rule = {
        "name": f"wg-ra-alias-{stamp}", "enabled": "true", "interface": "wgratest",
        "server_vpn_ip": [aliases["server_ip"]], "vpn_network": [aliases["vpn_group"]],
        "listen_port": [services["port"]], "public_endpoint": [aliases["endpoint"]],
        "internal_networks": [aliases["internal_group"], "172.16.0.0/16"], "dns": [aliases["dns"], "9.9.9.9"],
        "private_key": _keypair()["private"], "mtu": "1420",
    }
    status, valid = call(ctx, "create alias-backed server", "POST", f"{BASE}/remote-access", {"rule": valid_rule})
    require(ctx, status == 200 and valid.get("UUID"), "alias-backed server created", f"alias-backed server returned {status}")
    status, payload = call(ctx, "read alias-backed server masked", "GET", f"{BASE}/remote-access/{valid['UUID']}")
    entry = payload.get("entry", {}) if isinstance(payload, dict) else {}
    require(ctx, status == 200 and entry.get("server_vpn_ip") == [aliases["server_ip"]["name"]], "server API shows IP alias name", f"server IP alias not visible by name: {entry.get('server_vpn_ip')}")
    require(ctx, entry.get("internal_networks") == [aliases["internal_group"]["name"], "172.16.0.0/16"], "server API shows alias name and preserves literal", f"server visible mixed values invalid: {entry.get('internal_networks')}")
    require(ctx, entry.get("dns") == [aliases["dns"]["name"], "9.9.9.9"], "server API shows DNS alias name and preserves literal", f"server DNS visible values invalid: {entry.get('dns')}")
    require(ctx, entry.get("listen_port") == [services["port"]["name"]], "server API shows service alias name", f"server service alias not visible by name: {entry.get('listen_port')}")
    stored = json.loads(WIREGUARD.read_text())["remote_access"][valid["UUID"]]
    require(ctx, stored.get("server_vpn_ip") == [aliases["server_ip"]["UUID"]], "server storage uses IP alias UUID", f"server IP storage invalid: {stored.get('server_vpn_ip')}")
    require(ctx, stored.get("internal_networks") == [aliases["internal_group"]["UUID"], "172.16.0.0/16"], "server storage uses alias UUID and preserves literal", f"server mixed storage invalid: {stored.get('internal_networks')}")
    require(ctx, stored.get("dns") == [aliases["dns"]["UUID"], "9.9.9.9"], "server storage uses DNS alias UUID and preserves literal", f"server DNS storage invalid: {stored.get('dns')}")
    require(ctx, stored.get("listen_port") == [services["port"]["UUID"]], "server storage uses service alias UUID", f"server service storage invalid: {stored.get('listen_port')}")
    require(ctx, aliases["server_ip"]["name"] not in stored.get("server_vpn_ip", []) and services["port"]["name"] not in stored.get("listen_port", []), "server storage contains no alias names", "server storage leaked alias names")
    require(ctx, entry.get("private_key") == "********", "server private key masked", "server private key exposed")

    duplicate_interface = {**valid_rule, "name": f"bad-ra-interface-{stamp}", "listen_port": [services["port2"]]}
    status, _ = call(ctx, "negative-server duplicate interface", "POST", f"{BASE}/remote-access", {"rule": duplicate_interface})
    require(ctx, status == 409, "duplicate server interface rejected", f"duplicate server interface returned {status}")
    duplicate_port = {**valid_rule, "name": f"bad-ra-port-{stamp}", "interface": "wgratest2"}
    status, _ = call(ctx, "negative-server duplicate port", "POST", f"{BASE}/remote-access", {"rule": duplicate_port})
    require(ctx, status == 409, "duplicate server port rejected", f"duplicate server port returned {status}")
    status, _ = call(ctx, "delete alias-backed server", "DELETE", f"{BASE}/remote-access/{valid['UUID']}")
    require(ctx, status == 200, "alias-backed server deleted", f"alias-backed server delete returned {status}")

    accepted_endpoints: list[tuple[str, Any]] = [
        ("domain", "andres.com"), ("local-domain", "blablabla.local"), ("ipv4", "1.1.1.1"),
        ("ipv4-32", "1.1.1.1/32"), ("ipv6", "2001:db8::1"), ("ipv6-128", "2001:db8::1/128"),
        ("alias-ipv4", [aliases["endpoint"]]), ("alias-ipv6", [aliases["ipv6_endpoint"]]),
    ]
    for label, endpoint in accepted_endpoints:
        status, created_endpoint = call(ctx, f"create server endpoint {label}", "POST", f"{BASE}/remote-access", {"rule": {"name": f"wg-endpoint-{label}-{stamp}", "enabled": "false", "public_endpoint": endpoint}})
        require(ctx, status == 200 and created_endpoint.get("UUID"), f"server endpoint {label} accepted", f"server endpoint {label} returned {status}")
        status, _ = call(ctx, f"delete server endpoint {label}", "DELETE", f"{BASE}/remote-access/{created_endpoint['UUID']}")
        require(ctx, status == 200, f"server endpoint {label} cleanup", f"server endpoint {label} cleanup returned {status}")

    invalid_cases = [
        ("bad name", {"name": "bad name", "enabled": "false"}, 422),
        ("bad bool", {"name": f"bad-bool-{stamp}", "enabled": "maybe"}, 422),
        ("bad port", {**_ra_rule(name=f"bad-port-{stamp}"), "listen_port": "70000"}, 422),
        ("server ip outside vpn", {**_ra_rule(name=f"bad-ip-{stamp}"), "server_vpn_ip": "10.61.0.1/24"}, 422),
        ("network overlap", {**_ra_rule(name=f"bad-overlap-{stamp}"), "internal_networks": "10.60.0.0/24"}, 422),
        ("endpoint IPv4 network", {"name": f"bad-endpoint-net4-{stamp}", "enabled": "false", "public_endpoint": "10.0.0.0/24"}, 422),
        ("endpoint IPv6 network", {"name": f"bad-endpoint-net6-{stamp}", "enabled": "false", "public_endpoint": "2001:db8::/64"}, 422),
        ("endpoint group", {"name": f"bad-endpoint-group-{stamp}", "enabled": "false", "public_endpoint": [aliases["endpoint_group"]]}, 422),
        ("endpoint multiple", {"name": f"bad-endpoint-multi-{stamp}", "enabled": "false", "public_endpoint": [aliases["endpoint"], "andres.com"]}, 422),
        ("endpoint malformed", {"name": f"bad-endpoint-domain-{stamp}", "enabled": "false", "public_endpoint": "andres..com"}, 422),
        ("server IP group", {**valid_rule, "name": f"bad-server-group-{stamp}", "server_vpn_ip": [aliases["vpn_group"]], "interface": "badgroup"}, 422),
        ("listen range", {**valid_rule, "name": f"bad-listen-range-{stamp}", "listen_port": [services["range"]], "interface": "badrange"}, 422),
        ("dns group", {**valid_rule, "name": f"bad-dns-group-{stamp}", "dns": [aliases["internal_group"]], "interface": "baddns"}, 422),
    ]
    for label, rule, expected in invalid_cases:
        status, _ = call(ctx, f"negative-server {label}", "POST", f"{BASE}/remote-access", {"rule": rule})
        require(ctx, status == expected, f"server {label} rejected", f"server {label} returned {status}, expected {expected}")


def _run_remote_client_identity_export_tests(ctx) -> None:
    """Cubre identidad, relación con servidor, secretos y exportaciones de clientes."""
    stamp = str(int(time.time()))
    server_rule = _ra_rule(name=f"wg-client-server-{stamp}", private_key=_keypair()["private"])
    status, server = call(ctx, "create client test server", "POST", f"{BASE}/remote-access", {"rule": server_rule})
    require(ctx, status == 200 and server.get("UUID"), "client test server created", f"client test server returned {status}")
    server_uuid = server["UUID"]

    clients: list[dict[str, Any]] = []
    for label, ip in (("alpha", "10.60.0.10/32"), ("beta", "10.60.0.11/32")):
        status, payload = call(ctx, f"create client identity {label}", "POST", f"{BASE}/remote-clients", {"rule": _client_rule(name=f"wg-client-{label}-{stamp}", vpn=server_uuid, ip=ip)})
        require(ctx, status == 200, f"client identity {label} created", f"client identity {label} returned {status}")
        clients.append(payload)
    require(ctx, [item.get("id") for item in clients] == ["1", "2"], "client IDs allocated 1,2", f"unexpected client IDs: {[item.get('id') for item in clients]}")
    require(ctx, all(str(item.get("UUID", "")).startswith(f"wgclient-{item.get('id')}-") for item in clients), "client UUIDs use wgclient prefix and ID", "client UUID prefix/ID mismatch")

    first, second = clients
    status, payload = call(ctx, "get client by UUID masked", "GET", f"{BASE}/remote-clients/{first['UUID']}")
    entry = payload.get("entry", {}) if isinstance(payload, dict) else {}
    require(ctx, status == 200 and entry.get("id") == "1" and entry.get("UUID") == first["UUID"] and entry.get("vpn") == server_uuid, "client GET returns identity and server UUID", f"client GET failed {status}")
    require(ctx, entry.get("client_private_key") == "********" and bool(entry.get("client_public_key")), "client generated keys and masks private key", "client generated key contract failed")
    status, _ = call(ctx, "negative-get client by name", "GET", f"{BASE}/remote-clients/{first['name']}")
    require(ctx, status == 404, "client GET by name rejected", f"client GET by name returned {status}")

    edited_name = f"wg-client-alpha-edited-{stamp}"
    status, payload = call(ctx, "patch client protects identity and unchanged public key", "PATCH", f"{BASE}/remote-clients/{first['UUID']}", {"rule": {"id": "999", "UUID": "evil", "name": edited_name, "client_public_key": entry["client_public_key"], "keepalive": "30"}})
    require(ctx, status == 200 and payload.get("id") == "1" and payload.get("UUID") == first["UUID"] and payload.get("name") == edited_name, "client PATCH protects id/UUID and edits name", f"client PATCH identity failed {status}")
    status, payload = call(ctx, "get patched client secret masked", "GET", f"{BASE}/remote-clients/{first['UUID']}")
    patched = payload.get("entry", {}) if isinstance(payload, dict) else {}
    require(ctx, status == 200 and patched.get("client_private_key") == "********" and patched.get("client_public_key") == entry["client_public_key"] and patched.get("keepalive") == "30", "client keys preserved on PATCH", "client key preservation failed")
    changed_pair = _keypair()
    status, _ = call(ctx, "negative-patch client private key", "PATCH", f"{BASE}/remote-clients/{first['UUID']}", {"rule": {"client_private_key": changed_pair["private"]}})
    require(ctx, status == 422, "client private key modification rejected", f"client private key modification returned {status}")
    status, _ = call(ctx, "negative-patch client public key", "PATCH", f"{BASE}/remote-clients/{first['UUID']}", {"rule": {"client_public_key": changed_pair["public"]}})
    require(ctx, status == 422, "client public key modification rejected", f"client public key modification returned {status}")
    status, payload = call(ctx, "get client after rejected key patches", "GET", f"{BASE}/remote-clients/{first['UUID']}")
    protected = payload.get("entry", {}) if isinstance(payload, dict) else {}
    require(ctx, status == 200 and protected.get("client_private_key") == "********" and protected.get("client_public_key") == entry["client_public_key"], "client keys unchanged after rejected PATCH", "client keys changed after rejected PATCH")
    status, _ = call(ctx, "negative-duplicate client name", "POST", f"{BASE}/remote-clients", {"rule": {"name": edited_name, "enabled": "false"}})
    require(ctx, status == 409, "duplicate client name rejected", f"duplicate client name returned {status}")

    status, body, headers = _raw_download(f"{BASE}/remote-clients/{first['UUID']}/config", ctx.token)
    require(ctx, status == 200 and b"[Interface]" in body and f"# Cliente: {edited_name};".encode() in body and f'{edited_name}.conf' in headers.get("content-disposition", ""), "client config UUID export uses display name", f"client config export failed {status}")
    status, body, headers = _raw_download(f"{BASE}/remote-clients/{first['UUID']}/qr", ctx.token)
    require(ctx, status == 200 and body.startswith(b"\x89PNG") and f'{edited_name}.png' in headers.get("content-disposition", ""), "client QR UUID export uses display name", f"client QR export failed {status}")
    status, body, headers = _raw_download(f"{BASE}/remote-clients/{first['UUID']}/bundle", ctx.token)
    names = sorted(zipfile.ZipFile(io.BytesIO(body)).namelist()) if status == 200 and body.startswith(b"PK") else []
    require(ctx, status == 200 and names == [f"{edited_name}.conf", f"{edited_name}.png"] and f'{edited_name}.zip' in headers.get("content-disposition", ""), "client bundle UUID export names outer and inner files", f"client bundle export failed {status}: {names}")
    status, _, _ = _raw_download(f"{BASE}/remote-clients/{edited_name}/config", ctx.token)
    require(ctx, status == 404, "client config by name rejected", f"client config by name returned {status}")

    status, _ = call(ctx, "negative-delete server with clients", "DELETE", f"{BASE}/remote-access/{server_uuid}")
    require(ctx, status == 409, "server with clients delete blocked", f"server with clients delete returned {status}")
    status, _ = call(ctx, "negative-client missing server", "POST", f"{BASE}/remote-clients", {"rule": _client_rule(name=f"bad-client-server-{stamp}", vpn="notreal")})
    require(ctx, status == 404, "client missing server rejected", f"client missing server returned {status}")
    status, _ = call(ctx, "negative-client outside VPN", "POST", f"{BASE}/remote-clients", {"rule": _client_rule(name=f"bad-client-ip-{stamp}", vpn=server_uuid, ip="10.61.0.10/32")})
    require(ctx, status == 422, "client outside VPN rejected", f"client outside VPN returned {status}")
    status, _ = call(ctx, "negative-client duplicate IP", "POST", f"{BASE}/remote-clients", {"rule": _client_rule(name=f"bad-client-dup-ip-{stamp}", vpn=server_uuid, ip="10.60.0.11/32")})
    require(ctx, status == 409, "duplicate client IP rejected", f"duplicate client IP returned {status}")
    duplicate_public = patched.get("client_public_key")
    explicit = _keypair()
    duplicate_key_rule = {**_client_rule(name=f"bad-client-key-{stamp}", vpn=server_uuid, ip="10.60.0.12/32"), "client_private_key": explicit["private"], "client_public_key": duplicate_public}
    status, _ = call(ctx, "negative-client duplicate public key", "POST", f"{BASE}/remote-clients", {"rule": duplicate_key_rule})
    require(ctx, status == 409, "duplicate client public key rejected", f"duplicate client public key returned {status}")

    status, _ = call(ctx, "delete client for ID reuse", "DELETE", f"{BASE}/remote-clients/{first['UUID']}")
    require(ctx, status == 200, "client delete by UUID succeeded", f"client delete returned {status}")
    status, replacement = call(ctx, "create client reuses smallest ID", "POST", f"{BASE}/remote-clients", {"rule": _client_rule(name=f"wg-client-gamma-{stamp}", vpn=server_uuid, ip="10.60.0.12/32")})
    require(ctx, status == 200 and replacement.get("id") == "1" and str(replacement.get("UUID", "")).startswith("wgclient-1-"), "client reuses smallest free ID 1", f"client ID reuse failed {status}: {replacement}")
    for item in (second, replacement):
        status, _ = call(ctx, f"cleanup client {item['UUID']}", "DELETE", f"{BASE}/remote-clients/{item['UUID']}")
        require(ctx, status == 200, "client cleanup succeeded", f"client cleanup returned {status}")
    status, _ = call(ctx, "delete client test server", "DELETE", f"{BASE}/remote-access/{server_uuid}")
    require(ctx, status == 200, "client test server deleted", f"client test server delete returned {status}")


def run(ctx) -> None:
    ctx.log("=== WIREGUARD DESTRUCTIVE ===")
    _backup()
    try:
        if not _admin(ctx):
            for label, method, path, body in [
                ("negative-viewer create remote access", "POST", f"{BASE}/remote-access", {"rule": _ra_rule()}),
                ("negative-viewer patch remote access", "PATCH", f"{BASE}/remote-access/notreal", {"rule": {"enabled": "false"}}),
                ("negative-viewer delete remote access", "DELETE", f"{BASE}/remote-access/notreal", None),
                ("negative-viewer create site", "POST", f"{BASE}/site-to-site", {"rule": {"name": "viewer-site", "enabled": "false"}}),
                ("negative-viewer patch site", "PATCH", f"{BASE}/site-to-site/wgsite-1-19700101000000000-0000", {"rule": {"name": "viewer-site"}}),
                ("negative-viewer delete site", "DELETE", f"{BASE}/site-to-site/wgsite-1-19700101000000000-0000", None),
                ("negative-viewer create client", "POST", f"{BASE}/remote-clients", {"rule": {"name": "viewer-client", "enabled": "false"}}),
                ("negative-viewer patch client", "PATCH", f"{BASE}/remote-clients/wgclient-1-19700101000000000-0000", {"rule": {"name": "viewer-client"}}),
                ("negative-viewer delete client", "DELETE", f"{BASE}/remote-clients/wgclient-1-19700101000000000-0000", None),
            ]:
                status, payload = call(ctx, label, method, path, body)
                require(ctx, status == 403, f"{label} forbidden", f"{label} returned {status}")
            for label, path in [
                ("negative-viewer config export", f"{BASE}/remote-clients/notreal/config"),
                ("negative-viewer qr export", f"{BASE}/remote-clients/notreal/qr"),
                ("negative-viewer bundle export", f"{BASE}/remote-clients/notreal/bundle"),
            ]:
                status, _, _ = _raw_get(path, ctx.token)
                require(ctx, status == 403, f"{label} forbidden", f"{label} returned {status}")
            return

        _reset()
        _run_remote_access_identity_validation_tests(ctx)
        _reset()
        _run_remote_client_identity_export_tests(ctx)
        _reset()
        _run_site_to_site_identity_alias_tests(ctx)
    finally:
        _restore(ctx)
