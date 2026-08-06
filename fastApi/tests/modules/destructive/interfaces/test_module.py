"""Tests destructivos del módulo interfaces FastAPI."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from common.runner import call, require

INTERFACES = Path("/var/lib/praesidium/candidate/interfaces.json")
ALIAS_IP = Path("/var/lib/praesidium/candidate/alias_ip.json")
BACKUP = Path("/tmp/praesidium_interfaces_before_destructive_test.json")
SECTIONS = ("ethernets", "bridges", "bonds", "vlans", "wifis")

VALID_SELECT_CASES = [
    ("ethernets", "ens_matrix_eth", "ipv6-privacy", "true"),
    ("bridges", "br_matrix_select", "ipv6-privacy", "false"),
    ("vlans", "vlan260", "ipv6-privacy", "true"),
    ("bonds", "bond_matrix_select", "parameters.mode", "802.3ad"),
    ("bonds", "bond_matrix_select", "parameters.lacp-rate", "fast"),
    ("bonds", "bond_matrix_select", "parameters.transmit-hash-policy", "layer3+4"),
    ("bonds", "bond_matrix_select", "ipv6-privacy", "false"),
    ("wifis", "wlan_matrix_select", "ipv6-privacy", "true"),
]
INVALID_SELECT_CASES = [
    ("ethernets", "ens_bad_ipv6", "ipv6-privacy", "maybe"),
    ("bridges", "br_bad_iface", "interfaces", "no_such_iface"),
    ("vlans", "vlan261", "link", "no_such_iface"),
    ("bonds", "bond_bad_mode", "parameters.mode", "invalid-mode"),
    ("bonds", "bond_bad_lacp", "parameters.lacp-rate", "turbo"),
    ("bonds", "bond_bad_hash", "parameters.transmit-hash-policy", "layer9"),
    ("wifis", "wlan_bad_ipv6", "ipv6-privacy", "maybe"),
]
CHECKBOX_FIELDS = {
    "ethernets": [
        "dhcp4", "dhcp6", "optional", "accept-ra", "wakeonlan",
        "dhcp4-overrides.use-dns", "dhcp4-overrides.use-routes", "dhcp4-overrides.send-hostname", "dhcp4-overrides.use-hostname",
        "dhcp6-overrides.use-dns", "dhcp6-overrides.use-routes",
    ],
    "bridges": [
        "dhcp4", "dhcp6", "optional", "accept-ra", "parameters.stp",
        "dhcp4-overrides.use-dns", "dhcp4-overrides.use-routes", "dhcp4-overrides.send-hostname", "dhcp4-overrides.use-hostname",
        "dhcp6-overrides.use-dns", "dhcp6-overrides.use-routes",
    ],
    "vlans": ["dhcp4", "dhcp6"],
    "bonds": ["dhcp4", "dhcp6"],
}
OBJECT_FIELDS = ("addresses", "nameservers.addresses", "routes.to", "routes.via")


def _backup() -> None:
    shutil.copy2(INTERFACES, BACKUP)


def _restore(ctx) -> None:
    shutil.copy2(BACKUP, INTERFACES)
    INTERFACES.chmod(0o664)
    ctx.log("RESTORE interfaces.json applied")


def _read() -> dict[str, Any]:
    return json.loads(INTERFACES.read_text(encoding="utf-8"))


def _read_alias_ip() -> dict[str, Any]:
    return json.loads(ALIAS_IP.read_text(encoding="utf-8"))


def _first_alias(section: str) -> dict[str, Any]:
    values = _read_alias_ip().get(section, {})
    if isinstance(values, dict):
        for entry in values.values():
            if isinstance(entry, dict):
                return entry
    if isinstance(values, list):
        for entry in values:
            if isinstance(entry, dict):
                return entry
    raise RuntimeError(f"missing alias section {section}")


def _section(section: str) -> dict[str, Any]:
    return _read().get("network", {}).get(section, {})


def _network() -> dict[str, Any]:
    return _read().get("network", {})


def _detail(payload: Any) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        return json.dumps(detail, ensure_ascii=False, sort_keys=True) if isinstance(detail, dict) else str(detail)
    return str(payload)


def _expect_role(ctx, status: int, admin_expected: int, viewer_expected: int, label: str) -> None:
    expected = admin_expected if ctx.identity.role == "admin" else viewer_expected
    require(ctx, status == expected, f"{label} returned expected {expected}", f"{label} returned {status}, expected {expected}")


def _admin_only(ctx) -> bool:
    return ctx.identity.role == "admin"


def _first_name(section: str) -> str:
    values = _section(section)
    for name in values:
        return str(name)
    raise RuntimeError(f"missing candidate section {section}")


def _uuid_for(section: str, name: str) -> str:
    entry = _section(section).get(name)
    if not isinstance(entry, dict):
        raise RuntimeError(f"missing interface {section}.{name}")
    uuid = str(entry.get("uuid") or entry.get("UUID") or "").strip()
    if not uuid:
        raise RuntimeError(f"missing uuid for {section}.{name}")
    return uuid


def _base_config(section: str, name: str) -> dict[str, Any]:
    if section == "ethernets":
        return {"name": name}
    if section == "bridges":
        return {"name": name, "interfaces": _first_name("ethernets")}
    if section == "bonds":
        return {"name": name, "interfaces": _first_name("ethernets"), "parameters.mode": "active-backup"}
    if section == "vlans":
        digits = "".join(ch for ch in name if ch.isdigit()) or "260"
        return {"name": name, "id": digits, "link": _first_name("bridges")}
    if section == "wifis":
        return {"name": name}
    raise RuntimeError(section)


def _negative_label(label: str, expected_status: int) -> str:
    return f"negative-{label}" if expected_status >= 400 and not label.startswith("negative-") else label


def _create(ctx, section: str, body: dict[str, Any], expected_status: int = 200) -> Any:
    label = _negative_label(f"create {section} {body.get('name', '<auto>')}", expected_status)
    status, payload = call(ctx, label, "POST", f"/api/v1/interfaces/{section}", {"config": body})
    require(ctx, status == expected_status, f"create {section} returned {expected_status}", f"create {section} returned {status}: {_detail(payload)}")
    return payload


def _create_error(ctx, section: str, body: dict[str, Any], expected_detail: str, expected_status: int = 422) -> Any:
    payload = _create(ctx, section, body, expected_status)
    require(ctx, payload.get("detail") == expected_detail, f"create {section} rejected with {expected_detail}", f"create {section} wrong detail: {payload}")
    return payload


def _patch_existing_error(ctx, section: str, name: str, body: dict[str, Any], expected_detail: str, expected_status: int = 422) -> Any:
    target = _uuid_for(section, name)
    label = _negative_label(f"patch-existing {section} {name} {sorted(body.keys())}", expected_status)
    status, payload = call(ctx, label, "PATCH", f"/api/v1/interfaces/{section}/{target}", {"config": body})
    require(ctx, status == expected_status, f"patch-existing {section} returned {expected_status}", f"patch-existing {section} returned {status}: {_detail(payload)}")
    require(ctx, payload.get("detail") == expected_detail, f"patch-existing {section} rejected with {expected_detail}", f"patch-existing {section} wrong detail: {payload}")
    return payload


def _patch(ctx, section: str, name: str, body: dict[str, Any], expected_status: int = 200) -> Any:
    target = _uuid_for(section, name) if expected_status == 200 else name
    label = _negative_label(f"patch {section} {name} {sorted(body.keys())}", expected_status)
    status, payload = call(ctx, label, "PATCH", f"/api/v1/interfaces/{section}/{target}", {"config": body})
    require(ctx, status == expected_status, f"patch {section} returned {expected_status}", f"patch {section} returned {status}: {_detail(payload)}")
    return payload


def _delete(ctx, section: str, name: str, expected_status: int = 200) -> Any:
    target = _uuid_for(section, name) if expected_status == 200 else name
    label = _negative_label(f"delete {section} {name}", expected_status)
    status, payload = call(ctx, label, "DELETE", f"/api/v1/interfaces/{section}/{target}")
    require(ctx, status == expected_status, f"delete {section} returned {expected_status}", f"delete {section} returned {status}: {_detail(payload)}")
    return payload


def _create_patch_delete(ctx, section: str, create_body: dict[str, Any], expected_name: str, patch_body: dict[str, Any], patch_key: str, patch_value: Any) -> None:
    status, payload = call(ctx, f"create {section}", "POST", f"/api/v1/interfaces/{section}", {"config": create_body})
    _expect_role(ctx, status, 200, 403, f"create {section}")
    if not _admin_only(ctx):
        return
    name = payload.get("name")
    require(ctx, name == expected_name, f"{section} created expected name {expected_name}", f"{section} created wrong name {payload}")
    require(ctx, expected_name in _section(section), f"{section} exists in candidate", f"{section} missing after create")

    interface_uuid = _uuid_for(section, expected_name)
    status, payload = call(ctx, f"update {section}", "PATCH", f"/api/v1/interfaces/{section}/{interface_uuid}", {"config": patch_body})
    require(ctx, status == 200 and payload.get("action") == "patch" and payload.get("uuid") == interface_uuid, f"{section} update by uuid works", f"{section} update failed {status} {payload}")
    require(ctx, _section(section)[expected_name].get(patch_key) == patch_value, f"{section} update persisted", f"{section} update not persisted")

    status, payload = call(ctx, f"delete {section}", "DELETE", f"/api/v1/interfaces/{section}/{interface_uuid}")
    require(ctx, status == 200 and payload.get("action") == "delete" and payload.get("uuid") == interface_uuid, f"{section} delete by uuid works", f"{section} delete failed {status} {payload}")
    require(ctx, expected_name not in _section(section), f"{section} removed from candidate", f"{section} still exists after delete")


def _exercise_valid_selects(ctx) -> None:
    for section, name, field, value in VALID_SELECT_CASES:
        body = _base_config(section, name)
        if section == "bonds":
            # ES: Un bond válido necesita un miembro no esclavizado previamente.
            # EN: A valid bond needs a member that has not been enslaved before.
            seed = f"{name}_eth"
            _create(ctx, "ethernets", {"name": seed})
            body["interfaces"] = seed
        # ES: Las nuevas validaciones de bond son complementarias a los selects genéricos:
        # algunos parámetros sólo son válidos con modos concretos de bonding/Netplan.
        # EN: The new bond validations complement generic selects: some parameters are only
        # valid with specific bonding/Netplan modes.
        if section == "bonds" and field in {"parameters.lacp-rate", "parameters.transmit-hash-policy"}:
            body["parameters.mode"] = "802.3ad"
        body[field] = value
        _create(ctx, section, body)
        require(ctx, _section(section)[name].get(field) == value, f"valid select {section}.{field} persisted", f"valid select {section}.{field} not persisted")
        if section == "bonds":
            _delete(ctx, section, name)
            _delete(ctx, "ethernets", body["interfaces"])


def _exercise_invalid_selects(ctx) -> None:
    for section, name, field, value in INVALID_SELECT_CASES:
        body = _base_config(section, name)
        body[field] = value
        _create(ctx, section, body, 422)


def _exercise_checkboxes(ctx) -> None:
    for section, fields in CHECKBOX_FIELDS.items():
        name = f"{section[:4]}_matrix_checks" if section != "vlans" else "vlan270"
        body = _base_config(section, name)
        bond_seed = None
        if section == "bonds":
            bond_seed = f"{name}_eth"
            _create(ctx, "ethernets", {"name": bond_seed})
            body["interfaces"] = bond_seed
        for field in fields:
            body[field] = "True"
        _create(ctx, section, body)
        for field in fields:
            require(ctx, _section(section)[name].get(field) == "True", f"checkbox {section}.{field} True persisted", f"checkbox {section}.{field} missing")
            _patch(ctx, section, name, {field: "False"})
            require(ctx, _section(section)[name].get(field) == "False", f"checkbox {section}.{field} False persisted", f"checkbox {section}.{field} false missing")
            _patch(ctx, section, name, {field: "yes"}, 422)
        if section == "bonds":
            _delete(ctx, section, name)
            _delete(ctx, "ethernets", bond_seed)


def _exercise_object_fields(ctx, alias_uuid: str) -> None:
    for section in SECTIONS:
        name = f"{section[:4]}_matrix_obj" if section != "vlans" else "vlan280"
        body = _base_config(section, name)
        bond_seed = None
        if section == "bonds":
            bond_seed = f"{name}_eth"
            _create(ctx, "ethernets", {"name": bond_seed})
            body["interfaces"] = bond_seed
        body["addresses"] = alias_uuid
        body["nameservers.addresses"] = [alias_uuid, "1.1.1.1"]
        body["routes.to"] = [alias_uuid, "default"]
        body["routes.via"] = alias_uuid
        _create(ctx, section, body)
        stored = _section(section)[name]
        for field in OBJECT_FIELDS:
            require(ctx, field in stored, f"object field {section}.{field} persisted", f"object field {section}.{field} missing")
        _patch(ctx, section, name, {"nameservers.addresses": "8.8.8.8,1.1.1.1"})
        _patch(ctx, section, name, {"routes.to": ["default", alias_uuid]})
        _patch(ctx, section, name, {"routes.via": "1.1.1.1"})
        _patch(ctx, section, name, {"nameservers.addresses": "999.999.999.999"}, 422)
        _patch(ctx, section, name, {"routes.to": "not_an_ip_or_alias"}, 422)
        _patch(ctx, section, name, {"routes.via": ["1.1.1.1", "2.2.2.2"]})
        if section == "bonds":
            _delete(ctx, section, name)
            _delete(ctx, "ethernets", bond_seed)


def _exercise_alias_policy(ctx, alias_uuid: str, alias_name: str, group_uuid: str) -> None:
    _create(ctx, "bridges", {"name": "br_alias_uuid_api", "interfaces": _first_name("ethernets"), "addresses": alias_uuid})
    require(ctx, _section("bridges")["br_alias_uuid_api"].get("addresses") == alias_uuid, "alias_address UUID persisted", "alias_address UUID not persisted")
    _create(ctx, "bridges", {"name": "br_alias_name_api", "interfaces": _first_name("ethernets"), "addresses": alias_name})
    _create(ctx, "bridges", {"name": "br_alias_object_api", "interfaces": _first_name("ethernets"), "addresses": {"UUID": alias_uuid, "name": alias_name}})
    _create(ctx, "bridges", {"name": "br_alias_bad_object_api", "interfaces": _first_name("ethernets"), "addresses": {"UUID": alias_uuid, "name": "wrong-name"}}, 422)
    _create(ctx, "bridges", {"name": "br_alias_missing_api", "interfaces": _first_name("ethernets"), "addresses": "aliasad-missing"}, 422)
    _create(ctx, "bridges", {"name": "br_alias_group_bad_api", "interfaces": _first_name("ethernets"), "addresses": group_uuid}, 422)
    _create(ctx, "bridges", {"name": "br_alias_group_route_bad_api", "interfaces": _first_name("ethernets"), "routes.to": [group_uuid, "default"], "routes.via": alias_uuid}, 422)
    _create(ctx, "bridges", {"name": "br_alias_route_api", "interfaces": _first_name("ethernets"), "routes.to": [alias_uuid, "default"], "routes.via": alias_uuid})


def _exercise_gateway_hooks(ctx, alias_uuid: str) -> None:
    _create(ctx, "bridges", {"name": "br_gateway_api", "interfaces": _first_name("ethernets"), "gateway4": alias_uuid, "gateway6": "2001:db8::1"})
    require(ctx, _section("bridges")["br_gateway_api"].get("gateway4") == alias_uuid, "gateway4 alias persisted", "gateway4 alias missing")
    _patch(ctx, "bridges", "br_gateway_api", {"gateway4": "999.999.999.999"}, 422)
    _patch(ctx, "bridges", "br_gateway_api", {"gateway4": "192.168.1.1,192.168.1.2"}, 422)
    _patch(ctx, "bridges", "br_gateway_api", {"gateway6": "not_ipv6"}, 422)


def _exercise_bond_netplan_validation(ctx) -> None:
    # ES: Creamos ethernets sintéticas para que las pruebas de bond no dependan
    #     de miembros físicos ya esclavizados por la configuración inicial.
    # EN: Create synthetic ethernets so bond tests do not depend on physical
    #     members already enslaved by the initial configuration.
    first = "bond_seed_a_api"
    clean = "bond_seed_b_api"
    consumed = "bond_seed_c_api"
    for seed in (first, clean, consumed):
        _create(ctx, "ethernets", {"name": seed})
    _create(ctx, "bridges", {"name": "br_consumes_member_api", "interfaces": consumed})
    # ES: select_dynamic envía listas; FastAPI debe aceptarlas pero guardar CSV porque el generador actual usa split(',').
    # EN: select_dynamic sends lists; FastAPI must accept them but store CSV because the current generator uses split(',').
    _create(ctx, "bonds", {"name": "bond_list_members_api", "interfaces": [first], "parameters.mode": "active-backup"})
    require(ctx, _section("bonds")["bond_list_members_api"].get("interfaces") == first, "bond interfaces list normalized to CSV", "bond interfaces list was not normalized")
    _delete(ctx, "bonds", "bond_list_members_api")

    invalid_cases = [
        ("BOND_INTERFACES_REQUIRED", {"name": "bond_no_members_api", "parameters.mode": "active-backup"}),
        ("BOND_INTERFACE_ALREADY_USED", {"name": "bond_reuses_bridge_member_api", "interfaces": consumed, "parameters.mode": "active-backup"}),
        ("BOND_LACP_RATE_MODE_INVALID", {"name": "bond_bad_lacp_mode_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.lacp-rate": "fast"}),
        ("BOND_TRANSMIT_HASH_POLICY_MODE_INVALID", {"name": "bond_bad_hash_mode_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.transmit-hash-policy": "layer2"}),
        ("BOND_AD_SELECT_MODE_INVALID", {"name": "bond_bad_ad_select_mode_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.ad-select": "stable"}),
        ("BOND_PRIMARY_INVALID", {"name": "bond_bad_primary_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.primary": "not_member"}),
        ("BOND_PRIMARY_MODE_INVALID", {"name": "bond_bad_primary_mode_api", "interfaces": clean, "parameters.mode": "802.3ad", "parameters.primary": clean}),
        ("BOND_PRIMARY_RESELECT_POLICY_MODE_INVALID", {"name": "bond_bad_primary_reselect_no_primary_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.primary-reselect-policy": "always"}),
        ("BOND_ARP_IP_TARGETS_REQUIRED", {"name": "bond_bad_arp_missing_target_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.arp-interval": "100"}),
        ("BOND_ARP_IP_TARGETS_INVALID", {"name": "bond_bad_arp_ipv6_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.arp-interval": "100", "parameters.arp-ip-targets": ["2001:db8::1"]}),
        ("BOND_ARP_IP_TARGETS_INVALID", {"name": "bond_bad_arp_empty_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.arp-ip-targets": []}),
        ("BOND_ARP_IP_TARGETS_INVALID", {"name": "bond_bad_arp_too_many_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.arp-interval": "100", "parameters.arp-ip-targets": [f"192.0.2.{i}" for i in range(1, 18)]}),
        ("BOND_ARP_IP_TARGETS_REQUIRE_ARP_INTERVAL", {"name": "bond_bad_arp_target_no_interval_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.arp-ip-targets": ["192.0.2.1"]}),
        ("BOND_ARP_VALIDATE_REQUIRES_ARP_MONITOR", {"name": "bond_bad_arp_validate_no_monitor_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.arp-validate": "active"}),
        ("BOND_ARP_ALL_TARGETS_REQUIRES_ACTIVE_BACKUP_ARP_VALIDATE", {"name": "bond_bad_arp_all_no_validate_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.arp-interval": "100", "parameters.arp-ip-targets": ["192.0.2.1"], "parameters.arp-all-targets": "any"}),
        ("BOND_ARP_ALL_TARGETS_REQUIRES_ACTIVE_BACKUP_ARP_VALIDATE", {"name": "bond_bad_arp_all_wrong_mode_api", "interfaces": clean, "parameters.mode": "balance-rr", "parameters.arp-interval": "100", "parameters.arp-ip-targets": ["192.0.2.1"], "parameters.arp-validate": "active", "parameters.arp-all-targets": "any"}),
        ("BOND_UP_DELAY_REQUIRES_MII_MONITOR_INTERVAL", {"name": "bond_bad_up_delay_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.up-delay": "10"}),
        ("BOND_DOWN_DELAY_REQUIRES_MII_MONITOR_INTERVAL", {"name": "bond_bad_down_delay_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.down-delay": "10"}),
        ("BOND_GRATUITOUS_ARP_MODE_INVALID", {"name": "bond_bad_gratuitous_mode_api", "interfaces": clean, "parameters.mode": "802.3ad", "parameters.gratuitous-arp": "1"}),
        ("BOND_PACKETS_PER_MEMBER_MODE_INVALID", {"name": "bond_bad_packets_mode_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.packets-per-member": "1"}),
        ("BOND_PACKETS_PER_MEMBER_MODE_INVALID", {"name": "bond_bad_packets_slave_mode_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.packets-per-slave": "1"}),
        ("BOND_RESEND_IGMP_MODE_INVALID", {"name": "bond_bad_resend_mode_api", "interfaces": clean, "parameters.mode": "802.3ad", "parameters.resend-igmp": "1"}),
        ("BOND_LEARN_PACKET_INTERVAL_MODE_INVALID", {"name": "bond_bad_learn_mode_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.learn-packet-interval": "1"}),
        ("BOND_PARAMETER_NOT_SUPPORTED", {"name": "bond_bad_unknown_param_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.not-real": "x"}),
        ("BOND_ALL_MEMBERS_ACTIVE_INVALID", {"name": "bond_bad_all_members_api", "interfaces": clean, "parameters.mode": "802.3ad", "parameters.all-members-active": "yes"}),
        ("BOND_MII_MONITOR_INTERVAL_INVALID", {"name": "bond_bad_miimon_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.mii-monitor-interval": "abc"}),
        ("BOND_UP_DELAY_INVALID", {"name": "bond_bad_up_delay_text_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.up-delay": "abc"}),
        ("BOND_DOWN_DELAY_INVALID", {"name": "bond_bad_down_delay_text_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.down-delay": "abc"}),
        ("BOND_MIN_LINKS_INVALID", {"name": "bond_bad_min_links_api", "interfaces": clean, "parameters.mode": "802.3ad", "parameters.min-links": "abc"}),
        ("BOND_ARP_INTERVAL_INVALID", {"name": "bond_bad_arp_interval_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.arp-interval": "abc"}),
        ("BOND_GRATUITOUS_ARP_INVALID", {"name": "bond_bad_gratuitous_range_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.gratuitous-arp": "0"}),
        ("BOND_PACKETS_PER_MEMBER_INVALID", {"name": "bond_bad_packets_range_api", "interfaces": clean, "parameters.mode": "balance-rr", "parameters.packets-per-member": "65536"}),
        ("BOND_RESEND_IGMP_INVALID", {"name": "bond_bad_resend_range_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.resend-igmp": "256"}),
        ("BOND_LEARN_PACKET_INTERVAL_INVALID", {"name": "bond_bad_learn_range_api", "interfaces": clean, "parameters.mode": "balance-tlb", "parameters.learn-packet-interval": "0"}),
        ("BOND_FIELD_NOT_SUPPORTED", {"name": "bond_bad_field_api", "interfaces": clean, "parameters.mode": "active-backup", "custom.extra": "x"}),
        ("BOND_MTU_INVALID", {"name": "bond_bad_mtu_api", "interfaces": clean, "parameters.mode": "active-backup", "mtu": "abc"}),
        ("BOND_ROUTE_METRIC_INVALID", {"name": "bond_bad_metric_api", "interfaces": clean, "parameters.mode": "active-backup", "routes.metric": "abc"}),
        ("BOND_RENDERER_INVALID", {"name": "bond_bad_renderer_api", "interfaces": clean, "parameters.mode": "active-backup", "renderer": "bad"}),
        ("BOND_DHCP_IDENTIFIER_INVALID", {"name": "bond_bad_dhcp_id_api", "interfaces": clean, "parameters.mode": "active-backup", "dhcp-identifier": "bad"}),
        ("BOND_MACADDRESS_INVALID", {"name": "bond_bad_mac_api", "interfaces": clean, "parameters.mode": "active-backup", "macaddress": "bad"}),
        ("BOND_DHCP4_HOSTNAME_INVALID", {"name": "bond_bad_hostname_api", "interfaces": clean, "parameters.mode": "active-backup", "dhcp4-overrides.hostname": "bad host"}),
        ("BOND_LINK_LOCAL_INVALID", {"name": "bond_bad_link_local_api", "interfaces": clean, "parameters.mode": "active-backup", "link-local": "ipv4,bad"}),
        ("BOND_NAMESERVER_SEARCH_INVALID", {"name": "bond_bad_search_api", "interfaces": clean, "parameters.mode": "active-backup", "nameservers.search": "bad domain"}),
        ("BOND_IPV6_ADDRESS_GENERATION_INVALID", {"name": "bond_bad_ipv6_gen_api", "interfaces": clean, "parameters.mode": "active-backup", "ipv6-address-generation": "bad"}),
        ("BOND_IPV6_ADDRESS_TOKEN_INVALID", {"name": "bond_bad_ipv6_token_api", "interfaces": clean, "parameters.mode": "active-backup", "ipv6-address-generation": "eui64", "ipv6-address-token": "::1"}),
        ("BOND_LEGACY_ROUTES_INVALID", {"name": "bond_bad_legacy_routes_api", "interfaces": clean, "parameters.mode": "active-backup", "routes": {"to": "default"}}),
    ]
    for expected_detail, body in invalid_cases:
        _create_error(ctx, "bonds", body, expected_detail)

    # ES: estas rutas pasan por la validación genérica antes de llegar a service_bond; también quedan cubiertas.
    # EN: these paths are caught by generic validation before service_bond; they are still covered.
    _create_error(ctx, "bonds", {"name": "bond_bad_duplicate_api", "interfaces": f"{first},{first}", "parameters.mode": "active-backup"}, "DUPLICATE_MULTISELECT_VALUE")
    _create_error(ctx, "bonds", {"name": "bond_bad_missing_member_api", "interfaces": "not_real", "parameters.mode": "active-backup"}, "INVALID_MULTISELECT_VALUE")
    _create(ctx, "bonds", {"name": "bond_self_existing_api", "interfaces": clean, "parameters.mode": "active-backup"})
    _patch_existing_error(ctx, "bonds", "bond_self_existing_api", {"interfaces": "bond_self_existing_api"}, "BOND_SELF_REFERENCE")
    _delete(ctx, "bonds", "bond_self_existing_api")

    valid_cases = [
        {"name": "bond_valid_802_api", "interfaces": clean, "parameters.mode": "802.3ad", "parameters.lacp-rate": "fast", "parameters.transmit-hash-policy": "layer3+4", "parameters.ad-select": "stable", "parameters.min-links": "1", "parameters.all-members-active": "true"},
        {"name": "bond_valid_tlb_api", "interfaces": clean, "parameters.mode": "balance-tlb", "parameters.primary": clean, "parameters.primary-reselect-policy": "always", "parameters.transmit-hash-policy": "layer2", "parameters.learn-packet-interval": "1", "parameters.resend-igmp": "1"},
        {"name": "bond_valid_rr_api", "interfaces": clean, "parameters.mode": "balance-rr", "parameters.packets-per-member": "0", "parameters.resend-igmp": "0"},
        {"name": "bond_valid_arp_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.arp-interval": "100", "parameters.arp-ip-targets": ["192.0.2.1"], "parameters.arp-validate": "active", "parameters.arp-all-targets": "any"},
        {"name": "bond_valid_miimon_api", "interfaces": clean, "parameters.mode": "active-backup", "parameters.mii-monitor-interval": "100", "parameters.up-delay": "200", "parameters.down-delay": "200"},
    ]
    for body in valid_cases:
        _create(ctx, "bonds", body)
        _delete(ctx, "bonds", body["name"])
    _delete(ctx, "bridges", "br_consumes_member_api")
    for seed in (first, clean, consumed):
        _delete(ctx, "ethernets", seed)


def _exercise_interface_family_netplan_validation(ctx) -> None:
    first = _first_name("ethernets")
    first_bridge = _first_name("bridges")
    first_wifi = "wifi_vlan_link_seed_api"
    _create(ctx, "wifis", {"name": first_wifi})

    # ES: Ethernets: checks físicos/Netplan sin tocar alias/IP.
    # EN: Ethernets: physical/Netplan checks without touching aliases/IPs.
    _create(ctx, "ethernets", {"name": "eth_valid_netplan_api", "match.macaddress": "aa:bb:cc:dd:ee:01", "set-name": "ethvalid1", "mtu": "1500"})
    ethernet_invalid = [
        ("ETHERNET_MTU_INVALID", {"name": "eth_bad_mtu_api", "mtu": "abc"}),
        ("ETHERNET_MTU_INVALID", {"name": "eth_bad_mtu_zero_api", "mtu": "0"}),
        ("ETHERNET_ROUTE_METRIC_INVALID", {"name": "eth_bad_metric_api", "routes.metric": "abc"}),
        ("ETHERNET_MACADDRESS_INVALID", {"name": "eth_bad_mac_api", "macaddress": "bad"}),
        ("ETHERNET_MATCH_MACADDRESS_INVALID", {"name": "eth_bad_match_mac_api", "match.macaddress": "bad"}),
        ("ETHERNET_SET_NAME_REQUIRES_MATCH", {"name": "eth_bad_set_name_api", "set-name": "ethx1"}),
        ("ETHERNET_SET_NAME_INVALID", {"name": "eth_bad_set_name_chars_api", "match.macaddress": "aa:bb:cc:dd:ee:03", "set-name": "interface-name-too-long"}),
        ("ETHERNET_EMBEDDED_SWITCH_MODE_INVALID", {"name": "eth_bad_eswitch_api", "embedded-switch-mode": "bad"}),
        ("ETHERNET_INFINIBAND_MODE_INVALID", {"name": "eth_bad_infiniband_api", "infiniband-mode": "bad"}),
        ("ETHERNET_VIRTUAL_FUNCTION_COUNT_INVALID", {"name": "eth_bad_vf_api", "virtual-function-count": "abc"}),
        ("ETHERNET_DELAY_VF_REBIND_INVALID", {"name": "eth_bad_delay_vf_api", "delay-virtual-functions-rebind": "yes"}),
        ("ETHERNET_DHCP4_HOSTNAME_INVALID", {"name": "eth_bad_hostname_api", "dhcp4-overrides.hostname": "bad host"}),
        ("ETHERNET_FIELD_NOT_SUPPORTED", {"name": "eth_bad_field_api", "custom.extra": "x"}),
        ("ETHERNET_RENDERER_INVALID", {"name": "eth_bad_renderer_api", "renderer": "bad"}),
        ("ETHERNET_DHCP_IDENTIFIER_INVALID", {"name": "eth_bad_dhcp_id_api", "dhcp-identifier": "bad"}),
        ("ETHERNET_LINK_LOCAL_INVALID", {"name": "eth_bad_link_local_api", "link-local": "ipv4,bad"}),
        ("ETHERNET_NAMESERVER_SEARCH_INVALID", {"name": "eth_bad_search_api", "nameservers.search": "bad domain"}),
        ("ETHERNET_IPV6_ADDRESS_GENERATION_INVALID", {"name": "eth_bad_ipv6_gen_api", "ipv6-address-generation": "bad"}),
        ("ETHERNET_IPV6_ADDRESS_TOKEN_INVALID", {"name": "eth_bad_ipv6_token_api", "ipv6-address-generation": "eui64", "ipv6-address-token": "::1"}),
        ("ETHERNET_LEGACY_ROUTES_INVALID", {"name": "eth_bad_legacy_routes_api", "routes": {"to": "default"}}),
    ]
    for expected_detail, body in ethernet_invalid:
        _create_error(ctx, "ethernets", body, expected_detail)

    # ES: Bridges: members y parameters.* que Netplan sí entiende.
    # EN: Bridges: members and parameters.* accepted by Netplan.
    _create(ctx, "bridges", {"name": "br_valid_netplan_api", "interfaces": first, "parameters.priority": "100", "parameters.port-priority": {first: "10"}, "parameters.path-cost": {first: "100"}})
    bridge_invalid = [
        ("INVALID_SELECT_VALUE", {"name": "br_bad_dup_api", "interfaces": f"{first},{first}"}),
        ("INVALID_SELECT_VALUE", {"name": "br_bad_missing_member_api", "interfaces": "not_real"}),
        ("BRIDGE_INTERFACES_REQUIRED", {"name": "br_no_members_api"}),
        ("BRIDGE_PRIORITY_INVALID", {"name": "br_bad_priority_api", "interfaces": first, "parameters.priority": "70000"}),
        ("BRIDGE_PARAMETER_NOT_SUPPORTED", {"name": "br_bad_param_api", "interfaces": first, "parameters.not-real": "x"}),
        ("BRIDGE_PORT_PRIORITY_INVALID", {"name": "br_bad_port_priority_api", "interfaces": first, "parameters.port-priority": {first: "100"}}),
        ("BRIDGE_PORT_PRIORITY_INVALID", {"name": "br_bad_port_priority_shape_api", "interfaces": first, "parameters.port-priority": "bad"}),
        ("BRIDGE_PATH_COST_INVALID", {"name": "br_bad_path_cost_api", "interfaces": first, "parameters.path-cost": {"not_member": "10"}}),
        ("BRIDGE_PATH_COST_INVALID", {"name": "br_empty_path_cost_api", "interfaces": first, "parameters.path-cost": {}}),
        ("INVALID_CHECKBOX_VALUE", {"name": "br_bad_stp_api", "interfaces": first, "parameters.stp": "yes"}),
        ("BRIDGE_FORWARD_DELAY_INVALID", {"name": "br_bad_forward_delay_api", "interfaces": first, "parameters.forward-delay": "abc"}),
        ("BRIDGE_HELLO_TIME_INVALID", {"name": "br_bad_hello_api", "interfaces": first, "parameters.hello-time": "abc"}),
        ("BRIDGE_MAX_AGE_INVALID", {"name": "br_bad_max_age_api", "interfaces": first, "parameters.max-age": "abc"}),
        ("BRIDGE_AGEING_TIME_INVALID", {"name": "br_bad_ageing_api", "interfaces": first, "parameters.ageing-time": "abc"}),
        ("BRIDGE_AGING_TIME_INVALID", {"name": "br_bad_aging_api", "interfaces": first, "parameters.aging-time": "abc"}),
        ("BRIDGE_MTU_INVALID", {"name": "br_bad_mtu_api", "interfaces": first, "mtu": "abc"}),
        ("BRIDGE_ROUTE_METRIC_INVALID", {"name": "br_bad_metric_api", "interfaces": first, "routes.metric": "abc"}),
        ("BRIDGE_MACADDRESS_INVALID", {"name": "br_bad_mac_api", "interfaces": first, "macaddress": "bad"}),
        ("BRIDGE_DHCP4_HOSTNAME_INVALID", {"name": "br_bad_hostname_api", "interfaces": first, "dhcp4-overrides.hostname": "bad host"}),
        ("BRIDGE_FIELD_NOT_SUPPORTED", {"name": "br_bad_field_api", "interfaces": first, "custom.extra": "x"}),
        ("BRIDGE_RENDERER_INVALID", {"name": "br_bad_renderer_api", "interfaces": first, "renderer": "bad"}),
        ("BRIDGE_DHCP_IDENTIFIER_INVALID", {"name": "br_bad_dhcp_id_api", "interfaces": first, "dhcp-identifier": "bad"}),
        ("BRIDGE_LINK_LOCAL_INVALID", {"name": "br_bad_link_local_api", "interfaces": first, "link-local": "ipv4,bad"}),
        ("BRIDGE_NAMESERVER_SEARCH_INVALID", {"name": "br_bad_search_api", "interfaces": first, "nameservers.search": "bad domain"}),
        ("BRIDGE_IPV6_ADDRESS_GENERATION_INVALID", {"name": "br_bad_ipv6_gen_api", "interfaces": first, "ipv6-address-generation": "bad"}),
        ("BRIDGE_IPV6_ADDRESS_TOKEN_INVALID", {"name": "br_bad_ipv6_token_api", "interfaces": first, "ipv6-address-generation": "eui64", "ipv6-address-token": "::1"}),
        ("BRIDGE_LEGACY_ROUTES_INVALID", {"name": "br_bad_legacy_routes_api", "interfaces": first, "routes": {"to": "default"}}),
    ]
    for expected_detail, body in bridge_invalid:
        _create_error(ctx, "bridges", body, expected_detail)
    _create(ctx, "bridges", {"name": "br_self_existing_api", "interfaces": first})
    _patch_existing_error(ctx, "bridges", "br_self_existing_api", {"interfaces": "br_self_existing_api"}, "BRIDGE_SELF_REFERENCE")

    # ES: VLAN mantiene la validación existente de id/link y añade tipo de link/parameters.*.
    # EN: VLAN keeps existing id/link validation and adds link-type/parameters.* checks.
    vlan_invalid = [
        ("VLAN_LINK_TYPE_INVALID", {"name": "vlan281", "id": "281", "link": first_wifi}),
        ("VLAN_PARAMETER_NOT_SUPPORTED", {"name": "vlan282", "id": "282", "link": first_bridge, "parameters.not-real": "x"}),
        ("VLAN_MTU_INVALID", {"name": "vlan283", "id": "283", "link": first_bridge, "mtu": "abc"}),
        ("VLAN_ROUTE_METRIC_INVALID", {"name": "vlan284", "id": "284", "link": first_bridge, "routes.metric": "abc"}),
        ("VLAN_MACADDRESS_INVALID", {"name": "vlan285", "id": "285", "link": first_bridge, "macaddress": "bad"}),
        ("VLAN_DHCP4_HOSTNAME_INVALID", {"name": "vlan286", "id": "286", "link": first_bridge, "dhcp4-overrides.hostname": "bad host"}),
        ("VLAN_FIELD_NOT_SUPPORTED", {"name": "vlan287", "id": "287", "link": first_bridge, "custom.extra": "x"}),
        ("VLAN_RENDERER_INVALID", {"name": "vlan288", "id": "288", "link": first_bridge, "renderer": "bad"}),
        ("VLAN_DHCP_IDENTIFIER_INVALID", {"name": "vlan289", "id": "289", "link": first_bridge, "dhcp-identifier": "bad"}),
        ("VLAN_LINK_LOCAL_INVALID", {"name": "vlan290", "id": "290", "link": first_bridge, "link-local": "ipv4,bad"}),
        ("VLAN_NAMESERVER_SEARCH_INVALID", {"name": "vlan291", "id": "291", "link": first_bridge, "nameservers.search": "bad domain"}),
        ("VLAN_IPV6_ADDRESS_GENERATION_INVALID", {"name": "vlan292", "id": "292", "link": first_bridge, "ipv6-address-generation": "bad"}),
        ("VLAN_IPV6_ADDRESS_TOKEN_INVALID", {"name": "vlan293", "id": "293", "link": first_bridge, "ipv6-address-generation": "eui64", "ipv6-address-token": "::1"}),
        ("VLAN_LEGACY_ROUTES_INVALID", {"name": "vlan294", "id": "294", "link": first_bridge, "routes": {"to": "default"}}),
    ]
    for expected_detail, body in vlan_invalid:
        _create_error(ctx, "vlans", body, expected_detail)

    # ES: Wi-Fi valida access-points.* que el generador puede emitir.
    # EN: Wi-Fi validates access-points.* that the generator can emit.
    _create(ctx, "wifis", {"name": "wifi_valid_netplan_api", "access-points.TestSSID.mode": "infrastructure", "access-points.TestSSID.band": "5GHz", "access-points.TestSSID.channel": "36", "access-points.TestSSID.hidden": "true", "access-points.TestSSID.bssid": "aa:bb:cc:dd:ee:02"})
    wifi_invalid = [
        ("WIFI_WAKEONLAN_NOT_SUPPORTED", {"name": "wifi_bad_wol_api", "wakeonlan": "True"}),
        ("WIFI_ACCESS_POINT_FIELD_INVALID", {"name": "wifi_bad_ap_shape_api", "access-points.Bad.too.many": "x"}),
        ("WIFI_ACCESS_POINT_FIELD_NOT_SUPPORTED", {"name": "wifi_bad_field_api", "access-points.Bad.not-real": "x"}),
        ("WIFI_ACCESS_POINT_MODE_INVALID", {"name": "wifi_bad_ap_mode_api", "access-points.Bad.mode": "ap"}),
        ("WIFI_ACCESS_POINT_BAND_INVALID", {"name": "wifi_bad_band_api", "access-points.Bad.band": "6GHz"}),
        ("WIFI_ACCESS_POINT_CHANNEL_REQUIRES_BAND", {"name": "wifi_bad_channel_api", "access-points.Bad.channel": "6"}),
        ("WIFI_ACCESS_POINT_CHANNEL_INVALID", {"name": "wifi_bad_channel_text_api", "access-points.Bad.band": "5GHz", "access-points.Bad.channel": "abc"}),
        ("WIFI_ACCESS_POINT_HIDDEN_INVALID", {"name": "wifi_bad_hidden_api", "access-points.Bad.hidden": "yes"}),
        ("WIFI_ACCESS_POINT_BSSID_INVALID", {"name": "wifi_bad_bssid_api", "access-points.Bad.bssid": "bad"}),
        ("WIFI_MTU_INVALID", {"name": "wifi_bad_mtu_api", "mtu": "abc"}),
        ("WIFI_ROUTE_METRIC_INVALID", {"name": "wifi_bad_metric_api", "routes.metric": "abc"}),
        ("WIFI_MACADDRESS_INVALID", {"name": "wifi_bad_mac_api", "macaddress": "bad"}),
        ("WIFI_DHCP4_HOSTNAME_INVALID", {"name": "wifi_bad_hostname_api", "dhcp4-overrides.hostname": "bad host"}),
        ("WIFI_FIELD_NOT_SUPPORTED", {"name": "wifi_bad_unknown_api", "custom.extra": "x"}),
        ("WIFI_RENDERER_INVALID", {"name": "wifi_bad_renderer_api", "renderer": "bad"}),
        ("WIFI_DHCP_IDENTIFIER_INVALID", {"name": "wifi_bad_dhcp_id_api", "dhcp-identifier": "bad"}),
        ("WIFI_LINK_LOCAL_INVALID", {"name": "wifi_bad_link_local_api", "link-local": "ipv4,bad"}),
        ("WIFI_NAMESERVER_SEARCH_INVALID", {"name": "wifi_bad_search_api", "nameservers.search": "bad domain"}),
        ("WIFI_IPV6_ADDRESS_GENERATION_INVALID", {"name": "wifi_bad_ipv6_gen_api", "ipv6-address-generation": "bad"}),
        ("WIFI_IPV6_ADDRESS_TOKEN_INVALID", {"name": "wifi_bad_ipv6_token_api", "ipv6-address-generation": "eui64", "ipv6-address-token": "::1"}),
        ("WIFI_LEGACY_ROUTES_INVALID", {"name": "wifi_bad_legacy_routes_api", "routes": {"to": "default"}}),
    ]
    for expected_detail, body in wifi_invalid:
        _create_error(ctx, "wifis", body, expected_detail)



def _exercise_direct_validator_edges(ctx) -> None:
    # ES: Algunas ramas específicas quedan protegidas antes por validate_interface_field_values() en la API.
    # Para demostrar que los validadores familiares también rechazan esas configuraciones si reciben
    # datos ya normalizados, se prueban aquí directamente contra las funciones puras.
    # EN: Some specific branches are protected earlier by validate_interface_field_values() in the API.
    # To prove family validators also reject them if given already-normalized data, test the pure functions directly.
    import sys
    from fastapi import HTTPException

    app_path = str(Path(__file__).resolve().parents[4] / "app")
    if app_path not in sys.path:
        sys.path.insert(0, app_path)
    from modules.interfaces.service_bond import validate_and_normalize_bond_rule
    from modules.interfaces.service_bridge import validate_and_normalize_bridge_rule

    cfg = {"network": {"ethernets": {"ens19": {}}, "bridges": {"br0": {"interfaces": "ens19"}}, "bonds": {"bond0": {}}, "vlans": {}, "wifis": {}}}
    cases = [
        ("direct BOND_INTERFACES_DUPLICATED", validate_and_normalize_bond_rule, {"name": "bondx", "interfaces": "ens19,ens19", "parameters.mode": "active-backup"}, "BOND_INTERFACES_DUPLICATED"),
        ("direct BOND_INTERFACE_NOT_FOUND", validate_and_normalize_bond_rule, {"name": "bondx", "interfaces": "missing", "parameters.mode": "active-backup"}, "BOND_INTERFACE_NOT_FOUND"),
        ("direct BOND_INTERFACE_ALREADY_USED", validate_and_normalize_bond_rule, {"name": "bondx", "interfaces": "ens19", "parameters.mode": "active-backup"}, "BOND_INTERFACE_ALREADY_USED"),
        ("direct BRIDGE_INTERFACES_REQUIRED", validate_and_normalize_bridge_rule, {"name": "brx"}, "BRIDGE_INTERFACES_REQUIRED"),
        ("direct BRIDGE_INTERFACES_DUPLICATED", validate_and_normalize_bridge_rule, {"name": "brx", "interfaces": "ens19,ens19"}, "BRIDGE_INTERFACES_DUPLICATED"),
        ("direct BRIDGE_INTERFACE_NOT_FOUND", validate_and_normalize_bridge_rule, {"name": "brx", "interfaces": "missing"}, "BRIDGE_INTERFACE_NOT_FOUND"),
        ("direct BRIDGE_STP_INVALID", validate_and_normalize_bridge_rule, {"name": "brx", "interfaces": "ens19", "parameters.stp": "yes"}, "BRIDGE_STP_INVALID"),
    ]
    for label, fn, rule, expected in cases:
        try:
            fn(dict(rule), cfg)
        except HTTPException as exc:
            require(ctx, exc.detail == expected, f"{label} rejected with {expected}", f"{label} wrong detail: {exc.detail}")
        else:
            require(ctx, False, label, f"{label} unexpectedly accepted")


def _exercise_additional_alias_validation_hooks(ctx, alias_uuid: str) -> None:
    fields = [
        "local",
        "remote",
        "peers.allowed-ips",
        "peers.endpoint",
        "routing-policy.from",
        "routing-policy.to",
    ]
    for index, field in enumerate(fields, start=1):
        name = f"br_alias_hook_{index}"
        body = {"name": name, "interfaces": _first_name("ethernets"), field: alias_uuid}
        _create(ctx, "bridges", body)
        require(ctx, _section("bridges")[name].get(field) == alias_uuid, f"alias validation hook {field} accepts alias_address", f"alias validation hook {field} not persisted")
        _patch(ctx, "bridges", name, {field: "999.999.999.999"}, 422)


def _exercise_extra_field_passthrough(ctx) -> None:
    _create_error(ctx, "bridges", {"name": "br_extra_field_api", "interfaces": _first_name("ethernets"), "custom.extra": "kept"}, "BRIDGE_FIELD_NOT_SUPPORTED")


def _write_interfaces(data: dict[str, Any]) -> None:
    INTERFACES.write_text(json.dumps(data, ensure_ascii=False, indent=4), encoding="utf-8")
    INTERFACES.chmod(0o664)


def _exercise_candidate_shape_errors(ctx) -> None:
    original = _read()
    cases = [
        ("empty candidate", {}, 500),
        ("missing network", {"not_network": {}}, 500),
        ("missing section", {"network": {"ethernets": {}, "bridges": {}, "bonds": {}, "vlans": {}}}, 500),
        ("invalid section type", {"network": {"ethernets": [], "bridges": {}, "bonds": {}, "vlans": {}, "wifis": {}}}, 500),
    ]
    for label, data, expected in cases:
        _write_interfaces(data)
        status, payload = call(ctx, label, "GET", "/api/v1/interfaces")
        require(ctx, status == expected, f"candidate shape error {label} returned {expected}", f"candidate shape error {label} returned {status}: {_detail(payload)}")
        _write_interfaces(original)


def _exercise_name_and_shape_errors(ctx) -> None:
    _create(ctx, "ethernets", {"dhcp4": "True"}, 422)
    bridge_name = _first_name("bridges")
    _patch(ctx, "bridges", bridge_name, {"name": "different_name"}, 200)
    require(ctx, bridge_name in _section("bridges"), "patch body name ignored and uuid target preserved", "patch body name changed interface key")
    _create(ctx, "bridges", {"name": "br_empty_values", "interfaces": _first_name("ethernets"), "addresses": "", "nameservers.addresses": [], "routes.to": "", "routes.via": ""})
    status, payload = call(ctx, "create invalid payload type", "POST", "/api/v1/interfaces/bridges", {"config": []})
    require(ctx, status == 422, "invalid payload type rejected", f"invalid payload type not rejected: {status} {_detail(payload)}")
    status, payload = call(ctx, "patch invalid payload type", "PATCH", f"/api/v1/interfaces/bridges/{_uuid_for('bridges', _first_name('bridges'))}", {"config": []})
    require(ctx, status == 422, "invalid patch payload type rejected", f"invalid patch payload type not rejected: {status} {_detail(payload)}")


def run(ctx) -> None:
    ctx.log("=== INTERFACES DESTRUCTIVE ===")
    _backup()
    try:
        status, payload = call(ctx, "scan interfaces", "POST", "/api/v1/interfaces/scan")
        _expect_role(ctx, status, 200, 403, "scan interfaces")

        if _admin_only(ctx):
            alias_address = _first_alias("alias_address")
            alias_group = _first_alias("alias_addr_group")
            alias_uuid = alias_address["UUID"]
            alias_name = alias_address["name"]
            group_uuid = alias_group["UUID"]

            _exercise_alias_policy(ctx, alias_uuid, alias_name, group_uuid)
            _exercise_gateway_hooks(ctx, alias_uuid)
            _exercise_bond_netplan_validation(ctx)
            _exercise_interface_family_netplan_validation(ctx)
            _exercise_direct_validator_edges(ctx)
            _exercise_additional_alias_validation_hooks(ctx, alias_uuid)
            _exercise_extra_field_passthrough(ctx)
            _exercise_candidate_shape_errors(ctx)
            _exercise_valid_selects(ctx)
            _exercise_invalid_selects(ctx)
            _exercise_checkboxes(ctx)
            _exercise_object_fields(ctx, alias_uuid)
            _exercise_name_and_shape_errors(ctx)

        _create_patch_delete(ctx, "ethernets", {"name": "ens_test_api", "dhcp4": "True"}, "ens_test_api", {"dhcp4": "False"}, "dhcp4", "False")
        _create_patch_delete(ctx, "bridges", {"name": "br_test_api", "interfaces": _first_name("ethernets"), "addresses": "192.168.250.1/24"}, "br_test_api", {"addresses": "192.168.250.2/24"}, "addresses", "192.168.250.2/24")
        if _admin_only(ctx):
            _create(ctx, "ethernets", {"name": "bond_crud_seed_api"})
        _create_patch_delete(ctx, "bonds", {"interfaces": "bond_crud_seed_api", "parameters.mode": "active-backup"}, "bond0", {"dhcp4": "False"}, "dhcp4", "False")
        if _admin_only(ctx):
            _delete(ctx, "ethernets", "bond_crud_seed_api")
        _create_patch_delete(ctx, "vlans", {"id": "250", "link": _first_name("bridges"), "addresses": "10.250.0.1/24"}, "vlan250", {"addresses": "10.250.0.2/24"}, "addresses", "10.250.0.2/24")
        _create_patch_delete(ctx, "wifis", {"addresses": "192.168.60.1/24"}, "wlan0", {"addresses": "192.168.60.2/24"}, "addresses", "192.168.60.2/24")

        negative_cases = [
            ("invalid section generic", "GET", "/api/v1/interfaces/section/notreal", None, 422),
            ("invalid bridge member", "POST", "/api/v1/interfaces/bridges", {"config": {"name": "br_bad_api", "interfaces": "no_such_iface"}}, 422),
            ("duplicate bond member", "POST", "/api/v1/interfaces/bonds", {"config": {"name": "bond_bad_api", "interfaces": f"{_first_name('ethernets')},{_first_name('ethernets')}"}}, 422),
            ("invalid checkbox", "POST", "/api/v1/interfaces/bridges", {"config": {"name": "br_bad_checkbox", "interfaces": _first_name("ethernets"), "dhcp4": "yes"}}, 422),
            ("invalid ip", "POST", "/api/v1/interfaces/bridges", {"config": {"name": "br_bad_ip", "interfaces": _first_name("ethernets"), "addresses": "999.999.999.999"}}, 422),
            ("multiple address in single field", "POST", "/api/v1/interfaces/bridges", {"config": {"name": "br_bad_multi_ip", "interfaces": _first_name("ethernets"), "addresses": "192.168.1.1/24,192.168.1.2/24"}}, 422),
            ("vlan missing id", "POST", "/api/v1/interfaces/vlans", {"config": {"link": _first_name("bridges")}}, 422),
            ("vlan non numeric", "POST", "/api/v1/interfaces/vlans", {"config": {"id": "abc", "link": _first_name("bridges")}}, 422),
            ("vlan out of range", "POST", "/api/v1/interfaces/vlans", {"config": {"id": "5000", "link": _first_name("bridges")}}, 422),
            ("vlan missing link", "POST", "/api/v1/interfaces/vlans", {"config": {"id": "251"}}, 422),
            ("vlan name mismatch", "POST", "/api/v1/interfaces/vlans", {"config": {"name": "vlan999", "id": "251", "link": _first_name("bridges")}}, 422),
            ("update invalid uuid", "PATCH", "/api/v1/interfaces/bridges/br_missing_api", {"config": {"addresses": "192.168.1.1/24"}}, 422),
            ("delete invalid uuid", "DELETE", "/api/v1/interfaces/bridges/br_missing_api", None, 422),
            ("update missing interface uuid", "PATCH", "/api/v1/interfaces/bridges/bridge-missingapi-19700101000000000-0001", {"config": {"addresses": "192.168.1.1/24"}}, 404),
            ("delete missing interface uuid", "DELETE", "/api/v1/interfaces/bridges/bridge-missingapi-19700101000000000-0001", None, 404),
        ]
        for name, method, path, body, admin_expected in negative_cases:
            status, payload = call(ctx, name, method, path, body)
            _expect_role(ctx, status, admin_expected, 403 if method in {"POST", "PATCH", "DELETE"} else admin_expected, name)

        if _admin_only(ctx):
            status, payload = call(ctx, "create duplicate vlan first", "POST", "/api/v1/interfaces/vlans", {"config": {"id": "252", "link": _first_name("bridges")}})
            require(ctx, status == 200 and payload.get("name") == "vlan252", "duplicate vlan seed created", "duplicate vlan seed failed")
            status, payload = call(ctx, "reject duplicate vlan id link", "POST", "/api/v1/interfaces/vlans", {"config": {"name": "vlan252_alt", "id": "252", "link": _first_name("bridges")}})
            require(ctx, status in {409, 422}, f"duplicate vlan id+link rejected", f"duplicate vlan id+link not rejected: {status} {_detail(payload)}")
    finally:
        _restore(ctx)
