"""
Lógica del módulo Interfaces.
Interfaces module logic.

Gestiona la configuración de red declarativa en candidate/interfaces.json.
Siempre opera sobre /var/lib/praesidium/candidate/interfaces.json.
"""

from __future__ import annotations

import subprocess
from copy import deepcopy
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid, is_internal_uuid, parse_internal_uuid

from modules.alias_ip.domain import validate_mixed_ip_references
from modules.alias_ip.repository import read_config as read_alias_ip_config
from modules.interfaces import repository
from modules.interfaces.service_bond import validate_and_normalize_bond_rule
from modules.interfaces.service_bridge import validate_and_normalize_bridge_rule
from modules.interfaces.service_ethernet import validate_and_normalize_ethernet_rule
from modules.interfaces.service_vlan import validate_and_normalize_vlan_netplan_rule
from modules.interfaces.service_wifi import validate_and_normalize_wifi_rule

INTERFACES_SCAN_SCRIPT = "/var/lib/praesidium/scripts/checks/check_interfaces/main_interfaces_check.py"
ALLOWED_SECTIONS = ("bonds", "bridges", "ethernets", "vlans", "wifis")
PREFIX_MAP = {
    "bridges": "br",
    "bonds": "bond",
    "ethernets": "eth",
    "vlans": "vlan",
    "wifis": "wlan",
}
INTERFACE_UUID_PREFIXES = {
    "ethernets": "ethernet",
    "bridges": "bridge",
    "wifis": "wifi",
    "bonds": "bond",
    "vlans": "vlan",
}
FIELD_CONFIG: dict[str, dict[str, Any]] = {
    "ethernets": {
        "select": {
            "ipv6-privacy": [
                "",
                "true",
                "false"
            ]
        },
        "object_multiselect": {
            "addresses": [],
            "nameservers.addresses": [],
            "routes.to": [],
            "routes.via": []
        },
        "checkbox": {
            "dhcp4": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp6": {
                "checked": "True",
                "unchecked": "False"
            },
            "optional": {
                "checked": "True",
                "unchecked": "False"
            },
            "accept-ra": {
                "checked": "True",
                "unchecked": "False"
            },
            "wakeonlan": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp4-overrides.use-dns": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp4-overrides.use-routes": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp4-overrides.send-hostname": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp4-overrides.use-hostname": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp6-overrides.use-dns": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp6-overrides.use-routes": {
                "checked": "True",
                "unchecked": "False"
            }
        },
        "not_editable": {
            "name": []
        }
    },
    "bridges": {
        "select": {
            "interfaces": [
                ""
            ],
            "ipv6-privacy": [
                "",
                "true",
                "false"
            ]
        },
        "object_multiselect": {
            "addresses": [],
            "nameservers.addresses": [],
            "routes.to": [],
            "routes.via": []
        },
        "checkbox": {
            "dhcp4": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp6": {
                "checked": "True",
                "unchecked": "False"
            },
            "optional": {
                "checked": "True",
                "unchecked": "False"
            },
            "accept-ra": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp4-overrides.use-dns": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp4-overrides.use-routes": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp4-overrides.send-hostname": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp4-overrides.use-hostname": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp6-overrides.use-dns": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp6-overrides.use-routes": {
                "checked": "True",
                "unchecked": "False"
            },
            "parameters.stp": {
                "checked": "True",
                "unchecked": "False"
            }
        },
        "not_editable": {
            "name": []
        }
    },
    "vlans": {
        "select": {
            "link": [
                ""
            ],
            "ipv6-privacy": [
                "",
                "true",
                "false"
            ]
        },
        "object_multiselect": {
            "addresses": [],
            "nameservers.addresses": [],
            "routes.to": [],
            "routes.via": []
        },
        "checkbox": {
            "dhcp4": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp6": {
                "checked": "True",
                "unchecked": "False"
            }
        },
        "not_editable": {
            "name": []
        }
    },
    "bonds": {
        "select": {
            "parameters.mode": [
                "",
                "balance-rr",
                "active-backup",
                "balance-xor",
                "broadcast",
                "802.3ad",
                "balance-tlb",
                "balance-alb"
            ],
            "parameters.lacp-rate": [
                "",
                "slow",
                "fast"
            ],
            "parameters.transmit-hash-policy": [
                "",
                "layer2",
                "layer3+4",
                "layer2+3",
                "encap2+3",
                "encap3+4"
            ],
            "ipv6-privacy": [
                "",
                "true",
                "false"
            ]
        },
        "multiselect": {
            "interfaces": [
                ""
            ]
        },
        "object_multiselect": {
            "addresses": [],
            "nameservers.addresses": [],
            "routes.to": [],
            "routes.via": []
        },
        "checkbox": {
            "dhcp4": {
                "checked": "True",
                "unchecked": "False"
            },
            "dhcp6": {
                "checked": "True",
                "unchecked": "False"
            }
        },
        "not_editable": {
            "name": []
        }
    },
    "wifis": {
        "select": {
            "ipv6-privacy": [
                "",
                "true",
                "false"
            ]
        },
        "object_multiselect": {
            "addresses": [],
            "nameservers.addresses": [],
            "routes.to": [],
            "routes.via": []
        },
        "checkbox": {},
        "not_editable": {
            "name": []
        }
    }
}



def interface_existing_uuids(config: dict[str, Any]) -> set[str]:
    """Recoge UUIDs de interfaces existentes. / Collect existing interface UUIDs."""
    network = config.get("network", {}) if isinstance(config, dict) else {}
    if not isinstance(network, dict):
        return set()
    found: set[str] = set()
    for section in ALLOWED_SECTIONS:
        entries = network.get(section, {})
        if not isinstance(entries, dict):
            continue
        for entry in entries.values():
            if isinstance(entry, dict):
                uuid = entry.get("uuid") or entry.get("UUID")
                if uuid:
                    found.add(str(uuid))
    return found


def valid_interface_uuid(value: Any, section: str) -> bool:
    """Valida UUID de interfaz contra el prefijo de su familia."""
    if not isinstance(value, str) or not is_internal_uuid(value):
        return False
    return parse_internal_uuid(value)["prefix"] == INTERFACE_UUID_PREFIXES[section]


def order_interface_uuid(entry: dict[str, Any], uuid: str) -> dict[str, Any]:
    """Coloca uuid como primer campo visible de la entrada."""
    ordered: dict[str, Any] = {"uuid": uuid}
    for key, value in entry.items():
        if key in {"uuid", "UUID"}:
            continue
        ordered[key] = value
    return ordered


def stable_interface_uuid(config: dict[str, Any], section: str, name: str, current: Any) -> str:
    """Preserva uuid válido existente o genera uno nuevo para una interfaz."""
    if isinstance(current, dict):
        current_uuid = str(current.get("uuid") or current.get("UUID") or "").strip()
        if valid_interface_uuid(current_uuid, section):
            return current_uuid
    return generate_unique_internal_uuid(INTERFACE_UUID_PREFIXES[section], name, interface_existing_uuids(config))

def resolve_interface_by_uuid(config: dict[str, Any], section: str, interface_uuid: str) -> tuple[str, dict[str, Any]]:
    """Resuelve una interfaz por uuid dentro de su sección. / Resolve interface by uuid inside section."""
    clean_uuid = str(interface_uuid or "").strip()
    if not valid_interface_uuid(clean_uuid, section):
        fail("INVALID_INTERFACE_UUID")
    entries = config.get("network", {}).get(section, {})
    if not isinstance(entries, dict):
        fail("INVALID_INTERFACE_SECTION")
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        entry_uuid = str(entry.get("uuid") or entry.get("UUID") or "").strip()
        if entry_uuid == clean_uuid:
            return str(name), entry
    fail("INTERFACE_NOT_FOUND", status.HTTP_404_NOT_FOUND)

def module_name() -> str:
    return "interfaces"


def fail(error_code: str, http_status: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    raise HTTPException(status_code=http_status, detail=error_code)


def validate_section(section: str) -> str:
    section = str(section).strip()
    if section not in ALLOWED_SECTIONS:
        fail("INVALID_INTERFACE_SECTION")
    return section


def read_candidate_config() -> dict[str, Any]:
    data = repository.read_config()
    validate_config_shape(data)
    return data


def get_section(section: str) -> dict[str, Any]:
    section = validate_section(section)
    data = read_candidate_config()
    return {"section": section, "entries": data["network"][section]}


def scan_interfaces() -> dict[str, Any]:
    """Ejecuta la detección de interfaces y actualiza candidate/interfaces.json."""
    result = subprocess.run(
        ["/usr/bin/python3", INTERFACES_SCAN_SCRIPT],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": "INTERFACES_SCAN_FAILED",
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            },
        )
    return {
        "success": True,
        "action": "scan",
        "script": INTERFACES_SCAN_SCRIPT,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def update_interface(section: str, rule: dict[str, Any]) -> dict[str, Any]:
    """Equivalente FastAPI de get_update_interface.php."""
    section = validate_section(section)
    if not isinstance(rule, dict):
        fail("INVALID_INTERFACE_RULE")
    with repository.config_lock():
        config = read_candidate_config()
        normalized = normalize_rule(section, deepcopy(rule), config)
        name = str(normalized.get("name", "")).strip()
        if not name:
            fail("INTERFACE_NAME_REQUIRED")
        normalized.pop("name", None)
        current = config["network"][section].get(name)
        interface_uuid = stable_interface_uuid(config, section, name, current)
        normalized = order_interface_uuid(normalized, interface_uuid)
        config["network"][section][name] = normalized
        repository.write_config(config)
    return {"success": True, "section": section, "name": name, "uuid": interface_uuid, "action": "update"}


def upsert_named_interface(section: str, name: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Conveniencia REST: usa la misma validación insertando name en rule."""
    rule = dict(entry) if isinstance(entry, dict) else {}
    rule["name"] = name
    return update_interface(section, rule)


def patch_named_interface(section: str, interface_uuid: str, patch: dict[str, Any]) -> dict[str, Any]:
    """Modifica una interfaz existente identificada por uuid, no por nombre."""
    section = validate_section(section)
    if not isinstance(patch, dict):
        fail("INTERFACE_ENTRY_INVALID")
    with repository.config_lock():
        config = read_candidate_config()
        name, current = resolve_interface_by_uuid(config, section, interface_uuid)
        clean_uuid = str(current.get("uuid") or current.get("UUID") or "").strip()
        merged = dict(current)
        merged.update(patch)
        # ES: La identidad estable no puede cambiar por payload. El nombre real lo decide la entrada resuelta por uuid.
        # EN: Stable identity cannot be changed by payload. Real name comes from the uuid-resolved entry.
        merged["uuid"] = clean_uuid
        merged["name"] = name
        normalized = normalize_rule(section, merged, config)
        normalized_name = str(normalized.get("name", "")).strip()
        if normalized_name != name:
            fail("INTERFACE_NAME_MISMATCH")
        normalized.pop("name", None)
        normalized = order_interface_uuid(normalized, clean_uuid)
        config["network"][section][name] = normalized
        repository.write_config(config)
    return {"success": True, "section": section, "name": name, "uuid": clean_uuid, "action": "patch"}


def delete_interface(section: str, interface_uuid: str) -> dict[str, Any]:
    """Borra una interfaz identificada por uuid, no por nombre."""
    section = validate_section(section)
    with repository.config_lock():
        config = read_candidate_config()
        name, current = resolve_interface_by_uuid(config, section, interface_uuid)
        clean_uuid = str(current.get("uuid") or current.get("UUID") or "").strip()
        del config["network"][section][name]
        repository.write_config(config)
    return {"success": True, "section": section, "name": name, "uuid": clean_uuid, "action": "delete"}


def validate_config_shape(config: dict[str, Any]) -> None:
    if not isinstance(config, dict) or not config:
        fail("INTERFACES_CANDIDATE_CONFIG_NOT_FOUND", status.HTTP_500_INTERNAL_SERVER_ERROR)
    network = config.get("network")
    if not isinstance(network, dict):
        fail("INTERFACES_CANDIDATE_CONFIG_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
    for section in ALLOWED_SECTIONS:
        if section not in network:
            fail("INTERFACES_CANDIDATE_SECTION_MISSING", status.HTTP_500_INTERNAL_SERVER_ERROR)
        if not isinstance(network[section], dict):
            fail("INTERFACES_CANDIDATE_SECTION_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)


def normalize_rule(section: str, rule: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    validate_alias_fields(rule)
    validate_interface_field_values(rule, section, config)
    if section == "bonds":
        # ES: Los bonds conservan las validaciones genéricas/alias anteriores y sólo después
        # aplican reglas específicas de bonding/Netplan en un módulo separado.
        # EN: Bonds keep the previous generic/alias validations and only then apply
        # bonding/Netplan-specific rules in a separate module.
        return validate_and_normalize_bond_rule(check_create_name(rule, section, config), config)
    if section == "bridges":
        # ES/EN: Bridge-specific Netplan checks are complementary to generic select/alias validation.
        return validate_and_normalize_bridge_rule(check_create_name(rule, section, config), config)
    if section == "vlans":
        # ES: Primero se mantiene la validación VLAN existente; después se añaden checks Netplan extra.
        # EN: Keep the existing VLAN validation first; then add extra Netplan checks.
        return validate_and_normalize_vlan_netplan_rule(validate_and_normalize_vlan_rule(rule, config), config)
    if section == "wifis":
        # ES/EN: Wi-Fi-specific checks live outside service.py to keep this module small.
        return validate_and_normalize_wifi_rule(check_create_name(rule, section, config), config)
    if section == "ethernets":
        # ES/EN: Ethernet keeps mandatory-name behaviour but gains physical-device checks.
        return validate_and_normalize_ethernet_rule(rule, config)
    return rule


def validate_interface_field_values(rule: dict[str, Any], section: str, config: dict[str, Any]) -> None:
    """Valida valores permitidos, listas, checks y campos protegidos de una interfaz."""
    field_config = deepcopy(FIELD_CONFIG[section])
    all_names = all_candidate_interface_names(config)
    vlan_links = candidate_vlan_links(config)

    if "select" in field_config:
        if "interfaces" in field_config["select"]:
            field_config["select"]["interfaces"] = unique_list([*field_config["select"]["interfaces"], *all_names])
        if "link" in field_config["select"]:
            field_config["select"]["link"] = unique_list([*field_config["select"]["link"], *all_names, *vlan_links])
    if "multiselect" in field_config and "interfaces" in field_config["multiselect"]:
        field_config["multiselect"]["interfaces"] = unique_list([*field_config["multiselect"]["interfaces"], *all_names])

    for key, valid_values in field_config.get("select", {}).items():
        if key in rule:
            value = str(rule[key]).strip()
            if value and value not in valid_values:
                fail("INVALID_SELECT_VALUE")
    for key, valid_values in field_config.get("multiselect", {}).items():
        if key in rule:
            items = csv_items(rule[key])
            if len(items) != len(set(items)):
                fail("DUPLICATE_MULTISELECT_VALUE")
            for value in items:
                if value not in valid_values:
                    fail("INVALID_MULTISELECT_VALUE")
    for key, options in field_config.get("checkbox", {}).items():
        if key in rule:
            value = str(rule[key]).strip()
            if value and value not in checkbox_values(options):
                fail("INVALID_CHECKBOX_VALUE")
    for key, valid_values in field_config.get("not_editable", {}).items():
        if key == "id" or key not in rule:
            continue
        value = str(rule[key]).strip()
        if value and valid_values and value not in valid_values:
            fail("INVALID_NOT_EDITABLE_VALUE")


def validate_alias_fields(rule: dict[str, Any]) -> None:
    one_ip_fields = ("addresses", "gateway4", "gateway6")
    multiple_ip_fields = (
        "local",
        "nameservers.addresses",
        "peers.allowed-ips",
        "peers.endpoint",
        "remote",
        "routes.to",
        "routes.via",
        "routing-policy.from",
        "routing-policy.to",
    )
    alias_data = read_alias_ip_config("candidate")
    for field in one_ip_fields:
        if field in rule:
            try:
                validate_mixed_ip_references(alias_data, rule[field], allow_groups=False, allow_multiple=False)
            except HTTPException as exc:
                if exc.detail == "ALIAS_GROUP_NOT_ALLOWED":
                    fail("ALIAS_GROUP_NOT_ALLOWED")
                if exc.detail == "ONLY_ONE_IP_CIDR_OR_ALIAS_ALLOWED":
                    fail("ONLY_ONE_IP_CIDR_OR_ALIAS_ALLOWED")
                if isinstance(exc.detail, str):
                    fail("INVALID_IP_CIDR_OR_ALIAS")
                raise
    for field in multiple_ip_fields:
        if field in rule:
            try:
                validate_mixed_ip_references(alias_data, rule[field], allow_groups=False, allow_multiple=True, allow_default=(field == "routes.to"))
            except HTTPException as exc:
                if exc.detail == "ALIAS_GROUP_NOT_ALLOWED":
                    fail("ALIAS_GROUP_NOT_ALLOWED")
                if isinstance(exc.detail, str):
                    fail("INVALID_IP_CIDR_OR_ALIAS")
                raise


def validate_and_normalize_vlan_rule(rule: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    raw_id = str(rule.get("id", "")).strip()
    if raw_id == "":
        fail("VLAN_ID_REQUIRED")
    if not raw_id.isdigit():
        fail("VLAN_ID_MUST_BE_NUMERIC")
    vlan_id = int(raw_id)
    if vlan_id < 1 or vlan_id > 4094:
        fail("VLAN_ID_OUT_OF_RANGE")
    link = str(rule.get("link", "")).strip()
    if link == "":
        fail("VLAN_LINK_REQUIRED")
    expected_name = f"vlan{vlan_id}"
    current_name = str(rule.get("name", "")).strip()
    if current_name == "" or current_name.lower() == "auto":
        rule["name"] = expected_name
    elif current_name != expected_name:
        fail("VLAN_NAME_MISMATCH")
    vlans = config["network"].get("vlans", {})
    if not isinstance(vlans, dict):
        fail("VLAN_CONFIG_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
    for existing_name, existing_rule in vlans.items():
        if existing_name == rule["name"] or not isinstance(existing_rule, dict):
            continue
        if str(existing_rule.get("id", "")).strip() == str(vlan_id) and str(existing_rule.get("link", "")).strip() == link:
            fail("VLAN_ID_LINK_ALREADY_EXISTS", status.HTTP_409_CONFLICT)
    rule["id"] = str(vlan_id)
    return rule


def check_create_name(rule: dict[str, Any], section: str, config: dict[str, Any]) -> dict[str, Any]:
    if str(rule.get("name", "")).strip():
        return rule
    prefix = PREFIX_MAP.get(section)
    if prefix is None:
        fail("UNKNOWN_INTERFACE_SECTION")
    existing_names = set(config["network"][section].keys())
    index = 0
    while f"{prefix}{index}" in existing_names:
        index += 1
    rule["name"] = f"{prefix}{index}"
    return rule


def candidate_vlan_links(config: dict[str, Any]) -> list[str]:
    links: list[str] = []
    for section in ("ethernets", "bonds", "bridges"):
        block = config["network"].get(section, {})
        if isinstance(block, dict):
            links.extend(str(name) for name in block.keys())
    return unique_list([item for item in links if item])


def all_candidate_interface_names(config: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for section in ALLOWED_SECTIONS:
        block = config["network"].get(section, {})
        if isinstance(block, dict):
            names.extend(str(name) for name in block.keys())
    return unique_list(names)


def csv_items(value: Any) -> list[str]:
    if isinstance(value, list):
        raw: list[str] = []
        for item in value:
            raw.extend(str(item).split(","))
    else:
        raw = str(value).split(",")
    return [item.strip() for item in raw if item.strip()]


def checkbox_values(options: Any) -> list[str]:
    if isinstance(options, dict):
        return [str(value) for value in options.values()]
    if isinstance(options, list):
        return [str(value) for value in options]
    return []


def unique_list(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
