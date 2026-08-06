"""Tests destructivos de alias_ip. / Destructive alias_ip tests."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from common.runner import call, require

ALIAS_IP = Path("/var/lib/praesidium/candidate/alias_ip.json")
BACKUP = Path("/tmp/praesidium_alias_ip_before_destructive_test.json")


def _backup_alias_ip() -> None:
    # ES: Guarda alias_ip.json porque el orquestador solo restaura users.json.
    # EN: Save alias_ip.json because the orchestrator only restores users.json.
    shutil.copy2(ALIAS_IP, BACKUP)


def _restore_alias_ip(ctx) -> None:
    # ES: Restaura alias_ip.json tras pruebas destructivas temporales.
    # EN: Restore alias_ip.json after temporary destructive tests.
    shutil.copy2(BACKUP, ALIAS_IP)
    ctx.log("RESTORE alias_ip.json applied")


def _read_alias_ip() -> dict:
    # ES: Lee alias_ip.json para verificar storage interno.
    # EN: Read alias_ip.json to verify internal storage.
    return json.loads(ALIAS_IP.read_text(encoding="utf-8"))


def _status_ok(status: int) -> bool:
    # ES: Detecta respuestas 2xx.
    # EN: Detect 2xx responses.
    return 200 <= status <= 299


def _detail(payload) -> str:
    # ES: Extrae detail de una respuesta de error.
    # EN: Extract detail from an error response.
    return payload.get("detail") if isinstance(payload, dict) else str(payload)


def _assert_by_role(ctx, status: int, admin_expected: int, viewer_expected: int, label: str) -> None:
    # ES: Verifica status esperado según rol admin/viewer.
    # EN: Verify expected status depending on admin/viewer role.
    expected = admin_expected if ctx.identity.role == "admin" else viewer_expected
    require(ctx, status == expected, f"{label} returned expected {expected}", f"{label} returned {status}, expected {expected}")


def _check_sanitized_case(ctx, name: str, values: list[str], expected: list[str]) -> None:
    # ES: Crea un grupo temporal y verifica deep_translate_sanitized exacto.
    # EN: Create a temporary group and verify exact deep_translate_sanitized output.
    status, group = call(ctx, f"create sanitized case {name}", "POST", "/api/v1/alias-ip/address-groups", {"name": f"tmp_sanitized_{name}"[:29], "content": values})
    require(ctx, status == 201, f"sanitized case {name} group created", f"sanitized case {name} group create failed")
    group_uuid = group.get("UUID") if isinstance(group, dict) else None
    status, payload = call(ctx, f"deep translate sanitized case {name}", "POST", "/api/v1/alias-ip/deep_translate_sanitized", {"UUID": group_uuid})
    require(ctx, status == 200 and payload.get("deep_content_sanitized") == expected, f"sanitized case {name} exact output", f"sanitized case {name} unexpected {payload}")


def run(ctx) -> None:
    # ES: Ejecuta CRUD y ataques/basura sobre alias_ip.
    # EN: Execute CRUD and junk/malicious inputs against alias_ip.
    ctx.log("=== ALIAS_IP DESTRUCTIVE ===")
    _backup_alias_ip()
    try:
        # ES: Lectura permitida para ambos roles.
        # EN: Reading is allowed for both roles.
        status, payload = call(ctx, "list addresses", "GET", "/api/v1/alias-ip/addresses")
        require(ctx, status == 200, "list addresses allowed", "list addresses failed")
        status, payload = call(ctx, "list address groups", "GET", "/api/v1/alias-ip/address-groups")
        require(ctx, status == 200, "list address groups allowed", "list address groups failed")

        # ES: alias_address válido: exactamente una IP/CIDR.
        # EN: Valid alias_address: exactly one IP/CIDR.
        status, address = call(ctx, "create valid address", "POST", "/api/v1/alias-ip/addresses", {"name": f"tmp_addr_{ctx.identity.role}", "content": ["10.241.0.1/24"]})
        _assert_by_role(ctx, status, 201, 403, "create valid address")
        address_uuid = address.get("UUID") if isinstance(address, dict) else None

        # ES: alias_address no puede actuar como grupo.
        # EN: alias_address cannot act as a group.
        status, payload = call(ctx, "reject multiple address content", "POST", "/api/v1/alias-ip/addresses", {"name": f"tmp_multi_{ctx.identity.role}", "content": ["1.1.1.1", "2.2.2.2"]})
        _assert_by_role(ctx, status, 422, 403, "reject multiple address content")
        if ctx.identity.role == "admin":
            require(ctx, _detail(payload) == "ALIAS_ADDRESS_REQUIRES_SINGLE_CONTENT", "multi-address rejected by exact error", "multi-address wrong error")

        # ES: Basura/malicia que no son IP/CIDR.
        # EN: Junk/malicious values that are not IP/CIDR.
        for name, value, expected_detail in [
            ("reject plain text", "not-an-ip", "INVALID_IP_OR_CIDR"),
            ("reject domain", "example.com", "INVALID_IP_OR_CIDR"),
            ("reject port", "80", "INVALID_IP_OR_CIDR"),
            ("reject script", "<script>alert(1)</script>", "INVALID_IP_OR_CIDR"),
            ("reject service uuid", "aliaser-1-19700101000000000-0724", "INVALID_IP_OR_CIDR"),
        ]:
            status, payload = call(ctx, name, "POST", "/api/v1/alias-ip/addresses", {"name": f"tmp_bad_{ctx.identity.role}_{name.replace(' ', '_')[:12]}", "content": [value]})
            _assert_by_role(ctx, status, 422, 403, name)
            if ctx.identity.role == "admin":
                require(ctx, _detail(payload) == expected_detail, f"{name} exact error", f"{name} wrong error {_detail(payload)}")

        # ES: Campos extra prohibidos por Pydantic.
        # EN: Extra fields forbidden by Pydantic.
        status, payload = call(ctx, "reject extra field", "POST", "/api/v1/alias-ip/addresses", {"name": f"tmp_extra_{ctx.identity.role}", "content": ["10.241.0.2"], "UUID": "evil"})
        _assert_by_role(ctx, status, 422, 403, "reject extra field")

        if ctx.identity.role == "admin" and address_uuid:
            # ES: Grupo real con alias por UUID + literal IP/CIDR.
            # EN: Real group with alias UUID + literal IP/CIDR.
            status, group = call(ctx, "create valid address group", "POST", "/api/v1/alias-ip/address-groups", {"name": "tmp_addr_group_admin", "content": [address_uuid, "172.16.241.0/24"]})
            require(ctx, status == 201, "address group created", "address group create failed")
            group_uuid = group.get("UUID") if isinstance(group, dict) else None
            require(ctx, isinstance(group, dict) and group.get("content") == ["tmp_addr_admin", "172.16.241.0/24"], "address group visible content uses name + literal", "address group visible content unexpected")

            data = _read_alias_ip()
            stored_group = data.get("alias_addr_group", {}).get(group_uuid, {}) if group_uuid else {}
            require(ctx, stored_group.get("content") == [address_uuid, "172.16.241.0/24"], "address group storage uses UUID + literal", "address group storage unexpected")

            # ES: Grupo anidado por UUID.
            # EN: Nested group by UUID.
            status, nested = call(ctx, "create nested address group", "POST", "/api/v1/alias-ip/address-groups", {"name": "tmp_addr_nested_admin", "content": [group_uuid, "192.0.2.1"]})
            require(ctx, status == 201, "nested address group created", "nested address group create failed")
            nested_uuid = nested.get("UUID") if isinstance(nested, dict) else None

            status, deep = call(ctx, "deep translate nested address group", "POST", "/api/v1/alias-ip/deep_translate", {"UUID": nested_uuid})
            require(ctx, status == 200 and deep.get("deep_content") == ["10.241.0.1/24", "172.16.241.0/24", "192.0.2.1"], "deep_translate resolves nested group", "deep_translate nested group failed")

            status, sanitized_group = call(ctx, "create sanitized overlap group", "POST", "/api/v1/alias-ip/address-groups", {"name": "tmp_addr_sanitized_admin", "content": [address_uuid, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "10.16.0.0/24", "192.168.23.0/24", "10.1.1.1/32", "172.16.2.2", "10.0.0.0/8"]})
            require(ctx, status == 201, "sanitized overlap group created", "sanitized overlap group create failed")
            sanitized_uuid = sanitized_group.get("UUID") if isinstance(sanitized_group, dict) else None
            status, sanitized = call(ctx, "deep translate sanitized overlap group", "POST", "/api/v1/alias-ip/deep_translate_sanitized", {"UUID": sanitized_uuid})
            expected_sanitized = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
            require(ctx, status == 200 and sanitized.get("deep_content_sanitized") == expected_sanitized, "deep_translate_sanitized removes duplicates and covered networks", f"deep_translate_sanitized unexpected {sanitized}")

            for case_name, values, expected in [
                ("ipv4_private", ["10.0.0.0/8", "10.0.0.0/8", "10.1.2.0/24", "10.1.2.3", "10.1.2.3/32", "192.168.1.0/24", "192.168.1.55", "192.168.1.55/32"], ["10.0.0.0/8", "192.168.1.0/24"]),
                ("hostbits", ["10.0.0.1/24", "10.0.0.0/24", "10.0.0.128/25", "10.0.0.200", "10.0.1.1/24"], ["10.0.0.0/24", "10.0.1.0/24"]),
                ("public_mix", ["8.8.8.8", "8.8.8.8/32", "8.8.8.0/24", "8.8.4.4", "8.8.0.0/16"], ["8.8.0.0/16"]),
                ("ipv6_overlap", ["2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::1", "2001:db8:2::1/128", "2001:db8::/32"], ["2001:db8::/32"]),
                ("dual_stack", ["0.0.0.0/0", "10.1.1.1", "::/0", "2001:db8::1"], ["0.0.0.0/0", "::/0"]),
                ("non_overlap", ["10.0.0.0/9", "10.128.0.0/9", "172.16.1.1", "172.16.2.0/24", "192.0.2.1"], ["10.0.0.0/9", "10.128.0.0/9", "172.16.1.1", "172.16.2.0/24", "192.0.2.1"]),
            ]:
                _check_sanitized_case(ctx, case_name, values, expected)

            status, payload = call(ctx, "reject delete used address", "DELETE", f"/api/v1/alias-ip/addresses/{address_uuid}")
            require(ctx, status == 409 and _detail(payload) == "ALIAS_USED_BY_GROUP", "delete used address is blocked", "delete used address not blocked")

            status, payload = call(ctx, "reject group with service uuid", "POST", "/api/v1/alias-ip/address-groups", {"name": "tmp_bad_service_uuid_admin", "content": ["aliaser-1-19700101000000000-0724"]})
            require(ctx, status == 422 and _detail(payload) == "INVALID_ALIAS_ADDRESS_GROUP_CONTENT", "service UUID rejected in address group", "service UUID not rejected correctly")

            status, payload = call(ctx, "reject group with junk", "POST", "/api/v1/alias-ip/address-groups", {"name": "tmp_bad_junk_admin", "content": ["DROP TABLE alias", "999.999.999.999"]})
            require(ctx, status == 422 and _detail(payload) == "INVALID_ALIAS_ADDRESS_GROUP_CONTENT", "junk rejected in address group", "junk not rejected correctly")
        else:
            # ES: Viewer no puede crear grupos.
            # EN: Viewer cannot create groups.
            status, payload = call(ctx, "viewer cannot create address group", "POST", "/api/v1/alias-ip/address-groups", {"name": "viewer_bad_group", "content": ["1.1.1.1"]})
            require(ctx, status == 403, "viewer group create forbidden", "viewer group create was not forbidden")
    finally:
        _restore_alias_ip(ctx)
