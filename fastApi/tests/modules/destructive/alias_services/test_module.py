"""Tests destructivos de alias_services. / Destructive alias_services tests."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from common.runner import call, require

ALIAS_SERVICES = Path("/var/lib/praesidium/candidate/alias_services.json")
BACKUP = Path("/tmp/praesidium_alias_services_before_destructive_test.json")


def _backup_alias_services() -> None:
    # ES: Guarda alias_services.json porque el orquestador solo restaura users.json.
    # EN: Save alias_services.json because the orchestrator only restores users.json.
    shutil.copy2(ALIAS_SERVICES, BACKUP)


def _restore_alias_services(ctx) -> None:
    # ES: Restaura alias_services.json tras pruebas destructivas temporales.
    # EN: Restore alias_services.json after temporary destructive tests.
    shutil.copy2(BACKUP, ALIAS_SERVICES)
    ctx.log("RESTORE alias_services.json applied")


def _read_alias_services() -> dict:
    # ES: Lee alias_services.json para verificar storage interno.
    # EN: Read alias_services.json to verify internal storage.
    return json.loads(ALIAS_SERVICES.read_text(encoding="utf-8"))


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
    status, group = call(ctx, f"create sanitized service case {name}", "POST", "/api/v1/alias-services/service-groups", {"name": f"tmp_svc_sanitized_{name}"[:29], "content": values})
    require(ctx, status == 201, f"sanitized service case {name} group created", f"sanitized service case {name} group create failed")
    group_uuid = group.get("UUID") if isinstance(group, dict) else None
    status, payload = call(ctx, f"deep translate sanitized service case {name}", "POST", "/api/v1/alias-services/deep_translate_sanitized", {"UUID": group_uuid})
    require(ctx, status == 200 and payload.get("deep_content_sanitized") == expected, f"sanitized service case {name} exact output", f"sanitized service case {name} unexpected {payload}")


def run(ctx) -> None:
    # ES: Ejecuta CRUD y ataques/basura sobre alias_services.
    # EN: Execute CRUD and junk/malicious inputs against alias_services.
    ctx.log("=== ALIAS_SERVICES DESTRUCTIVE ===")
    _backup_alias_services()
    try:
        # ES: Lectura permitida para ambos roles.
        # EN: Reading is allowed for both roles.
        status, payload = call(ctx, "list services", "GET", "/api/v1/alias-services/services")
        require(ctx, status == 200, "list services allowed", "list services failed")
        status, payload = call(ctx, "list service groups", "GET", "/api/v1/alias-services/service-groups")
        require(ctx, status == 200, "list service groups allowed", "list service groups failed")

        # ES: alias_service válido: exactamente un puerto/rango.
        # EN: Valid alias_service: exactly one port/range.
        status, service = call(ctx, "create valid service", "POST", "/api/v1/alias-services/services", {"name": f"tmp_svc_{ctx.identity.role}", "content": ["65001"]})
        _assert_by_role(ctx, status, 201, 403, "create valid service")
        service_uuid = service.get("UUID") if isinstance(service, dict) else None

        status, range_service = call(ctx, "create valid service range", "POST", "/api/v1/alias-services/services", {"name": f"tmp_svc_range_{ctx.identity.role}", "content": ["65002-65003"]})
        _assert_by_role(ctx, status, 201, 403, "create valid service range")

        # ES: alias_service no puede actuar como grupo.
        # EN: alias_service cannot act as a group.
        status, payload = call(ctx, "reject multiple service content", "POST", "/api/v1/alias-services/services", {"name": f"tmp_multi_svc_{ctx.identity.role}", "content": ["80", "443"]})
        _assert_by_role(ctx, status, 422, 403, "reject multiple service content")
        if ctx.identity.role == "admin":
            require(ctx, _detail(payload) == "ALIAS_SERVICE_REQUIRES_SINGLE_CONTENT", "multi-service rejected by exact error", "multi-service wrong error")

        # ES: Basura/malicia que no son puertos/rangos válidos.
        # EN: Junk/malicious values that are not valid ports/ranges.
        for name, value, expected_detail in [
            ("reject plain text", "notaport", "INVALID_PORT"),
            ("reject domain", "example.com", "INVALID_PORT"),
            ("reject ip", "1.1.1.1", "INVALID_PORT"),
            ("reject zero", "0", "INVALID_PORT"),
            ("reject high port", "65536", "INVALID_PORT"),
            ("reject inverted range", "2000-1000", "INVALID_PORT_RANGE"),
            ("reject high range", "65000-70000", "INVALID_PORT_RANGE"),
            ("reject script", "<script>alert(1)</script>", "INVALID_PORT"),
            ("reject address uuid", "aliasad-1-19700101000000000-4469", "INVALID_PORT_RANGE"),
        ]:
            status, payload = call(ctx, name, "POST", "/api/v1/alias-services/services", {"name": f"tmp_bad_{ctx.identity.role}_{name.replace(' ', '_')[:12]}", "content": [value]})
            _assert_by_role(ctx, status, 422, 403, name)
            if ctx.identity.role == "admin":
                require(ctx, _detail(payload) == expected_detail, f"{name} exact error", f"{name} wrong error {_detail(payload)}")

        # ES: Campos extra prohibidos por Pydantic.
        # EN: Extra fields forbidden by Pydantic.
        status, payload = call(ctx, "reject extra field", "POST", "/api/v1/alias-services/services", {"name": f"tmp_extra_svc_{ctx.identity.role}", "content": ["65004"], "UUID": "evil"})
        _assert_by_role(ctx, status, 422, 403, "reject extra field")

        if ctx.identity.role == "admin" and service_uuid:
            # ES: Grupo real con alias por UUID + puertos/rangos literales.
            # EN: Real group with alias UUID + literal ports/ranges.
            status, group = call(ctx, "create valid service group", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_svc_group_admin", "content": [service_uuid, "65010", "65020-65021"]})
            require(ctx, status == 201, "service group created", "service group create failed")
            group_uuid = group.get("UUID") if isinstance(group, dict) else None
            require(ctx, isinstance(group, dict) and group.get("content") == ["tmp_svc_admin", "65010", "65020-65021"], "service group visible content uses name + literals", "service group visible content unexpected")

            data = _read_alias_services()
            stored_group = data.get("alias_service_group", {}).get(group_uuid, {}) if group_uuid else {}
            require(ctx, stored_group.get("content") == [service_uuid, "65010", "65020-65021"], "service group storage uses UUID + literals", "service group storage unexpected")

            # ES: Grupo anidado por UUID.
            # EN: Nested group by UUID.
            status, nested = call(ctx, "create nested service group", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_svc_nested_admin", "content": [group_uuid, "65030"]})
            require(ctx, status == 201, "nested service group created", "nested service group create failed")
            nested_uuid = nested.get("UUID") if isinstance(nested, dict) else None

            status, deep = call(ctx, "deep translate nested service group", "POST", "/api/v1/alias-services/deep_translate", {"UUID": nested_uuid})
            require(ctx, status == 200 and deep.get("deep_content") == ["65001", "65010", "65020-65021", "65030"], "deep_translate resolves nested service group", "deep_translate nested service group failed")

            status, sanitized_group = call(ctx, "create sanitized service overlap group", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_svc_sanitized_admin", "content": [service_uuid, "22", "22", "23-25", "26", "80", "1000-2000", "1500", "2001", "3000-4000", "3500-3600", "4001"]})
            require(ctx, status == 201, "sanitized service overlap group created", "sanitized service overlap group create failed")
            sanitized_uuid = sanitized_group.get("UUID") if isinstance(sanitized_group, dict) else None
            status, sanitized = call(ctx, "deep translate sanitized service overlap group", "POST", "/api/v1/alias-services/deep_translate_sanitized", {"UUID": sanitized_uuid})
            expected_sanitized = ["22-26", "80", "1000-2001", "3000-4001", "65001"]
            require(ctx, status == 200 and sanitized.get("deep_content_sanitized") == expected_sanitized, "deep_translate_sanitized compacts ports and ranges", f"service deep_translate_sanitized unexpected {sanitized}")

            for case_name, values, expected in [
                ("duplicates", ["22", "22", "22-22", "23", "23-23"], ["22-23"]),
                ("contained", ["100-200", "120", "150-160", "200"], ["100-200"]),
                ("contiguous", ["20-30", "31-40", "41", "80"], ["20-41", "80"]),
                ("unordered", ["500", "100-150", "151", "400-450", "451-499"], ["100-151", "400-500"]),
                ("boundaries", ["1", "2-3", "65534", "65535"], ["1-3", "65534-65535"]),
            ]:
                _check_sanitized_case(ctx, case_name, values, expected)

            status, svc53 = call(ctx, "create filthy service 53", "POST", "/api/v1/alias-services/services", {"name": "tmp_filthy_svc_53", "content": ["53"]})
            require(ctx, status == 201, "filthy service 53 created", "filthy service 53 create failed")
            status, svc1024 = call(ctx, "create filthy service 1024 range", "POST", "/api/v1/alias-services/services", {"name": "tmp_filthy_svc_1024", "content": ["1024-2048"]})
            require(ctx, status == 201, "filthy service 1024 range created", "filthy service 1024 range create failed")
            status, svc2049 = call(ctx, "create filthy service 2049", "POST", "/api/v1/alias-services/services", {"name": "tmp_filthy_svc_2049", "content": ["2049"]})
            require(ctx, status == 201, "filthy service 2049 created", "filthy service 2049 create failed")
            svc53_uuid = svc53.get("UUID") if isinstance(svc53, dict) else None
            svc1024_uuid = svc1024.get("UUID") if isinstance(svc1024, dict) else None
            svc2049_uuid = svc2049.get("UUID") if isinstance(svc2049, dict) else None

            status, filthy_a = call(ctx, "create filthy nested service group A", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_filthy_svc_group_a", "content": [svc53_uuid, "1", "2-4", "4", "5-5", "100-200", "150", "200", "65535"]})
            require(ctx, status == 201, "filthy nested service group A created", "filthy nested service group A create failed")
            filthy_a_uuid = filthy_a.get("UUID") if isinstance(filthy_a, dict) else None
            status, filthy_b = call(ctx, "create filthy nested service group B", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_filthy_svc_group_b", "content": [filthy_a_uuid, svc1024_uuid, svc2049_uuid, "201", "202-250", "251", "300", "299", "65534-65534", "1025", "2048"]})
            require(ctx, status == 201, "filthy nested service group B created", "filthy nested service group B create failed")
            filthy_b_uuid = filthy_b.get("UUID") if isinstance(filthy_b, dict) else None
            status, filthy_payload = call(ctx, "deep translate sanitized filthy nested service group", "POST", "/api/v1/alias-services/deep_translate_sanitized", {"UUID": filthy_b_uuid})
            filthy_expected = ["1-5", "53", "100-251", "299-300", "1024-2049", "65534-65535"]
            require(ctx, status == 200 and filthy_payload.get("deep_content_sanitized") == filthy_expected, "filthy nested sanitized service output exact", f"filthy nested sanitized service unexpected {filthy_payload}")

            status, payload = call(ctx, "reject delete used service", "DELETE", f"/api/v1/alias-services/services/{service_uuid}")
            require(ctx, status == 409 and _detail(payload) == "ALIAS_USED_BY_GROUP", "delete used service is blocked", "delete used service not blocked")

            status, payload = call(ctx, "reject group with address uuid", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_bad_address_uuid_admin", "content": ["aliasad-1-19700101000000000-4469"]})
            require(ctx, status == 422 and _detail(payload) == "INVALID_ALIAS_SERVICE_GROUP_CONTENT", "address UUID rejected in service group", "address UUID not rejected correctly")

            status, payload = call(ctx, "reject group with junk", "POST", "/api/v1/alias-services/service-groups", {"name": "tmp_bad_svc_junk_admin", "content": ["DROP TABLE alias", "65536"]})
            require(ctx, status == 422 and _detail(payload) == "INVALID_ALIAS_SERVICE_GROUP_CONTENT", "junk rejected in service group", "junk not rejected correctly")
        else:
            # ES: Viewer no puede crear grupos.
            # EN: Viewer cannot create groups.
            status, payload = call(ctx, "viewer cannot create service group", "POST", "/api/v1/alias-services/service-groups", {"name": "viewer_bad_service_group", "content": ["80"]})
            require(ctx, status == 403, "viewer service group create forbidden", "viewer service group create was not forbidden")
    finally:
        _restore_alias_services(ctx)
