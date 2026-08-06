"""Tests no destructivos de dnsmasq/DHCP. / Non-destructive dnsmasq/DHCP tests."""
from __future__ import annotations

from common.runner import call, request, require

BASE = "/api/v1/dnsmasq"


def _expect_role(ctx, status: int, admin_expected: int, viewer_expected: int, label: str) -> None:
    expected = admin_expected if ctx.identity.role == "admin" else viewer_expected
    require(ctx, status == expected, f"{label} returned expected {expected}", f"{label} returned {status}, expected {expected}")


def _admin(ctx) -> bool:
    return ctx.identity.role == "admin"


def _detail(payload) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code") or detail)
        return str(detail)
    return str(payload)


def _invalid_scope() -> dict:
    return {"rule": {"enable": "maybe", "mode": "server", "interface": "notreal"}}


def _invalid_reservation() -> dict:
    return {"rule": {"enable": "true", "interface": "notreal", "mac": "not-a-mac", "ip": "999.999.999.999"}}


def run(ctx) -> None:
    ctx.log("=== DNSMASQ NON-DESTRUCTIVE ===")

    for label, path in [
        ("status", f"{BASE}/status"),
        ("list config", BASE),
        ("list scopes", f"{BASE}/scopes"),
        ("list reservations", f"{BASE}/reservations"),
        ("list candidate interfaces", f"{BASE}/interfaces"),
        ("list reservation interfaces", f"{BASE}/reservation-interfaces"),
    ]:
        status, payload = call(ctx, label, "GET", path)
        require(ctx, status == 200, f"{label} readable", f"{label} failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-missing scope", "GET", f"{BASE}/scopes/999999")
    require(ctx, status == 404, "missing scope rejected", f"missing scope returned {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-missing reservation", "GET", f"{BASE}/reservations/999999")
    require(ctx, status == 404, "missing reservation rejected", f"missing reservation returned {status}: {_detail(payload)}")

    # ES: Mutaciones con payload inválido no deben modificar candidate; viewer debe quedar bloqueado.
    # EN: Invalid mutation payloads must not modify candidate; viewer must be blocked.
    mutation_cases = [
        ("create invalid scope", "POST", f"{BASE}/scopes", _invalid_scope(), 422),
        ("patch missing scope", "PATCH", f"{BASE}/scopes/999999", _invalid_scope(), 404),
        ("delete missing scope", "DELETE", f"{BASE}/scopes/999999", None, 404),
        ("create invalid reservation", "POST", f"{BASE}/reservations", _invalid_reservation(), 422),
        ("patch missing reservation", "PATCH", f"{BASE}/reservations/999999", _invalid_reservation(), 404),
        ("delete missing reservation", "DELETE", f"{BASE}/reservations/999999", None, 404),
    ]
    for label, method, path, body, admin_expected in mutation_cases:
        status, payload = call(ctx, f"negative-{label}", method, path, body)
        _expect_role(ctx, status, admin_expected, 403, label)

    # ES: La API pública nueva no debe exponer helpers del generic_table/WebGUI.
    # EN: New public API must not expose generic_table/WebGUI helper surfaces.
    status, openapi = request("GET", "/openapi.json", token=ctx.token)
    require(ctx, status == 200, "openapi readable", f"openapi failed {status}")
    paths = set(openapi.get("paths", {}).keys()) if isinstance(openapi, dict) else set()
    forbidden = [p for p in paths if p.startswith(BASE) and any(part in p for part in ["forms", "structure", "content", "table_content", "table_structure"])]
    require(ctx, not forbidden, "dnsmasq exposes no WebGUI helper routes", f"forbidden dnsmasq helper routes exposed: {forbidden}")

    if _admin(ctx):
        ctx.log("CHECK admin non-destructive mutation probes used invalid/missing targets only")
    else:
        ctx.log("CHECK viewer mutation probes forbidden")
