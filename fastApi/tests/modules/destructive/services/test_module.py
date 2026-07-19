"""Tests destructivos de Services."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from common.runner import call, require

BASE = "/api/v1/services"
SERVICES = Path("/var/lib/praesidium/candidate/services.json")
BACKUP = Path("/tmp/praesidium_services_before_destructive_test.json")


def _backup() -> None:
    shutil.copy2(SERVICES, BACKUP)


def _restore(ctx) -> None:
    shutil.copy2(BACKUP, SERVICES)
    ctx.log("RESTORE services.json applied")


def _read() -> dict[str, Any]:
    return json.loads(SERVICES.read_text(encoding="utf-8"))


def _write(data: dict[str, Any]) -> None:
    SERVICES.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    SERVICES.chmod(0o664)


def _admin(ctx) -> bool:
    return ctx.identity.role == "admin"


def run(ctx) -> None:
    ctx.log("=== SERVICES DESTRUCTIVE ===")
    _backup()
    try:
        if not _admin(ctx):
            for label, path, body in [
                ("negative-viewer update dnsmasq", f"{BASE}/dnsmasq", {"desired_enabled": "false"}),
                ("negative-viewer update forwarding", f"{BASE}/forwarding_ipv4", {"desired_enabled": "false"}),
                ("negative-viewer update monitor-only", f"{BASE}/apache2", {"desired_enabled": "false"}),
            ]:
                status, payload = call(ctx, label, "PATCH", path, body)
                require(ctx, status == 403, f"{label} forbidden", f"{label} returned {status}")
            return

        before = _read()
        original_dnsmasq = str(before.get("services", {}).get("dnsmasq", {}).get("desired_enabled", "true"))
        target_dnsmasq = "false" if original_dnsmasq == "true" else "true"
        status, payload = call(ctx, "update dnsmasq desired", "PATCH", f"{BASE}/dnsmasq", {"desired_enabled": target_dnsmasq})
        require(ctx, status == 200, "dnsmasq desired updated", f"dnsmasq update returned {status}")
        after = _read()
        require(ctx, after["services"]["dnsmasq"]["desired_enabled"] == target_dnsmasq, "dnsmasq candidate changed", "dnsmasq candidate did not change")
        status, payload = call(ctx, "read dnsmasq after update", "GET", f"{BASE}/dnsmasq")
        service = payload.get("service", {}) if isinstance(payload, dict) else {}
        require(ctx, status == 200 and service.get("desired_enabled") == target_dnsmasq, "dnsmasq read shows update", f"dnsmasq read after update returned {status}")

        status, payload = call(ctx, "update dnsmasq restore", "PATCH", f"{BASE}/dnsmasq", {"desired_enabled": original_dnsmasq})
        require(ctx, status == 200, "dnsmasq desired restored", f"dnsmasq restore returned {status}")

        original_forwarding = str(before.get("services", {}).get("forwarding_ipv4", {}).get("desired_enabled", "true"))
        target_forwarding = "false" if original_forwarding == "true" else "true"
        status, payload = call(ctx, "update forwarding desired", "PATCH", f"{BASE}/forwarding_ipv4", {"desired_enabled": target_forwarding})
        require(ctx, status == 200, "forwarding desired updated", f"forwarding update returned {status}")
        status, payload = call(ctx, "update forwarding restore", "PATCH", f"{BASE}/forwarding_ipv4", {"desired_enabled": original_forwarding})
        require(ctx, status == 200, "forwarding desired restored", f"forwarding restore returned {status}")

        negative_cases = [
            ("negative-missing service", f"{BASE}/notreal", {"desired_enabled": "true"}, 404),
            ("negative-monitor-only apache2", f"{BASE}/apache2", {"desired_enabled": "false"}, 409),
            ("negative-monitor-only docker", f"{BASE}/docker", {"desired_enabled": "false"}, 409),
            ("negative-monitor-only ssh", f"{BASE}/ssh", {"desired_enabled": "false"}, 409),
            ("negative-invalid desired text", f"{BASE}/dnsmasq", {"desired_enabled": "yes"}, 422),
            ("negative-invalid desired bool", f"{BASE}/dnsmasq", {"desired_enabled": True}, 422),
            ("negative-invalid desired empty", f"{BASE}/dnsmasq", {"desired_enabled": ""}, 422),
            ("negative-malformed payload", f"{BASE}/dnsmasq", {"rule": {"desired_enabled": "false"}}, 422),
        ]
        for label, path, body, expected in negative_cases:
            status, payload = call(ctx, label, "PATCH", path, body)
            require(ctx, status == expected, f"{label} rejected", f"{label} returned {status}, expected {expected}")

        malformed_fixtures = [
            ("negative-candidate services list", {"services": []}),
            ("negative-candidate service scalar", {"services": {"dnsmasq": "bad"}}),
        ]
        for label, bad in malformed_fixtures:
            _write(bad)
            status, payload = call(ctx, label, "GET", BASE)
            require(ctx, status == 500, f"{label} rejected", f"{label} returned {status}")
            shutil.copy2(BACKUP, SERVICES)
    finally:
        _restore(ctx)
