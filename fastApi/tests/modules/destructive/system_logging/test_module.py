"""Tests destructivos de System Logging."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from common.runner import call, require

BASE = "/api/v1/system-logging"
CONFIG = Path("/var/lib/praesidium/candidate/system_logging.json")
LOCK = CONFIG.with_suffix(CONFIG.suffix + ".lock")
BACKUP = Path("/tmp/praesidium_system_logging_before_destructive_test.json")


def _read() -> dict[str, Any]:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _write(data: Any) -> None:
    CONFIG.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    CONFIG.chmod(0o664)


def _different(current: Any, values: list[Any]) -> Any:
    return next(value for value in values if value != current)


def _expect_rejected(ctx, label: str, route: str, body: dict[str, Any], expected: int = 422) -> None:
    status, payload = call(ctx, label, "PATCH", f"{BASE}/{route}", body)
    require(ctx, status == expected, f"{label} rejected", f"{label} returned {status}, expected {expected}: {payload}")


def run(ctx) -> None:
    ctx.log("=== SYSTEM LOGGING DESTRUCTIVE ===")
    shutil.copy2(CONFIG, BACKUP)
    lock_existed = LOCK.exists()
    original_bytes = BACKUP.read_bytes()
    try:
        if ctx.identity.role != "admin":
            viewer_cases = [
                ("journald", {"compress": False}),
                ("system-logs", {"rotate": 8}),
                ("nftables-logs", {"enabled": False}),
            ]
            for route, body in viewer_cases:
                _expect_rejected(ctx, f"negative-viewer update {route}", route, body, 403)
            return

        original = _read()
        static_uuids = {section: original[section]["uuid"] for section in ("journald", "system_logs", "nftables_logs")}
        valid_updates = {
            "journald": {
                "system_max_use": _different(original["journald"]["system_max_use"], ["10M", "250M"]),
                "system_keep_free": _different(original["journald"]["system_keep_free"], ["500M", "2G"]),
                "runtime_max_use": _different(original["journald"]["runtime_max_use"], ["25M", "500M"]),
                "max_retention_sec": _different(original["journald"]["max_retention_sec"], ["3day", "30day"]),
                "compress": not original["journald"]["compress"],
            },
            "system-logs": {
                "enabled": not original["system_logs"]["enabled"],
                "rotation": _different(original["system_logs"]["rotation"], ["daily", "weekly"]),
                "rotate": _different(original["system_logs"]["rotate"], [3, 14]),
                "maxsize": _different(original["system_logs"]["maxsize"], ["25M", "500M"]),
                "compress": not original["system_logs"]["compress"],
                "delaycompress": not original["system_logs"]["delaycompress"],
            },
            "nftables-logs": {
                "enabled": not original["nftables_logs"]["enabled"],
                "size": _different(original["nftables_logs"]["size"], ["10M", "250M"]),
                "rotate": _different(original["nftables_logs"]["rotate"], [5, 20]),
                "compress": not original["nftables_logs"]["compress"],
                "delaycompress": not original["nftables_logs"]["delaycompress"],
            },
        }
        section_keys = {"journald": "journald", "system-logs": "system_logs", "nftables-logs": "nftables_logs"}
        for route, body in valid_updates.items():
            status, payload = call(ctx, f"update all {route} fields", "PATCH", f"{BASE}/{route}", body)
            require(ctx, status == 200 and payload.get("section") == section_keys[route], f"{route} updated", f"{route} update failed {status}: {payload}")
            status, payload = call(ctx, f"read {route} after update", "GET", f"{BASE}/{route}")
            section = payload.get(section_keys[route], {}) if isinstance(payload, dict) else {}
            require(ctx, status == 200 and all(section.get(k) == v for k, v in body.items()), f"{route} persisted", f"{route} values not persisted: {payload}")
            stored_section = _read()[section_keys[route]]
            require(ctx, stored_section.get("uuid") == static_uuids[section_keys[route]], f"{route} static uuid preserved", f"{route} static uuid changed")

        negative_cases = [
            ("journald bad system_max_use", "journald", {"system_max_use": "5M"}),
            ("journald bad system_keep_free", "journald", {"system_keep_free": "3G"}),
            ("journald bad runtime_max_use", "journald", {"runtime_max_use": "0M"}),
            ("journald bad retention", "journald", {"max_retention_sec": "2day"}),
            ("journald bad compress", "journald", {"compress": "true"}),
            ("system logs bad enabled", "system-logs", {"enabled": "true"}),
            ("system logs bad rotation", "system-logs", {"rotation": "monthly"}),
            ("system logs rotate low", "system-logs", {"rotate": 0}),
            ("system logs rotate high", "system-logs", {"rotate": 31}),
            ("system logs bad maxsize", "system-logs", {"maxsize": "3G"}),
            ("system logs bad compress", "system-logs", {"compress": "false"}),
            ("system logs bad delaycompress", "system-logs", {"delaycompress": 1}),
            ("nftables logs bad enabled", "nftables-logs", {"enabled": "false"}),
            ("nftables logs bad size", "nftables-logs", {"size": "5M"}),
            ("nftables logs rotate low", "nftables-logs", {"rotate": 0}),
            ("nftables logs rotate high", "nftables-logs", {"rotate": 31}),
            ("nftables logs bad compress", "nftables-logs", {"compress": "true"}),
            ("nftables logs bad delaycompress", "nftables-logs", {"delaycompress": 0}),
            ("journald empty patch", "journald", {}),
            ("system logs empty patch", "system-logs", {}),
            ("nftables logs empty patch", "nftables-logs", {}),
            ("journald extra field", "journald", {"notreal": "x"}),
            ("system logs extra field", "system-logs", {"notreal": "x"}),
            ("nftables logs extra field", "nftables-logs", {"notreal": "x"}),
            ("journald uuid forbidden", "journald", {"uuid": "changed"}),
            ("system logs uuid forbidden", "system-logs", {"uuid": "changed"}),
            ("nftables logs uuid forbidden", "nftables-logs", {"uuid": "changed"}),
        ]
        for label, route, body in negative_cases:
            _expect_rejected(ctx, f"negative-{label}", route, body)

        for method in ("POST", "DELETE"):
            status, payload = call(ctx, f"negative-{method.lower()} unsupported", method, BASE, {})
            require(ctx, status == 405, f"{method} unsupported", f"{method} returned {status}: {payload}")

        malformed_cases = [
            ("missing journald", {key: value for key, value in original.items() if key != "journald"}),
            ("journald scalar", {**original, "journald": "bad"}),
            ("journald missing uuid", {**original, "journald": {key: value for key, value in original["journald"].items() if key != "uuid"}}),
            ("system logs empty uuid", {**original, "system_logs": {**original["system_logs"], "uuid": ""}}),
            ("nftables logs non-string uuid", {**original, "nftables_logs": {**original["nftables_logs"], "uuid": 1}}),
            ("system logs bad bool", {**original, "system_logs": {**original["system_logs"], "enabled": "true"}}),
            ("nftables logs bad rotate", {**original, "nftables_logs": {**original["nftables_logs"], "rotate": 99}}),
        ]
        for label, malformed in malformed_cases:
            _write(malformed)
            status, payload = call(ctx, f"negative-candidate {label}", "GET", BASE)
            require(ctx, status == 500, f"candidate {label} rejected", f"candidate {label} returned {status}: {payload}")
            shutil.copy2(BACKUP, CONFIG)
    finally:
        shutil.copy2(BACKUP, CONFIG)
        if not lock_existed:
            LOCK.unlink(missing_ok=True)
        require(ctx, CONFIG.read_bytes() == original_bytes, "system_logging candidate restored byte-for-byte", "system_logging candidate restore mismatch")
        ctx.log("RESTORE system_logging.json applied")
