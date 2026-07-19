"""Tests no destructivos de Dashboard."""
from __future__ import annotations

from common.runner import call, require

BASE = "/api/v1/dashboard"


def ok(status: int) -> bool:
    return 200 <= status <= 299


def check(ctx, condition: bool, ok_msg: str, fail_msg: str) -> None:
    require(ctx, condition, ok_msg, fail_msg)


def run(ctx) -> None:
    ctx.log("=== DASHBOARD NON-DESTRUCTIVE ===")

    status, payload = call(ctx, "read dashboard status", "GET", f"{BASE}/status")
    check(ctx, ok(status), "dashboard status reachable", f"dashboard status failed status={status}")
    check(ctx, payload.get("module") == "dashboard", "dashboard module name valid", "dashboard module name invalid")

    status, payload = call(ctx, "read dashboard stats", "GET", f"{BASE}/stats")
    check(ctx, ok(status), "dashboard stats reachable", f"dashboard stats failed status={status}")

    for key in ("timestamp", "load_average", "uptime_seconds", "cpu", "ram", "disk", "network", "errors"):
        check(ctx, key in payload, f"dashboard stats contains {key}", f"dashboard stats missing {key}")

    cpu = payload.get("cpu", {})
    check(ctx, isinstance(cpu.get("cores"), list), "cpu cores list present", "cpu cores missing")
    check(ctx, isinstance(cpu.get("core_count"), int), "cpu core_count present", "cpu core_count missing")
    check(ctx, 0 <= float(cpu.get("average", -1)) <= 100, "cpu average bounded", "cpu average out of range")

    ram = payload.get("ram", {})
    check(ctx, int(ram.get("total", 0)) > 0, "ram total positive", "ram total invalid")
    check(ctx, 0 <= float(ram.get("used_percent", -1)) <= 100, "ram percent bounded", "ram percent invalid")

    disk = payload.get("disk", {})
    summary = disk.get("summary", {}) if isinstance(disk, dict) else {}
    check(ctx, int(summary.get("total", 0)) > 0, "disk total positive", "disk total invalid")
    check(ctx, isinstance(disk.get("mounts"), list), "disk mounts list present", "disk mounts missing")

    network = payload.get("network", {})
    check(ctx, isinstance(network.get("interfaces"), list), "network interfaces list present", "network interfaces missing")

    status, payload = call(ctx, "read dashboard stats second sample", "GET", f"{BASE}/stats")
    check(ctx, ok(status), "dashboard second stats reachable", f"dashboard second stats failed status={status}")
    check(ctx, "cpu" in payload and "network" in payload, "dashboard second sample valid", "dashboard second sample invalid")
