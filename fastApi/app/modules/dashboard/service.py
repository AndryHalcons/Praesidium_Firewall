"""Lógica de lectura de métricas del Dashboard."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

_CPU_LOCK = threading.Lock()
_NET_LOCK = threading.Lock()
_PREVIOUS_CPU: list[tuple[int, int]] | None = None
_PREVIOUS_NET: tuple[float, dict[str, tuple[int, int]]] | None = None

_IGNORED_FS = {
    "autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs", "debugfs",
    "devpts", "devtmpfs", "fusectl", "hugetlbfs", "mqueue", "nsfs", "overlay",
    "proc", "pstore", "ramfs", "rpc_pipefs", "securityfs", "squashfs", "sysfs",
    "tracefs", "tmpfs",
}
_IMPORTANT_MOUNTS = {
    "/", "/var", "/var/www", "/var/log", "/home", "/boot", "/boot/efi", "/tmp", "/opt", "/srv",
}
_MOUNT_PRIORITY = {
    "/": 0,
    "/var": 10,
    "/var/www": 11,
    "/var/log": 12,
    "/home": 20,
    "/boot": 30,
    "/boot/efi": 31,
    "/tmp": 40,
    "/opt": 50,
    "/srv": 60,
}
_CAPACITY_CRITICAL_MOUNTS = {"/", "/var", "/var/www", "/var/log", "/home", "/tmp", "/opt", "/srv"}


def _clamp_percent(value: float) -> float:
    return round(max(0.0, min(100.0, value)), 2)


def _unescape_mount_field(value: str) -> str:
    result = value
    for code in ("040", "011", "012", "134"):
        result = result.replace(f"\\{code}", chr(int(code, 8)))
    return result


def _read_cpu_counters() -> list[tuple[int, int]]:
    counters: list[tuple[int, int]] = []
    for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
        if not line.startswith("cpu") or line.startswith("cpu "):
            continue
        name, *values = line.split()
        if not name[3:].isdigit():
            continue
        numbers = [int(value) for value in values]
        idle = numbers[3] + (numbers[4] if len(numbers) > 4 else 0)
        total = sum(numbers)
        counters.append((idle, total))
    return counters


def cpu_stats() -> dict[str, Any]:
    global _PREVIOUS_CPU
    current = _read_cpu_counters()
    usages: list[float] = []
    with _CPU_LOCK:
        previous = _PREVIOUS_CPU
        _PREVIOUS_CPU = current
    if previous and len(previous) == len(current):
        for (prev_idle, prev_total), (idle, total) in zip(previous, current):
            idle_diff = idle - prev_idle
            total_diff = total - prev_total
            usage = 100.0 * (1.0 - (idle_diff / total_diff)) if total_diff > 0 else 0.0
            usages.append(_clamp_percent(usage))
    else:
        usages = [0.0 for _ in current]
    average = round(sum(usages) / len(usages), 2) if usages else 0.0
    return {"cores": usages, "average": average, "core_count": len(usages)}


def ram_stats() -> dict[str, Any]:
    info: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        parts = raw_value.strip().split()
        if parts:
            info[key] = int(parts[0])
    total = round(info.get("MemTotal", 0) / 1024)
    available = round(info.get("MemAvailable", 0) / 1024)
    free = round(info.get("MemFree", 0) / 1024)
    cached = round((info.get("Cached", 0) + info.get("SReclaimable", 0)) / 1024)
    used = max(0, total - available)
    used_percent = _clamp_percent((used / total) * 100.0) if total > 0 else 0.0
    return {"total": total, "used": used, "free": free, "cached": cached, "used_percent": used_percent}


def _is_storage_mount(fstype: str, target: str) -> bool:
    if fstype in _IGNORED_FS:
        return False
    if not target:
        return False
    return not target.startswith(("/proc", "/sys", "/dev", "/run"))


def _is_relevant_mount(target: str, used_percent: float) -> bool:
    return target in _IMPORTANT_MOUNTS or used_percent >= 80.0


def disk_stats() -> dict[str, Any]:
    mounts: list[dict[str, Any]] = []
    summary_by_device: dict[str, dict[str, int]] = {}
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        left_raw, separator, right_raw = line.partition(" - ")
        if not separator:
            continue
        left = left_raw.split()
        right = right_raw.split()
        if len(left) < 5 or len(right) < 3:
            continue
        device_id = left[2]
        target = _unescape_mount_field(left[4])
        fstype = right[0]
        source = _unescape_mount_field(right[1])
        if not _is_storage_mount(fstype, target):
            continue
        try:
            stat = os.statvfs(target)
        except OSError:
            continue
        total = int(stat.f_blocks * stat.f_frsize)
        available = int(stat.f_bavail * stat.f_frsize)
        if total <= 0:
            continue
        used = max(0, total - available)
        used_percent = _clamp_percent((used / total) * 100.0)
        summary_by_device.setdefault(device_id, {"total": total, "used": used, "available": available})
        if not _is_relevant_mount(target, used_percent):
            continue
        absolute_threshold = target in _CAPACITY_CRITICAL_MOUNTS
        if used_percent >= 90.0 or (absolute_threshold and available <= 1_073_741_824):
            status = "critical"
        elif used_percent >= 80.0 or (absolute_threshold and available <= 5_368_709_120):
            status = "warning"
        else:
            status = "ok"
        mounts.append({
            "mountpoint": target,
            "source": source,
            "fstype": fstype,
            "total": total,
            "used": used,
            "available": available,
            "used_percent": used_percent,
            "status": status,
            "priority": _MOUNT_PRIORITY.get(target, 100),
        })
    mounts.sort(key=lambda item: (item["priority"], item["mountpoint"]))
    for mount in mounts:
        mount.pop("priority", None)
    total = sum(item["total"] for item in summary_by_device.values())
    used = sum(item["used"] for item in summary_by_device.values())
    available = sum(item["available"] for item in summary_by_device.values())
    used_percent = _clamp_percent((used / total) * 100.0) if total > 0 else 0.0
    return {
        "summary": {"total": total, "used": used, "available": available, "used_percent": used_percent, "device_count": len(summary_by_device)},
        "mounts": mounts,
    }


def _read_net_counters() -> dict[str, tuple[int, int]]:
    counters: dict[str, tuple[int, int]] = {}
    for line in Path("/proc/net/dev").read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        name, data = [part.strip() for part in line.split(":", 1)]
        if name == "lo":
            continue
        parts = data.split()
        if len(parts) < 16:
            continue
        counters[name] = (int(parts[0]), int(parts[8]))
    return counters


def network_stats(timestamp: float) -> dict[str, Any]:
    global _PREVIOUS_NET
    current = _read_net_counters()
    with _NET_LOCK:
        previous = _PREVIOUS_NET
        _PREVIOUS_NET = (timestamp, current)
    interfaces: list[dict[str, Any]] = []
    for name, (rx_bytes, tx_bytes) in sorted(current.items()):
        rx_rate = 0.0
        tx_rate = 0.0
        if previous and name in previous[1]:
            elapsed = max(0.001, timestamp - previous[0])
            prev_rx, prev_tx = previous[1][name]
            rx_rate = max(0.0, (rx_bytes - prev_rx) / elapsed)
            tx_rate = max(0.0, (tx_bytes - prev_tx) / elapsed)
        interfaces.append({
            "name": name,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "rx_bytes_per_second": round(rx_rate, 2),
            "tx_bytes_per_second": round(tx_rate, 2),
        })
    return {"interfaces": interfaces}


def load_average() -> list[float]:
    return [round(value, 2) for value in os.getloadavg()]


def uptime_seconds() -> float:
    raw = Path("/proc/uptime").read_text(encoding="utf-8").split()[0]
    return round(float(raw), 2)


def dashboard_stats() -> dict[str, Any]:
    timestamp = time.time()
    errors: list[dict[str, Any]] = []

    def safe(name: str, fn, fallback):
        try:
            return fn()
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            errors.append({"section": name, "error": exc.__class__.__name__})
            return fallback

    return {
        "status": "ok",
        "timestamp": timestamp,
        "load_average": safe("load_average", load_average, [0.0, 0.0, 0.0]),
        "uptime_seconds": safe("uptime", uptime_seconds, 0.0),
        "cpu": safe("cpu", cpu_stats, {"cores": [], "average": 0.0, "core_count": 0}),
        "ram": safe("ram", ram_stats, {"total": 0, "used": 0, "free": 0, "cached": 0, "used_percent": 0.0}),
        "disk": safe("disk", disk_stats, {"summary": {"total": 0, "used": 0, "available": 0, "used_percent": 0.0, "device_count": 0}, "mounts": []}),
        "network": safe("network", lambda: network_stats(timestamp), {"interfaces": []}),
        "errors": errors,
    }
