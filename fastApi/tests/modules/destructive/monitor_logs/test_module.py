"""Tests destructivos de Monitor Logs."""
from __future__ import annotations

from pathlib import Path

from common.runner import call, require

BASE = "/api/v1/monitor-logs"
LOG_FILE = Path("/var/log/praesidium/nftables.log.fastapi_test")
STATE_DIR = Path("/var/lib/praesidium/state/monitor_log")
SPOOFED_USER = "spoofed_monitor_user"
TEST_LINE = "1970-01-01T00:00:00+00:00 host kernel: nftables 900 input drop IN=eth0 OUT= SRC=10.10.10.10 DST=20.20.20.20 PROTO=TCP SPT=12345 DPT=443\n"


def _write_log() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text(TEST_LINE, encoding="utf-8")
    LOG_FILE.chmod(0o644)


def _cleanup(ctx) -> None:
    if LOG_FILE.exists():
        LOG_FILE.unlink()
    for username in {ctx.identity.username, SPOOFED_USER}:
        path = STATE_DIR / f"{username}_log_view.json"
        if path.exists():
            path.unlink()
    ctx.log("RESTORE monitor-logs temp log/state files removed")


def _query(**overrides):
    base = {
        "Firewall": "NFTABLES",
        "Start_Date": "1970-01-01",
        "Start_Time": "12:00",
        "End_Date": "1970-01-01",
        "End_Time": "13:00",
        "Source_IP": "",
        "Destination_IP": "",
        "Source_Port": "",
        "Destination_Port": "",
        "Protocol": "",
        "Action": "",
        "Max_Records": "100",
    }
    base.update(overrides)
    return base


def run(ctx) -> None:
    ctx.log("=== MONITOR LOGS DESTRUCTIVE ===")
    _write_log()
    try:
        status, payload = call(ctx, "search nftables test log", "POST", f"{BASE}/search", _query(Source_IP="10.10.10.10"))
        require(ctx, status == 200, f"search returns 200", f"search returned {status}: {payload}")
        logs = payload.get("logs", {}) if isinstance(payload, dict) else {}
        found = next(iter(logs.values()), {}) if isinstance(logs, dict) and logs else {}
        require(ctx, found.get("SRC") == "10.10.10.10", "source parsed", f"source not parsed: {payload}")
        require(ctx, found.get("DST") == "20.20.20.20", "destination parsed", f"destination not parsed: {payload}")
        require(ctx, found.get("PROTO") == "TCP", "protocol parsed", f"protocol not parsed: {payload}")
        require(ctx, found.get("Action") == "DROP", "action parsed", f"action not parsed: {payload}")
        require(ctx, found.get("DPT") == "443", "destination port parsed", f"dpt not parsed: {payload}")

        authenticated_output = STATE_DIR / f"{ctx.identity.username}_log_view.json"
        spoofed_output = STATE_DIR / f"{SPOOFED_USER}_log_view.json"
        require(ctx, authenticated_output.exists(), "script output written for token user", f"missing authenticated output {authenticated_output}")
        require(ctx, not spoofed_output.exists(), "no spoofed user output before spoof test", f"unexpected spoofed output {spoofed_output}")

        status, payload = call(ctx, "spoofed user ignored", "POST", f"{BASE}/search", {**_query(Source_IP="10.10.10.10"), "user": SPOOFED_USER})
        require(ctx, status == 200, "spoofed user request accepted as normal filters", f"spoofed user returned {status}: {payload}")
        require(ctx, authenticated_output.exists(), "spoofed body still writes token user output", f"missing authenticated output {authenticated_output}")
        require(ctx, not spoofed_output.exists(), "spoofed body did not create spoofed output", f"spoofed output exists {spoofed_output}")

        positive_filters = [
            ("filter source ip", _query(Source_IP="10.10.10.10")),
            ("filter destination ip", _query(Destination_IP="20.20.20.20")),
            ("filter source port", _query(Source_Port="12345")),
            ("filter destination port", _query(Destination_Port="443")),
            ("filter protocol", _query(Protocol="TCP")),
            ("filter action", _query(Action="DROP")),
        ]
        for label, body in positive_filters:
            status, payload = call(ctx, label, "POST", f"{BASE}/search", body)
            logs = payload.get("logs", {}) if isinstance(payload, dict) else {}
            require(ctx, status == 200 and bool(logs), f"{label} matched", f"{label} returned {status}: {payload}")

        negative_filters = [
            ("no source ip match", _query(Source_IP="10.10.10.11")),
            ("no protocol match", _query(Source_IP="10.10.10.10", Protocol="UDP")),
            ("no action match", _query(Source_IP="10.10.10.10", Action="ACCEPT")),
        ]
        for label, body in negative_filters:
            status, payload = call(ctx, label, "POST", f"{BASE}/search", body)
            logs = payload.get("logs", {}) if isinstance(payload, dict) else {}
            require(ctx, status == 200 and logs == {}, f"{label} empty", f"{label} returned {status}: {payload}")

        status, payload = call(ctx, "bpfilter not implemented parity", "POST", f"{BASE}/search", _query(Firewall="BPFILTER"))
        require(ctx, status == 200 and "BPFILTER" in str(payload), "bpfilter parity response", f"bpfilter returned {status}: {payload}")
    finally:
        _cleanup(ctx)
