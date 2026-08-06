"""Tests destructivos de Monitor Session."""
from __future__ import annotations

from pathlib import Path

from common.runner import call, require

BASE = "/api/v1/monitor-session"
STATE_DIR = Path("/var/lib/praesidium/state/sessions_contrack")


def _snapshot(ctx) -> Path:
    return STATE_DIR / f"{ctx.identity.username}_session_conntrack.xml"


def _write_fixture(ctx) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    _snapshot(ctx).write_text("""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<conntrack>
  <flow>
    <meta direction=\"original\">
      <layer3><src>10.1.1.1</src><dst>10.2.2.2</dst></layer3>
      <layer4 protoname=\"tcp\"><sport>12345</sport><dport>443</dport></layer4>
    </meta>
    <meta direction=\"reply\">
      <layer3><src>10.2.2.2</src><dst>10.1.1.1</dst></layer3>
      <layer4><sport>443</sport><dport>12345</dport></layer4>
    </meta>
    <meta direction=\"independent\">
      <state>ESTABLISHED</state><timeout>300</timeout><assured/><id>777</id>
    </meta>
  </flow>
</conntrack>
""", encoding="utf-8")
    _snapshot(ctx).chmod(0o644)


def _cleanup(ctx) -> None:
    path = _snapshot(ctx)
    if path.exists():
        path.unlink()
    ctx.log("RESTORE monitor-session temp snapshot removed")


def run(ctx) -> None:
    ctx.log("=== MONITOR SESSION DESTRUCTIVE ===")
    _write_fixture(ctx)
    try:
        status, payload = call(ctx, "read fixture sessions", "GET", f"{BASE}/sessions")
        require(ctx, status == 200, "sessions fixture readable", f"sessions returned {status}: {payload}")
        rows = payload.get("rows", []) if isinstance(payload, dict) else []
        require(ctx, len(rows) == 1, "one session parsed", f"unexpected rows: {payload}")
        row = rows[0]
        require(ctx, row.get("proto") == "tcp", "proto parsed", f"proto bad: {row}")
        require(ctx, row.get("state") == "ESTABLISHED", "state parsed", f"state bad: {row}")
        require(ctx, row.get("source") == "10.1.1.1", "source parsed", f"source bad: {row}")
        require(ctx, row.get("destination_port") == "443", "dport parsed", f"dport bad: {row}")
        require(ctx, row.get("reply_source") == "10.2.2.2", "reply source parsed", f"reply source bad: {row}")
        require(ctx, row.get("assured") == "yes", "assured parsed", f"assured bad: {row}")
        require(ctx, row.get("id") == "777", "id parsed", f"id bad: {row}")

        status, payload = call(ctx, "columns destructive", "GET", f"{BASE}/columns")
        require(ctx, status == 200 and "PROTO" in payload.get("columns", []), "columns include PROTO", f"columns bad: {status} {payload}")
    finally:
        _cleanup(ctx)
