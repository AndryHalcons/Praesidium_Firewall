"""Tests no destructivos de health/docs. / Non-destructive health/docs tests."""
from __future__ import annotations

from common.runner import call


def ok(status: int) -> bool:
    return 200 <= status <= 299


def run(ctx) -> None:
    ctx.log("=== HEALTH NON-DESTRUCTIVE SAME FLOW ===")
    status, payload = call(ctx, "read health", "GET", "/health")
    ctx.log(f"CHECK health status={status} success={ok(status)}")

    status, payload = call(ctx, "read openapi", "GET", "/openapi.json")
    ctx.log(f"CHECK openapi status={status} success={ok(status)}")
