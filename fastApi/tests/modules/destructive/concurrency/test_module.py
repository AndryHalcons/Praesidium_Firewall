"""Tests destructivos de concurrencia users.json. / Destructive users.json concurrency tests."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from common.runner import RequestSummary, call, find_user_by_name, request


def ok(status: int) -> bool:
    return 200 <= status <= 299


def run(ctx) -> None:
    ctx.log("=== CONCURRENCY DESTRUCTIVE SAME FLOW ===")
    names = [f"api_concurrency_user_{idx}" for idx in range(5)]
    for name in names:
        existing = find_user_by_name(name)
        if existing and existing.get("UUID"):
            call(ctx, f"pre-clean concurrency {name}", "DELETE", f"/api/v1/users/{existing['UUID']}")

    def create_one(name: str):
        body = {
            "user_name": name,
            "user_pass": "ConcurrencyPass12345A*",
            "user_role": "viewer",
            "user_language": "english",
            "force_password_change": "false",
        }
        return name, request("POST", "/api/v1/users/", body, ctx.token)

    results = []
    with ThreadPoolExecutor(max_workers=len(names)) as executor:
        futures = [executor.submit(create_one, name) for name in names]
        for future in as_completed(futures):
            results.append(future.result())

    created_uuids = []
    for name, (status, payload) in sorted(results):
        detail = payload.get("detail", "ok") if isinstance(payload, dict) else str(payload)
        report_name = f"negative-concurrent create {name}" if status >= 400 else f"concurrent create {name}"
        ctx.log(f"REQUEST {report_name}: POST /api/v1/users/")
        ctx.log(f"RESPONSE {status}: {payload if status != 201 else {'UUID': payload.get('UUID'), 'user_name': payload.get('user_name')}}")
        ctx.request_summaries.append(RequestSummary(ctx.module_name, ctx.identity.role, ctx.identity.username, report_name, "POST", "/api/v1/users/", status, str(detail)))
        if ok(status) and isinstance(payload, dict) and payload.get("UUID"):
            created_uuids.append(payload["UUID"])

    ctx.log(f"CHECK concurrency created_count={len(created_uuids)} unique_count={len(set(created_uuids))}")

    for uuid in created_uuids:
        status, payload = call(ctx, f"cleanup concurrent {uuid}", "DELETE", f"/api/v1/users/{uuid}")
        ctx.log(f"CHECK cleanup concurrent status={status} success={ok(status)}")
