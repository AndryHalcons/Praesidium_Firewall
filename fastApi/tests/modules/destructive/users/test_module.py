"""Tests destructivos del módulo users. / Destructive users module tests."""
from __future__ import annotations

import json
import time
from common.runner import CANDIDATE, call, find_user_by_name, find_user_by_uuid, require

TEST_USER_INITIAL = {
    "user_name": "api_test_user_granular",
    "user_pass": "InitialPass12345A*",
    "user_role": "viewer",
    "user_language": "english",
    "force_password_change": "false",
}
TEST_USER_PASSWORD_2 = "ChangePass12345A*"
TEST_USER_PASSWORD_3 = "ThirdChangePass12345A*"
TEST_USER_PASSWORD_4 = "FourthChangePass12345A*"
TEST_USER_FULL_CREATE = {
    "user_name": "api_test_user_full",
    "user_pass": "FullCreatePass12345A*",
    "user_role": "viewer",
    "user_language": "english",
    "force_password_change": "true",
}
TEST_USER_FULL_UPDATE = {
    "user_name": "api_test_user_full_updated",
    "user_role": "admin",
    "user_language": "espanol",
    "force_password_change": "false",
}


def response_success(status: int) -> bool:
    # ES: Detecta respuestas 2xx sin depender del rol.
    # EN: Detect 2xx responses without depending on the role.
    return 200 <= status <= 299


def log_json_state(ctx, label: str, uuid: str | None) -> None:
    # ES: Registra si el objeto existe y sus campos actuales en candidate.
    # EN: Log whether the object exists and its current candidate fields.
    if not uuid:
        ctx.log(f"CHECK {label}: no UUID available")
        return
    user = find_user_by_uuid(uuid)
    if user is None:
        ctx.log(f"CHECK {label}: user not found in candidate")
        return
    safe = {k: v for k, v in user.items() if k != "user_pass"}
    ctx.log(f"CHECK {label}: candidate={safe}")
    ctx.log(f"CHECK {label}: api_access_present={'api_access' in user}")




def _set_policy_field(field: str, value: str) -> None:
    data = json.loads(CANDIDATE.read_text(encoding="utf-8"))
    policy_table = data.get("table_password_policy", [{}])
    if not isinstance(policy_table, list) or not policy_table:
        data["table_password_policy"] = [{}]
        policy_table = data["table_password_policy"]
    policy_table[0][field] = value
    CANDIDATE.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")


def _history_count_for_user_id(user_id: str) -> int:
    data = json.loads(CANDIDATE.read_text(encoding="utf-8"))
    rows = data.get("table_password_history", [])
    if not isinstance(rows, list):
        return 0
    return sum(1 for row in rows if str(row.get("user_id", "")) == str(user_id))


def check_password_history_and_min_age(ctx, user_uuid: str | None) -> None:
    # ES: Verifica min_age y recorte de password_history sobre candidate.
    # EN: Verify min_age and password_history trimming on candidate.
    if not user_uuid:
        ctx.log("CHECK password history/min_age skipped: no UUID")
        return
    user = find_user_by_uuid(user_uuid)
    if not user:
        ctx.log("CHECK password history/min_age skipped: user not found")
        return
    user_id = str(user.get("id", ""))

    _set_policy_field("password_min_age_days", "1")
    status, payload = call(ctx, "attempt password change before min age", "POST", f"/api/v1/users/{user_uuid}/password", {"current_password": ctx.current_password, "new_password": TEST_USER_PASSWORD_3, "confirm_password": TEST_USER_PASSWORD_3})
    ctx.log(f"CHECK password min_age status={status} expected_non_2xx={not response_success(status)} detail={payload.get('detail') if isinstance(payload, dict) else payload}")

    _set_policy_field("password_min_age_days", "0")
    _set_policy_field("password_history_count", "2")
    time.sleep(1)
    status, payload = call(ctx, "password history change 1", "POST", f"/api/v1/users/{user_uuid}/password", {"current_password": ctx.current_password, "new_password": TEST_USER_PASSWORD_3, "confirm_password": TEST_USER_PASSWORD_3})
    ctx.log(f"CHECK password history change 1 status={status} success={response_success(status)}")
    time.sleep(1)
    status, payload = call(ctx, "password history change 2", "POST", f"/api/v1/users/{user_uuid}/password", {"current_password": ctx.current_password, "new_password": TEST_USER_PASSWORD_4, "confirm_password": TEST_USER_PASSWORD_4})
    ctx.log(f"CHECK password history change 2 status={status} success={response_success(status)}")
    count = _history_count_for_user_id(user_id)
    ctx.log(f"CHECK password_history_count user_id={user_id} count={count} expected_max=2 ok={count <= 2}")

def cleanup_existing_test_users(ctx) -> None:
    # ES: Ejecuta la misma limpieza previa con la identidad inyectada.
    # EN: Run the same pre-cleanup with the injected identity.
    for name in [
        "api_test_user_granular",
        "api_test_user_granular_renamed",
        "api_test_user_full",
        "api_test_user_full_updated",
        "viewer_should_not_create",
    ]:
        user = find_user_by_name(name)
        if user and user.get("UUID"):
            status, _ = call(ctx, f"pre-test cleanup {name}", "DELETE", f"/api/v1/users/{user['UUID']}")
            ctx.log(f"CHECK pre-test cleanup {name}: status={status}")


def check_last_admin_guard(ctx) -> None:
    # ES: Prepara temporalmente candidate con un viewer y un único admin para probar el guard.
    # EN: Temporarily prepare candidate with one viewer and one admin to test the guard.
    original_candidate = CANDIDATE.read_text(encoding="utf-8")
    try:
        data = json.loads(original_candidate)
        selected = []
        for user in data.get("table_users", []):
            if user.get("user_name") == "testuser":
                clone = dict(user)
                clone["user_role"] = "viewer"
                selected.append(clone)
            if user.get("user_name") == "testuser2":
                clone = dict(user)
                clone["user_role"] = "admin"
                selected.append(clone)
        data["table_users"] = selected
        CANDIDATE.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
        admin = find_user_by_name("testuser2")
        admin_uuid = admin.get("UUID") if admin else "missing-uuid"

        status, payload = call(ctx, "attempt to downgrade the only admin", "PATCH", f"/api/v1/users/{admin_uuid}", {"user_role": "viewer"})
        ctx.log(f"CHECK last admin downgrade status={status} expected_non_2xx={not response_success(status)} detail={payload.get('detail') if isinstance(payload, dict) else payload}")

        status, payload = call(ctx, "attempt to delete the only admin", "DELETE", f"/api/v1/users/{admin_uuid}")
        ctx.log(f"CHECK last admin delete status={status} expected_non_2xx={not response_success(status)} detail={payload.get('detail') if isinstance(payload, dict) else payload}")
    finally:
        CANDIDATE.write_text(original_candidate, encoding="utf-8")
        ctx.log("CHECK last admin fixture restored")


def run(ctx) -> None:
    # ES: Ejecuta exactamente el mismo flujo con cualquier identidad inyectada.
    # EN: Execute exactly the same flow with any injected identity.
    ctx.log("=== USERS MODULE SAME FLOW ===")
    cleanup_existing_test_users(ctx)

    status, payload = call(ctx, "list users", "GET", "/api/v1/users/")
    ctx.log(f"CHECK list users status={status} success={response_success(status)}")
    if response_success(status):
        require(ctx, isinstance(payload, dict) and "users" in payload, "list response contains users", "list response does not contain users")

    status, created = call(ctx, "create granular user", "POST", "/api/v1/users/", TEST_USER_INITIAL)
    ctx.log(f"CHECK create granular status={status} success={response_success(status)}")
    user_uuid = created.get("UUID") if isinstance(created, dict) else None
    log_json_state(ctx, "after create granular", user_uuid)

    status, payload = call(ctx, "granular patch user_name", "PATCH", f"/api/v1/users/{user_uuid or 'missing-uuid'}", {"user_name": "api_test_user_granular_renamed"})
    ctx.log(f"CHECK patch user_name status={status} success={response_success(status)}")
    log_json_state(ctx, "after patch user_name", user_uuid)

    status, payload = call(ctx, "granular patch user_role", "PATCH", f"/api/v1/users/{user_uuid or 'missing-uuid'}", {"user_role": "admin"})
    ctx.log(f"CHECK patch user_role status={status} success={response_success(status)}")
    log_json_state(ctx, "after patch user_role", user_uuid)

    status, payload = call(ctx, "granular patch user_language", "PATCH", f"/api/v1/users/{user_uuid or 'missing-uuid'}", {"user_language": "espanol"})
    ctx.log(f"CHECK patch user_language status={status} success={response_success(status)}")
    log_json_state(ctx, "after patch user_language", user_uuid)

    status, payload = call(ctx, "granular patch force_password_change", "PATCH", f"/api/v1/users/{user_uuid or 'missing-uuid'}", {"force_password_change": "true"})
    ctx.log(f"CHECK patch force_password_change status={status} success={response_success(status)}")
    log_json_state(ctx, "after patch force_password_change", user_uuid)

    status, payload = call(ctx, "attempt to edit password_changed_at", "PATCH", f"/api/v1/users/{user_uuid or 'missing-uuid'}", {"password_changed_at": "1970-01-01T00:00:00+00:00"})
    ctx.log(f"CHECK edit password_changed_at status={status} expected_non_2xx={not response_success(status)}")

    status, payload = call(ctx, "attempt to edit api_access", "PATCH", f"/api/v1/users/{user_uuid or 'missing-uuid'}", {"api_access": "true"})
    ctx.log(f"CHECK edit api_access status={status} expected_non_2xx={not response_success(status)}")

    check_last_admin_guard(ctx)

    status, payload = call(ctx, "attempt password change with mismatched confirmation", "POST", f"/api/v1/users/{user_uuid or 'missing-uuid'}/password", {"current_password": ctx.current_password, "new_password": TEST_USER_PASSWORD_2, "confirm_password": "DifferentPass12345A*"})
    ctx.log(f"CHECK password confirm mismatch status={status} expected_non_2xx={not response_success(status)}")

    status, payload = call(ctx, "attempt password change with wrong current password", "POST", f"/api/v1/users/{user_uuid or 'missing-uuid'}/password", {"current_password": "WrongCurrentPassword123A*", "new_password": TEST_USER_PASSWORD_2, "confirm_password": TEST_USER_PASSWORD_2})
    ctx.log(f"CHECK password wrong current status={status} expected_non_2xx={not response_success(status)}")

    time.sleep(1)
    before_password_user = find_user_by_uuid(user_uuid) if user_uuid else None
    before_changed_at = before_password_user.get("password_changed_at") if before_password_user else None
    status, changed = call(ctx, "change user password", "POST", f"/api/v1/users/{user_uuid or 'missing-uuid'}/password", {"current_password": ctx.current_password, "new_password": TEST_USER_PASSWORD_2, "confirm_password": TEST_USER_PASSWORD_2})
    ctx.log(f"CHECK password change status={status} success={response_success(status)}")
    after_password_user = find_user_by_uuid(user_uuid) if user_uuid else None
    after_changed_at = after_password_user.get("password_changed_at") if after_password_user else None
    ctx.log(f"CHECK password_changed_at before={before_changed_at} after={after_changed_at} changed={before_changed_at != after_changed_at}")
    ctx.log(f"CHECK response exposes user_pass={isinstance(changed, dict) and 'user_pass' in changed}")

    check_password_history_and_min_age(ctx, user_uuid)

    status, created_full = call(ctx, "create full user", "POST", "/api/v1/users/", TEST_USER_FULL_CREATE)
    ctx.log(f"CHECK create full status={status} success={response_success(status)}")
    full_uuid = created_full.get("UUID") if isinstance(created_full, dict) else None
    log_json_state(ctx, "after create full", full_uuid)

    status, updated_full = call(ctx, "patch all editable fields", "PATCH", f"/api/v1/users/{full_uuid or 'missing-uuid'}", TEST_USER_FULL_UPDATE)
    ctx.log(f"CHECK patch all editable fields status={status} success={response_success(status)}")
    log_json_state(ctx, "after patch all editable fields", full_uuid)

    status, deleted = call(ctx, "delete granular user", "DELETE", f"/api/v1/users/{user_uuid or 'missing-uuid'}")
    ctx.log(f"CHECK delete granular status={status} success={response_success(status)} exists_after={find_user_by_uuid(user_uuid) is not None if user_uuid else 'no_uuid'}")

    status, deleted = call(ctx, "delete full user", "DELETE", f"/api/v1/users/{full_uuid or 'missing-uuid'}")
    ctx.log(f"CHECK delete full status={status} success={response_success(status)} exists_after={find_user_by_uuid(full_uuid) is not None if full_uuid else 'no_uuid'}")
