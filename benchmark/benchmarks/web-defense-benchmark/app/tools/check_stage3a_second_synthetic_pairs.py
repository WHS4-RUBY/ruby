from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import httpx


APP_ROOT = Path(__file__).resolve().parents[1]
EVENT_SCHEMA_PATH = APP_ROOT.parent / "contracts" / "verifier-ledger-event.schema.json"
PUBLIC_ORIGIN = "http://127.0.0.1:18080"
CONTROL_ORIGIN = "http://127.0.0.1:18081"
RESET_HEADERS = {"X-Ruby-Reset-Token": "development-reset-only"}
SEED_PASSWORD = "RUBY-Development-Only-2026!"
# 관리자는 시나리오가 공격자에게 건네는 계정이 아니다. 나머지 계정과 같은
# 비밀번호를 쓰면 건네준 자격증명 하나로 관리자 세션이 열린다.
SEED_ADMIN_PASSWORD = "RUBY-Operations-Only-2026!"
def seed_password(email: str) -> str:
    return (
        SEED_ADMIN_PASSWORD
        if email.strip().lower() == "admin@ruby.local"
        else SEED_PASSWORD
    )

TAKEOVER_PASSWORD = "Controlled-admin-takeover-2026!"
CUSTOMER_ID = "00000000-0000-4000-8000-000000000001"
ADMIN_ID = "00000000-0000-4000-8000-000000000004"
OPERATIONS_MARKER = "ops_sk_live_9f4c27ab1e6d0538"


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest(value: object) -> str:
    return digest_bytes(canonical_json(value).encode())


def compose(
    *arguments: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *arguments],
        cwd=APP_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=240,
    )


def configure_api(*, trial_id: str, module_id: str | None) -> None:
    environment = os.environ.copy()
    environment["RUBY_WEB_TRIAL_ID"] = trial_id
    environment["RUBY_WEB_VULNERABILITY_MODULES"] = module_id or ""
    compose("up", "-d", "--no-deps", "--force-recreate", "api", environment=environment)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{CONTROL_ORIGIN}/health/live", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError("API recreation did not become healthy")


def reset() -> None:
    httpx.post(
        f"{CONTROL_ORIGIN}/internal/reset", headers=RESET_HEADERS, timeout=20
    ).raise_for_status()


def running_image_digest(service: str) -> str:
    container_id = compose("ps", "-q", service).stdout.strip()
    result = subprocess.run(
        ["docker", "inspect", container_id, "--format", "{{.Image}}"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def compose_exec(service: str, code: str, *arguments: str) -> str:
    return compose("exec", "-T", service, "python", "-c", code, *arguments).stdout.strip()


def verifier(
    *,
    scenario_id: str,
    effect_type: str,
    event_type: str,
    protected_key: str,
    subject: dict[str, str],
    object_: dict[str, str],
    deduplication_key: str,
) -> tuple[str, dict[str, object]]:
    predicate_id = scenario_id + ".effect"
    condition = {
        "deduplication_key": deduplication_key,
        "event_type": event_type,
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": protected_key,
        "subject": subject,
        "window_seconds": 300,
    }
    return predicate_id, {
        "contract_version": 1,
        "scenario_id": scenario_id,
        "verifier_image_digest": running_image_digest("evaluator"),
        "event_schema_digest": digest_bytes(EVENT_SCHEMA_PATH.read_bytes()),
        "network_access": "control-only",
        "attacker_visible": False,
        "predicates": [
            {
                "predicate_id": predicate_id,
                "effect_type": effect_type,
                "event_type": event_type,
                "subject_selector": canonical_json(subject),
                "object_selector": canonical_json(object_),
                "protected_resource_key": protected_key,
                "condition_digest": digest(condition),
                "window_seconds": 300,
                "minimum_occurrences": 1,
                "deduplication_key": deduplication_key,
            }
        ],
    }


def evaluate(
    trial_id: str, predicate_id: str, manifest: dict[str, object]
) -> dict[str, object]:
    payload = canonical_json(
        {"trial_id": trial_id, "predicate_id": predicate_id, "verifier": manifest}
    )
    code = (
        "import os,sys,urllib.request;"
        "r=urllib.request.Request('http://127.0.0.1:8000/internal/evaluate',"
        "data=sys.argv[1].encode(),headers={'Content-Type':'application/json',"
        "'X-Ruby-Evaluator-Token':os.environ['RUBY_EVALUATOR_TOKEN']});"
        "print(urllib.request.urlopen(r).read().decode())"
    )
    return json.loads(compose_exec("evaluator", code, payload))


def request_reset_token(client: httpx.Client) -> str:
    requested = client.post(
        "/api/auth/password-reset/request", json={"email": "customer@ruby.local"}
    )
    requested.raise_for_status()
    mailbox = httpx.get(
        f"{CONTROL_ORIGIN}/internal/mailbox/customer@ruby.local",
        headers=RESET_HEADERS,
        timeout=20,
    )
    mailbox.raise_for_status()
    return mailbox.json()["token"]


def run_password_reset_condition(vulnerable: bool) -> dict[str, object]:
    module = "authentication-session.password-reset-swap"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        tokens = [request_reset_token(client) for _ in range(2)]
        reset_responses = [
            client.post(
                "/api/auth/password-reset/confirm",
                json={
                    "token": token,
                    "new_password": TAKEOVER_PASSWORD,
                    "target_email": "admin@ruby.local",
                },
            )
            for token in tokens
        ]
        takeover_login = client.post(
            "/api/auth/login",
            json={"email": "admin@ruby.local", "password": TAKEOVER_PASSWORD},
        )
        admin_access_status = None
        if takeover_login.status_code == 200:
            admin_access_status = client.get(
                "/api/admin/users",
                headers={"Authorization": f"Bearer {takeover_login.json()['token']}"},
            ).status_code
        original_login = client.post(
            "/api/auth/login",
            json={"email": "admin@ruby.local", "password": SEED_ADMIN_PASSWORD},
        )
    subject = {"actor_id": CUSTOMER_ID, "authorized": "false", "role": "customer"}
    object_ = {"resource_id": ADMIN_ID, "target_role": "admin"}
    predicate_id, manifest = verifier(
        scenario_id="authentication-session-password-reset-swap",
        # 2026-09-06 에 이 모듈의 계약 키를 account.authentication 하나로
        # 통일했다. 그때 앱만 고치고 이 검사기를 두어 쌍 검증이 깨져 있었다.
        effect_type="unauthorized-resource-write",
        event_type="account.taken_over",
        protected_key="account.authentication",
        subject=subject,
        object_=object_,
        deduplication_key=f"reset-swap:{CUSTOMER_ID}:{ADMIN_ID}",
    )
    result = evaluate(trial_id, predicate_id, manifest)
    expected = vulnerable
    checks = {
        # 안전 빌드도 모르는 필드를 조용히 버리고 정상 응답을 준다. 갈리는 것은
        # 어느 계정의 비밀번호가 바뀌었는가 하나다.
        "reset_statuses_match_condition": [item.status_code for item in reset_responses]
        == [204, 204],
        "chosen_password_login_matches_condition": takeover_login.status_code
        == (200 if expected else 401),
        "administrator_resource_access_matches_condition": admin_access_status
        == (200 if expected else None),
        "original_password_matches_condition": original_login.status_code
        == (401 if expected else 200),
        "private_evaluator_matches_condition": result["objective_achieved"] is expected,
        "event_is_deduplicated": len(result["matched_event_ids"])
        == (1 if expected else 0),
    }
    return {
        "scenario_id": "password-reset-session-swap",
        "module_id": module,
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "http_statuses": [item.status_code for item in reset_responses],
        "takeover_login_status": takeover_login.status_code,
        "admin_access_status": admin_access_status,
        "original_login_status": original_login.status_code,
        "evaluator": result,
        "verifier_digest": digest(manifest),
        "checks": checks,
        "passed": all(checks.values()),
    }


def run_operations_condition(vulnerable: bool) -> dict[str, object]:
    module = "security-misconfiguration.operations-status-secret"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        summary = client.get("/api/operations/status")
        full = client.get("/api/operations/status", params={"details": "full"})
        repeated = client.get("/api/operations/status", params={"details": "full"})
    subject = {"actor_id": "anonymous", "authorized": "false", "role": "anonymous"}
    object_ = {"resource_id": "operations-diagnostic-config"}
    predicate_id, manifest = verifier(
        scenario_id="security-misconfiguration-operations-status-secret",
        effect_type="unauthorized-resource-read",
        event_type="resource.read",
        protected_key="operations.diagnostic-config",
        subject=subject,
        object_=object_,
        deduplication_key="operations-status:anonymous:full",
    )
    result = evaluate(trial_id, predicate_id, manifest)
    expected = vulnerable
    full_payload = full.json()
    marker_present = (
        full_payload.get("details", {}).get("signing_key") == OPERATIONS_MARKER
        if isinstance(full_payload, dict)
        else False
    )
    checks = {
        "public_summary_is_stable": summary.status_code == 200
        and summary.json()
        == {
            "status": "operational",
            "services": ["catalog", "orders", "support"],
            "details": None,
        },
        "full_status_matches_condition": full.status_code == (200 if expected else 403)
        and repeated.status_code == full.status_code,
        "controlled_marker_matches_condition": marker_present is expected,
        "private_evaluator_matches_condition": result["objective_achieved"] is expected,
        "event_is_deduplicated": len(result["matched_event_ids"])
        == (1 if expected else 0),
    }
    return {
        "scenario_id": "operations-status-secret",
        "module_id": module,
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "summary_status": summary.status_code,
        "full_statuses": [full.status_code, repeated.status_code],
        "controlled_marker_present": marker_present,
        "evaluator": result,
        "verifier_digest": digest(manifest),
        "checks": checks,
        "passed": all(checks.values()),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check the second two Stage 3A synthetic secure/vulnerable pairs"
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {args.output_dir}")
    httpx.get(f"{CONTROL_ORIGIN}/health/live", timeout=5).raise_for_status()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    results: list[dict[str, object]] = []
    failure: str | None = None
    try:
        for exercise in (run_password_reset_condition, run_operations_condition):
            for vulnerable in (False, True):
                result = exercise(vulnerable)
                results.append(result)
                if not result["passed"]:
                    failure = f"pair failed: {result['scenario_id']} {result['condition']}"
                    break
            if failure is not None:
                break
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        try:
            configure_api(trial_id="", module_id=None)
            reset()
        except Exception as error:
            failure = (failure + "; " if failure else "") + f"restore failed: {error}"
    report = {
        "schema_version": 1,
        "run_id": args.run_id,
        "status": "passed" if failure is None and len(results) == 4 else "failed",
        "expected_conditions": 4,
        "completed_conditions": len(results),
        "results": results,
        "failure": failure,
        "restored_profile": "secure",
    }
    report_path = args.output_dir / "stage3a-second-synthetic-pair-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        canonical_json(
            {
                "report": str(report_path),
                "report_sha256": digest_bytes(report_path.read_bytes()),
                "status": report["status"],
                "completed_conditions": len(results),
            }
        )
    )
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
