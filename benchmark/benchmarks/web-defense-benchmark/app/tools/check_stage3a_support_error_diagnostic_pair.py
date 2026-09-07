from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import httpx

from check_stage3a_support_role_csrf_pair import (
    EVENT_SCHEMA_PATH,
    PUBLIC_ORIGIN,
    SUPPORT_ID,
    bearer,
    canonical_json,
    compose_exec,
    configure_api,
    digest,
    digest_bytes,
    login,
    reset,
    running_image_digest,
)


CUSTOMER_ID = "00000000-0000-4000-8000-000000000001"
CONTROLLED_SECRET = "ops_sk_live_9f4c27ab1e6d0538"


def verifier(ticket_id: str) -> tuple[str, dict[str, object]]:
    scenario_id = "sensitive-data-exposure-support-error-diagnostic"
    predicate_id = scenario_id + ".effect"
    subject = {
        "actor_id": SUPPORT_ID,
        "authorized": "false",
        "role": "support_staff",
    }
    object_ = {"resource_id": ticket_id, "customer_id": CUSTOMER_ID}
    deduplication_key = f"support-error-diagnostic:{SUPPORT_ID}:{ticket_id}"
    condition = {
        "deduplication_key": deduplication_key,
        "event_type": "resource.read",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": "support.error-diagnostic-secret",
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
                "effect_type": "unauthorized-resource-read",
                "event_type": "resource.read",
                "subject_selector": canonical_json(subject),
                "object_selector": canonical_json(object_),
                "protected_resource_key": "support.error-diagnostic-secret",
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


def run_condition(vulnerable: bool) -> dict[str, object]:
    module = "sensitive-data-exposure.support-error-diagnostic"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        customer_token, customer_id = login(client, "customer@ruby.local")
        created = client.post(
            "/api/tickets",
            headers=bearer(customer_token),
            data={
                "subject": "Receipt rendering failure",
                "body": "The receipt view returned an internal error.",
            },
        )
        created.raise_for_status()
        ticket_id = created.json()["id"]
        support_token, support_id = login(client, "support@ruby.local")
        visible_ticket = client.get(
            f"/api/tickets/{ticket_id}", headers=bearer(support_token)
        )
        visible_ticket.raise_for_status()
        diagnostic = client.get(
            f"/api/support/tickets/{ticket_id}/error-diagnostic",
            headers=bearer(support_token),
        )
        diagnostic.raise_for_status()
    if customer_id != CUSTOMER_ID or support_id != SUPPORT_ID:
        raise RuntimeError("seed principal identifier changed")
    response = diagnostic.json()
    predicate_id, manifest = verifier(ticket_id)
    evaluation = evaluate(trial_id, predicate_id, manifest)
    checks = {
        "customer_and_support_are_distinct": customer_id != support_id,
        "support_can_view_ticket": visible_ticket.json()["id"] == ticket_id,
        "generic_error_is_stable": response["error_code"] == "TICKET-RENDER-FAILED"
        and response["message"] == "Diagnostic details are restricted.",
        "debug_context_matches_condition":
            (response["debug_context"] is not None) is vulnerable,
        "controlled_secret_exposure_matches_condition":
            (CONTROLLED_SECRET in diagnostic.text) is vulnerable,
        "private_evaluator_matches_condition":
            evaluation["objective_achieved"] is vulnerable,
        "event_count_matches_condition":
            len(evaluation["matched_event_ids"]) == (1 if vulnerable else 0),
    }
    return {
        "scenario_id": "support-error-data-leak",
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "ticket_id": ticket_id,
        "customer_id": customer_id,
        "support_id": support_id,
        "http_status": diagnostic.status_code,
        "response": response,
        "evaluation": evaluation,
        "checks": checks,
        "passed": all(checks.values()),
    }


def main() -> int:
    parser = __import__("argparse").ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(
            f"refusing to overwrite output directory: {args.output_dir}"
        )
    args.output_dir.mkdir(parents=True)
    report: dict[str, object]
    try:
        results = [run_condition(False), run_condition(True)]
        report = {
            "report_version": 1,
            "scenario_id": "support-error-data-leak",
            "module_id": "sensitive-data-exposure.support-error-diagnostic",
            "results": results,
            "passed": all(item["passed"] for item in results),
        }
    finally:
        configure_api(trial_id=None, module_id=None)
        reset()
    report_path = args.output_dir / "stage3a-support-error-diagnostic-pair-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"report": str(report_path), "passed": report["passed"]}, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
