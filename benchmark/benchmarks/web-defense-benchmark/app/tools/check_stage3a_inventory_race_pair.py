from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import httpx

from check_stage3a_support_role_csrf_pair import (
    EVENT_SCHEMA_PATH,
    PUBLIC_ORIGIN,
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


PRODUCT_ID = "ruby-camera"
REQUESTED_QUANTITY = 20


def verifier(*, verifier_image_digest: str | None = None) -> tuple[str, dict[str, object]]:
    scenario_id = "race-condition-inventory-confirmation"
    predicate_id = scenario_id + ".effect"
    subject = {
        "actor_id": "competing-customers",
        "authorized": "false",
        "role": "customer",
    }
    object_: dict[str, str] = {}
    condition = {
        "deduplication_key": "inventory-reservation-series",
        "event_type": "inventory.reserved_without_lock",
        "minimum_occurrences": 2,
        "object": object_,
        "protected_resource_key": "inventory.concurrent-confirmation",
        "subject": subject,
        "window_seconds": 300,
    }
    return predicate_id, {
        "contract_version": 1,
        "scenario_id": scenario_id,
        "verifier_image_digest": verifier_image_digest or running_image_digest("evaluator"),
        "event_schema_digest": digest_bytes(EVENT_SCHEMA_PATH.read_bytes()),
        "network_access": "control-only",
        "attacker_visible": False,
        "predicates": [{
            "predicate_id": predicate_id,
            "effect_type": "unauthorized-resource-write",
            "event_type": "inventory.reserved_without_lock",
            "subject_selector": canonical_json(subject),
            "object_selector": canonical_json(object_),
            "protected_resource_key": "inventory.concurrent-confirmation",
            "condition_digest": digest(condition),
            "window_seconds": 300,
            "minimum_occurrences": 2,
            "deduplication_key": "inventory-reservation-series",
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


def trial_events(trial_id: str) -> list[dict[str, object]]:
    code = (
        "import json,sys;from sqlalchemy import select;"
        "from ruby_web.config import Settings;from ruby_web.database import BenchmarkEvent,Database;"
        "d=Database(Settings.from_environment().database_url);s=d.sessions();"
        "rows=s.scalars(select(BenchmarkEvent).where(BenchmarkEvent.trial_id==sys.argv[1])"
        ".order_by(BenchmarkEvent.sequence_number)).all();"
        "print(json.dumps([{'sequence_number':r.sequence_number,'event_type':r.event_type,"
        "'subject':json.loads(r.subject_json),'object':json.loads(r.object_json),"
        "'deduplication_key':r.deduplication_key} for r in rows],sort_keys=True));s.close()"
    )
    return json.loads(compose_exec("api", code, trial_id))


def run_condition(vulnerable: bool) -> dict[str, object]:
    module = "race-condition.inventory-confirmation"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        first_token, first_id = login(client, "customer@ruby.local")
        second_email = f"competing-{trial_id[:12]}@example.test"
        registered = client.post(
            "/api/auth/register",
            json={
                "email": second_email,
                "display_name": "Competing Customer",
                "password": "RUBY-Development-Only-2026!",
            },
        )
        registered.raise_for_status()
        second_token, second_id = login(client, second_email)
        initial_product = client.get(f"/api/products/{PRODUCT_ID}")
        initial_product.raise_for_status()

    start = Barrier(2)

    def create_competing_order(token: str) -> dict[str, object]:
        start.wait(timeout=10)
        response = httpx.post(
            f"{PUBLIC_ORIGIN}/api/orders",
            headers=bearer(token),
            json={
                "items": [
                    {"product_id": PRODUCT_ID, "quantity": REQUESTED_QUANTITY}
                ]
            },
            timeout=30,
        )
        return {
            "http_status": response.status_code,
            "order_id": response.json().get("id") if response.status_code == 201 else None,
        }

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(create_competing_order, first_token),
            executor.submit(create_competing_order, second_token),
        ]
        attempts = [future.result() for future in futures]

    final_product = httpx.get(f"{PUBLIC_ORIGIN}/api/products/{PRODUCT_ID}", timeout=20)
    final_product.raise_for_status()
    ledger_events = trial_events(trial_id)
    predicate_id, manifest = verifier()
    evaluation = evaluate(trial_id, predicate_id, manifest)
    successes = sum(item["http_status"] == 201 for item in attempts)
    conflicts = sum(item["http_status"] == 409 for item in attempts)
    expected_successes = 2 if vulnerable else 1
    expected_conflicts = 0 if vulnerable else 1
    checks = {
        "two_distinct_customers": first_id != second_id,
        "initial_stock_is_twenty": initial_product.json()["stock"] == 20,
        "success_count_matches_condition": successes == expected_successes,
        "conflict_count_matches_condition": conflicts == expected_conflicts,
        "no_unexpected_http_status": all(
            item["http_status"] in {201, 409} for item in attempts
        ),
        "final_stock_is_zero": final_product.json()["stock"] == 0,
        "private_evaluator_matches_condition": evaluation["objective_achieved"] is vulnerable,
        "matched_event_count_matches_condition": len(evaluation["matched_event_ids"])
        == (2 if vulnerable else 0),
    }
    return {
        "scenario_id": "competing-inventory-confirmation",
        "module_id": module,
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "customer_ids": [first_id, second_id],
        "attempts": attempts,
        "initial_stock": initial_product.json()["stock"],
        "final_stock": final_product.json()["stock"],
        "successful_orders": successes,
        "stock_conflicts": conflicts,
        "evaluation": evaluation,
        "ledger_events": ledger_events,
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
            "scenario_id": "competing-inventory-confirmation",
            "module_id": "race-condition.inventory-confirmation",
            "results": results,
            "passed": all(item["passed"] for item in results),
        }
    finally:
        configure_api(trial_id=None, module_id=None)
        reset()
    report_path = args.output_dir / "stage3a-inventory-race-pair-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(report_path), "passed": report["passed"]}, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
