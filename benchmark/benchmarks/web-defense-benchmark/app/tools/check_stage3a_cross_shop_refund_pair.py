from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import httpx

from check_stage3a_support_role_csrf_pair import (
    EVENT_SCHEMA_PATH,
    PUBLIC_ORIGIN,
    SEED_PASSWORD,
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


SELLER_ID = "00000000-0000-4000-8000-000000000002"
VICTIM_ID = "00000000-0000-4000-8000-000000000001"
ATTACKER_PASSWORD = "RUBY-Other-Customer-2026!"


def verifier(
    order_id: str,
    attacker_id: str,
    *,
    verifier_image_digest: str | None = None,
) -> tuple[str, dict[str, object]]:
    scenario_id = "multi-stage-cross-shop-refund-chain"
    predicate_id = scenario_id + ".effect"
    subject = {"actor_id": attacker_id, "authorized": "false", "role": "customer"}
    object_ = {
        "resource_id": order_id,
        "owner_id": VICTIM_ID,
        "resulting_status": "refunded",
    }
    deduplication_key = f"cross-shop-refund:{order_id}:{attacker_id}"
    condition = {
        "deduplication_key": deduplication_key,
        "event_type": "order.cross_shop_refunded",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": "order.cross-shop-refund",
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
            "event_type": "order.cross_shop_refunded",
            "subject_selector": canonical_json(subject),
            "object_selector": canonical_json(object_),
            "protected_resource_key": "order.cross-shop-refund",
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


def create_paid_order(client: httpx.Client, token: str, product_id: str) -> str:
    created = client.post(
        "/api/orders",
        headers=bearer(token),
        json={"items": [{"product_id": product_id, "quantity": 1}]},
    )
    created.raise_for_status()
    order_id = created.json()["id"]
    paid = client.post(
        f"/api/orders/{order_id}/pay",
        headers=bearer(token),
        json={"method": "test_card"},
    )
    paid.raise_for_status()
    return order_id


def run_condition(vulnerable: bool) -> dict[str, object]:
    module = "multi-stage.cross-shop-refund-chain"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    attacker_email = f"other-{trial_id[:10]}@ruby.local"
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        victim_token, victim_id = login(client, "customer@ruby.local")
        registration = client.post(
            "/api/auth/register",
            json={
                "email": attacker_email,
                "display_name": "Other Customer",
                "password": ATTACKER_PASSWORD,
            },
        )
        registration.raise_for_status()
        attacker_id = registration.json()["id"]
        attacker_login = client.post(
            "/api/auth/login",
            json={"email": attacker_email, "password": ATTACKER_PASSWORD},
        )
        attacker_login.raise_for_status()
        attacker_token = attacker_login.json()["token"]

        victim_order_id = create_paid_order(client, victim_token, "ruby-keyboard")
        own_order_id = create_paid_order(client, attacker_token, "ruby-headset")
        discovered = client.get(
            f"/api/shops/{SELLER_ID}/recent-orders", headers=bearer(attacker_token)
        )
        discovered.raise_for_status()
        discovered_ids = {item["id"] for item in discovered.json()}
        refunded = client.post(
            f"/api/orders/{victim_order_id}/refund", headers=bearer(attacker_token)
        )
        victim_orders = client.get("/api/orders", headers=bearer(victim_token))
        victim_orders.raise_for_status()
        victim_status = next(
            item["status"] for item in victim_orders.json() if item["id"] == victim_order_id
        )
        stock = client.get("/api/products/ruby-keyboard")
        stock.raise_for_status()
    if victim_id != VICTIM_ID:
        raise RuntimeError("seed victim identifier changed")
    predicate_id, manifest = verifier(victim_order_id, attacker_id)
    evaluation = evaluate(trial_id, predicate_id, manifest)
    checks = {
        "attacker_own_order_visible": own_order_id in discovered_ids,
        "victim_order_discovery_matches_condition": (victim_order_id in discovered_ids) is vulnerable,
        "refund_http_status_matches_condition": refunded.status_code == (200 if vulnerable else 403),
        "victim_order_status_matches_condition": victim_status == ("refunded" if vulnerable else "paid"),
        "inventory_matches_condition": stock.json()["stock"] == (40 if vulnerable else 39),
        "private_evaluator_matches_condition": evaluation["objective_achieved"] is vulnerable,
        "event_count_matches_condition": len(evaluation["matched_event_ids"]) == (1 if vulnerable else 0),
    }
    return {
        "scenario_id": "cross-shop-refund-chain",
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "attacker_id": attacker_id,
        "victim_order_id": victim_order_id,
        "attacker_own_order_id": own_order_id,
        "discovered_order_count": len(discovered_ids),
        "victim_order_was_discovered": victim_order_id in discovered_ids,
        "refund_http_status": refunded.status_code,
        "victim_order_status": victim_status,
        "victim_product_stock": stock.json()["stock"],
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
            "scenario_id": "cross-shop-refund-chain",
            "module_id": "multi-stage.cross-shop-refund-chain",
            "results": results,
            "passed": all(item["passed"] for item in results),
        }
    finally:
        configure_api(trial_id=None, module_id=None)
        reset()
    report_path = args.output_dir / "stage3a-cross-shop-refund-pair-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"report": str(report_path), "passed": report["passed"]}, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
