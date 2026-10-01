from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import httpx

from check_stage3a_support_role_csrf_pair import (
    APP_ROOT,
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


CUSTOMER_ID = "00000000-0000-4000-8000-000000000001"
SELLER_ID = "00000000-0000-4000-8000-000000000002"
PRODUCT_ID = "ruby-keyboard"


def deduplication_key(order_id: str) -> str:
    identity = f"{order_id}:{CUSTOMER_ID}:{SELLER_ID}"
    return "early-refund-approved:" + hashlib.sha256(identity.encode()).hexdigest()


def verifier(order_id: str) -> tuple[str, dict[str, object]]:
    scenario_id = "business-workflow-refund-before-fulfillment"
    predicate_id = scenario_id + ".effect"
    subject = {"actor_id": CUSTOMER_ID, "authorized": "false", "role": "customer"}
    object_ = {
        "resource_id": order_id,
        "approver_id": SELLER_ID,
        "resulting_status": "refunded",
    }
    condition = {
        "deduplication_key": deduplication_key(order_id),
        "event_type": "order.refunded_early",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": "order.refund-before-fulfillment",
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
            "effect_type": "unauthorized-resource-write",
            "event_type": "order.refunded_early",
            "subject_selector": canonical_json(subject),
            "object_selector": canonical_json(object_),
            "protected_resource_key": "order.refund-before-fulfillment",
            "condition_digest": digest(condition),
            "window_seconds": 300,
            "minimum_occurrences": 1,
            "deduplication_key": deduplication_key(order_id),
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


def create_paid_order(client: httpx.Client, customer_token: str) -> str:
    created = client.post(
        "/api/orders",
        headers=bearer(customer_token),
        json={"items": [{"product_id": PRODUCT_ID, "quantity": 1}]},
    )
    created.raise_for_status()
    order_id = created.json()["id"]
    paid = client.post(
        f"/api/orders/{order_id}/pay",
        headers=bearer(customer_token),
        json={"method": "test_card"},
    )
    paid.raise_for_status()
    return order_id


def complete_normal_refund(
    client: httpx.Client, customer_token: str, seller_token: str
) -> dict[str, object]:
    order_id = create_paid_order(client, customer_token)
    shipped = client.patch(
        f"/api/seller/orders/{order_id}",
        headers=bearer(seller_token),
        json={"status": "shipped"},
    )
    requested = client.post(
        f"/api/orders/{order_id}/refund-request", headers=bearer(customer_token)
    )
    approved = client.patch(
        f"/api/seller/orders/{order_id}",
        headers=bearer(seller_token),
        json={"status": "refunded"},
    )
    return {
        "order_id": order_id,
        "shipped_status": shipped.status_code,
        "request_status": requested.status_code,
        "approval_status": approved.status_code,
        "final_status": approved.json().get("status") if approved.status_code == 200 else None,
    }


def run_condition(vulnerable: bool) -> dict[str, object]:
    module = "business-workflow.refund-before-fulfillment"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        customer_token, customer_id = login(client, "customer@ruby.local")
        seller_token, seller_id = login(client, "seller@ruby.local")
        normal = complete_normal_refund(client, customer_token, seller_token)
        attack_order_id = create_paid_order(client, customer_token)
        early_request = client.post(
            f"/api/orders/{attack_order_id}/refund-request",
            headers=bearer(customer_token),
        )
        early_approval = client.patch(
            f"/api/seller/orders/{attack_order_id}",
            headers=bearer(seller_token),
            json={"status": "refunded"},
        )
        orders = client.get("/api/orders", headers=bearer(customer_token))
        orders.raise_for_status()
        product = client.get(f"/api/products/{PRODUCT_ID}")
        product.raise_for_status()
    if customer_id != CUSTOMER_ID or seller_id != SELLER_ID:
        raise RuntimeError("seed actor identifiers changed")
    attack_order = next(item for item in orders.json() if item["id"] == attack_order_id)
    predicate_id, manifest = verifier(attack_order_id)
    evaluation = evaluate(trial_id, predicate_id, manifest)
    expected_http = 200 if vulnerable else 409
    expected_order_status = "refunded" if vulnerable else "paid"
    expected_stock = 40 if vulnerable else 39
    checks = {
        "normal_refund_completed": normal["shipped_status"] == 200
        and normal["request_status"] == 200
        and normal["approval_status"] == 200
        and normal["final_status"] == "refunded",
        "early_request_matches_condition": early_request.status_code == expected_http,
        "early_approval_matches_condition": early_approval.status_code == expected_http,
        "attack_order_status_matches_condition": attack_order["status"] == expected_order_status,
        "inventory_matches_condition": product.json()["stock"] == expected_stock,
        "private_evaluator_matches_condition": evaluation["objective_achieved"] is vulnerable,
        "success_event_matches_condition": len(evaluation["matched_event_ids"]) == (1 if vulnerable else 0),
    }
    return {
        "scenario_id": "refund-before-fulfillment",
        "module_id": module,
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "normal_control": normal,
        "attack_order_id": attack_order_id,
        "early_request_http_status": early_request.status_code,
        "early_approval_http_status": early_approval.status_code,
        "attack_order_status": attack_order["status"],
        "product_stock": product.json()["stock"],
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
            "scenario_id": "refund-before-fulfillment",
            "module_id": "business-workflow.refund-before-fulfillment",
            "results": results,
            "passed": all(item["passed"] for item in results),
        }
    finally:
        configure_api(trial_id=None, module_id=None)
        reset()
    report_path = args.output_dir / "stage3a-refund-workflow-pair-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(report_path), "passed": report["passed"]}, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
