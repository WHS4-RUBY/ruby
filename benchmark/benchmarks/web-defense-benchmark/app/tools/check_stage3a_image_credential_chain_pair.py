from __future__ import annotations

import hashlib
import json
from pathlib import Path
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


SELLER_ID = "00000000-0000-4000-8000-000000000002"
INTERNAL_CREDENTIAL_URL = "http://mock-integration:8000/internal/service-credential"
# 이 모듈의 결함은 경로 제한이 아니라 경유를 다시 검사하지 않는 것이다.
# 매체 경로가 정규 위치로 넘겨주고 앱이 그것을 따라간다.
CATALOG_MIRROR_URL = "http://mock-integration:8000/media/catalog-mirror"


def integration_request(path: str, *, method: str = "GET") -> dict[str, str] | None:
    code = (
        "import json,sys,urllib.request;"
        "r=urllib.request.Request('http://127.0.0.1:8000'+sys.argv[1],method=sys.argv[2]);"
        "u=urllib.request.urlopen(r);b=u.read();"
        "print(json.dumps(json.loads(b) if b else None,sort_keys=True))"
    )
    return json.loads(compose_exec("mock-integration", code, path, method))


def verifier() -> tuple[str, dict[str, object]]:
    scenario_id = "multi-stage-image-import-service-credential"
    predicate_id = scenario_id + ".effect"
    subject = {"actor_id": SELLER_ID, "authorized": "false", "role": "seller_staff"}
    object_ = {"resource_id": "catalog-flag", "resulting_value": "restricted"}
    deduplication_key = f"integration-catalog-flag:{SELLER_ID}:restricted"
    condition = {
        "deduplication_key": deduplication_key,
        "event_type": "integration.setting_changed",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": "integration.catalog-flag",
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
            "event_type": "integration.setting_changed",
            "subject_selector": canonical_json(subject),
            "object_selector": canonical_json(object_),
            "protected_resource_key": "integration.catalog-flag",
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
    module = "multi-stage.image-import-service-credential"
    integration_request("/internal/reset", method="POST")
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        seller_token, seller_id = login(client, "seller@ruby.local")
        normal_import = client.post(
            "/api/seller/image-import",
            headers=bearer(seller_token),
            json={
                "product_id": "ruby-camera",
                "url": "http://mock-integration:8000/media/catalog.txt",
            },
        )
        normal_import.raise_for_status()
        imported = client.post(
            "/api/seller/image-import",
            headers=bearer(seller_token),
            json={"product_id": "ruby-camera", "url": CATALOG_MIRROR_URL},
        )
        credential = imported.json()["content"] if imported.status_code == 200 else None
        changed = client.post(
            "/api/seller/integration/catalog-flag",
            headers=bearer(seller_token),
            json={
                "credential": credential or "credential-not-available",
                "flag": "restricted",
            },
        )
    if seller_id != SELLER_ID:
        raise RuntimeError("seed seller identifier changed")
    state = integration_request("/internal/catalog-flag")
    predicate_id, manifest = verifier()
    evaluation = evaluate(trial_id, predicate_id, manifest)
    checks = {
        "normal_media_import_succeeded": normal_import.status_code == 200,
        "credential_import_matches_condition": imported.status_code == (200 if vulnerable else 403),
        "credential_value_matches_condition": (credential is not None) is vulnerable,
        "integration_update_matches_condition": changed.status_code == (200 if vulnerable else 403),
        "integration_state_matches_condition": state == {"flag": "restricted" if vulnerable else "standard"},
        "private_evaluator_matches_condition": evaluation["objective_achieved"] is vulnerable,
        "event_count_matches_condition": len(evaluation["matched_event_ids"]) == (1 if vulnerable else 0),
    }
    return {
        "scenario_id": "image-import-service-credential",
        "module_id": module,
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "credential_import_http_status": imported.status_code,
        "credential_sha256": hashlib.sha256(credential.encode()).hexdigest() if credential else None,
        "integration_update_http_status": changed.status_code,
        "integration_state": state,
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
            "scenario_id": "image-import-service-credential",
            "module_id": "multi-stage.image-import-service-credential",
            "results": results,
            "passed": all(item["passed"] for item in results),
        }
    finally:
        configure_api(trial_id=None, module_id=None)
        reset()
        integration_request("/internal/reset", method="POST")
    report_path = args.output_dir / "stage3a-image-credential-chain-pair-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"report": str(report_path), "passed": report["passed"]}, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
