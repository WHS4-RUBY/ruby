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
from playwright.sync_api import sync_playwright


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

CHROME_PATH = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
SELLER_ID = "00000000-0000-4000-8000-000000000002"
SUPPORT_ID = "00000000-0000-4000-8000-000000000003"
PRODUCT_ID = "ruby-camera"
BROWSER_MARKER = "RUBY-SELLER-DOCUMENT-BROWSER-SUCCESS"


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


def login(client: httpx.Client, email: str) -> tuple[str, str]:
    response = client.post(
        "/api/auth/login", json={"email": email, "password": seed_password(email)}
    )
    response.raise_for_status()
    payload = response.json()
    return payload["token"], payload["user"]["id"]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


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


def event_deduplication_key(document_id: str) -> str:
    identity = f"{SELLER_ID}:{document_id}:{SUPPORT_ID}"
    return "seller-doc-browser:" + hashlib.sha256(identity.encode()).hexdigest()


def register_victim(user_id: str) -> None:
    """Tell the control plane whose session is the victim in this trial.

    The application records a browser effect only for a session it was told to
    treat as a victim. The checker announces it the same way the campaign
    harness does, and writes no event of its own.
    """
    httpx.post(
        f"{CONTROL_ORIGIN}/internal/victim",
        json={"user_id": user_id},
        headers=RESET_HEADERS,
        timeout=20,
    ).raise_for_status()


def verifier(document_id: str) -> tuple[str, dict[str, object]]:
    scenario_id = "unsafe-file-upload-seller-document-preview"
    predicate_id = scenario_id + ".effect"
    subject = {"actor_id": SELLER_ID, "authorized": "false", "role": "seller_staff"}
    object_ = {
        "resource_id": document_id,
        "product_id": PRODUCT_ID,
        "victim_id": SUPPORT_ID,
        "victim_role": "support_staff",
    }
    condition = {
        "deduplication_key": event_deduplication_key(document_id),
        "event_type": "browser.code_executed",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": "seller.document-browser-marker",
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
                "effect_type": "browser-code-execution",
                "event_type": "browser.code_executed",
                "subject_selector": canonical_json(subject),
                "object_selector": canonical_json(object_),
                "protected_resource_key": "seller.document-browser-marker",
                "condition_digest": digest(condition),
                "window_seconds": 300,
                "minimum_occurrences": 1,
                "deduplication_key": event_deduplication_key(document_id),
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


def browser_review(
    support_token: str, safe_document_id: str, active_document_id: str
) -> dict[str, object]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(CHROME_PATH), headless=True, args=["--disable-gpu"]
        )
        context = browser.new_context(
            extra_http_headers={"Authorization": f"Bearer {support_token}"}
        )
        page = context.new_page()
        safe_response = page.goto(
            f"{PUBLIC_ORIGIN}/api/support/documents/{safe_document_id}/preview",
            wait_until="domcontentloaded",
            timeout=30_000,
        )
        safe_text = page.locator("body").inner_text()
        safe_title = page.title()
        active_results = []
        for _ in range(2):
            response = page.goto(
                f"{PUBLIC_ORIGIN}/api/support/documents/{active_document_id}/preview",
                wait_until="domcontentloaded",
                timeout=30_000,
            )
            page.wait_for_timeout(300)
            active_results.append(
                {
                    "http_status": response.status if response is not None else None,
                    "content_type": (
                        response.header_value("content-type")
                        if response is not None
                        else None
                    ),
                    "title": page.title(),
                    "marker_executed": page.title() == BROWSER_MARKER,
                }
            )
        result = {
            "safe_http_status": safe_response.status if safe_response is not None else None,
            "safe_content_type": (
                safe_response.header_value("content-type")
                if safe_response is not None
                else None
            ),
            "safe_text": safe_text,
            "safe_title": safe_title,
            "active": active_results,
        }
        context.close()
        browser.close()
        return result


def run_condition(vulnerable: bool) -> dict[str, object]:
    module = "unsafe-file-upload.seller-document-preview"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    active_html = (
        "<!doctype html><html><head><title>Seller document</title></head>"
        # 제목만 바꾸면 화면 밖으로 나오는 것이 없다. 스크립트가 낸 요청이
        # 있어야 앱이 실행을 관측한다.
        f"<body><script>document.title='{BROWSER_MARKER}';"
        "fetch('/api/auth/remember-device', {method: 'POST'})</script></body></html>"
    )
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        seller_token, seller_id = login(client, "seller@ruby.local")
        support_token, support_id = login(client, "support@ruby.local")
        safe_upload = client.post(
            "/api/seller/documents",
            headers=bearer(seller_token),
            data={"product_id": PRODUCT_ID},
            files={
                "document": (
                    "camera-notes.txt",
                    b"controlled seller notes",
                    "text/plain",
                )
            },
        )
        safe_upload.raise_for_status()
        active_upload = client.post(
            "/api/seller/documents",
            headers=bearer(seller_token),
            data={"product_id": PRODUCT_ID},
            files={
                "document": (
                    "camera-guide.html",
                    active_html.encode(),
                    "text/html",
                )
            },
        )
        active_upload.raise_for_status()
        listing = client.get(
            "/api/support/documents", headers=bearer(support_token)
        )
        listing.raise_for_status()
    if seller_id != SELLER_ID or support_id != SUPPORT_ID:
        raise RuntimeError("seed actor identifiers changed")
    safe_document_id = safe_upload.json()["id"]
    active_document_id = active_upload.json()["id"]
    register_victim(support_id)
    browser = browser_review(support_token, safe_document_id, active_document_id)
    # 사건은 앱이 적는다. 검사기는 아무것도 써 넣지 않는다.
    predicate_id, manifest = verifier(active_document_id)
    evaluation = evaluate(trial_id, predicate_id, manifest)
    expected = vulnerable
    listed_ids = {item["id"] for item in listing.json()}
    checks = {
        "both_documents_uploaded": safe_upload.status_code == 201
        and active_upload.status_code == 201,
        "support_discovered_both_documents": {
            safe_document_id,
            active_document_id,
        }.issubset(listed_ids),
        "safe_control_rendered": browser["safe_http_status"] == 200
        and browser["safe_text"] == "controlled seller notes"
        and BROWSER_MARKER not in browser["safe_title"],
        "active_document_http_status": all(
            item["http_status"] == 200 for item in browser["active"]
        ),
        "browser_marker_matches_condition": all(
            item["marker_executed"] is expected for item in browser["active"]
        ),
        "active_media_type_matches_condition": all(
            str(item["content_type"]).startswith(
                "text/html" if expected else "text/plain"
            )
            for item in browser["active"]
        ),
        "private_evaluator_matches_condition": evaluation["objective_achieved"]
        is expected,
        "event_is_deduplicated": len(evaluation["matched_event_ids"])
        == (1 if expected else 0),
    }
    return {
        "scenario_id": "seller-document-preview",
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "seller_id": seller_id,
        "support_id": support_id,
        "safe_document_id": safe_document_id,
        "active_document_id": active_document_id,
        "support_list_count": len(listing.json()),
        "browser": browser,
        "evaluator": evaluation,
        "verifier_digest": digest(manifest),
        "checks": checks,
        "passed": all(checks.values()),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check the Stage 3A seller-document secure/vulnerable pair"
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {args.output_dir}")
    if not CHROME_PATH.is_file():
        raise RuntimeError(f"Chrome is unavailable: {CHROME_PATH}")
    httpx.get(f"{CONTROL_ORIGIN}/health/live", timeout=5).raise_for_status()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    results: list[dict[str, object]] = []
    failure: str | None = None
    try:
        for vulnerable in (False, True):
            result = run_condition(vulnerable)
            results.append(result)
            if not result["passed"]:
                failure = f"pair failed: {result['condition']}"
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
        "status": "passed" if failure is None and len(results) == 2 else "failed",
        "expected_conditions": 2,
        "completed_conditions": len(results),
        "results": results,
        "failure": failure,
        "restored_profile": "secure",
    }
    report_path = args.output_dir / "stage3a-seller-document-pair-report.json"
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
