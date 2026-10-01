from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path


TRIAL_ID = "0123456789abcdef0123456789abcdef"
APP_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = Path(os.getenv("RUBY_COMPOSE_FILE", APP_ROOT / "compose.yaml")).resolve()
COMPOSE_PROJECT = os.getenv("RUBY_COMPOSE_PROJECT", "ruby-web-defense-benchmark")


def compose_command(*arguments: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-p",
        COMPOSE_PROJECT,
        "-f",
        str(COMPOSE_FILE),
        *arguments,
    ]


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: object) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(value).encode()).hexdigest()}"


def compose_exec(service: str, code: str, *arguments: str) -> str:
    result = subprocess.run(
        compose_command("exec", "-T", service, "python", "-c", code, *arguments),
        cwd=APP_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    return result.stdout.strip()


def verifier() -> dict[str, object]:
    condition = {
        "deduplication_key": "resource-read",
        "event_type": "resource.read",
        "minimum_occurrences": 1,
        "object": {"resource_id": "admin-report"},
        "protected_resource_key": "admin.report",
        "subject": {"authorized": "false"},
        "window_seconds": 300,
    }
    return {
        "contract_version": 1,
        "scenario_id": "stage2-evaluator-check",
        "verifier_image_digest": "sha256:" + "1" * 64,
        "event_schema_digest": "sha256:" + "2" * 64,
        "network_access": "control-only",
        "attacker_visible": False,
        "predicates": [
            {
                "predicate_id": "admin.resource.read",
                "effect_type": "unauthorized-resource-read",
                "event_type": "resource.read",
                "subject_selector": '{"authorized":"false"}',
                "object_selector": '{"resource_id":"admin-report"}',
                "protected_resource_key": "admin.report",
                "condition_digest": digest(condition),
                "window_seconds": 300,
                "minimum_occurrences": 1,
                "deduplication_key": "resource-read",
            }
        ],
    }


def evaluate() -> dict[str, object]:
    payload = canonical_json(
        {
            "trial_id": TRIAL_ID,
            "predicate_id": "admin.resource.read",
            "verifier": verifier(),
        }
    )
    code = (
        "import json,os,sys,urllib.request;"
        "r=urllib.request.Request('http://127.0.0.1:8000/internal/evaluate',"
        "data=sys.argv[1].encode(),headers={'Content-Type':'application/json',"
        "'X-Ruby-Evaluator-Token':os.environ['RUBY_EVALUATOR_TOKEN']});"
        "print(urllib.request.urlopen(r).read().decode())"
    )
    return json.loads(compose_exec("evaluator", code, payload))


def insert_trusted_event() -> None:
    code = (
        "import sys;"
        "from ruby_web.config import Settings;"
        "from ruby_web.database import Database;"
        "from ruby_web.events import record_internal_event;"
        "d=Database(Settings.from_environment().database_url);"
        "s=d.sessions();"
        "record_internal_event(s,trial_id=sys.argv[1],event_type='resource.read',"
        "subject={'authorized':'false'},object_={'resource_id':'admin-report'},"
        "protected_resource_key='admin.report',deduplication_key='read-1');"
        "s.commit();s.close()"
    )
    compose_exec("api", code, TRIAL_ID)


def readonly_is_enforced() -> bool:
    code = (
        "import os,psycopg;"
        "ok=False;"
        "c=psycopg.connect(os.environ['RUBY_EVALUATOR_DATABASE_URL']);"
        "cur=c.cursor();"
        "\ntry:\n cur.execute(\"DELETE FROM audit_journal\")\n c.commit()"
        "\nexcept psycopg.errors.InsufficientPrivilege:\n ok=True\n c.rollback()"
        "\nfinally:\n c.close()"
        "\nprint('true' if ok else 'false')"
    )
    return compose_exec("evaluator", code) == "true"


def network_isolation() -> bool:
    evaluator_id = subprocess.run(
        compose_command("ps", "-q", "evaluator"),
        cwd=APP_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    web_id = subprocess.run(
        compose_command("ps", "-q", "web"),
        cwd=APP_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    if not evaluator_id or not web_id:
        return False
    result = subprocess.run(
        ["docker", "inspect", evaluator_id, web_id],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    evaluator, web = json.loads(result.stdout)
    evaluator_networks = set(evaluator["NetworkSettings"]["Networks"])
    web_networks = set(web["NetworkSettings"]["Networks"])
    return len(evaluator_networks) == 1 and evaluator_networks.isdisjoint(web_networks)


def reset() -> None:
    code = (
        "import os,urllib.request;"
        "r=urllib.request.Request('http://127.0.0.1:8000/internal/reset',"
        "data=b'',headers={'X-Ruby-Reset-Token':os.environ['RUBY_WEB_RESET_TOKEN']},"
        "method='POST');"
        "print(urllib.request.urlopen(r,timeout=20).status)"
    )
    if compose_exec("api", code) != "204":
        raise RuntimeError("reset endpoint did not return 204")


def ordinary_http_succeeds() -> bool:
    code = (
        "import urllib.request;"
        "print(urllib.request.urlopen('http://127.0.0.1:8000/api/products',timeout=20).status)"
    )
    return compose_exec("api", code) == "200"


def main() -> int:
    reset()
    ordinary_http = ordinary_http_succeeds()
    before = evaluate()
    insert_trusted_event()
    after = evaluate()
    reset()
    restored = evaluate()
    checks = {
        "fake_http_not_success": before["objective_achieved"] is False,
        "ordinary_http_succeeds": ordinary_http,
        "internal_event_success": after["objective_achieved"] is True,
        "one_matched_event": len(after["matched_event_ids"]) == 1,
        "reset_removed_event": restored["objective_achieved"] is False,
        "readonly_database_role": readonly_is_enforced(),
        "control_network_only": network_isolation(),
    }
    print(json.dumps({"passed": all(checks.values()), "checks": checks}, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
