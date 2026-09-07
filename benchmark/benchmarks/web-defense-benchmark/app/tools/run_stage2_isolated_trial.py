from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
from pathlib import Path

import httpx

from ruby_runner.ledger import TrialLedger


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def docker_items(kind: str, project: str) -> list[str]:
    command = ["docker", kind, "ls"]
    if kind == "container":
        command.append("-a")
    command.extend(
        [
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.Name}}" if kind != "container" else "{{.Names}}",
        ]
    )
    result = subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8")
    return sorted(item for item in result.stdout.splitlines() if item)


def resources(project: str) -> dict[str, list[str]]:
    return {
        "containers": docker_items("container", project),
        "networks": docker_items("network", project),
        "volumes": docker_items("volume", project),
    }


def compose(project: str, environment: dict[str, str], *arguments: str) -> None:
    subprocess.run(
        ["docker", "compose", "-p", project, "-f", "compose.yaml", *arguments],
        check=True,
        env=environment,
    )


def compose_output(project: str, environment: dict[str, str], *arguments: str) -> str:
    result = subprocess.run(
        ["docker", "compose", "-p", project, "-f", "compose.yaml", *arguments],
        check=False,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout + result.stderr


def main() -> int:
    trial_id = secrets.token_hex(16)
    project = f"rubytrial{trial_id[:12]}"
    ledger = TrialLedger.create(Path("evaluation/stage2-isolated"), trial_id)
    environment = dict(os.environ)
    public_port = free_port()
    control_port = free_port()
    environment["RUBY_PUBLIC_PORT"] = str(public_port)
    environment["RUBY_CONTROL_PORT"] = str(control_port)
    environment["RUBY_WEB_TRIAL_ID"] = trial_id
    public_url = f"http://127.0.0.1:{public_port}"
    control_url = f"http://127.0.0.1:{control_port}"
    control_headers = {"X-Ruby-Reset-Token": "development-reset-only"}
    created: dict[str, list[str]] = {"containers": [], "networks": [], "volumes": []}
    cleanup_error: str | None = None
    failure: str | None = None
    initial_sha256: str | None = None
    restored_sha256: str | None = None
    residue_count: int | None = None
    try:
        compose(project, environment, "up", "-d", "--no-build", "--wait", "--wait-timeout", "120")
        created = resources(project)
        reset = httpx.post(f"{control_url}/internal/reset", headers=control_headers, timeout=20)
        reset.raise_for_status()
        initial = httpx.get(f"{control_url}/internal/state", headers=control_headers, timeout=20)
        initial.raise_for_status()
        initial_state = initial.json()
        initial_sha256 = initial_state["sha256"]
        residue_count = sum(initial_state["payload"]["transient_counts"].values())
        ledger.artifact(
            "reset-attestation.json",
            {"residue_count": residue_count, "state_sha256": initial_sha256},
        )
        ledger.transition("running")
        response = httpx.get(f"{public_url}/api/products", timeout=20)
        response.raise_for_status()
        ledger.artifact(
            "request-trace.json",
            {"method": "GET", "path": "/api/products", "status_code": response.status_code},
        )
        final_reset = httpx.post(f"{control_url}/internal/reset", headers=control_headers, timeout=20)
        final_reset.raise_for_status()
        restored = httpx.get(f"{control_url}/internal/state", headers=control_headers, timeout=20)
        restored.raise_for_status()
        restored_sha256 = restored.json()["sha256"]
        if residue_count != 0 or restored_sha256 != initial_sha256:
            raise RuntimeError("isolated trial reset attestation failed")
    except Exception as error:
        failure = str(error)[:500]
    finally:
        created = resources(project)
        ledger.artifact(
            "compose-final-logs.json",
            {
                "text": compose_output(
                    project, environment, "logs", "--no-color", "--timestamps"
                )
            },
        )
        try:
            compose(project, environment, "down", "-v", "--remove-orphans", "--timeout", "15")
        except Exception as error:
            cleanup_error = str(error)[:500]
    remaining = resources(project)
    removed = all(not items for items in remaining.values())
    ledger.artifact(
        "resource-attestation.json",
        {
            "created": created,
            "project": project,
            "remaining": remaining,
            "removed": removed,
        },
    )
    ledger.artifact(
        "final-reset-attestation.json",
        {
            "initial_state_sha256": initial_sha256,
            "residue_count": residue_count,
            "restored_state_sha256": restored_sha256,
            "state_matches_initial": initial_sha256 is not None and restored_sha256 == initial_sha256,
        },
    )
    if failure is None and cleanup_error is None and removed:
        ledger.transition("completed")
    else:
        reason = failure or cleanup_error or "trial resources remain after cleanup"
        ledger.transition("failed", reason=reason)
    manifest = ledger.seal()
    print(
        json.dumps(
            {
                "artifact_manifest": str(manifest),
                "created_resource_counts": {key: len(value) for key, value in created.items()},
                "resources_removed": removed,
                "status": ledger.status,
                "trial_id": trial_id,
            },
            sort_keys=True,
        )
    )
    return 0 if ledger.status == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
