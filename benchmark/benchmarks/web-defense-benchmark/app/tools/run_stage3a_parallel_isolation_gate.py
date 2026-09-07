from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

import httpx


APP_ROOT = Path(__file__).resolve().parents[1]
RUNNER = Path(__file__).with_name("run_stage3a_codex_http_pilot.py")
WORKERS = (
    ("codex-1", "codex", 18100, 18101),
    ("codex-2", "codex", 18200, 18201),
    ("claude-1", "claude", 18300, 18301),
    ("claude-2", "claude", 18400, 18401),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def worker_environment(project: str, public_port: int, control_port: int) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "COMPOSE_PROJECT_NAME": project,
            "RUBY_PUBLIC_PORT": str(public_port),
            "RUBY_CONTROL_PORT": str(control_port),
            "RUBY_TEST_PUBLIC_ORIGIN": f"http://127.0.0.1:{public_port}",
            "RUBY_TEST_CONTROL_ORIGIN": f"http://127.0.0.1:{control_port}",
        }
    )
    return environment


def compose(project: str, environment: dict[str, str], *arguments: str) -> subprocess.CompletedProcess[str]:
    if re.fullmatch(r"ruby-baseline-gate-[a-z0-9-]+", project) is None:
        raise ValueError("refusing to manage an unexpected Compose project")
    return subprocess.run(
        ["docker", "compose", "-p", project, *arguments],
        cwd=APP_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=300,
    )


def wait_healthy(control_port: int) -> None:
    deadline = time.monotonic() + 120
    origin = f"http://127.0.0.1:{control_port}"
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{origin}/health/live", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise TimeoutError(f"isolated stack did not become healthy: {origin}")


def run_worker(
    worker_id: str,
    provider: str,
    project: str,
    environment: dict[str, str],
    output_dir: Path,
) -> dict[str, object]:
    run_dir = output_dir / worker_id
    started = time.monotonic()
    process = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--provider",
            provider,
            "--output-dir",
            str(run_dir),
        ],
        cwd=APP_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=600,
    )
    (output_dir / f"{worker_id}-launcher.stdout.txt").write_text(process.stdout, encoding="utf-8")
    (output_dir / f"{worker_id}-launcher.stderr.txt").write_text(process.stderr, encoding="utf-8")
    report_path = run_dir / f"{provider}-http-pilot-report.json"
    if process.returncode not in (0, 2) or not report_path.is_file():
        return {
            "provider": provider,
            "worker_id": worker_id,
            "project": project,
            "status": "infrastructure-failure",
            "returncode": process.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return {
        "provider": provider,
        "worker_id": worker_id,
        "project": project,
        "status": "completed",
        "returncode": process.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "trial_id": report["trial_id"],
        "target_origin": report["target_origin"],
        "compose_project": report["compose_project"],
        "objective_achieved": report["objective_achieved"],
        "model_calls": report["model_calls"],
        "http_requests": report["http_requests"],
        "report_path": str(report_path),
        "report_sha256": sha256(report_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[a-z0-9-]{3,40}", args.run_id) is None:
        raise ValueError("run-id must contain only lowercase letters, digits and hyphens")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output directory: {output_dir}")
    output_dir.mkdir(parents=True)
    worker_specs: list[tuple[str, str, str, dict[str, str], int]] = []
    results: list[dict[str, object]] = []
    failure: str | None = None
    try:
        for worker_id, provider, public_port, control_port in WORKERS:
            project = f"ruby-baseline-gate-{args.run_id}-{worker_id}"
            environment = worker_environment(project, public_port, control_port)
            worker_specs.append((worker_id, provider, project, environment, control_port))
            compose(project, environment, "up", "-d")
            wait_healthy(control_port)
        with ThreadPoolExecutor(max_workers=len(worker_specs)) as executor:
            futures = {
                executor.submit(
                    run_worker, worker_id, provider, project, environment, output_dir
                ): worker_id
                for worker_id, provider, project, environment, _ in worker_specs
            }
            for future in as_completed(futures):
                results.append(future.result())
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        cleanup_errors: list[str] = []
        for _, _, project, environment, _ in worker_specs:
            try:
                compose(project, environment, "down", "-v", "--remove-orphans")
            except Exception as error:
                cleanup_errors.append(f"{project}: {error}")
        if cleanup_errors:
            cleanup = "; ".join(cleanup_errors)
            failure = f"{failure}; cleanup: {cleanup}" if failure else f"cleanup: {cleanup}"
    results.sort(key=lambda item: str(item["worker_id"]))
    projects = {str(item.get("compose_project")) for item in results}
    origins = {str(item.get("target_origin")) for item in results}
    trials = {str(item.get("trial_id")) for item in results}
    isolation_pass = (
        failure is None
        and len(results) == len(WORKERS)
        and all(item["status"] == "completed" for item in results)
        and len(projects) == len(WORKERS)
        and len(origins) == len(WORKERS)
        and len(trials) == len(WORKERS)
    )
    report = {
        "report_version": 1,
        "run_id": args.run_id,
        "started_workers": len(worker_specs),
        "parallel_workers": len(WORKERS),
        "isolation_pass": isolation_pass,
        "failure": failure,
        "results": results,
        "completed_at": datetime.now(UTC).isoformat(),
    }
    report_path = output_dir / "parallel-isolation-gate-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(report_path)
    return 0 if isolation_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
