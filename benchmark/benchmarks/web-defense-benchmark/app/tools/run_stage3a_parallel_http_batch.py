from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

from run_stage3a_parallel_isolation_gate import (
    APP_ROOT,
    RUNNER,
    WORKERS,
    compose,
    wait_healthy,
    worker_environment,
)


CONFIG = APP_ROOT / "configs" / "stage3a-autonomous-http-scenarios-v1.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def load_scenarios() -> list[str]:
    value = json.loads(CONFIG.read_text(encoding="utf-8"))
    return [str(item["scenario_id"]) for item in value["scenarios"]]


def task_path(output_dir: Path, scenario_id: str, provider: str, repetition: int) -> Path:
    return output_dir / "runs" / scenario_id / provider / f"run-{repetition:02d}"


def validated_existing_result(
    output_dir: Path, scenario_id: str, provider: str, repetition: int
) -> dict[str, object] | None:
    task_root = task_path(output_dir, scenario_id, provider, repetition)
    reports = sorted(
        task_root.glob(f"attempts/attempt-*/{provider}-http-pilot-report.json")
    )
    if not reports:
        return None
    report_path = reports[-1]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("scenario_id") != scenario_id or report.get("provider") != f"{provider}-cli-subscription":
        raise ValueError(f"existing result identity mismatch: {report_path}")
    return {
        "scenario_id": scenario_id,
        "provider": provider,
        "repetition": repetition,
        "status": "completed",
        "objective_achieved": bool(report["objective_achieved"]),
        "model_calls": int(report["model_calls"]),
        "http_requests": int(report["http_requests"]),
        "trial_id": str(report["trial_id"]),
        "report_path": str(report_path),
        "report_sha256": sha256(report_path),
        "resumed": True,
    }


def run_task(
    *,
    worker_id: str,
    provider: str,
    environment: dict[str, str],
    output_dir: Path,
    scenario_id: str,
    repetition: int,
) -> dict[str, object]:
    task_root = task_path(output_dir, scenario_id, provider, repetition)
    attempts_root = task_root / "attempts"
    attempts_root.mkdir(parents=True, exist_ok=True)
    existing_attempts = sorted(attempts_root.glob("attempt-*"))
    directory = attempts_root / f"attempt-{len(existing_attempts) + 1:03d}"
    started = time.monotonic()
    process = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--provider",
            provider,
            "--scenario-id",
            scenario_id,
            "--output-dir",
            str(directory),
        ],
        cwd=APP_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=1200,
    )
    launcher = directory.parent / f"attempt-{len(existing_attempts) + 1:03d}-{worker_id}-launcher"
    launcher.with_suffix(".stdout.txt").write_text(process.stdout, encoding="utf-8")
    launcher.with_suffix(".stderr.txt").write_text(process.stderr, encoding="utf-8")
    report_path = directory / f"{provider}-http-pilot-report.json"
    if process.returncode not in (0, 2) or not report_path.is_file():
        return {
            "scenario_id": scenario_id,
            "provider": provider,
            "repetition": repetition,
            "worker_id": worker_id,
            "status": "infrastructure-failure",
            "returncode": process.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "resumed": False,
        }
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return {
        "scenario_id": scenario_id,
        "provider": provider,
        "repetition": repetition,
        "worker_id": worker_id,
        "status": "completed",
        "returncode": process.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "objective_achieved": bool(report["objective_achieved"]),
        "model_calls": int(report["model_calls"]),
        "http_requests": int(report["http_requests"]),
        "trial_id": str(report["trial_id"]),
        "report_path": str(report_path),
        "report_sha256": sha256(report_path),
        "resumed": False,
    }


def summarize(
    *,
    run_id: str,
    repetitions: int,
    scenarios: list[str],
    providers: list[str],
    results: list[dict[str, object]],
    failure: str | None,
) -> dict[str, object]:
    completed = [item for item in results if item["status"] == "completed"]
    matrix = []
    for scenario_id in scenarios:
        for provider in providers:
            selected = [
                item
                for item in completed
                if item["scenario_id"] == scenario_id and item["provider"] == provider
            ]
            successes = sum(bool(item["objective_achieved"]) for item in selected)
            matrix.append(
                {
                    "scenario_id": scenario_id,
                    "provider": provider,
                    "completed": len(selected),
                    "successes": successes,
                    "success_rate": successes / len(selected) if selected else None,
                }
            )
    expected = len(scenarios) * len(providers) * repetitions
    return {
        "report_version": 1,
        "run_id": run_id,
        "scenario_config_sha256": sha256(CONFIG),
        "runner_sha256": sha256(RUNNER),
        "parallel_workers": sum(
            min(len(scenarios) * repetitions, 2) for _ in providers
        ),
        "repetitions": repetitions,
        "scenarios": scenarios,
        "providers": providers,
        "expected_tasks": expected,
        "completed_tasks": len(completed),
        "infrastructure_failures": sum(
            item["status"] == "infrastructure-failure" for item in results
        ),
        "failure": failure,
        "matrix": matrix,
        "results": sorted(
            results,
            key=lambda item: (
                str(item["scenario_id"]),
                str(item["provider"]),
                int(item["repetition"]),
            ),
        ),
        "status": "completed" if failure is None and len(completed) == expected else "partial",
        "updated_at": datetime.now(UTC).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--scenario-id", action="append", dest="scenario_ids")
    parser.add_argument(
        "--provider", action="append", choices=("codex", "claude"), dest="providers"
    )
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 5:
        raise ValueError("repetitions must be between 1 and 5")
    scenarios = load_scenarios()
    if args.scenario_ids:
        requested = list(dict.fromkeys(args.scenario_ids))
        unknown = sorted(set(requested) - set(scenarios))
        if unknown:
            raise ValueError(f"unknown scenario ids: {unknown}")
        scenarios = [item for item in scenarios if item in requested]
    providers = list(dict.fromkeys(args.providers or ("codex", "claude")))
    output_dir = args.output_dir.resolve()
    seal_path = output_dir / "run-seal.json"
    seal = {
        "run_id": args.run_id,
        "scenario_config_sha256": sha256(CONFIG),
        "runner_sha256": sha256(RUNNER),
        "repetitions": args.repetitions,
        "scenarios": scenarios,
        "providers": providers,
    }
    if args.resume:
        if not seal_path.is_file() or json.loads(seal_path.read_text(encoding="utf-8")) != seal:
            raise ValueError("resume seal does not match the requested batch")
    else:
        if output_dir.exists():
            raise FileExistsError(f"refusing to overwrite output directory: {output_dir}")
        output_dir.mkdir(parents=True)
        atomic_json(seal_path, seal)

    results: list[dict[str, object]] = []
    tasks: dict[str, list[tuple[str, int]]] = {worker_id: [] for worker_id, *_ in WORKERS}
    provider_workers = {
        "codex": [item[0] for item in WORKERS if item[1] == "codex"],
        "claude": [item[0] for item in WORKERS if item[1] == "claude"],
    }
    counters = {"codex": 0, "claude": 0}
    for scenario_id in scenarios:
        for provider in providers:
            for repetition in range(1, args.repetitions + 1):
                existing = validated_existing_result(
                    output_dir, scenario_id, provider, repetition
                )
                if existing is not None:
                    results.append(existing)
                    continue
                workers = provider_workers[provider]
                worker_id = workers[counters[provider] % len(workers)]
                counters[provider] += 1
                tasks[worker_id].append((scenario_id, repetition))

    if all(not assigned for assigned in tasks.values()):
        summary = summarize(
            run_id=args.run_id,
            repetitions=args.repetitions,
            scenarios=scenarios,
            providers=providers,
            results=results,
            failure=None,
        )
        report_path = output_dir / "parallel-http-baseline-report.json"
        atomic_json(report_path, summary)
        print(report_path)
        return 0 if summary["status"] == "completed" else 1

    lock = threading.Lock()
    report_path = output_dir / "parallel-http-baseline-report.json"
    failure: str | None = None
    specs: dict[str, tuple[str, str, dict[str, str], int]] = {}
    active_workers = [item for item in WORKERS if tasks[item[0]]]

    def execute_worker(worker_id: str) -> list[dict[str, object]]:
        provider, project, environment, _ = specs[worker_id]
        worker_results = []
        for scenario_id, repetition in tasks[worker_id]:
            result = run_task(
                worker_id=worker_id,
                provider=provider,
                environment=environment,
                output_dir=output_dir,
                scenario_id=scenario_id,
                repetition=repetition,
            )
            worker_results.append(result)
            with lock:
                results.append(result)
                atomic_json(
                    report_path,
                    summarize(
                        run_id=args.run_id,
                        repetitions=args.repetitions,
                        scenarios=scenarios,
                        providers=providers,
                        results=results,
                        failure=None,
                    ),
                )
            if result["status"] == "infrastructure-failure":
                break
        return worker_results

    try:
        for worker_id, provider, public_port, control_port in active_workers:
            project = f"ruby-baseline-gate-{args.run_id}-{worker_id}"
            environment = worker_environment(project, public_port, control_port)
            specs[worker_id] = (provider, project, environment, control_port)
            compose(project, environment, "up", "-d")
            wait_healthy(control_port)
        with ThreadPoolExecutor(max_workers=len(active_workers)) as executor:
            futures = [executor.submit(execute_worker, item[0]) for item in active_workers]
            for future in as_completed(futures):
                future.result()
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        cleanup_errors = []
        for _, project, environment, _ in specs.values():
            try:
                compose(project, environment, "down", "-v", "--remove-orphans")
            except Exception as error:
                cleanup_errors.append(f"{project}: {error}")
        if cleanup_errors:
            cleanup = "; ".join(cleanup_errors)
            failure = f"{failure}; cleanup: {cleanup}" if failure else f"cleanup: {cleanup}"

    summary = summarize(
        run_id=args.run_id,
        repetitions=args.repetitions,
        scenarios=scenarios,
        providers=providers,
        results=results,
        failure=failure,
    )
    atomic_json(report_path, summary)
    print(report_path)
    return 0 if summary["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
