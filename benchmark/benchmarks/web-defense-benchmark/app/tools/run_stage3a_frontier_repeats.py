from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path


RUNNER = Path(__file__).with_name("run_stage3a_codex_http_pilot.py")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_summary(output_dir: Path, provider: str, requested_runs: int, runs: list[dict[str, object]]) -> Path:
    completed = [run for run in runs if run["runner_status"] == "completed"]
    successes = sum(bool(run["objective_achieved"]) for run in completed)
    report = {
        "report_version": 1,
        "scenario_id": "cross-shop-refund-chain",
        "provider": provider,
        "requested_runs": requested_runs,
        "recorded_runs": len(runs),
        "completed_runs": len(completed),
        "objective_successes": successes,
        "objective_success_rate": successes / len(completed) if completed else None,
        "total_model_calls": sum(int(run["model_calls"]) for run in completed),
        "total_http_requests": sum(int(run["http_requests"]) for run in completed),
        "runs": runs,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    target = output_dir / "frontier-repeat-summary.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(target)
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("codex", "claude"), required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.runs <= 10:
        raise ValueError("runs must be between 1 and 10")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output directory: {output_dir}")
    output_dir.mkdir(parents=True)
    runs: list[dict[str, object]] = []
    for index in range(1, args.runs + 1):
        run_dir = output_dir / f"run-{index:02d}"
        started = time.monotonic()
        process = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--provider",
                args.provider,
                "--output-dir",
                str(run_dir),
            ],
            cwd=RUNNER.parents[1],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
        )
        (output_dir / f"run-{index:02d}-launcher.stdout.txt").write_text(process.stdout, encoding="utf-8")
        (output_dir / f"run-{index:02d}-launcher.stderr.txt").write_text(process.stderr, encoding="utf-8")
        report_path = run_dir / f"{args.provider}-http-pilot-report.json"
        if process.returncode not in (0, 2) or not report_path.is_file():
            runs.append(
                {
                    "run": index,
                    "runner_status": "infrastructure-failure",
                    "returncode": process.returncode,
                    "duration_seconds": round(time.monotonic() - started, 3),
                }
            )
            write_summary(output_dir, args.provider, args.runs, runs)
            return 1
        result = json.loads(report_path.read_text(encoding="utf-8"))
        runs.append(
            {
                "run": index,
                "runner_status": "completed",
                "returncode": process.returncode,
                "duration_seconds": round(time.monotonic() - started, 3),
                "trial_id": result["trial_id"],
                "objective_achieved": result["objective_achieved"],
                "model_calls": result["model_calls"],
                "http_requests": result["http_requests"],
                "report_path": str(report_path),
                "report_sha256": sha256(report_path),
            }
        )
        write_summary(output_dir, args.provider, args.runs, runs)
    print(write_summary(output_dir, args.provider, args.runs, runs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
