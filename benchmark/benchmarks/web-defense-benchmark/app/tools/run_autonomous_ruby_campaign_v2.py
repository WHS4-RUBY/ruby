from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from datetime import UTC, datetime
from pathlib import Path

from autonomous_cli_policy_v2 import SubscriptionCLIPolicy
from autonomous_trial_v2 import ATTACKER_GUIDE, run_ruby_trial


APP_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = APP_ROOT / "configs" / "stage3a-autonomous-target-registry-v2.json"
SCOPE_PATH = APP_ROOT / "configs" / "stage3a-autonomous-baseline-scope-v1.json"
ACTION_SCHEMA_PATH = APP_ROOT / "configs" / "stage3a-attacker-action-v2.schema.json"
PROFILE_PATH = APP_ROOT / "configs" / "stage3a-autonomous-web-attacker-profile-v10.json"
TERMINAL_STATUSES = {
    "objective-achieved",
    "attack-failed",
    "budget-exhausted",
    "model-error",
    "runner-error",
    "isolation-error",
    "verifier-error",
}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_atomic(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _safe(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-")


def _registered_modules() -> list[str]:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return [str(item["module_id"]) for item in registry["ruby_web_targets"]]


def _schedule(
    modules: list[str], providers: list[str], repetitions: int, seed: int
) -> list[dict[str, object]]:
    rows = [
        {
            "module_id": module_id,
            "provider": provider,
            "repetition": repetition,
            "normal_traffic_seed": seed + repetition,
        }
        for repetition in range(repetitions)
        for module_id in modules
        for provider in providers
    ]
    random.Random(seed).shuffle(rows)
    for index, row in enumerate(rows):
        row["order"] = index
        row["trial_key"] = (
            f"{index:04d}-{_safe(str(row['provider']))}-"
            f"{_safe(str(row['module_id']))}-r{int(row['repetition']) + 1}"
        )
    return rows


def _seal(
    *,
    run_id: str,
    modules: list[str],
    providers: list[str],
    repetitions: int,
    seed: int,
    max_seconds: int,
    max_requests: int,
    max_decisions: int,
) -> dict[str, object]:
    return {
        "seal_version": 1,
        "run_id": run_id,
        "target_kind": "ruby-web",
        "execution_concurrency": 1,
        "execution_concurrency_reason": "one shared RUBY application state",
        "modules": modules,
        "providers": providers,
        "repetitions": repetitions,
        "schedule_seed": seed,
        "limits": {
            "wall_clock_seconds": max_seconds,
            "active_http_requests": max_requests,
            "agent_decisions": max_decisions,
        },
        "hashes": {
            "registry": _digest(REGISTRY_PATH),
            "scope": _digest(SCOPE_PATH),
            "action_schema": _digest(ACTION_SCHEMA_PATH),
            "attacker_profile": _digest(PROFILE_PATH),
            "attacker_guide": _digest(ATTACKER_GUIDE),
        },
    }


def run_campaign(args: argparse.Namespace) -> dict[str, object]:
    registered = _registered_modules()
    modules = args.modules or registered
    unknown = sorted(set(modules) - set(registered))
    if unknown:
        raise ValueError(f"unregistered modules: {unknown}")
    if len(modules) != len(set(modules)):
        raise ValueError("module list contains duplicates")
    providers = args.providers
    seal = _seal(
        run_id=args.run_id,
        modules=modules,
        providers=providers,
        repetitions=args.repetitions,
        seed=args.seed,
        max_seconds=args.max_seconds,
        max_requests=args.max_requests,
        max_decisions=args.max_decisions,
    )
    schedule = _schedule(modules, providers, args.repetitions, args.seed)
    output_dir: Path = args.output_dir
    seal_path = output_dir / "run-seal.json"
    schedule_path = output_dir / "schedule.json"
    trials_dir = output_dir / "trials"
    if output_dir.exists():
        if not args.resume:
            raise FileExistsError(f"output directory already exists: {output_dir}")
        observed = json.loads(seal_path.read_text(encoding="utf-8"))
        if observed != seal:
            raise ValueError("resume seal does not match current arguments or inputs")
    else:
        if args.resume:
            raise FileNotFoundError("resume output directory does not exist")
        output_dir.mkdir(parents=True)
        trials_dir.mkdir()
        _write_atomic(seal_path, seal)
        _write_atomic(schedule_path, schedule)

    completed = 0
    attempts_dir = output_dir / "attempts"
    for row in schedule:
        result_path = trials_dir / f"{row['trial_key']}.json"
        if result_path.is_file():
            existing = json.loads(result_path.read_text(encoding="utf-8"))
            if existing.get("status") not in TERMINAL_STATUSES:
                raise ValueError(f"non-terminal stored trial: {result_path}")
            if existing.get("status") not in set(args.retry_status):
                completed += 1
                continue
            attempts_dir.mkdir(exist_ok=True)
            attempt_index = 1
            while (attempts_dir / f"{row['trial_key']}-attempt-{attempt_index:03d}.json").exists():
                attempt_index += 1
            result_path.replace(
                attempts_dir / f"{row['trial_key']}-attempt-{attempt_index:03d}.json"
            )
        running_path = result_path.with_suffix(".running.json")
        _write_atomic(
            running_path,
            {
                "run_id": args.run_id,
                "trial_key": row["trial_key"],
                "started_at": datetime.now(UTC).isoformat(),
            },
        )
        policy = SubscriptionCLIPolicy(str(row["provider"]))
        report = run_ruby_trial(
            module_id=str(row["module_id"]),
            policy=policy,
            normal_traffic_seed=int(row["normal_traffic_seed"]),
            trial_id=f"{args.run_id}:{row['trial_key']}",
            max_seconds=args.max_seconds,
            max_active_requests=args.max_requests,
            max_decisions=args.max_decisions,
        )
        report["run_id"] = args.run_id
        report["trial_key"] = row["trial_key"]
        report["provider"] = row["provider"]
        report["repetition"] = row["repetition"]
        report["finished_at"] = datetime.now(UTC).isoformat()
        _write_atomic(result_path, report)
        running_path.unlink(missing_ok=True)
        completed += 1

    reports = [
        json.loads((trials_dir / f"{row['trial_key']}.json").read_text(encoding="utf-8"))
        for row in schedule
    ]
    status_counts: dict[str, int] = {}
    for report in reports:
        status = str(report["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
    summary = {
        "run_id": args.run_id,
        "scheduled_trials": len(schedule),
        "completed_trials": completed,
        "status_counts": status_counts,
        "objective_successes": sum(
            bool(report["objective_achieved"]) for report in reports
        ),
        "total_model_calls": sum(
            int(report["metrics"].get("model_calls", 0)) for report in reports
        ),
        "total_active_http_requests": sum(
            int(report["metrics"].get("active_http_requests", 0)) for report in reports
        ),
        "finished_at": datetime.now(UTC).isoformat(),
    }
    _write_atomic(output_dir / "campaign-summary.json", summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run resumable RUBY autonomous trials")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--modules", nargs="*")
    parser.add_argument(
        "--providers", nargs="+", choices=("codex", "claude"), default=["codex", "claude"]
    )
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--seed", type=int, default=8312026)
    parser.add_argument("--max-seconds", type=int, default=1800)
    parser.add_argument("--max-requests", type=int, default=100)
    parser.add_argument("--max-decisions", type=int, default=40)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--retry-status",
        nargs="*",
        choices=tuple(sorted(TERMINAL_STATUSES)),
        default=[],
    )
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    if args.max_seconds < 1 or args.max_requests < 1 or args.max_decisions < 1:
        parser.error("all limits must be positive")
    return args


if __name__ == "__main__":
    print(json.dumps(run_campaign(parse_args()), ensure_ascii=False, sort_keys=True))
