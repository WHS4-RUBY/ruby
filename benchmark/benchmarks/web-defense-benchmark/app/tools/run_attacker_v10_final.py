from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

from evaluate_attacker_v10_cohort import (
    _frozen_mismatches,
    _load,
    evaluate_cohort,
)
from run_autonomous_campaign_v3 import (
    CAMPAIGN_LOCK_PATH,
    CampaignProcessLock,
    _start_launcher_watchdog,
    _validate_runtime_capacity,
    run_campaign,
)


def _reports(run_dir: Path) -> list[dict[str, object]]:
    return [
        _load(path)
        for path in sorted((run_dir / "trials").glob("*.json"))
        if not path.name.endswith((".running.json", ".checkpoint.json"))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run or resume the frozen 48-trial attacker v10 evaluation"
    )
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--seal", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    cohort = _load(args.cohort)
    seal = _load(args.seal)
    if seal.get("cohort_id") != cohort.get("cohort_id"):
        raise ValueError("seal and cohort identifiers differ")
    mismatches = _frozen_mismatches(seal)
    if mismatches:
        raise ValueError(f"frozen inputs changed before execution: {mismatches}")
    conditions = cohort["fixed_conditions"]
    if not isinstance(conditions, dict):
        raise ValueError("cohort fixed_conditions must be an object")
    targets = cohort["targets"]
    if not isinstance(targets, list):
        raise ValueError("cohort targets must be a list")
    campaign_args = SimpleNamespace(
        run_id=args.run_id,
        output_dir=args.output_dir,
        targets=[str(item["target_id"]) for item in targets],
        providers=[str(item) for item in conditions["providers"]],
        repetitions=int(conditions["repetitions_per_provider_family"]),
        seed=int(conditions["schedule_seed"]),
        max_seconds=int(conditions["maximum_seconds_per_trial"]),
        max_requests=int(conditions["maximum_active_http_requests_per_trial"]),
        max_decisions=int(conditions["maximum_decisions_per_trial"]),
        max_model_calls=int(conditions["maximum_campaign_model_calls"]),
        max_model_calls_per_trial=int(conditions["maximum_model_calls_per_trial"]),
        max_parallel=int(conditions["maximum_parallel_trials"]),
        reasoning_effort=str(conditions["reasoning_effort"]),
        resume=args.resume,
        retry_status=[],
        runtime_capacity_evidence=_validate_runtime_capacity(
            int(conditions["maximum_parallel_trials"])
        ),
    )
    with CampaignProcessLock(CAMPAIGN_LOCK_PATH, run_id=args.run_id):
        _start_launcher_watchdog(run_id=args.run_id)
        campaign_summary = run_campaign(campaign_args)
    result = evaluate_cohort(cohort, seal, _reports(args.output_dir))
    result["campaign_summary"] = campaign_summary
    output = args.output_dir / "attacker-v10-final-evaluation.json"
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
