from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

from evaluate_attacker_v11_qualification import _load, evaluate_qualification
from freeze_attacker_v11 import frozen_mismatches
from run_autonomous_campaign_v3 import (
    CAMPAIGN_LOCK_PATH,
    CampaignProcessLock,
    _start_launcher_watchdog,
    _validate_runtime_capacity,
    run_campaign,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the frozen 240-trial attacker v11 qualification")
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument("--freeze-seal", required=True, type=Path)
    parser.add_argument("--variant-manifest", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    cohort = _load(args.cohort)
    freeze_seal = _load(args.freeze_seal)
    variants = _load(args.variant_manifest)
    if variants.get("freeze_id") != freeze_seal.get("freeze_id"):
        raise ValueError("variant manifest was not generated from this freeze seal")
    mismatches = frozen_mismatches(freeze_seal)
    if mismatches:
        raise ValueError(f"attacker changed after freeze: {mismatches}")
    conditions = cohort["fixed_conditions"]
    targets = cohort["targets"]
    campaign_args = SimpleNamespace(
        run_id=args.run_id,
        output_dir=args.output_dir,
        attacker_profile=Path("app/configs/stage3a-autonomous-web-attacker-profile-v11.json"),
        variant_manifest=args.variant_manifest,
        targets=[str(item["target_id"]) for item in targets],
        providers=[str(item) for item in conditions["providers"]],
        repetitions=int(conditions["repetitions_per_target_provider"]),
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
    reports = [
        _load(path)
        for path in sorted((args.output_dir / "trials").glob("*.json"))
        if not path.name.endswith((".running.json", ".checkpoint.json"))
    ]
    retries = [
        str(path.relative_to(args.output_dir)).replace("\\", "/")
        for path in sorted((args.output_dir / "attempts").glob("**/*"))
        if path.is_file()
    ] if (args.output_dir / "attempts").exists() else []
    result = evaluate_qualification(
        cohort,
        _load(args.output_dir / "run-seal.json"),
        reports,
        retry_artifacts=retries,
    )
    result["campaign_summary"] = campaign_summary
    result["freeze_id"] = freeze_seal["freeze_id"]
    output = args.output_dir / "attacker-v11-qualification.json"
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
