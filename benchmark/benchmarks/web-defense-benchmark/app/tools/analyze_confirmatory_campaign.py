from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import NormalDist

from jsonschema import Draft202012Validator


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLAN_SCHEMA = PROJECT_ROOT / "contracts" / "confirmatory-analysis-plan.schema.json"
DEFAULT_PLAN = PROJECT_ROOT / "app" / "configs" / "confirmatory-analysis-plan-v1.json"
TARGET_LOST_MARKERS = (
    "ConnectError",
    "ConnectTimeout",
    "connection refused",
    "10061",
)


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def portable_path(path: Path) -> str:
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path.name


def validate_plan(plan: dict[str, object]) -> None:
    schema = load_json(PLAN_SCHEMA)
    errors = sorted(Draft202012Validator(schema).iter_errors(plan), key=lambda item: list(item.path))
    if errors:
        raise ValueError("invalid analysis plan: " + "; ".join(error.message for error in errors))
    joint = plan["expected_joint_outcomes"]
    assert isinstance(joint, dict)
    total = sum(float(value) for value in joint.values())
    if not math.isclose(total, 1.0, abs_tol=1e-9):
        raise ValueError("expected joint outcome probabilities must sum to 1")
    effect = float(joint["control_only"]) - float(joint["treatment_only"])
    if effect <= 0:
        raise ValueError("expected control-only probability must exceed treatment-only")
    if not math.isclose(float(plan["confidence_level"]), 1.0 - float(plan["alpha"]), abs_tol=1e-9):
        raise ValueError("confidence_level must equal 1 - alpha")
    execution = plan["execution"]
    assert isinstance(execution, dict)
    if plan.get("claim_scope") == "single-target-provider" and (
        len(execution["target_ids"]) != 1 or len(execution["providers"]) != 1
    ):
        raise ValueError(
            "single-target-provider claim scope requires exactly one target and provider"
        )


def wilson_interval(successes: int, trials: int, confidence: float = 0.95) -> tuple[float, float]:
    if trials < 1 or successes < 0 or successes > trials:
        raise ValueError("invalid binomial counts")
    z = NormalDist().inv_cdf(0.5 + confidence / 2.0)
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    center = (proportion + z * z / (2.0 * trials)) / denominator
    radius = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / trials
            + z * z / (4.0 * trials * trials)
        )
        / denominator
    )
    return max(0.0, center - radius), min(1.0, center + radius)


def paired_newcombe_interval(
    both_succeed: int,
    control_only: int,
    treatment_only: int,
    neither_succeeds: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Newcombe method 10 interval for a paired difference of proportions."""
    counts = (both_succeed, control_only, treatment_only, neither_succeeds)
    if any(value < 0 for value in counts):
        raise ValueError("paired counts cannot be negative")
    trials = sum(counts)
    if trials < 1:
        raise ValueError("at least one pair is required")
    control_successes = both_succeed + control_only
    treatment_successes = both_succeed + treatment_only
    control_rate = control_successes / trials
    treatment_rate = treatment_successes / trials
    difference = control_rate - treatment_rate
    control_low, control_high = wilson_interval(control_successes, trials, confidence)
    treatment_low, treatment_high = wilson_interval(treatment_successes, trials, confidence)
    denominator = math.sqrt(
        (both_succeed + control_only)
        * (treatment_only + neither_succeeds)
        * (both_succeed + treatment_only)
        * (control_only + neither_succeeds)
    )
    correlation = (
        (both_succeed * neither_succeeds - control_only * treatment_only) / denominator
        if denominator
        else 0.0
    )
    lower_radius = math.sqrt(
        max(
            0.0,
            (control_rate - control_low) ** 2
            + (treatment_high - treatment_rate) ** 2
            - 2.0
            * correlation
            * (control_rate - control_low)
            * (treatment_high - treatment_rate),
        )
    )
    upper_radius = math.sqrt(
        max(
            0.0,
            (control_high - control_rate) ** 2
            + (treatment_rate - treatment_low) ** 2
            - 2.0
            * correlation
            * (control_high - control_rate)
            * (treatment_rate - treatment_low),
        )
    )
    return max(-1.0, difference - lower_radius), min(1.0, difference + upper_radius)


def exact_mcnemar_p_value(control_only: int, treatment_only: int) -> float:
    discordant = control_only + treatment_only
    if discordant == 0:
        return 1.0
    tail = min(control_only, treatment_only)
    probability = sum(math.comb(discordant, value) for value in range(tail + 1)) / (2**discordant)
    return min(1.0, 2.0 * probability)


def paired_sample_size(plan: dict[str, object]) -> int:
    joint = plan["expected_joint_outcomes"]
    assert isinstance(joint, dict)
    control_only = float(joint["control_only"])
    treatment_only = float(joint["treatment_only"])
    discordance = control_only + treatment_only
    effect = control_only - treatment_only
    alternative_variance = max(0.0, discordance - effect * effect)
    z_alpha = NormalDist().inv_cdf(1.0 - float(plan["alpha"]) / 2.0)
    z_power = NormalDist().inv_cdf(float(plan["power"]))
    numerator = z_alpha * math.sqrt(discordance) + z_power * math.sqrt(alternative_variance)
    return math.ceil((numerator / effect) ** 2)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def condition(trial: dict[str, object]) -> str:
    value = trial.get("condition")
    return str(value) if value else "undefended"


def load_trials(run_dir: Path) -> list[dict[str, object]]:
    paths = sorted((run_dir / "trials").glob("*.json"))
    rows = []
    for path in paths:
        if path.name.endswith((".checkpoint.json", ".running.json")):
            continue
        rows.append(load_json(path))
    return rows


def exclusion_reason(trial: dict[str, object], invalid_statuses: set[str]) -> str | None:
    status = str(trial.get("status", ""))
    if status in invalid_statuses:
        return status
    attack_seconds = float(trial.get("attack_seconds") or 0.0)
    if attack_seconds <= 0.0:
        return "attack-not-started"
    runner_error = str(trial.get("runner_error") or "")
    if any(marker in runner_error for marker in TARGET_LOST_MARKERS):
        return "target-lost"
    return None


def normal_probe(trial: dict[str, object]) -> dict[str, object] | None:
    value = trial.get("normal_traffic_through_gateway")
    return value if isinstance(value, dict) else None


def normal_metrics(trial: dict[str, object]) -> dict[str, object]:
    metrics = trial.get("metrics")
    if not isinstance(metrics, dict):
        return {}
    value = metrics.get("normal_traffic_defense")
    return value if isinstance(value, dict) else {}


def summarize_condition_rows(
    trials: list[dict[str, object]], confidence: float
) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
    for trial in trials:
        grouped[(str(trial.get("target_id", "")), str(trial.get("provider", "")), condition(trial))].append(trial)
    rows = []
    for (target_id, provider, condition_id), items in sorted(grouped.items()):
        successes = sum(bool(item.get("objective_achieved")) for item in items)
        low, high = wilson_interval(successes, len(items), confidence)
        probes = [normal_probe(item) for item in items]
        normal = [normal_metrics(item) for item in items]
        latency = [float(item.get("defense_latency_seconds") or 0.0) for item in normal]
        rows.append(
            {
                "target_id": target_id,
                "provider": provider,
                "condition": condition_id,
                "trials": len(items),
                "successes": successes,
                "success_rate": round(successes / len(items), 6),
                "success_rate_interval": {
                    "method": "wilson",
                    "confidence": confidence,
                    "lower": round(low, 6),
                    "upper": round(high, 6),
                },
                "statuses": dict(sorted(Counter(str(item.get("status", "")) for item in items).items())),
                "normal_traffic": {
                    "post_attachment_probes": sum(item is not None for item in probes),
                    "all_workflows_completed_trials": sum(
                        isinstance(item, dict) and item.get("all_workflows_completed") is True
                        for item in probes
                    ),
                    "blocked_requests": sum(int(item.get("blocked_requests") or 0) for item in normal),
                    "defense_errors": sum(int(item.get("defense_errors") or 0) for item in normal),
                    "defense_latency_seconds_p50": round(percentile(latency, 0.5) or 0.0, 6),
                    "defense_latency_seconds_p95": round(percentile(latency, 0.95) or 0.0, 6),
                },
                "attack_cost": {
                    "active_http_requests": sum(
                        int(item.get("metrics", {}).get("active_http_requests", 0))
                        for item in items
                        if isinstance(item.get("metrics"), dict)
                    ),
                    "model_calls": sum(
                        int(item.get("metrics", {}).get("model_calls", 0))
                        for item in items
                        if isinstance(item.get("metrics"), dict)
                    ),
                },
            }
        )
    return rows


def pair_invariants_match(control: dict[str, object], treatment: dict[str, object]) -> bool:
    fields = (
        "target_id",
        "provider",
        "pair_id",
        "repetition",
        "requested_model_id",
        "observed_model_id",
        "model_identity_source",
        "model_identity_verified",
    )
    if any(control.get(field) != treatment.get(field) for field in fields):
        return False
    control_normal = control.get("normal_traffic")
    treatment_normal = treatment.get("normal_traffic")
    if isinstance(control_normal, dict) and isinstance(treatment_normal, dict):
        if control_normal.get("seed") != treatment_normal.get("seed"):
            return False
    control_isolation = control.get("isolation")
    treatment_isolation = treatment.get("isolation")
    if isinstance(control_isolation, dict) and isinstance(treatment_isolation, dict):
        if control_isolation.get("account_namespace_sha256") != treatment_isolation.get("account_namespace_sha256"):
            return False
    return True


def trial_keys(rows: list[object]) -> list[str]:
    return [
        str(item.get("trial_key", "")) if isinstance(item, dict) else ""
        for item in rows
    ]


def analyze(run_dir: Path, plan: dict[str, object]) -> dict[str, object]:
    validate_plan(plan)
    run_dir = run_dir.resolve()
    seal_path = run_dir / "run-seal.json"
    schedule_path = run_dir / "schedule.json"
    summary_path = run_dir / "campaign-summary.json"
    seal = load_json(seal_path)
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    summary = load_json(summary_path)
    if not isinstance(schedule, list):
        raise ValueError("schedule must be a list")
    trials = load_trials(run_dir)
    invalid_statuses = {str(item) for item in plan["invalid_trial_statuses"]}
    eligible: list[dict[str, object]] = []
    excluded = []
    for trial in trials:
        reason = exclusion_reason(trial, invalid_statuses)
        if reason is None:
            eligible.append(trial)
        else:
            excluded.append(
                {
                    "trial_key": trial.get("trial_key"),
                    "target_id": trial.get("target_id"),
                    "provider": trial.get("provider"),
                    "condition": condition(trial),
                    "status": trial.get("status"),
                    "reason": reason,
                }
            )

    execution = plan["execution"]
    qualification = plan["qualification"]
    comparison = plan["primary_comparison"]
    normal_policy = plan["normal_traffic"]
    assert isinstance(execution, dict)
    assert isinstance(qualification, dict)
    assert isinstance(comparison, dict)
    assert isinstance(normal_policy, dict)
    qualification_condition = str(qualification["condition"])
    control_condition = str(comparison["control_condition"])
    treatment_condition = str(comparison["treatment_condition"])
    required_conditions = {qualification_condition, control_condition, treatment_condition}

    qualification_groups: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for trial in eligible:
        if condition(trial) == qualification_condition:
            qualification_groups[(str(trial.get("target_id", "")), str(trial.get("provider", "")))].append(trial)
    qualification_rows = []
    qualified: set[tuple[str, str]] = set()
    for key, items in sorted(qualification_groups.items()):
        successes = sum(bool(item.get("objective_achieved")) for item in items)
        rate = successes / len(items)
        passed = len(items) >= int(qualification["minimum_trials"]) and rate >= float(qualification["minimum_success_rate"])
        if passed:
            qualified.add(key)
        low, high = wilson_interval(successes, len(items), float(plan["confidence_level"]))
        qualification_rows.append(
            {
                "target_id": key[0],
                "provider": key[1],
                "trials": len(items),
                "successes": successes,
                "success_rate": round(rate, 6),
                "wilson_interval": {"lower": round(low, 6), "upper": round(high, 6)},
                "qualified": passed,
            }
        )

    comparison_groups: dict[tuple[str, str, str], dict[str, list[dict[str, object]]]] = defaultdict(lambda: defaultdict(list))
    for trial in eligible:
        condition_id = condition(trial)
        if condition_id not in {control_condition, treatment_condition}:
            continue
        key = (
            str(trial.get("target_id", "")),
            str(trial.get("provider", "")),
            str(trial.get("pair_id", "")),
        )
        comparison_groups[key][condition_id].append(trial)

    complete_pairs: dict[tuple[str, str], list[tuple[dict[str, object], dict[str, object]]]] = defaultdict(list)
    pair_exclusions = []
    for key, by_condition in sorted(comparison_groups.items()):
        control_rows = by_condition.get(control_condition, [])
        treatment_rows = by_condition.get(treatment_condition, [])
        reason = None
        if len(control_rows) != 1 or len(treatment_rows) != 1:
            reason = "missing-or-duplicate-condition"
        elif not pair_invariants_match(control_rows[0], treatment_rows[0]):
            reason = "paired-input-mismatch"
        if reason:
            pair_exclusions.append(
                {"target_id": key[0], "provider": key[1], "pair_id": key[2], "reason": reason}
            )
        else:
            complete_pairs[(key[0], key[1])].append((control_rows[0], treatment_rows[0]))

    required_pairs = paired_sample_size(plan)
    comparison_rows = []
    for key, pairs in sorted(complete_pairs.items()):
        both = sum(bool(c.get("objective_achieved")) and bool(t.get("objective_achieved")) for c, t in pairs)
        control_only = sum(bool(c.get("objective_achieved")) and not bool(t.get("objective_achieved")) for c, t in pairs)
        treatment_only = sum(not bool(c.get("objective_achieved")) and bool(t.get("objective_achieved")) for c, t in pairs)
        neither = len(pairs) - both - control_only - treatment_only
        difference = (control_only - treatment_only) / len(pairs)
        lower, upper = paired_newcombe_interval(
            both, control_only, treatment_only, neither, float(plan["confidence_level"])
        )
        normal_ok = all(
            normal_probe(item) is not None
            and normal_probe(item).get("all_workflows_completed") is True
            and int(normal_metrics(item).get("blocked_requests") or 0)
            <= int(normal_policy["maximum_blocked_requests"])
            and int(normal_metrics(item).get("defense_errors") or 0)
            <= int(normal_policy["maximum_defense_errors"])
            for pair in pairs
            for item in pair
        )
        p_value = exact_mcnemar_p_value(control_only, treatment_only)
        claim_ready = (
            key in qualified
            and len(pairs) >= required_pairs
            and normal_ok
            and lower > 0.0
            and p_value < float(plan["alpha"])
        )
        comparison_rows.append(
            {
                "target_id": key[0],
                "provider": key[1],
                "valid_pairs": len(pairs),
                "required_pairs": required_pairs,
                "joint_outcomes": {
                    "both_succeed": both,
                    "control_only": control_only,
                    "treatment_only": treatment_only,
                    "neither_succeeds": neither,
                },
                "attack_success_risk_difference": round(difference, 6),
                "newcombe_paired_interval": {
                    "method": "newcombe-method-10-paired",
                    "confidence": float(plan["confidence_level"]),
                    "lower": round(lower, 6),
                    "upper": round(upper, 6),
                },
                "mcnemar_exact_two_sided_p": round(p_value, 12),
                "qualification_passed": key in qualified,
                "normal_traffic_passed": normal_ok,
                "sample_size_passed": len(pairs) >= required_pairs,
                "positive_effect_claim_ready": claim_ready,
            }
        )

    seal_conditions = {str(item) for item in seal.get("conditions", [])}
    seal_targets = [str(item) for item in seal.get("targets", [])]
    seal_providers = [str(item) for item in seal.get("providers", [])]
    expected_targets = [str(item) for item in execution["target_ids"]]
    expected_providers = [str(item) for item in execution["providers"]]
    sealed_inputs = seal.get("sealed_inputs", {})
    seal_limits = seal.get("limits", {})
    expected_limits = execution["trial_limits"]
    assert isinstance(sealed_inputs, dict)
    assert isinstance(seal_limits, dict)
    assert isinstance(expected_limits, dict)
    expected_knowledge_condition = str(
        execution.get("knowledge_condition", "hidden-black-box")
    )
    public_brief_input = execution.get("public_brief_sealed_input")
    public_brief_digest = execution.get("public_brief_sha256")
    scope_input = execution.get("scope_sealed_input")
    scope_digest = execution.get("scope_sha256")
    if expected_knowledge_condition == "hidden-black-box":
        knowledge_condition_matches = (
            seal.get("knowledge_condition", "hidden-black-box")
            == "hidden-black-box"
            and not seal.get("public_brief")
            and all(
                item.get("knowledge_condition", "hidden-black-box")
                == "hidden-black-box"
                and item.get("public_brief_sha256") in (None, "")
                for item in trials
            )
        )
        public_brief_digest_matches = True
    else:
        knowledge_condition_matches = (
            seal.get("knowledge_condition") == expected_knowledge_condition
            and seal.get("public_brief") == public_brief_input
            and bool(trials)
            and all(
                item.get("knowledge_condition") == expected_knowledge_condition
                for item in trials
            )
        )
        public_brief_digest_matches = (
            isinstance(public_brief_input, str)
            and isinstance(public_brief_digest, str)
            and sealed_inputs.get(public_brief_input) == public_brief_digest
            and bool(trials)
            and all(
                item.get("public_brief_sha256") == public_brief_digest
                for item in trials
            )
        )
    scope_digest_matches = (
        True
        if scope_input is None and scope_digest is None
        else isinstance(scope_input, str)
        and isinstance(scope_digest, str)
        and seal.get("scope") == scope_input
        and sealed_inputs.get(scope_input) == scope_digest
    )
    schedule_keys = trial_keys(schedule)
    observed_keys = trial_keys(trials)
    schedule_key_set = set(schedule_keys)
    observed_key_set = set(observed_keys)
    expected_schedule_cells = {
        (target_id, provider, condition_id, repetition)
        for target_id in expected_targets
        for provider in expected_providers
        for condition_id in required_conditions
        for repetition in range(int(execution["confirmatory_repetitions"]))
    }
    observed_schedule_cells = {
        (
            str(item.get("target_id", "")),
            str(item.get("provider", "")),
            str(item.get("condition", "")),
            int(item.get("repetition", -1)),
        )
        for item in schedule
        if isinstance(item, dict)
    }
    integrity_checks = {
        "run_targets_match_plan": seal_targets == expected_targets,
        "run_providers_match_plan": seal_providers == expected_providers,
        "attacker_profile_digest_matches_plan": sealed_inputs.get(
            execution["attacker_profile_sealed_input"]
        )
        == execution["attacker_profile_sha256"],
        "attacker_profile_id_matches_plan": bool(trials)
        and all(
            item.get("attacker_profile_id") == execution["attacker_profile_id"]
            for item in trials
        ),
        "knowledge_condition_matches_plan": knowledge_condition_matches,
        "public_brief_digest_matches_plan": public_brief_digest_matches,
        "scope_digest_matches_plan": scope_digest_matches,
        "reasoning_effort_matches_plan": seal.get("reasoning_effort")
        == execution["reasoning_effort"],
        "schedule_seed_matches_plan": seal.get("schedule_seed")
        == execution["schedule_seed"],
        "parallelism_matches_plan": seal.get("maximum_parallel_trials")
        == execution["maximum_parallel_trials"],
        "confirmatory_repetitions_match_plan": seal.get("repetitions")
        == execution["confirmatory_repetitions"],
        "trial_limits_match_plan": all(
            seal_limits.get(key) == expected_limits[key]
            for key in (
                "wall_clock_seconds",
                "active_http_requests",
                "agent_decisions",
                "model_calls_per_trial",
            )
        ),
        "campaign_model_call_budget_matches_schedule": seal_limits.get(
            "campaign_model_calls"
        )
        == len(schedule) * int(expected_limits["model_calls_per_trial"]),
        "run_conditions_match_plan": required_conditions == seal_conditions,
        "schedule_cells_match_plan": observed_schedule_cells
        == expected_schedule_cells,
        "schedule_entries_have_trial_keys": bool(schedule_keys)
        and all(schedule_keys),
        "schedule_trial_keys_unique": len(schedule_keys) == len(schedule_key_set),
        "completed_trial_keys_present": bool(observed_keys) and all(observed_keys),
        "completed_trial_keys_unique": len(observed_keys) == len(observed_key_set),
        "completed_trial_keys_match_schedule": schedule_key_set == observed_key_set,
        "schedule_matches_summary": len(schedule) == int(summary.get("scheduled_trials", -1)),
        "all_scheduled_trials_completed": int(summary.get("scheduled_trials", -1))
        == int(summary.get("completed_trials", -2))
        and int(summary.get("unstarted_trials", -1)) == 0,
        "trial_files_match_summary": len(trials) == int(summary.get("completed_trials", -1)),
        "model_identity_evidence_verified": bool(trials)
        and all(item.get("model_identity_verified") is True for item in trials),
        "post_attachment_normal_probe_available": bool(eligible) and all(
            normal_probe(item) is not None for item in eligible
        ),
    }
    return {
        "report_version": 1,
        "analysis_id": plan["analysis_id"],
        "run_id": seal.get("run_id"),
        "analysis_plan_sha256": None,
        "run_inputs": {
            "run_seal": {
                "path": portable_path(seal_path),
                "sha256": digest(seal_path),
            },
            "schedule": {
                "path": portable_path(schedule_path),
                "sha256": digest(schedule_path),
            },
            "campaign_summary": {
                "path": portable_path(summary_path),
                "sha256": digest(summary_path),
            },
        },
        "sample_size": {
            "method": "paired-mcnemar-normal-approximation",
            "alpha": plan["alpha"],
            "power": plan["power"],
            "expected_joint_outcomes": plan["expected_joint_outcomes"],
            "required_pairs_per_target_provider": required_pairs,
        },
        "integrity_checks": integrity_checks,
        "trials_read": len(trials),
        "valid_trials": len(eligible),
        "excluded_trials": excluded,
        "excluded_pairs": pair_exclusions,
        "qualification": qualification_rows,
        "condition_rows": summarize_condition_rows(
            eligible, float(plan["confidence_level"])
        ),
        "primary_comparisons": comparison_rows,
        "claim_status": {
            "analysis_complete": all(integrity_checks.values()),
            "eligible_comparisons": sum(item["positive_effect_claim_ready"] for item in comparison_rows),
            "statistical_effect_gate_passed": all(integrity_checks.values())
            and any(item["positive_effect_claim_ready"] for item in comparison_rows),
            "independent_review_completed": False,
            "positive_effect_claim_allowed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--analysis-plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite report: {output}")
    plan_path = args.analysis_plan.resolve()
    plan = load_json(plan_path)
    report = analyze(args.run_dir, plan)
    report["analysis_plan_sha256"] = digest(plan_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "analysis_complete": report["claim_status"]["analysis_complete"],
                "positive_effect_claim_allowed": report["claim_status"]["positive_effect_claim_allowed"],
                "report": str(output),
            }
        )
    )
    return 0 if report["claim_status"]["analysis_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
