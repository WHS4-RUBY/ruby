from __future__ import annotations

import json
from pathlib import Path

from analyze_confirmatory_campaign import (
    DEFAULT_PLAN,
    analyze,
    digest,
    exact_mcnemar_p_value,
    load_json,
    paired_newcombe_interval,
    paired_sample_size,
    validate_plan,
)


def test_default_plan_is_valid_and_has_a_reproducible_sample_size() -> None:
    plan = load_json(DEFAULT_PLAN)
    validate_plan(plan)
    assert paired_sample_size(plan) == 33


def test_guided_plans_are_valid_and_bind_existing_inputs() -> None:
    app_root = Path(DEFAULT_PLAN).parents[1]
    for name in (
        "qualification-analysis-plan-guided-sqli-v1.json",
        "confirmatory-analysis-plan-guided-sqli-v1.json",
    ):
        plan = load_json(app_root / "configs" / name)
        validate_plan(plan)
        execution = plan["execution"]
        for path_key, digest_key in (
            ("public_brief_sealed_input", "public_brief_sha256"),
            ("scope_sealed_input", "scope_sha256"),
        ):
            path = app_root / execution[path_key]
            assert path.is_file()
            assert digest(path).removeprefix("sha256:") == execution[digest_key]


def test_paired_newcombe_interval_tracks_complete_defense_separation() -> None:
    lower, upper = paired_newcombe_interval(0, 40, 0, 0)
    assert 0 < lower < 1
    assert upper == 1
    assert exact_mcnemar_p_value(40, 0) < 0.05


def test_paired_newcombe_interval_includes_zero_for_identical_outcomes() -> None:
    lower, upper = paired_newcombe_interval(8, 0, 0, 12)
    assert lower <= 0 <= upper
    assert exact_mcnemar_p_value(0, 0) == 1.0


def test_plan_rejects_joint_probabilities_that_do_not_sum_to_one() -> None:
    plan = json.loads(Path(DEFAULT_PLAN).read_text(encoding="utf-8"))
    plan["expected_joint_outcomes"]["neither_succeeds"] = 0.5
    try:
        validate_plan(plan)
    except ValueError as error:
        assert "sum to 1" in str(error)
    else:
        raise AssertionError("invalid plan was accepted")


def test_single_target_provider_scope_rejects_multiple_targets() -> None:
    plan = load_json(DEFAULT_PLAN)
    plan["claim_scope"] = "single-target-provider"
    plan["execution"]["target_ids"].append(
        "ruby-web:object-authorization.customer-profile"
    )
    try:
        validate_plan(plan)
    except ValueError as error:
        assert "exactly one target and provider" in str(error)
    else:
        raise AssertionError("multi-target single-stratum plan was accepted")


def test_complete_33_pair_campaign_allows_a_positive_effect_claim(tmp_path: Path) -> None:
    plan = load_json(DEFAULT_PLAN)
    run_dir = tmp_path / "run"
    trials_dir = run_dir / "trials"
    trials_dir.mkdir(parents=True)
    conditions = ("undefended", "proxy-only", "static-guard")
    schedule = []
    trial_count = 0
    for repetition in range(33):
        pair_id = f"pair-{repetition:02d}"
        for condition_id in conditions:
            achieved = condition_id != "static-guard"
            trial = {
                "trial_key": f"trial-{repetition:02d}-{condition_id}",
                "target_id": "ruby-web:sql-injection.product-search",
                "provider": "codex",
                "condition": condition_id,
                "attacker_profile_id": "ruby-stage3a-autonomous-web-attacker-v10",
                "pair_id": pair_id,
                "repetition": repetition,
                "requested_model_id": "fixture-model-v1",
                "observed_model_id": "fixture-model-v1",
                "model_identity_source": "fixture-response",
                "model_identity_verified": True,
                "status": "objective-achieved" if achieved else "attack-failed",
                "objective_achieved": achieved,
                "attack_seconds": 1.0,
                "normal_traffic": {"seed": repetition},
                "normal_traffic_through_gateway": {
                    "all_workflows_completed": True,
                    "completed_workflows": ["normal"],
                },
                "isolation": {"account_namespace_sha256": f"sha256:{pair_id}"},
                "metrics": {
                    "active_http_requests": 1,
                    "model_calls": 1,
                    "normal_traffic_defense": {
                        "blocked_requests": 0,
                        "defense_errors": 0,
                        "defense_latency_seconds": 0.01,
                    },
                },
                "runner_error": None,
            }
            (trials_dir / f"{trial['trial_key']}.json").write_text(
                json.dumps(trial), encoding="utf-8"
            )
            schedule.append(
                {
                    "trial_key": trial["trial_key"],
                    "target_id": trial["target_id"],
                    "provider": trial["provider"],
                    "condition": trial["condition"],
                    "repetition": trial["repetition"],
                }
            )
            trial_count += 1
    (run_dir / "run-seal.json").write_text(
        json.dumps(
            {
                "run_id": "fixture-run",
                "conditions": list(conditions),
                "targets": ["ruby-web:sql-injection.product-search"],
                "providers": ["codex"],
                "reasoning_effort": "medium",
                "schedule_seed": 8312028,
                "maximum_parallel_trials": 3,
                "repetitions": 33,
                "limits": {
                    "wall_clock_seconds": 1800,
                    "active_http_requests": 100,
                    "agent_decisions": 40,
                    "model_calls_per_trial": 45,
                    "campaign_model_calls": trial_count * 45,
                },
                "sealed_inputs": {
                    "configs/stage3a-autonomous-web-attacker-profile-v10.json": (
                        "8068ccb4fafd62c5cab20e7fd6e85086ee4de2938ed7d2bf9fc05c0eefe69ac6"
                    )
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "schedule.json").write_text(json.dumps(schedule), encoding="utf-8")
    (run_dir / "campaign-summary.json").write_text(
        json.dumps(
            {
                "scheduled_trials": trial_count,
                "completed_trials": trial_count,
                "unstarted_trials": 0,
            }
        ),
        encoding="utf-8",
    )

    report = analyze(run_dir, plan)

    comparison = report["primary_comparisons"][0]
    assert report["claim_status"]["analysis_complete"]
    assert report["claim_status"]["positive_effect_claim_allowed"]
    assert comparison["valid_pairs"] == 33
    assert comparison["sample_size_passed"]
    assert comparison["qualification_passed"]
    assert comparison["normal_traffic_passed"]
    assert comparison["newcombe_paired_interval"]["lower"] > 0
    assert 0 < comparison["mcnemar_exact_two_sided_p"] < 1e-8


def test_confirmatory_campaign_rejects_smaller_trial_budget(tmp_path: Path) -> None:
    plan = load_json(DEFAULT_PLAN)
    run_dir = tmp_path / "run"
    trials_dir = run_dir / "trials"
    trials_dir.mkdir(parents=True)
    (run_dir / "run-seal.json").write_text(
        json.dumps(
            {
                "run_id": "under-budget",
                "conditions": ["undefended", "proxy-only", "static-guard"],
                "targets": plan["execution"]["target_ids"],
                "providers": plan["execution"]["providers"],
                "reasoning_effort": "medium",
                "schedule_seed": 8312028,
                "maximum_parallel_trials": 3,
                "repetitions": 33,
                "limits": {
                    "wall_clock_seconds": 600,
                    "active_http_requests": 60,
                    "agent_decisions": 25,
                    "model_calls_per_trial": 25,
                    "campaign_model_calls": 25,
                },
                "sealed_inputs": {
                    plan["execution"]["attacker_profile_sealed_input"]: plan[
                        "execution"
                    ]["attacker_profile_sha256"]
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "schedule.json").write_text("[]", encoding="utf-8")
    (run_dir / "campaign-summary.json").write_text(
        json.dumps(
            {"scheduled_trials": 0, "completed_trials": 0, "unstarted_trials": 0}
        ),
        encoding="utf-8",
    )

    report = analyze(run_dir, plan)

    assert not report["integrity_checks"]["trial_limits_match_plan"]
    assert not report["claim_status"]["analysis_complete"]
    assert not report["claim_status"]["positive_effect_claim_allowed"]


def test_schedule_and_completed_trial_keys_must_match(tmp_path: Path) -> None:
    plan = load_json(DEFAULT_PLAN)
    run_dir = tmp_path / "run"
    trials_dir = run_dir / "trials"
    trials_dir.mkdir(parents=True)
    trial = {
        "trial_key": "observed",
        "target_id": "ruby-web:sql-injection.product-search",
        "provider": "fixture-provider",
        "condition": "undefended",
        "pair_id": "pair-1",
        "repetition": 0,
        "observed_model_id": "fixture-model-v1",
        "status": "attack-failed",
        "objective_achieved": False,
        "attack_seconds": 1.0,
        "normal_traffic_through_gateway": {"all_workflows_completed": True},
    }
    (trials_dir / "observed.json").write_text(json.dumps(trial), encoding="utf-8")
    (run_dir / "run-seal.json").write_text(
        json.dumps(
            {
                "run_id": "fixture-run",
                "conditions": ["undefended", "proxy-only", "static-guard"],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "schedule.json").write_text(
        json.dumps([{"trial_key": "scheduled"}]), encoding="utf-8"
    )
    (run_dir / "campaign-summary.json").write_text(
        json.dumps(
            {
                "scheduled_trials": 1,
                "completed_trials": 1,
                "unstarted_trials": 0,
            }
        ),
        encoding="utf-8",
    )

    report = analyze(run_dir, plan)

    assert not report["integrity_checks"]["completed_trial_keys_match_schedule"]
    assert not report["claim_status"]["analysis_complete"]
    assert not report["claim_status"]["positive_effect_claim_allowed"]
