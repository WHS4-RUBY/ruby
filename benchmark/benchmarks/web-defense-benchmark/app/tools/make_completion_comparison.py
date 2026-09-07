from __future__ import annotations

import argparse
import json
from pathlib import Path


CONDITIONS = ("undefended", "proxy-only", "honeyval")
INFRASTRUCTURE_STATUSES = {
    "runner-error",
    "model-error",
    "invalid-defense-error",
    "isolation-error",
    "verifier-error",
}


def load_results(run_dir: Path) -> list[dict[str, object]]:
    rows = []
    for path in sorted((run_dir / "trials").glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if "status" in value:
            rows.append(value)
    return rows


def one_value(rows: list[dict[str, object]], path: tuple[str, ...]) -> object:
    values = []
    for row in rows:
        value: object = row
        for key in path:
            value = value[key]  # type: ignore[index]
        values.append(value)
    encoded = {json.dumps(value, sort_keys=True) for value in values}
    return values[0] if len(encoded) == 1 else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    rows = load_results(args.run_dir)
    if sorted(str(row["condition"]) for row in rows) != sorted(CONDITIONS):
        raise RuntimeError("comparison needs exactly one result for each condition")
    excluded = [row for row in rows if row["status"] in INFRASTRUCTURE_STATUSES]
    eligible = [row for row in rows if row not in excluded]
    condition_rows = {str(row["condition"]): row for row in eligible}
    conditions: dict[str, object] = {}
    for condition in CONDITIONS:
        row = condition_rows.get(condition)
        if row is None:
            continue
        metrics = row["metrics"]
        defense = metrics.get("defense") or {}
        conditions[condition] = {
            "valid_trials": 1,
            "objective_successes": int(bool(row["objective_achieved"])),
            "attack_success_rate": float(bool(row["objective_achieved"])),
            "status": row["status"],
            "active_http_requests": metrics["active_http_requests"],
            "attacker_model_calls": metrics["model_calls"],
            "attacker_decisions": row["decision_count"],
            "attack_seconds_excluding_defense": metrics[
                "attack_seconds_excluding_defense"
            ],
            "setup_seconds": row["setup_seconds"],
            "normal_workflows": row["normal_traffic"]["completed_workflows"],
            "normal_http_requests": row["normal_traffic"]["http_requests"],
            "runner_error": row["runner_error"],
            "model_error": row["model_error"],
            "defense_error": row["defense_error"],
            "defense_model_calls": defense.get("defense_model_calls", 0),
            "defense_model_ids": defense.get("defense_model_ids", []),
            "defense_model_identity_match": defense.get(
                "defense_model_identity_match"
            ),
            "decoy_responses": defense.get("decoy_responses", 0),
        }
    invariants = {
        "target_id": one_value(rows, ("target_id",)),
        "provider": one_value(rows, ("provider",)),
        "observed_attacker_model_id": one_value(rows, ("observed_model_id",)),
        "attacker_profile_id": one_value(rows, ("attacker_profile_id",)),
        "pair_id": one_value(rows, ("pair_id",)),
        "normal_traffic_seed": one_value(rows, ("normal_traffic", "seed")),
        "account_namespace_sha256": one_value(
            rows, ("isolation", "account_namespace_sha256")
        ),
        "public_api_prefix": one_value(rows, ("isolation", "public_api_prefix")),
        "normal_workflows": one_value(
            rows, ("normal_traffic", "completed_workflows")
        ),
    }
    paired_inputs_match = all(value is not None for value in invariants.values())
    undefended = conditions.get("undefended", {})
    honeyval = conditions.get("honeyval", {})
    report = {
        "contract_version": 1,
        "run_id": json.loads(
            (args.run_dir / "campaign-summary.json").read_text(encoding="utf-8")
        )["run_id"],
        "paired_inputs_match": paired_inputs_match,
        "paired_invariants": invariants,
        "infrastructure_errors_excluded": len(excluded),
        "excluded_trials": [
            {"trial_id": row["trial_id"], "status": row["status"]}
            for row in excluded
        ],
        "conditions": conditions,
        "normal_traffic_impact_observed": len(
            {
                json.dumps(value["normal_workflows"], sort_keys=True)
                for value in conditions.values()
            }
        )
        != 1,
        "functional_defense_effect_observed": bool(
            undefended.get("objective_successes") == 1
            and honeyval.get("objective_successes") == 0
        ),
        "limitations": [
            "This is one paired repetition on one target and does not establish statistical generalization.",
            "The subscription model is nondeterministic even when the sealed inputs match.",
        ],
    }
    if not paired_inputs_match or excluded:
        raise RuntimeError("comparison integrity gate failed")
    output_json = args.run_dir / "comparison.json"
    output_json.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# Completion paired comparison",
        "",
        f"Run: `{report['run_id']}`",
        "",
        "| Condition | Status | Success | HTTP requests | Attacker calls | Attack seconds | Normal workflows |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for condition in CONDITIONS:
        item = conditions[condition]
        lines.append(
            f"| {condition} | {item['status']} | {item['objective_successes']}/1 | "
            f"{item['active_http_requests']} | {item['attacker_model_calls']} | "
            f"{item['attack_seconds_excluding_defense']} | {len(item['normal_workflows'])}/5 |"
        )
    lines.extend(
        [
            "",
            f"Paired input integrity: `{paired_inputs_match}`",
            f"Infrastructure errors excluded: `{len(excluded)}`",
            f"Functional defense effect observed: `{report['functional_defense_effect_observed']}`",
            "",
            "This single paired repetition is a functional qualification result, not a statistical efficacy estimate.",
        ]
    )
    (args.run_dir / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
