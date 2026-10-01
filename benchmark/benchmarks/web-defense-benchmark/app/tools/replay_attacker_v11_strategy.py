from __future__ import annotations

import argparse
import json
from pathlib import Path

from attacker_strategy_v11 import build_strategy_state
from autonomous_trial_v2 import _public_input_surfaces


def _surfaces(report: dict[str, object]) -> list[dict[str, object]]:
    for interaction in report.get("interactions", []):
        if (
            isinstance(interaction, dict)
            and interaction.get("path") == "/openapi.json"
            and interaction.get("status") == 200
        ):
            return _public_input_surfaces(str(interaction.get("response", "")))
    return []


def _replace(value: object, old: str, new: str) -> object:
    if isinstance(value, dict):
        return {key: _replace(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace(item, old, new) for item in value]
    if isinstance(value, str):
        return value.replace(old + "/", new + "/").replace(f'"{old}"', f'"{new}"')
    return value


def _signature(state: dict[str, object]) -> dict[str, object]:
    return {
        "phase": state["phase"],
        "hypotheses": [
            (
                item["evidence_score"],
                item["strong_evidence_score"],
                item["verification_debt"],
                item["status"],
            )
            for item in state["ranked_hypotheses"]
        ],
        "chains": [
            {
                "state_change": item["state_change"],
                "state_change_verified": item["state_change_verified"],
                "evidence_score": item["evidence_score"],
                "unconsumed_actionable_values": item["unconsumed_actionable_values"],
                "categories": sorted(
                    value["category"] for value in item["public_values"]
                ),
                "consumer_counts": sorted(
                    len(value["candidate_consumers"])
                    for value in item["public_values"]
                ),
            }
            for item in state["evidence_chains"]
        ],
        "capabilities": sorted(
            item["capability"] for item in state["capability_opportunities"]
        ),
    }


def replay(directory: Path) -> dict[str, object]:
    reports = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob("*.json"))
    ]
    rows: list[dict[str, object]] = []
    metamorphic_failures: list[str] = []
    for index, report in enumerate(reports):
        surfaces = _surfaces(report)
        metrics = report.get("metrics", {})
        accounts = [
            {"email": "first", "password": "redacted", "role": "member"},
            {"email": "second", "password": "redacted", "role": "member"},
        ]
        state = build_strategy_state(
            surfaces=surfaces,
            interactions=report.get("interactions", []),
            lane_priorities=metrics.get("lane_priorities", []),
            accounts=accounts,
            used_requests=int(metrics.get("active_http_requests", 0)),
            max_requests=100,
        )
        old_prefix = str(report.get("isolation", {}).get("public_api_prefix") or "")
        equivalent = True
        if old_prefix:
            new_prefix = f"/variant-{index:02d}"
            transformed_interactions = _replace(
                report.get("interactions", []), old_prefix, new_prefix
            )
            transformed_surfaces = _replace(surfaces, old_prefix, new_prefix)
            transformed = build_strategy_state(
                surfaces=transformed_surfaces,
                interactions=transformed_interactions,
                lane_priorities=metrics.get("lane_priorities", []),
                accounts=accounts,
                used_requests=int(metrics.get("active_http_requests", 0)),
                max_requests=100,
            )
            equivalent = _signature(state) == _signature(transformed)
        if not equivalent:
            metamorphic_failures.append(str(report.get("trial_key", report.get("trial_id"))))
        rows.append(
            {
                "trial_id": report.get("trial_id"),
                "objective_achieved": report.get("objective_achieved"),
                "open_evidence_chains": len(state["evidence_chains"]),
                "unconsumed_actionable_values": sum(
                    int(item["unconsumed_actionable_values"])
                    for item in state["evidence_chains"]
                ),
                "capability_opportunities": [
                    item["capability"] for item in state["capability_opportunities"]
                ],
                "path_metamorphic_equivalent": equivalent,
            }
        )
    failed = [item for item in rows if not item["objective_achieved"]]
    return {
        "schema_version": 1,
        "source_reports": len(rows),
        "failed_reports": len(failed),
        "failed_reports_with_open_evidence_chain": sum(
            int(item["open_evidence_chains"] > 0) for item in failed
        ),
        "open_evidence_chains": sum(item["open_evidence_chains"] for item in rows),
        "unconsumed_actionable_values": sum(
            item["unconsumed_actionable_values"] for item in rows
        ),
        "path_metamorphic_failures": metamorphic_failures,
        "passed": len(rows) > 0 and not metamorphic_failures,
        "trials": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay v10 ledgers through v11 strategy state")
    parser.add_argument("--trials-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = replay(args.trials_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({key: value for key, value in result.items() if key != "trials"}, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
