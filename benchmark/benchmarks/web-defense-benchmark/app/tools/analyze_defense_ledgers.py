"""Aggregate the Honeyval defense ledgers of a run into evidence tables.

Answers the questions the final report has to separate:
what the dynamic model actually produced, what the rule code rejected, and
where the defense never engaged at all.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = APP_ROOT / "evaluation"


def read_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def analyze(run_dir: Path) -> dict[str, Any]:
    per_target: list[dict[str, Any]] = []
    validation_codes: Counter[str] = Counter()
    skip_reasons: Counter[str] = Counter()
    upstream_statuses: Counter[str] = Counter()
    served_statuses: Counter[str] = Counter()
    deceived_templates: Counter[str] = Counter()
    latencies: list[float] = []
    samples: list[dict[str, Any]] = []
    fact_keys: Counter[str] = Counter()
    spec_states: Counter[str] = Counter()
    chain_rows: list[dict[str, Any]] = []
    chain_rejections: Counter[str] = Counter()
    chain_stage_statuses: Counter[str] = Counter()

    trials = run_dir / "trials"
    if not trials.is_dir():
        return {"error": f"no trials directory in {run_dir}"}

    for directory in sorted(trials.iterdir()):
        events = read_ledger(directory / "defense-ledger.jsonl")
        chain_rows.append(_chain_row(directory.name, events))
        for event in events:
            if event.get("type") == "decoy_chain_rejected":
                chain_rejections[str(event.get("reason"))] += 1
            elif event.get("type") == "decoy_chain_stage":
                chain_stage_statuses[str(event.get("served_status"))] += 1
        if not events:
            continue
        target_id = directory.name
        decoys = 0
        failures = 0
        skipped = 0
        target_latencies: list[float] = []
        for event in events:
            kind = event.get("type")
            if kind == "spec_loaded":
                spec_states[
                    f"available={event.get('available')} operations={event.get('operation_count')}"
                ] += 1
            elif kind == "exchange":
                upstream_statuses[str(event.get("upstream_status"))] += 1
                served_statuses[f"{event.get('source')}:{event.get('served_status')}"] += 1
            elif kind == "defense_response":
                decoys += 1
                deceived_templates[str(event.get("template"))] += 1
                value = float(event.get("latency_seconds") or 0)
                latencies.append(value)
                target_latencies.append(value)
                for key in event.get("fact_keys") or []:
                    fact_keys[str(key).split(":", 1)[0]] += 1
                if len(samples) < 40 and event.get("body_preview"):
                    samples.append(
                        {
                            "target": target_id,
                            "method": event.get("method"),
                            "path": event.get("path"),
                            "upstream_status": event.get("upstream_status"),
                            "served_status": event.get("served_status"),
                            "body_preview": event.get("body_preview"),
                            "fact_keys": event.get("fact_keys"),
                        }
                    )
            elif kind == "defense_validation_failed":
                failures += 1
                for reason in event.get("reasons") or []:
                    validation_codes[str(reason).split(":", 1)[0]] += 1
            elif kind == "defense_generation_failed":
                failures += 1
                validation_codes["generator-failure"] += 1
            elif kind == "defense_skipped":
                skipped += 1
                skip_reasons[str(event.get("reason"))] += 1

        per_target.append(
            {
                "target": target_id,
                "decoy_responses": decoys,
                "rejected_generations": failures,
                "skipped_by_budget": skipped,
                "median_generation_latency_seconds": (
                    round(statistics.median(target_latencies), 3) if target_latencies else None
                ),
            }
        )

    engaged = [item for item in per_target if item["decoy_responses"] > 0]
    return {
        "run": run_dir.name,
        "targets_with_ledger": len(per_target),
        "targets_where_defense_engaged": len(engaged),
        "targets_where_defense_never_engaged": [
            item["target"] for item in per_target if item["decoy_responses"] == 0
        ],
        "generation_latency_seconds": {
            "count": len(latencies),
            "median": round(statistics.median(latencies), 3) if latencies else None,
            "mean": round(statistics.fmean(latencies), 3) if latencies else None,
            "min": round(min(latencies), 3) if latencies else None,
            "max": round(max(latencies), 3) if latencies else None,
        },
        "upstream_status_counts": dict(upstream_statuses.most_common()),
        "served_source_status_counts": dict(served_statuses.most_common()),
        "validation_rejection_codes": dict(validation_codes.most_common()),
        "budget_skip_reasons": dict(skip_reasons.most_common()),
        "deceived_route_templates": dict(deceived_templates.most_common(40)),
        "invented_fact_kinds": dict(fact_keys.most_common(30)),
        "openapi_states": dict(spec_states),
        "per_target": per_target,
        "generated_response_samples": samples,
        "decoy_chain": _chain_summary(chain_rows, chain_rejections, chain_stage_statuses),
    }


def _chain_row(name: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    """What the chain did in one trial, read from that trial's ledger.

    The chain counters were added to the gateway after the run that this reads
    was launched, so the ledger rather than the result file is the source.
    """

    advertised = None
    entry_path = None
    entry_hits = 0
    followups = 0
    walked: list[str] = []
    for event in events:
        if event.get("type") == "decoy_chain_advertised":
            advertised = event.get("chain")
            try:
                entry_path = json.loads(str(advertised)).get("entry_path")
            except json.JSONDecodeError:
                entry_path = None
        elif event.get("type") == "decoy_chain_stage":
            path = str(event.get("path"))
            walked.append(path)
            if path == entry_path:
                entry_hits += 1
            else:
                followups += 1
    return {
        "trial": name,
        "chain_advertised": advertised is not None,
        "entry_path": entry_path,
        "entry_hits": entry_hits,
        "followups": followups,
        "distinct_stages_walked": len(set(walked)),
        "walk": walked,
    }


def _chain_summary(
    rows: list[dict[str, Any]],
    rejections: Counter[str],
    stage_statuses: Counter[str],
) -> dict[str, Any]:
    built = [row for row in rows if row["chain_advertised"]]
    entered = [row for row in built if row["entry_hits"] > 0]
    return {
        "trials_seen": len(rows),
        "chain_built": len(built),
        "chain_not_built": len(rows) - len(built),
        "build_rejection_reasons": dict(rejections.most_common()),
        "trials_where_the_entry_was_found": len(entered),
        "decoy_entry_hits": sum(row["entry_hits"] for row in built),
        "decoy_followups_intercepted": sum(row["followups"] for row in built),
        "stage_status_counts": dict(stage_statuses.most_common()),
        "per_trial": rows,
    }
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", required=True)
    parsed = parser.parse_args()
    run_dir = Path(parsed.run)
    if not run_dir.is_absolute() and not run_dir.exists():
        run_dir = EVALUATION_ROOT / parsed.run
    report = analyze(run_dir)
    output = Path(parsed.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "targets_with_ledger",
                    "targets_where_defense_engaged",
                    "generation_latency_seconds",
                    "validation_rejection_codes",
                    "budget_skip_reasons",
                )
                if key in report
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
