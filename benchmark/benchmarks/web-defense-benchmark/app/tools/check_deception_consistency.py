"""Measure the observables an attacker can use to separate deception from truth.

The earlier analysis found that the generated responses were separable because
the same path answered differently depending on the caller credential, and
because a path could serve both a generated answer and a genuine one. This tool
counts those observables directly so a change to the defense can be judged.

Lower is better for every count reported here.
"""

from __future__ import annotations

import argparse
import collections
import json
import statistics
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = APP_ROOT / "evaluation"


def read_exchanges(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.is_file():
        return events
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def analyse_trial(directory: Path) -> dict[str, Any] | None:
    events = read_exchanges(directory / "defense-ledger.jsonl")
    if not events:
        return None
    result_path = directory / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8")) if result_path.is_file() else {}
    exchanges = [item for item in events if item.get("type") == "exchange"]
    if not exchanges:
        return None

    def world_of(item: dict[str, Any]) -> Any:
        # Runs made before the actor scope existed have no world_id. Their
        # deception world was the session, so fall back to it for comparison.
        return item.get("world_id", item.get("session_id"))

    by_path: dict[tuple[str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for item in exchanges:
        by_path[(item.get("method", ""), item.get("path", ""))].append(item)

    mixed_paths = 0
    mixed_multi_world = 0
    decoy_variants = 0
    for entries in by_path.values():
        has_decoy = any(item.get("source") == "decoy" for item in entries)
        has_real_ok = any(
            item.get("source") == "upstream" and 200 <= int(item.get("upstream_status", 0)) < 300
            for item in entries
        )
        if has_decoy and has_real_ok:
            mixed_paths += 1
            if len({world_of(item) for item in entries}) > 1:
                mixed_multi_world += 1
        if has_decoy:
            if len({world_of(item) for item in entries if item.get("source") == "decoy"}) > 1:
                decoy_variants += 1

    skipped = collections.Counter()
    admitted_fallbacks = 0
    reuse = 0
    admitted_templates = set()
    for item in events:
        if item.get("type") == "defense_response":
            admitted_templates.add(str(item.get("template")))
        elif item.get("type") == "defense_template_reuse":
            reuse += 1
            admitted_templates.add(str(item.get("template")))
        elif item.get("type") == "defense_skipped":
            skipped[str(item.get("reason"))] += 1

    # A 404 on a route the application declares is an ordinary missing record,
    # and inventing one there is intended. What must never happen is inventing a
    # route the application says does not exist at all, because a single random
    # string then reveals the layer. Only the second kind is counted.
    declared_templates = {
        str(item.get("template"))
        for item in events
        if item.get("type") in {"defense_response", "defense_template_reuse"}
    }
    template_by_path = {
        (str(item.get("method")), str(item.get("path"))): str(item.get("template"))
        for item in events
        if item.get("type") in {"defense_response", "defense_template_reuse"}
    }
    undeclared_decoys = 0
    for item in exchanges:
        if item.get("source") != "decoy" or int(item.get("upstream_status", 0)) != 404:
            continue
        template = template_by_path.get((str(item.get("method")), str(item.get("path"))))
        if template is None or template not in declared_templates:
            undeclared_decoys += 1

    # A route that already answered with a generated response and later falls
    # back to the genuine refusal is the break that matters. Budget pressure
    # absorbed by reuse is not a break, so it is counted separately.
    for item in events:
        if item.get("type") != "defense_skipped":
            continue
        if str(item.get("reason")) not in {"template-budget", "trial-budget"}:
            continue
        if str(item.get("template")) in admitted_templates:
            admitted_fallbacks += 1

    closing = next((item for item in reversed(events) if item.get("type") == "gateway_closed"), {})
    return {
        "trial": directory.name,
        "objective_achieved": bool(result.get("objective_achieved")),
        "status": result.get("final_status"),
        "exchanges": len(exchanges),
        "decoys": sum(1 for item in exchanges if item.get("source") == "decoy"),
        "worlds": len({world_of(item) for item in exchanges}),
        "sessions": len({item.get("session_id") for item in exchanges}),
        "P1_paths_with_world_dependent_decoys": decoy_variants,
        "P2_paths_serving_decoy_and_genuine_success": mixed_paths,
        "P2_of_which_across_worlds": mixed_multi_world,
        "P3_consistency_breaks": admitted_fallbacks,
        "template_reuse": reuse,
        "reported_consistency_breaks": closing.get("defense_consistency_breaks"),
        "P3_skipped_reasons": dict(skipped),
        "P4_undeclared_not_found_decoys": undeclared_decoys,
        "deception_set": closing.get("deception_set"),
        "state_scope": closing.get("state_scope"),
    }


def analyse_run(run_dir: Path) -> dict[str, Any]:
    trials = run_dir / "trials"
    rows = []
    for directory in sorted(trials.iterdir()) if trials.is_dir() else []:
        row = analyse_trial(directory)
        if row is not None:
            rows.append(row)
    totals = {
        key: sum(int(row.get(key) or 0) for row in rows)
        for key in (
            "exchanges",
            "decoys",
            "P1_paths_with_world_dependent_decoys",
            "P2_paths_serving_decoy_and_genuine_success",
            "P2_of_which_across_worlds",
            "P4_undeclared_not_found_decoys",
        )
    }
    totals["P3_consistency_breaks"] = sum(
        int(row.get("P3_consistency_breaks") or 0) for row in rows
    )
    totals["template_reuse"] = sum(int(row.get("template_reuse") or 0) for row in rows)
    skipped: collections.Counter[str] = collections.Counter()
    for row in rows:
        skipped.update(row.get("P3_skipped_reasons") or {})
    return {
        "run": run_dir.name,
        "trials": len(rows),
        "successes": sum(1 for row in rows if row["objective_achieved"]),
        "median_worlds_per_trial": statistics.median([row["worlds"] for row in rows]) if rows else None,
        "median_sessions_per_trial": statistics.median([row["sessions"] for row in rows]) if rows else None,
        "totals": totals,
        "skipped_reasons": dict(skipped),
        "per_trial": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", nargs="+", required=True)
    parser.add_argument("--output")
    parsed = parser.parse_args()
    reports = []
    for name in parsed.run:
        run_dir = Path(name)
        if not run_dir.is_absolute() and not run_dir.exists():
            run_dir = EVALUATION_ROOT / name
        reports.append(analyse_run(run_dir))
    if parsed.output:
        Path(parsed.output).parent.mkdir(parents=True, exist_ok=True)
        Path(parsed.output).write_text(
            json.dumps(reports, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    header = (
        f"{'run':<40}{'시험':>4}{'성공':>4}{'교환':>8}{'기만':>7}"
        f"{'P1':>5}{'P2':>5}{'P2교차':>7}{'P3':>5}{'P4':>5}"
    )
    print(header)
    for report in reports:
        t = report["totals"]
        print(
            f"{report['run'][:39]:<40}{report['trials']:>4}{report['successes']:>4}"
            f"{t['exchanges']:>8}{t['decoys']:>7}"
            f"{t['P1_paths_with_world_dependent_decoys']:>5}"
            f"{t['P2_paths_serving_decoy_and_genuine_success']:>5}"
            f"{t['P2_of_which_across_worlds']:>7}"
            f"{t['P3_consistency_breaks']:>5}"
            f"{t['P4_undeclared_not_found_decoys']:>5}"
        )
    print()
    print("P1 세계에 따라 내용이 갈린 기만 경로, P2 기만과 실제 2xx를 함께 낸 경로")
    print("P2교차 그중 여러 세계에 걸친 것, P3 예산으로 기만이 끊긴 횟수, P4 404를 기만한 횟수")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
