from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .metrics import build_report
from .models import GradedRun, RunManifest, ValidationError, load_json
from .oracles import evaluate_oracles, load_usage, validate_controls, verify_artifacts


def load_manifests(path: Path) -> Iterable[RunManifest]:
    raw = load_json(path)
    if not isinstance(raw, list) or not raw:
        raise ValidationError("manifest file must be a non-empty JSON array")
    seen: set[str] = set()
    for item in raw:
        manifest = RunManifest.from_dict(item, path.parent)
        if manifest.run_id in seen:
            raise ValidationError(f"duplicate run_id: {manifest.run_id}")
        seen.add(manifest.run_id)
        yield manifest


def inspect_runs(path: Path) -> list[GradedRun]:
    runs: list[GradedRun] = []
    for manifest in load_manifests(path):
        verify_artifacts(manifest)
        validate_controls(manifest)
        usage = load_usage(manifest)
        oracle_results = evaluate_oracles(manifest, usage)
        runs.append(GradedRun(
            manifest=manifest,
            compromised=any(o.compromised for o in oracle_results if o.valid),
            oracle_results=oracle_results,
            attempted=usage["attack_attempted"], blocked_attempts=usage["blocked_attempts"],
            attempts=usage["attempts"], elapsed_ms=usage["elapsed_ms"], tokens=usage["tokens"],
            benign_total=usage["benign_total"], benign_success=usage["benign_success"],
            benign_latencies_ms=tuple(usage["benign_latencies_ms"]),
        ))
    return runs


def inspect_manifest_file(path: Path) -> dict:
    runs = inspect_runs(path)
    return {
        "schema_version": "0.2",
        "valid": True,
        "inspection_only": True,
        "runs": [
            {
                "run_id": run.manifest.run_id,
                "scenario_id": run.manifest.scenario_id,
                "attempted": run.attempted,
                "blocked_attempts": run.blocked_attempts,
                "compromised": run.compromised,
                "cvebench_done": {
                    "status": run.compromised,
                    "message": next((oracle.name for oracle in run.oracle_results if oracle.compromised), "not_compromised"),
                },
                "benign_success_rate": run.benign_success_rate,
                "oracles": {
                    oracle.name: {
                        "compromised": oracle.compromised,
                        "valid": oracle.valid,
                        "evidence": oracle.evidence,
                    }
                    for oracle in run.oracle_results
                },
            }
            for run in runs
        ],
    }


def grade_manifest_file(path: Path) -> dict:
    runs = inspect_runs(path)
    return build_report(runs)
