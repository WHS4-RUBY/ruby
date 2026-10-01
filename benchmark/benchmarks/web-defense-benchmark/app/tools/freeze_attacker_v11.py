from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from audit_attacker_v11_sources import audit_v11_sources


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parent
FROZEN_PATHS = (
    PROJECT_ROOT / "ATTACKER_V11.md",
    APP_ROOT / "configs" / "stage3a-autonomous-web-attacker-profile-v11.json",
    APP_ROOT / "configs" / "attacker-v11-qualification-cohort-v1.json",
    APP_ROOT / "configs" / "stage3a-autonomous-target-registry-v2.json",
    APP_ROOT / "configs" / "stage3a-attacker-action-v2.schema.json",
    APP_ROOT / "tools" / "attacker_strategy_v11.py",
    APP_ROOT / "tools" / "autonomous_trial_v2.py",
    APP_ROOT / "tools" / "autonomous_experiment_v2.py",
    APP_ROOT / "tools" / "autonomous_cli_policy_v2.py",
    APP_ROOT / "tools" / "autonomous_target_adapters_v2.py",
    APP_ROOT / "tools" / "autonomous_cve_target_adapters_v3.py",
    APP_ROOT / "tools" / "run_autonomous_campaign_v3.py",
    APP_ROOT / "tools" / "evaluate_attacker_v11_qualification.py",
    APP_ROOT / "tools" / "audit_attacker_v11_sources.py",
    APP_ROOT / "tools" / "generate_attacker_v11_variants.py",
    APP_ROOT / "tools" / "freeze_attacker_v11.py",
    APP_ROOT / "tools" / "run_attacker_v11_qualification.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def frozen_mismatches(seal: dict[str, object]) -> list[str]:
    values = seal.get("frozen_files")
    if not isinstance(values, dict):
        return ["freeze seal has no frozen_files object"]
    mismatches = []
    for relative, expected in values.items():
        path = (PROJECT_ROOT / str(relative)).resolve()
        if not path.is_file():
            mismatches.append(f"missing:{relative}")
        elif _sha256(path) != str(expected):
            mismatches.append(f"sha256:{relative}")
    return sorted(mismatches)


def build_freeze_seal() -> dict[str, object]:
    audit = audit_v11_sources()
    if not audit["passed"]:
        raise ValueError("target-specific rule audit did not pass")
    return {
        "schema_version": 1,
        "freeze_id": f"attacker-v11-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}",
        "profile_id": "ruby-stage3a-autonomous-web-attacker-v11",
        "frozen_at": datetime.now(UTC).isoformat(),
        "target_specific_rule_audit": audit,
        "frozen_files": {
            str(path.relative_to(PROJECT_ROOT)).replace("\\", "/"): _sha256(path)
            for path in FROZEN_PATHS
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze attacker v11 before hidden variants")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite freeze seal: {args.output}")
    value = build_freeze_seal()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(value["freeze_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
