from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from validate_manifest import validate_manifest  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate every RUBY scenario completion contract."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        type=Path,
        default=PROJECT_ROOT / "app" / "configs" / "scenario-contracts",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = sorted(args.directory.glob("*.json"))
    if not paths:
        print(f"no scenario contracts: {args.directory}", file=sys.stderr)
        return 2

    findings: list[str] = []
    seen: dict[str, set[str]] = {
        "scenario_id": set(),
        "module_id": set(),
        "protected_resource_key": set(),
    }
    for path in paths:
        try:
            contract = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            findings.append(f"{path.name}: {error}")
            continue
        for finding in validate_manifest("scenario-completion", contract):
            findings.append(f"{path.name}: {finding}")
        values = {
            "scenario_id": contract.get("scenario_id"),
            "module_id": contract.get("module_id"),
            "protected_resource_key": contract.get("objective", {}).get(
                "protected_resource_key"
            ),
        }
        for field, value in values.items():
            if value in seen[field]:
                findings.append(f"{path.name}: duplicate {field}: {value}")
            if value is not None:
                seen[field].add(value)

    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 2
    print(f"valid scenario contracts: {len(paths)} files in {args.directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
