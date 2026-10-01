from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parent
REGISTRY_PATH = APP_ROOT / "configs" / "stage3a-autonomous-target-registry-v2.json"
CATALOG_PATH = APP_ROOT / "configs" / "stage3-vulnerability-module-catalog-v1.json"
V11_SOURCES = (
    PROJECT_ROOT / "ATTACKER_V11.md",
    APP_ROOT / "configs" / "stage3a-autonomous-web-attacker-profile-v11.json",
    APP_ROOT / "tools" / "attacker_strategy_v11.py",
)


def audit_v11_sources() -> dict[str, object]:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    forbidden: set[str] = set()
    for section in ("ruby_web_targets", "original_cve_targets"):
        for item in registry[section]:
            for key in ("target_id", "module_id", "cve_id", "product"):
                value = item.get(key)
                if isinstance(value, str) and len(value) >= 4:
                    forbidden.add(value.lower())
    for item in catalog.get("modules", []):
        request = item.get("request", {})
        path = request.get("path") if isinstance(request, dict) else None
        if isinstance(path, str) and len(path) > 1:
            forbidden.add(path.lower())

    findings: list[dict[str, object]] = []
    for path in V11_SOURCES:
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for literal in sorted(forbidden):
            if literal in lowered:
                findings.append(
                    {
                        "file": str(path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                        "kind": "target_literal",
                        "literal": literal,
                    }
                )
        if path.suffix == ".py":
            tree = ast.parse(text, filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                value = node.value
                if value.startswith("/") and len(value) > 1 and not value.startswith("//"):
                    findings.append(
                        {
                            "file": str(path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                            "kind": "hard_coded_route_literal",
                            "literal": value,
                            "line": node.lineno,
                        }
                    )
    return {
        "schema_version": 1,
        "audited_files": [
            str(path.relative_to(PROJECT_ROOT)).replace("\\", "/")
            for path in V11_SOURCES
        ],
        "target_specific_rule_findings": findings,
        "passed": not findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit v11 production inputs for target literals")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = audit_v11_sources()
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
