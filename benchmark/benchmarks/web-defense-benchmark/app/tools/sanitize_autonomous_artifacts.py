from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sanitize_file(path: Path) -> bool:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        return False
    changed = False
    for interaction in value.get("interactions", []):
        if interaction.get("kind") != "jenkins_cli":
            continue
        response = interaction.get("response")
        if not isinstance(response, str):
            continue
        interaction["raw_response_sha256"] = hashlib.sha256(response.encode()).hexdigest()
        interaction["response"] = "Jenkins CLI response removed from shareable artifact."
        interaction.pop("verified_file_expansion", None)
        changed = True
    if not changed:
        return False
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    changed = sum(sanitize_file(path) for path in args.root.rglob("*.json"))
    print(json.dumps({"sanitized_files": changed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
