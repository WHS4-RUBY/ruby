from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "dist",
    "evaluation",
    "node_modules",
}
EXCLUDED_PATHS = {
    "docs/stage1-baseline-manifest-20260830.json",
    "docs/stage2-local-gate-manifest-20260830.json",
    "docs/stage3-synthetic-local-gate-manifest-20260830.json",
    "docs/stage3-local-gate-manifest-20260830.json",
    "docs/stage3a-local-gate-manifest-20260830.json",
    "docs/stage3a-mid-validation-manifest-20260830.json",
    "docs/stage3a-derived-pairs-manifest-20260830.json",
    "docs/stage3a-second-synthetic-pairs-manifest-20260830.json",
    "docs/stage3a-seller-document-pair-manifest-20260830.json",
}


def main() -> int:
    aggregate = hashlib.sha256()
    entries: list[dict[str, str]] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        normalized = relative.as_posix()
        if normalized in EXCLUDED_PATHS:
            continue
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({"path": normalized, "sha256": digest})
    entries.sort(key=lambda item: item["path"])
    for item in entries:
        aggregate.update(item["path"].encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(item["sha256"].encode("ascii"))
        aggregate.update(b"\n")
    print(
        json.dumps(
            {
                "algorithm": "sha256(path_utf8 + NUL + file_sha256_ascii + LF)",
                "file_count": len(entries),
                "source_sha256": aggregate.hexdigest(),
                "files": entries,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
