"""Copy the defense source into a run directory and record its hashes.

The defense package lives outside version control, and it has been edited
between runs. Without a copy taken at launch time a result cannot be tied back
to the code that produced it. This module takes that copy and writes a
manifest, so every run carries its own defense source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_version(package_dir: Path) -> str | None:
    for init in sorted((package_dir / "src").rglob("__init__.py")):
        for line in init.read_text(encoding="utf-8").splitlines():
            if line.startswith("__version__"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def snapshot(run_dir: Path, package_dir: Path) -> dict[str, Any]:
    """Copy the defense sources into run_dir/defense-source and hash them.

    A run that is stopped and resumed keeps the seal it started with. The
    runner re-seals on every start, and one run resumed four times across two
    defense versions ended up labelled with the last of them while trials
    finished earlier had been produced by the first. Nothing in the record said
    so, and the run read as a clean comparison.

    So a seal is written once. A later call reports whether the working tree has
    moved on and which files differ, and leaves the seal alone.
    """

    target = run_dir / "defense-source"
    target.mkdir(parents=True, exist_ok=True)
    existing_path = target / "manifest.json"
    existing: dict[str, Any] | None = None
    if existing_path.is_file():
        try:
            existing = json.loads(existing_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = None

    files: dict[str, str] = {}
    fresh = existing is None
    source_root = package_dir / "src"
    if not source_root.is_dir():
        raise FileNotFoundError(f"defense package has no src directory: {package_dir}")
    for source in sorted(source_root.rglob("*.py")):
        relative = source.relative_to(package_dir)
        if fresh:
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        files[relative.as_posix()] = _sha256(source)
    for name in ("README.md", "docs/connection-points.md"):
        source = package_dir / name
        if source.is_file():
            if fresh:
                shutil.copy2(source, target / Path(name).name)
            files[name] = _sha256(source)

    combined = hashlib.sha256()
    for name in sorted(files):
        combined.update(name.encode("utf-8"))
        combined.update(files[name].encode("utf-8"))

    if existing is not None:
        sealed_files = existing.get("file_sha256") or {}
        moved = sorted(
            name for name in set(files) | set(sealed_files)
            if files.get(name) != sealed_files.get(name)
        )
        if moved:
            existing["source_moved_on"] = True
            existing["files_differing_now"] = moved
            existing["checked_again_at"] = datetime.now(timezone.utc).isoformat()
            existing_path.write_text(
                json.dumps(existing, ensure_ascii=False, indent=2) + chr(10),
                encoding="utf-8",
            )
        else:
            existing["source_moved_on"] = False
        return existing

    manifest = {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "package_version": package_version(package_dir),
        "package_dir": str(package_dir),
        "file_sha256": files,
        "combined_sha256": combined.hexdigest(),
        "note": (
            "The defense package is not under version control. This copy is the "
            "authoritative record of the code that produced this run."
        ),
    }
    (target / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--package-dir", required=True)
    parsed = parser.parse_args()
    manifest = snapshot(Path(parsed.run_dir), Path(parsed.package_dir))
    print(
        json.dumps(
            {
                "package_version": manifest["package_version"],
                "files": len(manifest["file_sha256"]),
                "combined_sha256": manifest["combined_sha256"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
