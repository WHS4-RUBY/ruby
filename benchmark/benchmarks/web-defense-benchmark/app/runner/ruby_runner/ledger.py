from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


STATUS_TRANSITIONS = {
    "preparing": {"running", "failed", "cancelled"},
    "running": {"completed", "failed", "cancelled"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def atomic_write(path: Path, value: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(value)
    os.replace(temporary, path)


@dataclass
class TrialLedger:
    root: Path
    trial_id: str
    status: str = "preparing"
    sequence_number: int = 0
    previous_record_digest: str = "sha256:" + "0" * 64

    @classmethod
    def create(cls, output_root: Path, trial_id: str) -> "TrialLedger":
        if len(trial_id) != 32 or any(character not in "0123456789abcdef" for character in trial_id):
            raise ValueError("trial_id must contain exactly 32 lowercase hexadecimal characters")
        root = output_root / trial_id
        root.mkdir(parents=True, exist_ok=False)
        ledger = cls(root=root, trial_id=trial_id)
        ledger._append("trial-created", {"status": "preparing"})
        ledger._write_state()
        return ledger

    def _append(self, event_type: str, payload: dict[str, object]) -> None:
        self.sequence_number += 1
        record_without_digest = {
            "event_type": event_type,
            "payload": payload,
            "previous_record_digest": self.previous_record_digest,
            "recorded_at": datetime.now(UTC).isoformat(),
            "sequence_number": self.sequence_number,
            "trial_id": self.trial_id,
        }
        digest = sha256_bytes(canonical_bytes(record_without_digest))
        record = {**record_without_digest, "record_digest": digest}
        with (self.root / "run-ledger.jsonl").open("ab") as stream:
            stream.write(canonical_bytes(record) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.previous_record_digest = digest

    def _write_state(self) -> None:
        atomic_write(
            self.root / "trial-state.json",
            canonical_bytes(
                {
                    "last_record_digest": self.previous_record_digest,
                    "sequence_number": self.sequence_number,
                    "status": self.status,
                    "trial_id": self.trial_id,
                }
            ),
        )

    def transition(self, status: str, *, reason: str | None = None) -> None:
        if status not in STATUS_TRANSITIONS[self.status]:
            raise ValueError(f"invalid trial transition: {self.status} -> {status}")
        previous = self.status
        self.status = status
        payload: dict[str, object] = {"from": previous, "to": status}
        if reason is not None:
            payload["reason"] = reason
        self._append("trial-status", payload)
        self._write_state()

    def artifact(self, name: str, value: object) -> Path:
        if not name.endswith(".json") or Path(name).name != name:
            raise ValueError("artifact name must be one local JSON file")
        path = self.root / name
        if path.exists():
            raise FileExistsError(f"refusing to overwrite artifact: {name}")
        content = canonical_bytes(value)
        atomic_write(path, content)
        self._append(
            "artifact-written",
            {"name": name, "sha256": sha256_bytes(content), "size_bytes": len(content)},
        )
        self._write_state()
        return path

    def seal(self) -> Path:
        if self.status not in {"completed", "failed", "cancelled"}:
            raise ValueError("only a terminal trial can be sealed")
        entries = []
        for path in sorted(self.root.iterdir(), key=lambda item: item.name):
            if not path.is_file() or path.name == "artifact-manifest.json":
                continue
            content = path.read_bytes()
            entries.append(
                {"name": path.name, "sha256": sha256_bytes(content), "size_bytes": len(content)}
            )
        manifest = {
            "files": entries,
            "status": self.status,
            "trial_id": self.trial_id,
        }
        path = self.root / "artifact-manifest.json"
        atomic_write(path, canonical_bytes(manifest))
        return path
