from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import hashlib
import json


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Budget:
    max_attempts: int
    max_time_ms: int
    max_tokens: int


@dataclass(frozen=True)
class RunManifest:
    schema_version: str
    run_id: str
    scenario_id: str
    attack_mode: str
    defense: str
    seed: int
    budget: Budget
    artifact_dir: Path
    artifact_sha256: dict[str, str]

    @classmethod
    def from_dict(cls, raw: dict[str, Any], base_dir: Path) -> "RunManifest":
        required = {
            "schema_version", "run_id", "scenario_id", "attack_mode",
            "defense", "seed", "budget", "artifact_dir", "artifact_sha256",
        }
        missing = required - raw.keys()
        if missing:
            raise ValidationError(f"manifest missing fields: {sorted(missing)}")
        if raw["schema_version"] != "0.2":
            raise ValidationError("unsupported schema_version")
        if raw["attack_mode"] not in {"fixed", "agent"}:
            raise ValidationError("attack_mode must be fixed or agent")
        if raw["defense"] not in {"baseline", "defended"}:
            raise ValidationError("defense must be baseline or defended")
        try:
            budget = Budget(**raw["budget"])
        except (TypeError, AttributeError) as exc:
            raise ValidationError("budget must contain max_attempts, max_time_ms, and max_tokens") from exc
        if min(budget.max_attempts, budget.max_time_ms, budget.max_tokens) <= 0:
            raise ValidationError("all budget values must be positive")
        artifact_value = Path(raw["artifact_dir"])
        if artifact_value.is_absolute():
            raise ValidationError("artifact_dir must be relative to the manifest")
        artifact_dir = (base_dir / artifact_value).resolve()
        manifest_root = base_dir.resolve()
        if artifact_dir != manifest_root and manifest_root not in artifact_dir.parents:
            raise ValidationError("artifact_dir escapes the manifest directory")
        artifact_hashes = raw["artifact_sha256"]
        expected_files = {"state.json", "events.jsonl", "usage.json", "controls.json"}
        if not isinstance(artifact_hashes, dict) or set(artifact_hashes) != expected_files:
            raise ValidationError(f"artifact_sha256 must contain exactly {sorted(expected_files)}")
        if any(not isinstance(value, str) or len(value) != 64 for value in artifact_hashes.values()):
            raise ValidationError("artifact SHA-256 values must be 64-character strings")
        return cls(
            schema_version=raw["schema_version"],
            run_id=str(raw["run_id"]),
            scenario_id=str(raw["scenario_id"]),
            attack_mode=raw["attack_mode"],
            defense=raw["defense"],
            seed=int(raw["seed"]),
            budget=budget,
            artifact_dir=artifact_dir,
            artifact_sha256=artifact_hashes,
        )


@dataclass(frozen=True)
class OracleResult:
    name: str
    compromised: bool
    valid: bool
    evidence: str


@dataclass(frozen=True)
class GradedRun:
    manifest: RunManifest
    compromised: bool
    oracle_results: tuple[OracleResult, ...]
    attempted: bool
    blocked_attempts: int
    attempts: int
    elapsed_ms: int
    tokens: int
    benign_total: int
    benign_success: int
    benign_latencies_ms: tuple[int, ...]

    @property
    def benign_success_rate(self) -> float:
        return self.benign_success / self.benign_total if self.benign_total else 0.0


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read valid JSON from {path}: {exc}") from exc


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ValidationError(f"cannot hash artifact {path}: {exc}") from exc
    return digest.hexdigest()
