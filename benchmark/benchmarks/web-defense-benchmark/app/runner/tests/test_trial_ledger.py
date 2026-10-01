from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from ruby_runner.ledger import TrialLedger, sha256_bytes


TRIAL_ID = "0123456789abcdef0123456789abcdef"


def test_completed_ledger_is_hash_chained_and_cannot_be_reused() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        ledger = TrialLedger.create(root, TRIAL_ID)
        ledger.artifact("reset-attestation.json", {"residue_count": 0})
        ledger.transition("running")
        ledger.transition("completed")
        manifest_path = ledger.seal()
        records = [
            json.loads(line)
            for line in (ledger.root / "run-ledger.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        previous = "sha256:" + "0" * 64
        for record in records:
            digest = record.pop("record_digest")
            assert record["previous_record_digest"] == previous
            assert digest == sha256_bytes(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            )
            previous = digest
        assert json.loads(manifest_path.read_text(encoding="utf-8"))["status"] == "completed"
        with pytest.raises(FileExistsError):
            TrialLedger.create(root, TRIAL_ID)


def test_failure_reason_and_prior_artifact_are_preserved() -> None:
    with tempfile.TemporaryDirectory() as directory:
        ledger = TrialLedger.create(Path(directory), TRIAL_ID)
        artifact = ledger.artifact("reset-attestation.json", {"state": "restored"})
        ledger.transition("failed", reason="injected local failure")
        ledger.seal()
        assert artifact.exists()
        state = json.loads((ledger.root / "trial-state.json").read_text(encoding="utf-8"))
        assert state["status"] == "failed"


def test_invalid_transition_and_artifact_path_are_rejected() -> None:
    with tempfile.TemporaryDirectory() as directory:
        ledger = TrialLedger.create(Path(directory), TRIAL_ID)
        with pytest.raises(ValueError, match="invalid trial transition"):
            ledger.transition("completed")
        with pytest.raises(ValueError, match="local JSON"):
            ledger.artifact("../escape.json", {})
