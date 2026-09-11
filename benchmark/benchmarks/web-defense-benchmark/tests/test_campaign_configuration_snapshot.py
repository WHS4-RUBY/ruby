from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest


TOOLS = Path(__file__).resolve().parents[1] / "app" / "tools"
sys.path.insert(0, str(TOOLS))

from run_autonomous_campaign_v3 import (  # noqa: E402
    _append_configuration_history,
    _capture_configuration_snapshot,
    _configuration_changes,
    _ruby_image_prefix,
    _ruby_image_references,
    _verify_configuration_snapshot,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_ruby_image_references_use_the_configured_checkout_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RUBY_IMAGE_PREFIX", "ruby-web-defense-a1b2c3d4e5f6")

    references = _ruby_image_references()

    assert _ruby_image_prefix() == "ruby-web-defense-a1b2c3d4e5f6"
    assert references[0] == "ruby-web-defense-a1b2c3d4e5f6-api:latest"
    assert references[-1] == "ruby-web-defense-a1b2c3d4e5f6-redis:latest"
    assert len(references) == 8


def test_ruby_image_prefix_rejects_a_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RUBY_IMAGE_PREFIX", "../shared")

    with pytest.raises(ValueError, match="RUBY_IMAGE_PREFIX"):
        _ruby_image_references()


def fixture_seal(app_root: Path, inputs: tuple[Path, ...]) -> dict[str, object]:
    return {
        "seal_version": 1,
        "run_id": "configuration-test",
        "targets": ["ruby-web:sql-injection.product-search"],
        "providers": ["codex"],
        "conditions": ["undefended"],
        "repetitions": 1,
        "limits": {"wall_clock_seconds": 60},
        "sealed_inputs": {
            os.path.relpath(path.resolve(), app_root.resolve()).replace("\\", "/"): digest(
                path
            )
            for path in inputs
        },
    }


def test_snapshot_keeps_effective_settings_original_files_and_hashes(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    app_root = repository / "app"
    config = app_root / "configs" / "target.json"
    contract = repository / "contracts" / "target.schema.json"
    config.parent.mkdir(parents=True)
    contract.parent.mkdir(parents=True)
    config.write_text('{"mode":"vulnerable"}\n', encoding="utf-8")
    contract.write_text('{"type":"object"}\n', encoding="utf-8")
    inputs = (config, contract)
    seal = fixture_seal(app_root, inputs)
    output = tmp_path / "run"
    output.mkdir()

    manifest = _capture_configuration_snapshot(
        output, seal, inputs, app_root=app_root
    )

    assert manifest["effective_settings"]["conditions"] == ["undefended"]
    assert {
        item["source_path"]: item["sha256"] for item in manifest["files"]
    } == seal["sealed_inputs"]
    assert (
        output / "configuration-snapshot" / "inputs" / "app" / "configs" / "target.json"
    ).read_text(encoding="utf-8") == '{"mode":"vulnerable"}\n'
    assert (
        output
        / "configuration-snapshot"
        / "inputs"
        / "contracts"
        / "target.schema.json"
    ).is_file()
    _verify_configuration_snapshot(output, seal)

    history = [
        json.loads(line)
        for line in (output / "configuration-history.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert history[0]["event"] == "configuration-captured"
    assert history[0]["captured_input_count"] == 2
    assert len(history[0]["record_sha256"]) == 64


def test_configuration_changes_records_values_and_input_digests() -> None:
    sealed = {
        "run_id": "one",
        "repetitions": 1,
        "sealed_inputs": {"configs/one.json": "a" * 64},
    }
    observed = {
        "run_id": "one",
        "repetitions": 2,
        "sealed_inputs": {
            "configs/one.json": "b" * 64,
            "configs/two.json": "c" * 64,
        },
    }

    changes = _configuration_changes(sealed, observed)

    assert changes["setting_changes"] == [
        {"field": "repetitions", "sealed": 1, "observed": 2}
    ]
    assert changes["input_changes"] == [
        {
            "path": "configs/one.json",
            "sealed_sha256": "a" * 64,
            "observed_sha256": "b" * 64,
        },
        {
            "path": "configs/two.json",
            "sealed_sha256": None,
            "observed_sha256": "c" * 64,
        },
    ]


def test_snapshot_verification_rejects_a_changed_copy(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    app_root = repository / "app"
    config = app_root / "configs" / "target.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"mode":"safe"}\n', encoding="utf-8")
    seal = fixture_seal(app_root, (config,))
    output = tmp_path / "run"
    output.mkdir()
    _capture_configuration_snapshot(output, seal, (config,), app_root=app_root)
    copied = (
        output / "configuration-snapshot" / "inputs" / "app" / "configs" / "target.json"
    )
    copied.write_text('{"mode":"changed"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="digest mismatch"):
        _verify_configuration_snapshot(output, seal)


def test_snapshot_verification_rejects_changed_effective_settings(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    app_root = repository / "app"
    config = app_root / "configs" / "target.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"mode":"safe"}\n', encoding="utf-8")
    seal = fixture_seal(app_root, (config,))
    output = tmp_path / "run"
    output.mkdir()
    _capture_configuration_snapshot(output, seal, (config,), app_root=app_root)
    manifest_path = output / "configuration-snapshot" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["effective_settings"]["repetitions"] = 2
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="settings do not match"):
        _verify_configuration_snapshot(output, seal)


def test_history_appends_distinct_hashed_events(tmp_path: Path) -> None:
    output = tmp_path / "run"
    output.mkdir()
    first = _append_configuration_history(output, "captured", {"value": 1})
    second = _append_configuration_history(output, "resume-verified", {"value": 1})

    assert first["event_index"] == 0
    assert second["event_index"] == 1
    assert second["previous_record_sha256"] == first["record_sha256"]
    assert first["record_sha256"] != second["record_sha256"]
