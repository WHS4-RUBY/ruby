from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


TOOLS = Path(__file__).resolve().parents[1] / "app" / "tools"
sys.path.insert(0, str(TOOLS))

from check_stage3a_langflow_cve_pair import (  # noqa: E402
    inspect_running_image,
    pinned_reference,
)


DIGEST = "sha256:" + "a" * 64


def result(value: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["docker"],
        returncode=0,
        stdout=json.dumps(value),
        stderr="",
    )


def test_pinned_reference_removes_a_mutable_tag() -> None:
    assert pinned_reference("langflowai/langflow:1.2.0", DIGEST) == (
        f"langflowai/langflow@{DIGEST}"
    )
    assert pinned_reference("registry.local:5000/team/langflow:1.2.0", DIGEST) == (
        f"registry.local:5000/team/langflow@{DIGEST}"
    )


def test_pinned_reference_rejects_an_invalid_digest() -> None:
    with pytest.raises(ValueError, match="invalid Langflow image digest"):
        pinned_reference("langflowai/langflow:1.2.0", "sha256:short")


def test_running_image_must_match_the_pinned_linux_amd64_image() -> None:
    reference = f"langflowai/langflow@{DIGEST}"
    image = {
        "Id": "sha256:image-id",
        "RepoDigests": [reference],
        "Os": "linux",
        "Architecture": "amd64",
    }
    container = {"Image": "sha256:image-id"}

    with patch(
        "check_stage3a_langflow_cve_pair.docker",
        side_effect=[result([image]), result([container])],
    ):
        record = inspect_running_image("langflow-test", reference, DIGEST)

    assert record["digest_matches"] is True
    assert record["container_matches_image"] is True
    assert record["linux_amd64"] is True
    assert record["passed"] is True


def test_running_image_rejects_a_different_container_image() -> None:
    reference = f"langflowai/langflow@{DIGEST}"
    image = {
        "Id": "sha256:expected",
        "RepoDigests": [reference],
        "Os": "linux",
        "Architecture": "amd64",
    }
    container = {"Image": "sha256:different"}

    with patch(
        "check_stage3a_langflow_cve_pair.docker",
        side_effect=[result([image]), result([container])],
    ):
        record = inspect_running_image("langflow-test", reference, DIGEST)

    assert record["container_matches_image"] is False
    assert record["passed"] is False
