"""Read the active upstream from a small, atomically replaced selection file.

Only URLs configured by the operator are eligible. The selection file contains
an ID and experiment metadata, never a URL supplied by an HTTP client.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
from typing import Mapping
from urllib.parse import urlsplit
import uuid


# 경계값은 shared/target-selection.json 의 선언과 같아야 한다 —
# defense/tests/test_target_selection_contract.py 가 강제한다.
_TARGET_ID = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_MAX_SELECTION_BYTES = 8192


class TargetSelectionError(RuntimeError):
    """The selection cannot be trusted, so forwarding must stop."""


def resolve_target_url(env=None) -> str:
    """Build the legacy upstream URL from TARGET_HOST and TARGET_PORT."""
    env = os.environ if env is None else env
    host = (env.get("TARGET_HOST") or "").strip() or "localhost"
    raw_port = (env.get("TARGET_PORT") or "").strip() or "9000"
    try:
        port = int(raw_port)
    except ValueError:
        raise RuntimeError(f"TARGET_PORT must be an integer, got {raw_port!r}") from None
    if not 1 <= port <= 65535:
        raise RuntimeError(f"TARGET_PORT must be between 1 and 65535, got {port}")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # bare IPv6 literal
    return f"http://{host}:{port}"


def _is_canonical_uuid(value) -> bool:
    """Detection 은 crypto.randomUUID() 만 쓴다. 헤더 경로도 이미 이 규칙이다."""
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value


def _is_iso_timestamp(value) -> bool:
    """Detection 은 Date.toISOString() 만 쓴다. 길이만 보면 'now' 도 통과했다."""
    if not isinstance(value, str) or not value:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _validate_url(value: str) -> str:
    url = value.strip()
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("TARGET_CHOICES contains an invalid URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(char.isspace() for char in url)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise RuntimeError("TARGET_CHOICES must contain HTTP(S) upstream URLs without credentials or query strings")
    return url.rstrip("/")


@dataclass(frozen=True)
class SelectedTarget:
    target_id: str
    url: str
    run_id: str | None
    changed_at: str | None

    def public_metadata(self) -> dict[str, str | None]:
        return {
            "targetId": self.target_id,
            "runId": self.run_id,
            "changedAt": self.changed_at,
        }


class TargetSelector:
    def __init__(self, choices: dict[str, str], default_id: str, selection_file: str | None):
        if not choices or default_id not in choices:
            raise RuntimeError("TARGET_DEFAULT_ID must name a configured TARGET_CHOICES entry")
        for target_id, url in choices.items():
            if not _TARGET_ID.fullmatch(target_id):
                raise RuntimeError("TARGET_CHOICES contains an invalid target ID")
            _validate_url(url)
        self.choices = {key: _validate_url(value) for key, value in choices.items()}
        self.default_id = default_id
        self.selection_file = Path(selection_file) if selection_file else None

    @classmethod
    def from_environment(cls, env=None) -> "TargetSelector":
        env = os.environ if env is None else env
        raw_choices = (env.get("TARGET_CHOICES") or "").strip()
        if raw_choices:
            choices = {}
            for entry in raw_choices.split(","):
                target_id, separator, url = entry.strip().partition("=")
                if not separator or target_id in choices:
                    raise RuntimeError("TARGET_CHOICES must contain unique id=url entries")
                choices[target_id] = url
        else:
            choices = {"legacy": resolve_target_url(env)}
        return cls(
            choices,
            (env.get("TARGET_DEFAULT_ID") or "legacy").strip(),
            (env.get("TARGET_SELECTION_FILE") or "").strip() or None,
        )

    def current(self) -> SelectedTarget:
        if self.selection_file is None:
            return SelectedTarget(self.default_id, self.choices[self.default_id], None, None)
        try:
            with self.selection_file.open("rb") as selection:
                content = selection.read(_MAX_SELECTION_BYTES + 1)
        except FileNotFoundError:
            return SelectedTarget(self.default_id, self.choices[self.default_id], None, None)
        except OSError as exc:
            raise TargetSelectionError("target selection is unreadable") from exc
        if len(content) > _MAX_SELECTION_BYTES:
            raise TargetSelectionError("target selection is too large")
        try:
            value = json.loads(content)
        except (UnicodeDecodeError, ValueError) as exc:
            raise TargetSelectionError("target selection is malformed") from exc
        if not isinstance(value, dict):
            raise TargetSelectionError("target selection is malformed")
        target_id = value.get("targetId")
        run_id = value.get("runId")
        changed_at = value.get("changedAt")
        if not isinstance(target_id, str) or target_id not in self.choices:
            raise TargetSelectionError("target selection is outside the configured allowlist")
        if not _is_canonical_uuid(run_id):
            raise TargetSelectionError("target selection has an invalid run ID")
        if not _is_iso_timestamp(changed_at):
            raise TargetSelectionError("target selection has an invalid timestamp")
        return SelectedTarget(target_id, self.choices[target_id], run_id, changed_at)

    def for_request(self, headers: Mapping[str, str]) -> SelectedTarget:
        """Use Detection's request snapshot when present, otherwise current state.

        Detection strips client-provided copies of these headers before setting
        its own. The ID still resolves only through the operator allowlist.
        """
        target_id = headers.get("x-ruby-target-id")
        run_id = headers.get("x-ruby-run-id")
        if target_id is None and run_id is None:
            return self.current()
        if not isinstance(target_id, str) or target_id not in self.choices:
            raise TargetSelectionError("request target is outside the configured allowlist")
        if not _is_canonical_uuid(run_id):
            raise TargetSelectionError("request run ID is invalid")
        return SelectedTarget(target_id, self.choices[target_id], run_id, None)


target_selector = TargetSelector.from_environment()
