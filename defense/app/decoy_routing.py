"""Optional private CHeaT proxy routes for the selected benchmark target."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from .target_selection import _TARGET_ID, _validate_url


DECOY_STRATEGIES = frozenset({
    "maze", "decoy_maze", "decoy_t21_shell", "decoy_migration",
})
_ACTION = re.compile(r"[a-z0-9][a-z0-9:!_-]{0,63}\Z")
ACTION_HEADER = "x-ruby-decoy-action"
STRATEGIES_HEADER = "x-ruby-decoy-strategies"
BLOCK_ACTIONS = frozenset({"ambig-block", "post-rce-block"})


def parse_decoy_upstreams(raw: str | None, target_ids) -> dict[str, str]:
    """Validate a fixed map, then use entries enabled in this deployment."""
    if not raw or not raw.strip():
        return {}
    allowed = set(target_ids)
    configured: dict[str, str] = {}
    for item in raw.split(","):
        target_id, separator, url = item.strip().partition("=")
        if not separator or not _TARGET_ID.fullmatch(target_id) or target_id in configured:
            raise RuntimeError("DECOY_UPSTREAM_CHOICES must contain unique valid id=url entries")
        origin = _validate_url(url)
        parsed = urlsplit(origin)
        if parsed.path not in {"", "/"}:
            raise RuntimeError("DECOY_UPSTREAM_CHOICES URLs must be HTTP(S) origins without paths")
        configured[target_id] = origin
    if len(set(configured.values())) != len(configured):
        raise RuntimeError("Each DECOY_UPSTREAM_CHOICES target must have a separate proxy origin")
    return {target_id: origin for target_id, origin in configured.items() if target_id in allowed}


def decoy_plan(plan: list[dict]) -> list[dict]:
    """Never ask the sidecar to repeat official Defense delay or rate limiting."""
    return [step for step in plan if step["name"] in DECOY_STRATEGIES]


def decoy_plan_header(plan: list[dict]) -> str:
    return json.dumps(decoy_plan(plan), separators=(",", ":"))


def decoy_action(headers) -> str | None:
    raw = headers.get(ACTION_HEADER)
    return raw if isinstance(raw, str) and _ACTION.fullmatch(raw) else None


def applied_decoy_strategies(headers) -> list[str]:
    """Use the sidecar's applied set, including sticky plans from earlier requests."""
    raw = headers.get(STRATEGIES_HEADER, "")
    if not isinstance(raw, str) or len(raw) > 256:
        return []
    result = []
    for name in raw.split(","):
        name = name.strip()
        if name in DECOY_STRATEGIES and name not in result:
            result.append(name)
    return result
