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
# Keep this expression in sync with CHeaT transforms.MAZE_DEFAULT_PATTERN.
# CHeaT can make a maze out of sensitive-looking files and paths well beyond
# its advertised roots. Otherwise an overlay actor could follow a generated
# maze link and unexpectedly arrive at the account overlay instead.
MAZE_DEFAULT_PATTERN = (
    r"^/(\.(git|env|svn|aws|ssh)|_?internal|admin|backup|backups|config|configs|"
    r"debug|private|secret|secrets|credentials|dump|db|database|management|"
    r"api/v[0-9]+/internal|\.well-known/security|"
    r"[\w.\-/]+\.(bak|old|orig|sql|ya?ml|env|ini|log|pem|key|json\.bak))"
    r"($|/|\?|\.)")
_MAZE_DEFAULT_RE = re.compile(MAZE_DEFAULT_PATTERN, re.I)
_MAZE_ROOT = re.compile(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")


def _parse_maze_root_choices(raw: str | None, target_ids, name: str) -> dict[str, tuple[str, ...]]:
    if not raw or not raw.strip():
        return {}
    allowed = set(target_ids)
    configured: dict[str, tuple[str, ...]] = {}
    for item in raw.split(","):
        target_id, separator, paths = item.strip().partition("=")
        roots = paths.split("|")
        normalized = tuple(root.lower() for root in roots)
        if (not separator or target_id not in allowed or target_id in configured
                or not roots or any(not _MAZE_ROOT.fullmatch(root) or
                                     any(segment in {".", ".."} for segment in root.split("/"))
                                     for root in roots)
                or len(set(normalized)) != len(normalized)):
            raise RuntimeError(f"{name} must contain valid id=/root entries")
        configured[target_id] = normalized
    return configured


def parse_maze_extra_roots(raw: str | None, target_ids) -> dict[str, tuple[str, ...]]:
    """Target-specific CHeaT preset entries, such as Apache's /server-status."""
    return _parse_maze_root_choices(raw, target_ids, "DECOY_MAZE_EXTRA_ROOT_CHOICES")


def parse_maze_excluded_roots(raw: str | None, target_ids) -> dict[str, tuple[str, ...]]:
    """Mirror sidecar MAZE_EXCLUDE roots that belong to the real application."""
    return _parse_maze_root_choices(raw, target_ids, "DECOY_MAZE_EXCLUDED_ROOT_CHOICES")


def is_maze_decoy_request(method: str, path: str, *, extra_roots=(), excluded_roots=()) -> bool:
    if method not in {"GET", "HEAD"}:
        return False
    candidate = path.lower().rstrip("/") or "/"
    if any(candidate == root or candidate.startswith(root + "/") for root in excluded_roots):
        return False
    return bool(_MAZE_DEFAULT_RE.match(candidate) or any(
        candidate == root or candidate.startswith(root + "/") or candidate.startswith(root + ".")
        for root in extra_roots
    ))


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
