"""Rotating path aliases for protected API prefixes (alias technique stage 2b)."""

import base64
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

LOGGER_NAME = "ruby.defense.path_alias"
DEFAULT_PREFIXES = ("/rest/", "/api/")
STALE_LOOKBACK_EPOCHS = 12
REWRITABLE_TYPES = frozenset({
    "text/html", "application/javascript", "text/javascript",
    "application/x-javascript", "application/json",
})
_ALIAS_PATH = re.compile(r"/(p[a-z2-7]{10})(/.*)?", re.S)


def _configure_logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def _parse_prefixes(raw: str) -> tuple[str, ...]:
    prefixes = []
    for item in raw.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if not (item.startswith("/") and item.endswith("/")) or item == "/":
            raise ValueError("PATH_ALIAS_PREFIXES entries must look like /name/")
        prefixes.append(item)
    if not prefixes:
        raise ValueError("PATH_ALIAS_PREFIXES must not be empty")
    # Longest first so nested prefixes such as /api/v2/ win over /api/.
    return tuple(sorted(set(prefixes), key=len, reverse=True))


@dataclass(frozen=True)
class PathAliasConfig:
    mode: str = "off"
    secret: bytes = b""
    epoch_s: int = 600
    grace_epochs: int = 1
    prefixes: tuple[str, ...] = DEFAULT_PREFIXES
    max_rewrite_bytes: int = 8 * 1024 * 1024

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "PathAliasConfig":
        mode = environ.get("PATH_ALIAS_MODE", "off").strip().lower()
        if mode not in {"off", "observe", "enforce"}:
            raise ValueError("PATH_ALIAS_MODE must be off, observe or enforce")
        if mode == "off":
            return cls()
        try:
            epoch_s = int(environ.get("PATH_ALIAS_EPOCH_S", "600"))
            grace = int(environ.get("PATH_ALIAS_GRACE_EPOCHS", "1"))
            max_bytes = int(environ.get("PATH_ALIAS_MAX_REWRITE_BYTES", str(8 * 1024 * 1024)))
        except ValueError as exc:
            raise ValueError("Path alias epoch, grace and size limit must be integers") from exc
        if epoch_s < 1 or not 0 <= grace <= 10 or max_bytes < 1:
            raise ValueError("Path alias requires epoch >= 1, grace 0..10 and a positive size limit")
        prefixes = _parse_prefixes(environ.get("PATH_ALIAS_PREFIXES", ",".join(DEFAULT_PREFIXES)))
        secret = environ.get("PATH_ALIAS_SECRET", "").encode("utf-8")
        logger = _configure_logger()
        if not secret:
            secret = secrets.token_bytes(32)
            logger.warning("PATH_ALIAS_SECRET is empty; generated an ephemeral key (restart invalidates aliases)")
        return cls(mode, secret, epoch_s, grace, prefixes, max_bytes)


@lru_cache(maxsize=512)
def alias_for(secret: bytes, epoch: int, prefix: str) -> str:
    digest = hmac.new(secret, f"alias|{epoch}|{prefix}".encode("ascii"), hashlib.sha256).digest()
    return "/p" + base64.b32encode(digest).decode("ascii").lower()[:10] + "/"


def current_aliases(cfg: PathAliasConfig, now: float) -> dict[str, str]:
    epoch = math.floor(now / cfg.epoch_s)
    return {prefix: alias_for(cfg.secret, epoch, prefix) for prefix in cfg.prefixes}


def _normalize(path: str) -> str:
    """Collapse the variants Express treats as the same route: case, //, . and .."""
    parts: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    normalized = "/" + "/".join(parts)
    if parts and path.endswith("/"):
        normalized += "/"
    return normalized.lower()


@dataclass(frozen=True)
class Resolution:
    kind: str  # alias | stale | direct | other
    upstream_path: str
    prefix: str | None = None
    alias_state: str | None = None  # current | grace | stale


def resolve(path: str, now: float, cfg: PathAliasConfig) -> Resolution:
    if cfg.mode == "off":
        return Resolution("other", path)
    match = _ALIAS_PATH.fullmatch(path)
    if match:
        segment = f"/{match.group(1)}/"
        rest = (match.group(2) or "/")[1:]
        epoch = math.floor(now / cfg.epoch_s)
        for age in range(cfg.grace_epochs + STALE_LOOKBACK_EPOCHS + 1):
            for prefix in cfg.prefixes:
                if hmac.compare_digest(alias_for(cfg.secret, epoch - age, prefix), segment):
                    state = "current" if age == 0 else "grace" if age <= cfg.grace_epochs else "stale"
                    return Resolution("stale" if state == "stale" else "alias", prefix + rest, prefix, state)
    normalized = _normalize(path)
    for prefix in cfg.prefixes:
        if normalized == prefix.rstrip("/") or normalized.startswith(prefix):
            return Resolution("direct", path, prefix)
    return Resolution("other", path)


def decide(resolution: Resolution, cfg: PathAliasConfig) -> str:
    if resolution.kind == "alias":
        return "translate"
    if resolution.kind in ("direct", "stale"):
        return "block" if cfg.mode == "enforce" else "would_block"
    return "pass"


def rewritable(content_type: str, content_encoding: str, status: int, method: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return (
        method.upper() != "HEAD"
        and status not in (204, 304)
        and content_encoding.strip().lower() in ("", "identity")
        and (media_type in REWRITABLE_TYPES or media_type.endswith("+json"))
    )


def _prefix_pattern(prefixes) -> re.Pattern:
    alternatives = b"|".join(re.escape(prefix.encode("ascii")) for prefix in prefixes)
    # A prefix glued to a host or segment (example.com/api/, /foo/rest/) is another URL and stays;
    # relative ./rest/ and template `${host}/rest/` are same-origin API paths and get rewritten.
    return re.compile(rb"(?<![A-Za-z0-9_\-])(" + alternatives + rb")", re.IGNORECASE)


def rewrite_body(body: bytes, aliases: Mapping[str, str]) -> tuple[bytes, int]:
    if not body or not aliases:
        return body, 0
    lookup = {prefix.lower(): alias.encode("ascii") for prefix, alias in aliases.items()}
    count = 0

    def replace(match: re.Match) -> bytes:
        nonlocal count
        count += 1
        return lookup[match.group(1).decode("ascii").lower()]

    return _prefix_pattern(sorted(aliases, key=len, reverse=True)).sub(replace, body), count


def rewrite_location(value: str, aliases: Mapping[str, str], public_host: str) -> str:
    parts = urlsplit(value)
    if parts.netloc and parts.netloc.lower() != public_host.lower():
        return value
    for prefix in sorted(aliases, key=len, reverse=True):
        if parts.path.lower().startswith(prefix):
            path = aliases[prefix] + parts.path[len(prefix):]
            return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
    return value


def build_log(resolution: Resolution, decision: str, *, now: float, mode: str, method: str,
              path: str, headers: Mapping[str, str], upstream_status: int | None = None,
              rewrites: int = 0, rewrite_skipped: str | None = None, ua_family: str = "none") -> dict:
    return {
        "event": "path_alias", "ts": now, "mode": mode,
        "client_id": {k.lower(): v for k, v in headers.items()}.get("x-client-id"),
        "method": method, "path": path, "real_path": resolution.upstream_path,
        "kind": resolution.kind, "alias_state": resolution.alias_state, "decision": decision,
        "upstream_status": upstream_status, "rewrites": rewrites,
        "rewrite_skipped": rewrite_skipped, "ua_family": ua_family,
    }


def emit(log: dict) -> None:
    logging.getLogger(LOGGER_NAME).info(json.dumps(log, separators=(",", ":"), ensure_ascii=False))
