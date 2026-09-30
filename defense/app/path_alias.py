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
from urllib.parse import unquote, urlsplit, urlunsplit

LOGGER_NAME = "ruby.defense.path_alias"
DEFAULT_PREFIXES = ("/rest/", "/api/")
STALE_LOOKBACK_EPOCHS = 12
FUTURE_SKEW_EPOCHS = 1  # accept aliases from an instance whose clock is one epoch ahead
MIN_SECRET_BYTES = 16
REWRITABLE_TYPES = frozenset({
    "text/html", "application/javascript", "text/javascript",
    "application/x-javascript", "application/json",
})
# Long, app-unlikely namespace so generated aliases cannot collide with a real
# app route (Codex review #2): 16 base32 chars = 80 bits under a reserved marker.
_ALIAS_MARKER = "__ruby_alias_"
_ALIAS_PATH = re.compile(r"/" + re.escape(_ALIAS_MARKER) + r"([a-z2-7]{16})(/.*)?", re.S)


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
        if not item.isascii():
            raise ValueError("PATH_ALIAS_PREFIXES entries must be ASCII")
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
    app_id: str = ""  # mixed into the alias so reusing one secret across apps yields different aliases

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
        app_id = environ.get("PATH_ALIAS_APP_ID", "").strip()
        if not app_id.isascii():
            raise ValueError("PATH_ALIAS_APP_ID must be ASCII")
        secret = environ.get("PATH_ALIAS_SECRET", "").encode("utf-8")
        logger = _configure_logger()
        if secret and len(secret) < MIN_SECRET_BYTES:
            raise ValueError(f"PATH_ALIAS_SECRET must be at least {MIN_SECRET_BYTES} bytes")
        if not secret:
            # enforce blocks requests, so a stable, strong key is mandatory; observe only logs.
            if mode == "enforce":
                raise ValueError("PATH_ALIAS_SECRET is required when PATH_ALIAS_MODE=enforce")
            secret = secrets.token_bytes(32)
            logger.warning("PATH_ALIAS_SECRET is empty; generated an ephemeral key "
                           "(restart invalidates aliases; not shared across processes)")
        return cls(mode, secret, epoch_s, grace, prefixes, max_bytes, app_id)


@lru_cache(maxsize=512)
def alias_for(secret: bytes, app_id: str, epoch: int, prefix: str) -> str:
    material = f"alias|{app_id}|{epoch}|{prefix}".encode("ascii")
    digest = hmac.new(secret, material, hashlib.sha256).digest()
    return "/" + _ALIAS_MARKER + base64.b32encode(digest).decode("ascii").lower()[:16] + "/"


def current_aliases(cfg: PathAliasConfig, now: float) -> dict[str, str]:
    epoch = math.floor(now / cfg.epoch_s)
    return {prefix: alias_for(cfg.secret, cfg.app_id, epoch, prefix) for prefix in cfg.prefixes}


def _normalize(path: str) -> str:
    """Conservatively fold every variant some backend might route to the same path.

    Over-blocking is intended (finding #2 decision): a memorized real path must not
    slip past direct-detection by re-encoding it, even if that means the occasional
    benign lookalike is refused. The observe-mode validation is what catches those.
    Covers case, % -encoding (incl. %2f, %2e), backslash separators, // , . , .. ,
    and trailing dot/space folding.
    """
    decoded = unquote(path).replace("\\", "/")
    parts: list[str] = []
    for segment in decoded.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        segment = segment.rstrip(". ")  # IIS/Windows fold "rest." and "rest " to "rest"
        if not segment:
            continue
        parts.append(segment)
    normalized = "/" + "/".join(parts)
    if parts and (decoded.endswith("/") or path.endswith("/")):
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
        segment = f"/{_ALIAS_MARKER}{match.group(1)}/"
        rest = (match.group(2) or "/")[1:]
        epoch = math.floor(now / cfg.epoch_s)
        # age < 0 covers an instance whose clock is a little behind the one that issued it.
        for age in range(-FUTURE_SKEW_EPOCHS, cfg.grace_epochs + STALE_LOOKBACK_EPOCHS + 1):
            for prefix in cfg.prefixes:
                if hmac.compare_digest(alias_for(cfg.secret, cfg.app_id, epoch - age, prefix), segment):
                    state = "current" if age <= 0 else "grace" if age <= cfg.grace_epochs else "stale"
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
