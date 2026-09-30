"""Cookie observations for proxied HTTP requests; token state never blocks traffic."""

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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

COOKIE_NAME = "__ruby_tg"
LOGGER_NAME = "ruby.defense.token_gate"
DEFAULT_EXEMPT = ("/healthz", "/__defense/", "/__detection/")
_TOKEN = re.compile(r"v1\.([0-9]{1,12})\.([A-Za-z0-9_-]{22})")


def _configure_logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


@dataclass(frozen=True)
class TokenGateConfig:
    mode: str = "off"
    secret: bytes = b""
    epoch_s: int = 300
    grace_epochs: int = 1
    exempt_prefixes: tuple[str, ...] = DEFAULT_EXEMPT
    cookie_secure: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "TokenGateConfig":
        mode = environ.get("TOKEN_GATE_MODE", "off").strip().lower()
        if mode not in {"off", "observe", "enforce"}:
            raise ValueError("TOKEN_GATE_MODE must be off, observe or enforce")
        if mode == "off":
            return cls()
        try:
            epoch_s = int(environ.get("TOKEN_GATE_EPOCH_S", "300"))
            grace = int(environ.get("TOKEN_GATE_GRACE_EPOCHS", "1"))
        except ValueError as exc:
            raise ValueError("Token gate epoch and grace must be integers") from exc
        if epoch_s < 1 or not 0 <= grace <= 10:
            raise ValueError("Token gate requires epoch >= 1 and grace between 0 and 10")
        secure = environ.get("TOKEN_GATE_COOKIE_SECURE", "false").strip().lower()
        if secure not in {"true", "false"}:
            raise ValueError("TOKEN_GATE_COOKIE_SECURE must be true or false")
        exempt = tuple(
            item.strip()
            for item in environ.get("TOKEN_GATE_EXEMPT_PREFIXES", ",".join(DEFAULT_EXEMPT)).split(",")
            if item.strip()
        )
        secret = environ.get("TOKEN_GATE_SECRET", "").encode("utf-8")
        logger = _configure_logger()
        if mode == "enforce":
            logger.warning("TOKEN_GATE_MODE=enforce is deprecated; using observe (tokens never authorize or block requests)")
            mode = "observe"
        if not secret:
            secret = secrets.token_bytes(32)
            logger.warning("TOKEN_GATE_SECRET is empty; generated an ephemeral key (restart invalidates tokens)")
        return cls(mode, secret, epoch_s, grace, exempt, secure == "true")


def _mac(secret: bytes, payload: str) -> str:
    digest = hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")[:22]


def make_token(secret: bytes, epoch: int) -> str:
    payload = f"v1.{epoch}"
    return f"{payload}.{_mac(secret, payload)}"


def token_state(value: str | None, secret: bytes, now: float, cfg: TokenGateConfig) -> str:
    if value is None:
        return "missing"
    if len(value) > 64:
        return "invalid"
    match = _TOKEN.fullmatch(value)
    if match is None:
        return "invalid"
    epoch_text, mac = match.groups()
    if not hmac.compare_digest(mac, _mac(secret, f"v1.{epoch_text}")):
        return "invalid"
    age = math.floor(now / cfg.epoch_s) - int(epoch_text)
    if age < 0:
        return "invalid"
    if age == 0:
        return "valid"
    return "grace" if age <= cfg.grace_epochs else "stale"


def _normalized(headers: Mapping[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def classify(method: str, path: str, headers: Mapping[str, str], exempt: Sequence[str]) -> str:
    method = method.upper()
    if method == "OPTIONS" or any(
        path.startswith(item) if item.endswith("/") else path == item for item in exempt
    ):
        return "exempt"
    headers = _normalized(headers)
    if method in {"GET", "HEAD"} and (
        "text/html" in headers.get("accept", "").lower()
        or headers.get("sec-fetch-dest", "").lower() == "document"
        or headers.get("sec-fetch-mode", "").lower() == "navigate"
    ):
        return "page"
    return "api"


def ua_family(user_agent: str | None) -> str:
    if not user_agent:
        return "none"
    ua = user_agent.lower()
    for needle, family in (
        ("curl", "curl"), ("wget", "wget"), ("python-requests", "python-requests"),
        ("python-urllib", "python-urllib"), ("httpx", "httpx"), ("aiohttp", "aiohttp"),
        ("go-http-client", "go"), ("node", "node"), ("undici", "node"), ("mozilla", "browser"),
    ):
        if needle in ua:
            return family
    return "other"


@dataclass(frozen=True)
class GateDecision:
    kind: str
    token_state: str
    decision: str
    issue_cookie: bool = False


def evaluate(method, path, headers, cookie_value, now, cfg: TokenGateConfig) -> GateDecision:
    kind = classify(method, path, headers, cfg.exempt_prefixes)
    if cfg.mode == "off" or kind == "exempt":
        return GateDecision(kind, "missing", "pass")
    state = token_state(cookie_value, cfg.secret, now, cfg)
    if kind == "page":
        return GateDecision(kind, state, "pass" if state == "valid" else "issue",
                            issue_cookie=state != "valid")
    if state == "valid":
        return GateDecision(kind, state, "pass")
    if state == "grace":
        return GateDecision(kind, state, "refresh", issue_cookie=True)
    return GateDecision(kind, state, "observe")


def build_set_cookie(cfg: TokenGateConfig, now: float) -> str:
    epoch = math.floor(now / cfg.epoch_s)
    expires_at = (epoch + cfg.grace_epochs + 1) * cfg.epoch_s
    max_age = max(1, math.floor(expires_at - now))
    value = (f"{COOKIE_NAME}={make_token(cfg.secret, epoch)}; Path=/; HttpOnly; "
             f"SameSite=Lax; Max-Age={max_age}")
    return value + ("; Secure" if cfg.cookie_secure else "")


def observe_response(decision: GateDecision, method: str, status: int | None,
                     content_type: str) -> str | None:
    media_type = content_type.split(";", 1)[0].strip().lower()
    if (decision.kind == "page" and method.upper() == "GET" and status == 200
            and (media_type == "application/json" or media_type.endswith("+json"))):
        return "page_declared_json"
    return None


def build_log(decision: GateDecision, *, now: float, mode: str, method: str,
              path: str, headers: Mapping[str, str], upstream_status: int | None = None,
              observation: str | None = None) -> dict:
    headers = _normalized(headers)
    return {
        "event": "token_gate", "ts": now, "mode": mode,
        "client_id": headers.get("x-client-id"), "method": method, "path": path,
        "kind": decision.kind, "token_state": decision.token_state,
        "has_sec_fetch": any(key.startswith("sec-fetch-") for key in headers),
        "ua_family": ua_family(headers.get("user-agent")), "decision": decision.decision,
        "upstream_status": upstream_status, "observation": observation,
    }


def emit(log: dict) -> None:
    logging.getLogger(LOGGER_NAME).info(json.dumps(log, separators=(",", ":"), ensure_ascii=False))

