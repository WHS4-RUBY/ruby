"""Defense dashboard routes and authentication boundary."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel
from starlette.responses import Response

from .dashboard_auth import (
    DashboardAuthManager,
    InvalidCredentialsError,
    LoginRateLimitedError,
)
from .monitoring import event_store
from .overlay_routing import OVERLAY_NAMES
from .strategies.registry import STRATEGY_REGISTRY
from . import target_selection
from .target_selection import TargetSelectionError

DASHBOARD_SESSION_COOKIE = "defense_dashboard_session"
DASHBOARD_SESSION_TTL_SECONDS = 12 * 60 * 60
DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), "public", "dashboard.html")


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


DASHBOARD_COOKIE_SECURE = os.getenv("DEFENSE_DASHBOARD_COOKIE_SECURE", "false").lower() == "true"
DASHBOARD_REQUIRE_HTTPS = os.getenv("DEFENSE_DASHBOARD_REQUIRE_HTTPS", "false").lower() == "true"
ALLOW_INSECURE_DASHBOARD_HTTP = os.getenv("ALLOW_INSECURE_DASHBOARD_HTTP", "false").lower() == "true"
if os.getenv("RUBY_ENV") == "production":
    if not os.getenv("DEFENSE_DASHBOARD_PASSWORD"):
        raise RuntimeError("DEFENSE_DASHBOARD_PASSWORD is required in production")
    if ALLOW_INSECURE_DASHBOARD_HTTP and (DASHBOARD_COOKIE_SECURE or DASHBOARD_REQUIRE_HTTPS):
        raise RuntimeError("HTTP dashboard mode requires HTTPS enforcement and Secure cookies to be disabled")
    if not ALLOW_INSECURE_DASHBOARD_HTTP and (not DASHBOARD_COOKIE_SECURE or not DASHBOARD_REQUIRE_HTTPS):
        raise RuntimeError("production dashboard authentication requires HTTPS and Secure cookies")
auth_manager = DashboardAuthManager(
    password=os.getenv("DEFENSE_DASHBOARD_PASSWORD", ""),
    session_ttl_seconds=DASHBOARD_SESSION_TTL_SECONDS,
    max_sessions=_positive_int("DEFENSE_DASHBOARD_MAX_SESSIONS", 1000),
    max_attempts=_positive_int("DEFENSE_DASHBOARD_LOGIN_ATTEMPTS", 5),
    attempt_window_seconds=_positive_int("DEFENSE_DASHBOARD_LOGIN_WINDOW_SECONDS", 300),
)

router = APIRouter()


def _dashboard_config() -> dict:
    config = {
        "availableStrategies": sorted(set(STRATEGY_REGISTRY) | (
            OVERLAY_NAMES if os.getenv("OVERLAY_UPSTREAM_CHOICES") else set()
        )),
        "authenticationEnabled": auth_manager.enabled,
        "eventLimit": event_store.max_events,
    }
    try:
        config["activeTarget"] = target_selection.target_selector.current().public_metadata()
    except TargetSelectionError:
        config["activeTarget"] = None
        config["targetSelectionError"] = "target selection unavailable"
    return config


class DashboardLogin(BaseModel):
    password: str = ""


def _session_token(request: Request) -> str:
    return request.cookies.get(DASHBOARD_SESSION_COOKIE, "")


def _client_key(request: Request) -> str:
    trusted_client = request.headers.get("x-defense-management-client")
    if trusted_client:
        return trusted_client
    return request.client.host if request.client else "unknown"


def _is_secure_request(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
    return request.url.scheme == "https" or forwarded_proto == "https"


def require_dashboard_auth(request: Request) -> None:
    if not auth_manager.is_authenticated(_session_token(request)):
        raise HTTPException(status_code=401, detail="dashboard authentication required")


@router.get("/__defense")
async def defense_root():
    return RedirectResponse(url="/__defense/dashboard")


@router.get("/__defense/dashboard")
async def defense_dashboard():
    return FileResponse(DASHBOARD_PATH, media_type="text/html")


@router.get("/__defense/api/auth/status")
async def dashboard_auth_status(request: Request):
    return {
        "enabled": auth_manager.enabled,
        "authenticated": auth_manager.is_authenticated(_session_token(request)),
        "httpsRequired": DASHBOARD_REQUIRE_HTTPS,
    }


@router.post("/__defense/api/login")
async def dashboard_login(payload: DashboardLogin, request: Request):
    if DASHBOARD_REQUIRE_HTTPS and not _is_secure_request(request):
        raise HTTPException(status_code=426, detail="dashboard login requires HTTPS")
    try:
        token = auth_manager.login(payload.password, _client_key(request))
    except InvalidCredentialsError as exc:
        raise HTTPException(status_code=401, detail="invalid password") from exc
    except LoginRateLimitedError as exc:
        raise HTTPException(
            status_code=429,
            detail="too many login attempts",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    response = Response(status_code=204)
    if token:
        response.set_cookie(
            DASHBOARD_SESSION_COOKIE,
            token,
            httponly=True,
            samesite="strict",
            secure=DASHBOARD_COOKIE_SECURE,
            max_age=DASHBOARD_SESSION_TTL_SECONDS,
            path="/__defense",
        )
    return response


@router.post("/__defense/api/logout")
async def dashboard_logout(request: Request):
    auth_manager.logout(_session_token(request))
    response = Response(status_code=204)
    response.delete_cookie(DASHBOARD_SESSION_COOKIE, path="/__defense")
    return response


@router.get("/__defense/api/snapshot", dependencies=[Depends(require_dashboard_auth)])
async def defense_snapshot(limit: int = 250, buckets: int = 48):
    snapshot = event_store.dashboard_snapshot(limit=limit, buckets=buckets)
    snapshot["config"] = _dashboard_config()
    return snapshot


@router.get("/__defense/api/summary", dependencies=[Depends(require_dashboard_auth)])
async def defense_summary():
    return event_store.summary()


@router.get("/__defense/api/requests", dependencies=[Depends(require_dashboard_auth)])
async def defense_requests(limit: int = 150):
    return {"requests": event_store.recent(limit)}


@router.get("/__defense/api/actions", dependencies=[Depends(require_dashboard_auth)])
async def defense_actions():
    return {"actions": event_store.action_counts()}


@router.get("/__defense/api/timeline", dependencies=[Depends(require_dashboard_auth)])
async def defense_timeline(buckets: int = 48):
    return {"buckets": event_store.timeline(buckets=buckets)}


@router.get("/__defense/api/config", dependencies=[Depends(require_dashboard_auth)])
async def defense_config():
    return _dashboard_config()


@router.api_route(
    "/__defense/{unknown_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def reject_unknown_dashboard_path(unknown_path: str):
    raise HTTPException(status_code=404, detail="unknown dashboard path")
