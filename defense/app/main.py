"""RUBY Defense proxy."""

from contextlib import asynccontextmanager
import asyncio
from dataclasses import dataclass, field
import json
import os
import re
import time
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import httpx
import websockets
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from starlette.responses import Response, StreamingResponse
from websockets.exceptions import ConnectionClosedOK

from .dashboard import router as dashboard_router
from .dashboard import DASHBOARD_SESSION_COOKIE, auth_manager
from .decoy_routing import (
    ACTION_HEADER, BLOCK_ACTIONS, STRATEGIES_HEADER,
    applied_decoy_strategies, decoy_action, decoy_plan_header, parse_decoy_upstreams,
)
from .monitoring import event_store
from .overlay_routing import (
    MAX_OVERLAY_BODY, OVERLAY_HIGH, OVERLAY_MEDIUM, OverlayRouteError,
    OverlayRouteStore, actor_id, parse_overlay_upstreams, raw_target,
    requested_tier, signed_headers,
)
from .strategies.state import StateCapacityError, StrategyStateStore
from .strategies.registry import STRATEGY_REGISTRY
from . import target_selection, path_alias, token_gate

TOKEN_GATE = token_gate.TokenGateConfig.from_env()
PATH_ALIAS = path_alias.PathAliasConfig.from_env()
PATH_ALIAS_TABLE = path_alias.PathAliasTable(PATH_ALIAS)
from .target_selection import TargetSelectionError, resolve_target_url


TARGET_URL = target_selection.target_selector.choices[target_selection.target_selector.default_id]
DECOY_UPSTREAMS = parse_decoy_upstreams(
    os.getenv("DECOY_UPSTREAM_CHOICES"), target_selection.target_selector.choices,
)
OVERLAY_UPSTREAMS = parse_overlay_upstreams(
    os.getenv("OVERLAY_UPSTREAM_CHOICES"), target_selection.target_selector.choices,
)
OVERLAY_DETECTOR_KEY = os.getenv("OVERLAY_DETECTOR_KEY", "").encode("utf-8")
OVERLAY_STATE_DB = os.getenv("DEFENSE_OVERLAY_STATE_DB", "/app/overlay-state/routes.sqlite3")


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


TRANSFORM_BODY_LIMIT = _positive_int("DEFENSE_TRANSFORM_BODY_LIMIT", 4 * 1024 * 1024)

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
_RESPONSE_SKIP = {
    "connection",
    "keep-alive",
    "transfer-encoding",
    "content-encoding",
    "content-length",
    "date",
    "server",
    "x-defense-signal",
    "x-defense-applied",
    ACTION_HEADER,
    STRATEGIES_HEADER,
}
_DEFENSE_INTERNAL_HEADERS = {
    "x-client-id",
    "x-defense-plan",
    "x-defense-management-client",
    "x-ruby-request-id",
    "x-ruby-automation-score",
    "x-ruby-attack-score",
    "x-ruby-risk-score",
    "x-ruby-confirmed-attack-score",
    "x-ruby-policy-source",
    "x-ruby-target-id",
    "x-ruby-run-id",
    "x-ruby-candidate-id",
    "x-ruby-client-flow-id",
    "x-ruby-defense-tier",
    "x-defense-signal",
    ACTION_HEADER,
    STRATEGIES_HEADER,
}
_FORWARDED_HEADERS = {"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"}
_REQUEST_SKIP = _HOP_BY_HOP | {"accept-encoding"} | _DEFENSE_INTERNAL_HEADERS | _FORWARDED_HEADERS
_CONDITIONAL_REQUEST_HEADERS = {"if-none-match", "if-modified-since"}
_REWRITTEN_RESPONSE_SKIP = _RESPONSE_SKIP | {"etag", "last-modified", "cache-control"}
_STREAM_RESPONSE_SKIP = _HOP_BY_HOP | {
    "date", "server", "x-defense-signal", "x-defense-applied",
    ACTION_HEADER, STRATEGIES_HEADER,
}
_WEBSOCKET_SKIP = _HOP_BY_HOP | {
    "sec-websocket-accept",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
} | _DEFENSE_INTERNAL_HEADERS | _FORWARDED_HEADERS


@asynccontextmanager
async def lifespan(app: FastAPI):
    if OVERLAY_UPSTREAMS or OverlayRouteStore.exists(OVERLAY_STATE_DB):
        app.state.overlay_routes = OverlayRouteStore.bootstrap(
            OVERLAY_STATE_DB, OVERLAY_DETECTOR_KEY, OVERLAY_UPSTREAMS
        )
    # The private sidecar may spend up to 30 seconds waiting for its target.
    # Leave room for the second proxy hop to return a response or a 502.
    async with httpx.AsyncClient(timeout=35.0) as client:
        app.state.http_client = client
        yield


app = FastAPI(title="RUBY Defense Proxy", lifespan=lifespan)
app.include_router(dashboard_router)
strategy_state = StrategyStateStore()


@app.middleware("http")
async def secure_dashboard_responses(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == "/__defense" or request.url.path.startswith("/__defense/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
    return response


def parse_plan(raw: str | None) -> list[dict]:
    if not raw or len(raw) > 8192:
        return []
    try:
        plan = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(plan, list):
        return []
    return [
        step for step in plan[:16]
        if isinstance(step, dict)
        and isinstance(step.get("name"), str)
        and isinstance(step.get("params") or {}, dict)
    ]


def _score_header(headers, name: str) -> float | None:
    try:
        value = float(headers.get(name, ""))
    except ValueError:
        return None
    return value if 0 <= value <= 1 else None


def _event_metadata(request: Request | WebSocket, selected=None) -> dict:
    headers = request.headers
    return {
        "client_id": headers.get("x-client-id"),
        "request_id": headers.get("x-ruby-request-id"),
        "automation_score": _score_header(headers, "x-ruby-automation-score"),
        "attack_score": _score_header(headers, "x-ruby-attack-score"),
        "confirmed_attack_score": _score_header(headers, "x-ruby-confirmed-attack-score"),
        "risk_score": _score_header(headers, "x-ruby-risk-score"),
        "policy_source": headers.get("x-ruby-policy-source"),
        "candidate_id": headers.get("x-ruby-candidate-id"),
        "client_flow_id": headers.get("x-ruby-client-flow-id"),
        "defense_tier": headers.get("x-ruby-defense-tier"),
        "target_id": selected.target_id if selected else None,
        "run_id": selected.run_id if selected else None,
    }


def _client_id(request: Request | WebSocket) -> str:
    return (request.headers.get("x-client-id") or (
        request.client.host if request.client else "unknown"
    ))[:128]


@dataclass
class AppliedPlan:
    names: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    transforms: list = field(default_factory=list)
    short_circuit: Response | None = None


async def _apply_plan(plan: list[dict], request: Request | WebSocket, selected=None) -> AppliedPlan:
    applied = AppliedPlan()
    for step in plan:
        name = step["name"]
        strategy = STRATEGY_REGISTRY.get(name)
        if strategy is None:
            continue
        if strategy.uses_state:
            try:
                client_key = _client_id(request)
                if selected is not None:
                    client_key = f"{selected.run_id or selected.target_id}:{client_key}"
                async with strategy_state.use(name, client_key) as entry:
                    result = await strategy.apply(request, step.get("params") or {}, dict(entry.state))
                    if result.state_update is not None:
                        if not isinstance(result.state_update, dict):
                            raise TypeError("strategy state_update must be a dict")
                        entry.state = dict(result.state_update)
            except StateCapacityError:
                applied.short_circuit = Response(status_code=503)
                return applied
        else:
            result = await strategy.apply(request, step.get("params") or {}, {})
        applied.names.append(name)
        applied.headers.update(result.extra_headers)
        if result.response_transform is not None:
            applied.transforms.append(result.response_transform)
        if result.short_circuit is not None:
            applied.short_circuit = result.short_circuit
            return applied
    return applied


def _header_value(value) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    if isinstance(value, str):
        return value
    return str(value)


def build_upstream_headers(request: Request, extra: dict) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        if key.lower() in _REQUEST_SKIP or key.lower().startswith("x-defense-"):
            continue
        headers[key] = _header_value(value)
    headers["accept-encoding"] = "identity"
    headers["x-forwarded-host"] = request.headers.get("x-forwarded-host") or request.headers.get(
        "host", ""
    )
    headers["x-forwarded-proto"] = request.headers.get("x-forwarded-proto") or request.url.scheme
    for key, value in extra.items():
        if (key.lower() in _HOP_BY_HOP | _DEFENSE_INTERNAL_HEADERS | {"x-forwarded-for"}
                or key.lower().startswith("x-defense-") and key.lower() != "x-defense-applied"):
            continue
        headers[key] = _header_value(value)
    return headers


def build_decoy_headers(request: Request, extra: dict, selected, plan: list[dict]) -> dict[str, str]:
    """Reissue only trusted identity and decoy instructions to a private sidecar."""
    headers = build_upstream_headers(request, extra)
    headers["X-Client-Id"] = _client_id(request)
    headers["X-Defense-Plan"] = decoy_plan_header(plan)
    headers["X-Ruby-Target-Id"] = selected.target_id
    if selected.run_id:
        headers["X-Ruby-Run-Id"] = selected.run_id
    request_id = request.headers.get("x-ruby-request-id")
    if request_id:
        headers["X-Ruby-Request-Id"] = request_id[:128]
    return headers


async def _overlay_route(request: Request | WebSocket, selected, plan: list[dict]) -> tuple[str, str, str] | None:
    """Select a durable route using only Detection's private plan and actor ID."""
    origin = OVERLAY_UPSTREAMS.get(selected.target_id)
    if origin is None:
        if any(step.get("name") in {OVERLAY_MEDIUM, OVERLAY_HIGH} for step in plan):
            raise OverlayRouteError("selected target has no overlay")
        return None
    raw_plan = request.headers.get("x-defense-plan")
    try:
        original_plan = json.loads(raw_plan) if raw_plan and len(raw_plan) <= 8192 else None
    except (TypeError, ValueError):
        original_plan = None
    if (not isinstance(original_plan, list) or len(original_plan) > 16
            or len(original_plan) != len(plan)
            or any(not isinstance(step, dict)
                   or not isinstance(step.get("name"), str)
                   or not isinstance(step.get("params", {}), dict)
                   for step in original_plan)):
        raise OverlayRouteError("trusted defense plan missing or malformed")
    requested = requested_tier(
        plan,
        risk_score=_score_header(request.headers, "x-ruby-risk-score"),
        confirmed_attack_score=_score_header(request.headers, "x-ruby-confirmed-attack-score"),
    )
    if len(OVERLAY_DETECTOR_KEY) < 32:
        raise OverlayRouteError("overlay detector key unavailable")
    client_id = request.headers.get("x-client-id")
    if client_id is None:
        raise OverlayRouteError("trusted client identity unavailable")
    actor = actor_id(OVERLAY_DETECTOR_KEY, selected.target_id, selected.run_id, client_id)
    store = getattr(app.state, "overlay_routes", None)
    if store is None:
        # Unit tests may use ASGITransport without lifespan. In production the
        # lifespan has already bootstrapped this store before serving traffic.
        store = OverlayRouteStore.bootstrap(OVERLAY_STATE_DB, OVERLAY_DETECTOR_KEY,
                                            OVERLAY_UPSTREAMS)
        app.state.overlay_routes = store
    tier = await asyncio.to_thread(store.observe, actor, requested)
    return (origin, tier, actor) if tier else None


def _public_origin(request: Request) -> str:
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme).split(",", 1)[0].strip()
    host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    return f"{scheme}://{host}" if host else ""


def _rewrite_response_header(
    key: str, value: str, request: Request | None, target_url: str | None = None
) -> str:
    if request is None:
        return value
    if key.lower() == "location":
        target = (target_url or TARGET_URL).rstrip("/")
        if value == target or value.startswith(f"{target}/"):
            return f"{_public_origin(request)}{value[len(target):]}"
    if key.lower() == "set-cookie":
        return re.sub(r";\s*Domain=[^;]+", "", value, flags=re.IGNORECASE)
    return value


def proxy_response(
    upstream: httpx.Response, request: Request | None = None, content: bytes | None = None,
    *, target_url: str | None = None,
) -> Response:
    response = Response(
        content=upstream.content if content is None else content,
        status_code=upstream.status_code,
    )
    for key, value in upstream.headers.multi_items():
        if key.lower() in _RESPONSE_SKIP or key.lower().startswith("x-defense-"):
            continue
        response.raw_headers.append(
            (
                key.encode("latin-1"),
                _rewrite_response_header(key, _header_value(value), request, target_url).encode("latin-1"),
            )
        )
    return response


async def _stream_body(upstream: httpx.Response, on_complete=None):
    outcome = "forwarded"
    try:
        async for chunk in upstream.aiter_raw():
            yield chunk
    except BaseException:
        outcome = "error"
        raise
    finally:
        try:
            await upstream.aclose()
        except Exception:
            outcome = "error"
            raise
        finally:
            if on_complete is not None:
                on_complete(outcome)


class TransformBodyLimitError(Exception):
    pass


async def _buffer_transform_body(upstream: httpx.Response) -> bytes:
    body = bytearray()
    async for chunk in upstream.aiter_bytes():
        body.extend(chunk)
        if len(body) > TRANSFORM_BODY_LIMIT:
            raise TransformBodyLimitError
    return bytes(body)


def streaming_proxy_response(
    upstream: httpx.Response, request: Request, on_complete=None, *, target_url: str | None = None, body=None
) -> StreamingResponse:
    response = StreamingResponse(body if body is not None else _stream_body(upstream, on_complete), status_code=upstream.status_code)
    for key, value in upstream.headers.multi_items():
        if key.lower() in _STREAM_RESPONSE_SKIP or key.lower().startswith("x-defense-"):
            continue
        response.raw_headers.append(
            (
                key.encode("latin-1"),
                _rewrite_response_header(key, _header_value(value), request, target_url).encode("latin-1"),
            )
        )
    return response


def _log_gate(request: Request, decision: token_gate.GateDecision | None,
              upstream_status: int | None = None, content_type: str = "") -> None:
    if decision is None or decision.kind == "exempt":
        return
    token_gate.emit(token_gate.build_log(
        decision, now=time.time(), mode=TOKEN_GATE.mode, method=request.method,
        path=request.url.path, headers=request.headers, upstream_status=upstream_status,
        observation=token_gate.observe_response(decision, request.method, upstream_status, content_type),
    ))


def _log_alias(request: Request, resolution: path_alias.Resolution, decision: str,
               upstream_status: int | None = None, rewrites: int = 0,
               skipped: str | None = None, alias_client: str | None = None,
               rotation: str | None = None) -> None:
    if PATH_ALIAS.mode == "off" or (resolution.kind == "other" and not rewrites and skipped is None):
        return
    path_alias.emit(path_alias.build_log(
        resolution, decision, now=time.time(), mode=PATH_ALIAS.mode, method=request.method,
        path=request.url.path, headers=request.headers, upstream_status=upstream_status,
        rewrites=rewrites, rewrite_skipped=skipped,
        ua_family=token_gate.ua_family(request.headers.get("user-agent")),
        alias_client=alias_client, rotation=rotation,
    ))


async def _alias_db(call, *args):
    """Alias table calls block on the database; keep them off the event loop."""
    if PATH_ALIAS.mode == "off":
        return call(*args)
    return await asyncio.to_thread(call, *args)


async def _rotate_on_event(resolution: path_alias.Resolution, alias_client: str | None) -> str | None:
    """Replace a client's aliases as soon as it hits a real route or a bad alias."""
    if resolution.kind not in PATH_ALIAS.rotate_on or alias_client is None:
        return None
    if PATH_ALIAS.mode != "enforce":
        return "would_rotate"
    rotated = await _alias_db(PATH_ALIAS_TABLE.rotate_client, alias_client, time.time(), resolution.kind)
    return "rotated" if rotated else None


def _alias_not_found() -> Response:
    return Response(content=b'{"error":"not_found"}', status_code=404,
                    media_type="application/json", headers={"Cache-Control": "no-store"})


async def _replay_body(consumed: list[bytes], rest, upstream: httpx.Response, on_complete=None):
    outcome = "forwarded"
    try:
        for chunk in consumed:
            yield chunk
        async for chunk in rest:
            yield chunk
    except BaseException:
        outcome = "error"
        raise
    finally:
        await upstream.aclose()
        if on_complete is not None:
            on_complete(outcome)


async def alias_proxy_response(upstream: httpx.Response, request: Request,
                               alias_client: str | None, *, target_url: str | None = None, on_complete=None) -> tuple[Response, int, str | None]:
    """Serve an upstream response with configured routes replaced by this client's aliases."""
    rewrites, skipped = 0, None
    client_id = alias_client or path_alias.new_client_id()
    if not path_alias.rewritable(upstream.headers.get("content-type", ""),
                                 upstream.headers.get("content-encoding", ""),
                                 upstream.status_code, request.method):
        response = streaming_proxy_response(upstream, request, on_complete=on_complete, target_url=target_url)
    else:
        consumed, size = [], 0
        stream = upstream.aiter_raw()
        async for chunk in stream:
            consumed.append(chunk)
            size += len(chunk)
            if size > PATH_ALIAS.max_rewrite_bytes:
                break
        if size > PATH_ALIAS.max_rewrite_bytes:
            skipped = "too_large"
            response = streaming_proxy_response(upstream, request, target_url=target_url, body=_replay_body(consumed, stream, upstream, on_complete))
        else:
            await upstream.aclose()
            body, rewrites = await _alias_db(PATH_ALIAS_TABLE.rewrite_body, b"".join(consumed),
                                             time.time(), client_id)
            skip = _REWRITTEN_RESPONSE_SKIP if rewrites else _RESPONSE_SKIP
            response = Response(content=body, status_code=upstream.status_code)
            for key, value in upstream.headers.multi_items():
                if key.lower() in skip or key.lower().startswith("x-defense-"):
                    continue
                response.raw_headers.append(
                    (
                        key.encode("latin-1"),
                        _rewrite_response_header(key, _header_value(value), request, target_url).encode("latin-1"),
                    )
                )
            if rewrites:
                response.headers["cache-control"] = "no-store"
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    raw_headers, location_rewritten = [], False
    for key, value in response.raw_headers:
        if key.lower() == b"location":
            original = value.decode("latin-1")
            rewritten = await _alias_db(PATH_ALIAS_TABLE.rewrite_location, original, host,
                                        time.time(), client_id)
            location_rewritten |= rewritten != original
            value = rewritten.encode("latin-1")
        raw_headers.append((key, value))
    response.raw_headers = raw_headers
    if alias_client is None and (rewrites or location_rewritten):
        # Aliases were issued to a new client id; bind them to this browser.
        response.raw_headers.append(
            (b"set-cookie", path_alias.build_set_cookie(PATH_ALIAS, client_id).encode("latin-1"))
        )
        response.headers["cache-control"] = "no-store"
    if not isinstance(response, StreamingResponse) and on_complete is not None:
        on_complete("forwarded")
    return response, rewrites, skipped


def _websocket_target(full_path: str, query: str, target_url: str | None = None) -> str:
    target = urlsplit(target_url or TARGET_URL)
    scheme = "wss" if target.scheme == "https" else "ws"
    base_path = target.path.rstrip("/")
    path = f"{base_path}/{full_path}" if full_path else (base_path or "/")
    return urlunsplit((scheme, target.netloc, path, query, ""))


def _websocket_headers(websocket: WebSocket, extra: dict[str, str]) -> dict[str, str]:
    headers = {
        key: value
        for key, value in websocket.headers.items()
        if key.lower() not in _WEBSOCKET_SKIP and not key.lower().startswith("x-defense-")
    }
    headers["x-forwarded-host"] = websocket.headers.get("x-forwarded-host") or websocket.headers.get(
        "host", ""
    )
    headers["x-forwarded-proto"] = websocket.headers.get("x-forwarded-proto") or (
        "https" if websocket.url.scheme == "wss" else "http"
    )
    for key, value in extra.items():
        if key.lower() not in _WEBSOCKET_SKIP and (
            not key.lower().startswith("x-defense-") or key.lower() == "x-defense-applied"
        ):
            headers[key] = _header_value(value)
    return headers


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "defense"}


@app.get("/readyz")
async def readyz():
    """Report ready only while the selected target and its sidecar are reachable."""
    try:
        selected = target_selection.target_selector.current()
    except TargetSelectionError:
        return Response(status_code=503)
    urls = [selected.url]
    if decoy_url := DECOY_UPSTREAMS.get(selected.target_id):
        urls.append(decoy_url)
    if overlay_url := OVERLAY_UPSTREAMS.get(selected.target_id):
        urls.append(overlay_url)
        try:
            app.state.overlay_routes.health()
        except (AttributeError, OverlayRouteError):
            return Response(status_code=503)
    for url in urls:
        target = urlsplit(url)
        if target.scheme not in {"http", "https"} or not target.hostname:
            return Response(status_code=503)
        try:
            port = target.port or (443 if target.scheme == "https" else 80)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.hostname, port), timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
        except (OSError, ValueError, asyncio.TimeoutError):
            return Response(status_code=503)
    return {"status": "ready", "service": "defense"}


@app.websocket("/{full_path:path}")
async def websocket_proxy(websocket: WebSocket, full_path: str):
    # The management namespace has HTTP routes only. Never tunnel its upgrades
    # to a target, even when a valid dashboard session exists.
    if full_path == "__defense" or full_path.startswith("__defense/"):
        reason = (
            "management websocket unsupported"
            if auth_manager.is_authenticated(websocket.cookies.get(DASHBOARD_SESSION_COOKIE))
            else "dashboard authentication required"
        )
        await websocket.close(code=1008, reason=reason)
        return

    started_at = time.perf_counter()
    try:
        selected = target_selection.target_selector.for_request(websocket.headers)
    except TargetSelectionError:
        event_store.record(
            method="WEBSOCKET",
            path=websocket.url.path,
            status=503,
            strategies=[],
            outcome="error",
            duration_ms=(time.perf_counter() - started_at) * 1000,
            **_event_metadata(websocket),
        )
        await websocket.close(code=1013, reason="target selection unavailable")
        return
    metadata = _event_metadata(websocket, selected)
    plan = parse_plan(websocket.headers.get("x-defense-plan"))
    try:
        overlay_route = await _overlay_route(websocket, selected, plan)
    except OverlayRouteError:
        event_store.record(
            method="WEBSOCKET",
            path=websocket.url.path,
            status=503,
            strategies=[],
            outcome="error",
            duration_ms=(time.perf_counter() - started_at) * 1000,
            **metadata,
        )
        await websocket.close(code=1013, reason="overlay route unavailable")
        return
    overlay_strategy = ([OVERLAY_HIGH if overlay_route[1] == "high" else OVERLAY_MEDIUM]
                        if overlay_route else [])
    action_name = f"account-overlay-{overlay_route[1]}" if overlay_route else None
    try:
        applied = await _apply_plan(plan, websocket, selected)
    except Exception:
        event_store.record(
            method="WEBSOCKET",
            path=websocket.url.path,
            status=500,
            strategies=overlay_strategy,
            outcome="error",
            duration_ms=(time.perf_counter() - started_at) * 1000,
            decoy_action=action_name,
            **metadata,
        )
        await websocket.close(code=1011, reason="defense strategy failed")
        return
    if applied.short_circuit is not None or applied.transforms:
        capacity_error = applied.short_circuit is not None and applied.short_circuit.status_code == 503
        outcome = "error" if capacity_error or applied.transforms else "blocked"
        event_store.record(
            method="WEBSOCKET",
            path=websocket.url.path,
            status=(applied.short_circuit.status_code if applied.short_circuit else 503),
            strategies=applied.names,
            outcome=outcome,
            duration_ms=(time.perf_counter() - started_at) * 1000,
            signal=applied.short_circuit.headers.get("x-defense-signal") if applied.short_circuit else None,
            **metadata,
        )
        await websocket.close(
            code=1013 if capacity_error else 1008,
            reason="strategy unavailable" if capacity_error or applied.transforms else "request blocked by defense policy",
        )
        return

    if overlay_route is not None:
        # PR34 accepts HTTP only. An isolated actor's upgrade must not reach
        # the real target through the ordinary WebSocket forwarding path.
        event_store.record(
            method="WEBSOCKET",
            path=websocket.url.path,
            status=403,
            strategies=applied.names + overlay_strategy,
            outcome="blocked",
            duration_ms=(time.perf_counter() - started_at) * 1000,
            decoy_action=action_name,
            **metadata,
        )
        await websocket.close(code=1008, reason="isolated websocket unsupported")
        return

    extra_headers = applied.headers
    extra_headers["X-Defense-Applied"] = ",".join(applied.names) or "none"
    requested_protocols = [
        protocol.strip()
        for protocol in websocket.headers.get("sec-websocket-protocol", "").split(",")
        if protocol.strip()
    ]
    status = 101
    outcome = "forwarded"
    upgraded = False
    try:
        async with websockets.connect(
            _websocket_target(full_path, websocket.url.query, selected.url),
            extra_headers=_websocket_headers(websocket, extra_headers),
            subprotocols=requested_protocols or None,
            max_size=None,
        ) as upstream:
            await websocket.accept(subprotocol=upstream.subprotocol)
            upgraded = True

            async def client_to_upstream():
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    payload = message.get("bytes")
                    if payload is None:
                        payload = message.get("text", "")
                    await upstream.send(payload)

            async def upstream_to_client():
                async for payload in upstream:
                    if isinstance(payload, bytes):
                        await websocket.send_bytes(payload)
                    else:
                        await websocket.send_text(payload)

            tasks = {
                asyncio.create_task(client_to_upstream()),
                asyncio.create_task(upstream_to_client()),
            }
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
    except (WebSocketDisconnect, ConnectionClosedOK):
        pass
    except Exception:
        # Once accepted, the handshake remains 101 even if a later frame fails.
        status = 101 if upgraded else 502
        outcome = "error"
        try:
            await websocket.close(code=1011, reason="upstream websocket unavailable")
        except RuntimeError:
            pass
    finally:
        event_store.record(
            method="WEBSOCKET",
            path=websocket.url.path,
            status=status,
            strategies=applied.names,
            outcome=outcome,
            duration_ms=(time.perf_counter() - started_at) * 1000,
            **metadata,
        )


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def catch_all(request: Request, full_path: str):
    started_at = time.perf_counter()
    try:
        selected = target_selection.target_selector.for_request(request.headers)
    except TargetSelectionError:
        event_store.record(
            method=request.method,
            path=request.url.path,
            status=503,
            strategies=[],
            outcome="error",
            duration_ms=(time.perf_counter() - started_at) * 1000,
            **_event_metadata(request),
        )
        return Response(status_code=503)
    plan = parse_plan(request.headers.get("x-defense-plan"))
    metadata = _event_metadata(request, selected)
    alias_client = path_alias.valid_client_id(request.cookies.get(path_alias.COOKIE_NAME))
    alias = await _alias_db(PATH_ALIAS_TABLE.resolve_request, request.url.path,
                            request.scope.get("query_string", b""), request.method,
                            time.time(), alias_client)
    alias_decision = path_alias.decide(alias, PATH_ALIAS)
    rotation = await _rotate_on_event(alias, alias_client)
    translated = (alias.kind == "alias" or
                  (alias.query_string is not None and alias.upstream_path != request.url.path))
    record_path = alias.upstream_path if translated else request.url.path

    gate = None
    if TOKEN_GATE.mode != "off":
        gate = token_gate.evaluate(
            request.method, request.url.path, request.headers,
            request.cookies.get(token_gate.COOKIE_NAME), time.time(), TOKEN_GATE,
        )

    strategy_request = request
    if translated:
        # Keep the ingress request for alias logs, but expose the restored route
        # consistently to subsequent strategies (including cached Request.url).
        scope = dict(request.scope)
        scope["path"] = unquote(alias.upstream_path)
        scope["raw_path"] = quote(alias.upstream_path, safe="/%:@!$&'()*+,;=-._~").encode("ascii")
        scope["path_params"] = {**scope.get("path_params", {}),
                                "full_path": scope["path"].lstrip("/")}
        if alias.query_string is not None:
            scope["query_string"] = alias.query_string
        strategy_request = Request(scope, request.receive)


    def record(
        status: int, outcome: str, names: list[str], signal: str | None = None,
        decoy_action_name: str | None = None,
    ) -> None:
        event_store.record(
            method=request.method,
            path=record_path,
            status=status,
            strategies=names,
            outcome=outcome,
            duration_ms=(time.perf_counter() - started_at) * 1000,
            signal=signal,
            decoy_action=decoy_action_name,
            **metadata,
        )

    if alias_decision == "block":
        _log_gate(request, gate)
        _log_alias(request, alias, alias_decision, alias_client=alias_client, rotation=rotation)
        record(404, "blocked", ["path_alias"])
        return _alias_not_found()

    try:
        overlay_route = await _overlay_route(strategy_request, selected, plan)
    except OverlayRouteError:
        _log_gate(request, gate)
        _log_alias(request, alias, alias_decision, alias_client=alias_client, rotation=rotation)
        record(503, "error", [])
        return Response(status_code=503)

    overlay_strategy = ([OVERLAY_HIGH if overlay_route[1] == "high" else OVERLAY_MEDIUM]
                        if overlay_route else [])
    action_name = f"account-overlay-{overlay_route[1]}" if overlay_route else None

    try:
        applied = await _apply_plan(plan, strategy_request, selected)
    except Exception:
        _log_gate(request, gate)
        _log_alias(request, alias, alias_decision, alias_client=alias_client, rotation=rotation)
        record(500, "error", overlay_strategy, decoy_action_name=action_name)
        return Response(status_code=500)

    if alias.kind != "other":
        applied.names.insert(0, "path_alias")
    applied_header = ",".join(applied.names) or "none"
    if applied.short_circuit is not None:
        response = applied.short_circuit
        for key, value in applied.headers.items():
            response.headers[key] = value
        response.headers["X-Defense-Applied"] = applied_header
        _log_gate(request, gate)
        record(
            response.status_code,
            "error" if response.status_code == 503 else "blocked",
            applied.names,
            response.headers.get("x-defense-signal"),
            decoy_action_name=action_name,
        )
        return response

    attempted_strategies = applied.names + overlay_strategy
    applied.headers["X-Defense-Applied"] = applied_header
    decoy_url = None if overlay_route else DECOY_UPSTREAMS.get(selected.target_id)
    if overlay_route:
        overlay_url, tier, actor = overlay_route
        try:
            target = raw_target(strategy_request.scope)
        except OverlayRouteError:
            record(400, "error", attempted_strategies, decoy_action_name=action_name)
            return Response(status_code=400)
        body = bytearray()
        async for chunk in strategy_request.stream():
            if len(body) + len(chunk) > MAX_OVERLAY_BODY:
                record(413, "error", attempted_strategies, decoy_action_name=action_name)
                return Response(status_code=413)
            body.extend(chunk)
        headers = build_upstream_headers(request, applied.headers)
        headers.update(signed_headers(
            OVERLAY_DETECTOR_KEY, actor, request.method, target, bytes(body), tier=tier,
        ))
        try:
            upstream_url = httpx.URL(overlay_url).copy_with(raw_path=target.encode("ascii"))
        except (httpx.InvalidURL, ValueError):
            record(400, "error", attempted_strategies, decoy_action_name=action_name)
            return Response(status_code=400)
        if upstream_url.raw_path != target.encode("ascii"):
            record(400, "error", attempted_strategies, decoy_action_name=action_name)
            return Response(status_code=400)
    else:
        headers = (
            build_decoy_headers(request, applied.headers, selected, plan)
            if decoy_url else build_upstream_headers(request, applied.headers)
        )
        upstream_path = alias.upstream_path.lstrip("/") if translated else full_path
        upstream_url = httpx.URL(f"{(decoy_url or selected.url).rstrip('/')}/{upstream_path}")
        raw_query = strategy_request.scope.get("query_string", b"")
        if raw_query:
            upstream_url = upstream_url.copy_with(query=raw_query)

    if PATH_ALIAS.mode != "off":
        headers = {key: value for key, value in headers.items()
                   if key.lower() not in _CONDITIONAL_REQUEST_HEADERS}

    try:
        upstream_request = request.app.state.http_client.build_request(
            method=request.method,
            url=str(upstream_url),
            headers=headers,
            content=bytes(body) if overlay_route else (
                strategy_request.stream() if request.method not in {"GET", "HEAD"} else None
            ),
        )
        if overlay_route and upstream_request.url.raw_path != target.encode("ascii"):
            record(400, "error", attempted_strategies, decoy_action_name=action_name)
            return Response(status_code=400)
        upstream = await request.app.state.http_client.send(upstream_request, stream=True)
    except (httpx.InvalidURL, ValueError):
        status = 400 if overlay_route else 502
        record(status, "error", attempted_strategies, decoy_action_name=action_name)
        return Response(status_code=status)
    except httpx.RequestError:
        _log_gate(request, gate)
        _log_alias(request, alias, alias_decision, alias_client=alias_client, rotation=rotation)
        record(502, "error", attempted_strategies, decoy_action_name=action_name)
        return Response(status_code=502)

    sidecar_action = decoy_action(upstream.headers) if decoy_url else None
    sidecar_strategies = applied_decoy_strategies(upstream.headers) if decoy_url else []
    recorded_strategies = applied.names + sidecar_strategies + overlay_strategy
    applied_header = ",".join(recorded_strategies) or "none"
    public_applied_header = (",".join(applied.names) or "none") if overlay_route else applied_header
    if overlay_route:
        sidecar_outcome = (
            "error" if upstream.status_code < 200 or upstream.status_code >= 500
            or upstream.status_code in {400, 403, 413}
            else "blocked" if tier == "high" else "forwarded"
        )
    else:
        sidecar_outcome = "blocked" if sidecar_action in BLOCK_ACTIONS else "forwarded"
        action_name = sidecar_action

    if applied.transforms:
        # Body transforms require a complete response before headers are sent.
        try:
            body = await _buffer_transform_body(upstream)
            response = proxy_response(upstream, request, body, target_url=selected.url)
            for transform in applied.transforms:
                response = transform(response)
                if not isinstance(response, Response):
                    raise TypeError("response_transform must return a Response")
                if not isinstance(getattr(response, "body", None), bytes):
                    raise TypeError("response_transform must return a buffered Response")
                if len(response.body) > TRANSFORM_BODY_LIMIT:
                    raise TransformBodyLimitError
            if PATH_ALIAS.mode != "off":
                buffered = httpx.Response(response.status_code, headers=response.raw_headers,
                                          stream=httpx.ByteStream(response.body))
                response, rewrites, skipped = await alias_proxy_response(
                    buffered, request, alias_client, target_url=selected.url)
                _log_alias(request, alias, alias_decision, upstream.status_code, rewrites, skipped,
                           alias_client, rotation)
            if gate is not None and gate.issue_cookie and upstream.status_code < 500:
                response.raw_headers.append((
                    b"set-cookie", token_gate.build_set_cookie(TOKEN_GATE, time.time()).encode("latin-1")
                ))
                response.headers["cache-control"] = "no-store"
            _log_gate(request, gate, upstream.status_code, upstream.headers.get("content-type", ""))
            response.headers["X-Defense-Applied"] = public_applied_header
            record(response.status_code, sidecar_outcome, recorded_strategies,
                   decoy_action_name=action_name)
            return response
        except (httpx.RequestError, TransformBodyLimitError):
            record(502, "error", attempted_strategies, decoy_action_name=action_name)
            return Response(status_code=502)
        except Exception:
            record(500, "error", attempted_strategies, decoy_action_name=action_name)
            return Response(status_code=500)
        finally:
            await upstream.aclose()

    on_complete = lambda outcome: record(
        upstream.status_code,
        sidecar_outcome if outcome == "forwarded" else outcome,
        recorded_strategies,
        decoy_action_name=action_name,
    )
    if PATH_ALIAS.mode != "off":
        try:
            response, rewrites, skipped = await alias_proxy_response(
                upstream, request, alias_client, target_url=selected.url, on_complete=on_complete)
        except Exception:
            await upstream.aclose()
            record(502, "error", attempted_strategies, decoy_action_name=action_name)
            return Response(status_code=502)
        _log_alias(request, alias, alias_decision, upstream.status_code, rewrites, skipped,
                   alias_client, rotation)
    else:
        response = streaming_proxy_response(upstream, request, on_complete=on_complete,
                                            target_url=selected.url)
    if gate is not None and gate.issue_cookie and upstream.status_code < 500:
        response.raw_headers.append((b"set-cookie", token_gate.build_set_cookie(TOKEN_GATE, time.time()).encode("latin-1")))
        response.headers["cache-control"] = "no-store"
    _log_gate(request, gate, upstream.status_code, upstream.headers.get("content-type", ""))
    response.headers["X-Defense-Applied"] = public_applied_header
    return response
