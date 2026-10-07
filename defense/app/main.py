"""RUBY Defense proxy."""

from contextlib import asynccontextmanager
import asyncio
from dataclasses import dataclass, field
import json
import os
import re
import time
from urllib.parse import urlsplit, urlunsplit

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
from .strategies.state import StateCapacityError, StrategyStateStore
from .strategies.registry import STRATEGY_REGISTRY
from . import target_selection
from .target_selection import TargetSelectionError, resolve_target_url


TARGET_URL = target_selection.target_selector.choices[target_selection.target_selector.default_id]
DECOY_UPSTREAMS = parse_decoy_upstreams(
    os.getenv("DECOY_UPSTREAM_CHOICES"), target_selection.target_selector.choices,
)


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
    "x-ruby-policy-source",
    "x-ruby-target-id",
    "x-ruby-run-id",
    "x-defense-signal",
    ACTION_HEADER,
    STRATEGIES_HEADER,
}
_FORWARDED_HEADERS = {"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"}
_REQUEST_SKIP = _HOP_BY_HOP | {"accept-encoding"} | _DEFENSE_INTERNAL_HEADERS | _FORWARDED_HEADERS
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
    return round(value, 6) if 0 <= value <= 1 else None


def _event_metadata(request: Request | WebSocket, selected=None) -> dict:
    headers = request.headers
    return {
        "client_id": headers.get("x-client-id"),
        "request_id": headers.get("x-ruby-request-id"),
        "automation_score": _score_header(headers, "x-ruby-automation-score"),
        "attack_score": _score_header(headers, "x-ruby-attack-score"),
        "risk_score": _score_header(headers, "x-ruby-risk-score"),
        "policy_source": headers.get("x-ruby-policy-source"),
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
        if key.lower() in _REQUEST_SKIP:
            continue
        headers[key] = _header_value(value)
    headers["accept-encoding"] = "identity"
    headers["x-forwarded-host"] = request.headers.get("x-forwarded-host") or request.headers.get(
        "host", ""
    )
    headers["x-forwarded-proto"] = request.headers.get("x-forwarded-proto") or request.url.scheme
    for key, value in extra.items():
        if key.lower() in _HOP_BY_HOP | _DEFENSE_INTERNAL_HEADERS | {"x-forwarded-for"}:
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
        if key.lower() in _RESPONSE_SKIP:
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
    upstream: httpx.Response, request: Request, on_complete=None, *, target_url: str | None = None
) -> StreamingResponse:
    response = StreamingResponse(_stream_body(upstream, on_complete), status_code=upstream.status_code)
    for key, value in upstream.headers.multi_items():
        if key.lower() in _STREAM_RESPONSE_SKIP:
            continue
        response.raw_headers.append(
            (
                key.encode("latin-1"),
                _rewrite_response_header(key, _header_value(value), request, target_url).encode("latin-1"),
            )
        )
    return response


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
        if key.lower() not in _WEBSOCKET_SKIP
    }
    headers["x-forwarded-host"] = websocket.headers.get("x-forwarded-host") or websocket.headers.get(
        "host", ""
    )
    headers["x-forwarded-proto"] = websocket.headers.get("x-forwarded-proto") or (
        "https" if websocket.url.scheme == "wss" else "http"
    )
    for key, value in extra.items():
        if key.lower() not in _WEBSOCKET_SKIP:
            headers[key] = _header_value(value)
    return headers


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "defense"}


@app.get("/readyz")
async def readyz():
    """Report ready only while the selected target accepts TCP connections."""
    try:
        selected = target_selection.target_selector.current()
    except TargetSelectionError:
        return Response(status_code=503)
    target = urlsplit(selected.url)
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
        applied = await _apply_plan(plan, websocket, selected)
    except Exception:
        event_store.record(
            method="WEBSOCKET",
            path=websocket.url.path,
            status=500,
            strategies=[],
            outcome="error",
            duration_ms=(time.perf_counter() - started_at) * 1000,
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
            status=503 if capacity_error else 403,
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

    def record(
        status: int, outcome: str, names: list[str], signal: str | None = None,
        decoy_action_name: str | None = None,
    ) -> None:
        event_store.record(
            method=request.method,
            path=request.url.path,
            status=status,
            strategies=names,
            outcome=outcome,
            duration_ms=(time.perf_counter() - started_at) * 1000,
            signal=signal,
            decoy_action=decoy_action_name,
            **metadata,
        )

    try:
        applied = await _apply_plan(plan, request, selected)
    except Exception:
        record(500, "error", [])
        return Response(status_code=500)

    applied_header = ",".join(applied.names) or "none"
    if applied.short_circuit is not None:
        response = applied.short_circuit
        for key, value in applied.headers.items():
            response.headers[key] = value
        response.headers["X-Defense-Applied"] = applied_header
        record(
            response.status_code,
            "error" if response.status_code == 503 else "blocked",
            applied.names,
            response.headers.get("x-defense-signal"),
        )
        return response

    applied.headers["X-Defense-Applied"] = applied_header
    decoy_url = DECOY_UPSTREAMS.get(selected.target_id)
    headers = (
        build_decoy_headers(request, applied.headers, selected, plan)
        if decoy_url else build_upstream_headers(request, applied.headers)
    )

    try:
        upstream_request = request.app.state.http_client.build_request(
            method=request.method,
            url=f"{(decoy_url or selected.url).rstrip('/')}/{full_path}",
            headers=headers,
            content=request.stream() if request.method not in {"GET", "HEAD"} else None,
            params=list(request.query_params.multi_items()),
        )
        upstream = await request.app.state.http_client.send(upstream_request, stream=True)
    except httpx.RequestError:
        record(502, "error", applied.names)
        return Response(status_code=502)

    sidecar_action = decoy_action(upstream.headers) if decoy_url else None
    sidecar_strategies = applied_decoy_strategies(upstream.headers) if decoy_url else []
    recorded_strategies = applied.names + sidecar_strategies
    applied_header = ",".join(recorded_strategies) or "none"
    sidecar_outcome = "blocked" if sidecar_action in BLOCK_ACTIONS else "forwarded"

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
            response.headers["X-Defense-Applied"] = applied_header
            record(response.status_code, sidecar_outcome, recorded_strategies,
                   decoy_action_name=sidecar_action)
            return response
        except (httpx.RequestError, TransformBodyLimitError):
            record(502, "error", applied.names)
            return Response(status_code=502)
        except Exception:
            record(500, "error", applied.names)
            return Response(status_code=500)
        finally:
            await upstream.aclose()

    response = streaming_proxy_response(
        upstream,
        request,
        on_complete=lambda outcome: record(
            upstream.status_code,
            sidecar_outcome if outcome == "forwarded" else outcome,
            recorded_strategies,
            decoy_action_name=sidecar_action,
        ),
        target_url=selected.url,
    )
    response.headers["X-Defense-Applied"] = applied_header
    return response
