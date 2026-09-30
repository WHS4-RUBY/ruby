"""RUBY Defense proxy."""

from contextlib import asynccontextmanager
import asyncio
import json
import os
import re
import time
from urllib.parse import urlsplit, urlunsplit

import httpx
import websockets
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from starlette.responses import Response, StreamingResponse
from websockets.exceptions import ConnectionClosed

from .dashboard import router as dashboard_router
from .monitoring import event_store
from .strategies.registry import STRATEGY_REGISTRY
from . import token_gate

TOKEN_GATE = token_gate.TokenGateConfig.from_env()

BENCHMARK_TARGET_URL = os.getenv("BENCHMARK_TARGET_URL", "http://localhost:9000")

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
}
_DEFENSE_INTERNAL_HEADERS = {"x-defense-plan", "x-defense-management-client"}
_FORWARDED_HEADERS = {"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"}
_REQUEST_SKIP = _HOP_BY_HOP | {"accept-encoding"} | _DEFENSE_INTERNAL_HEADERS | _FORWARDED_HEADERS
_STREAM_RESPONSE_SKIP = _HOP_BY_HOP | {"date", "server"}
_WEBSOCKET_SKIP = _HOP_BY_HOP | {
    "sec-websocket-accept",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
} | _DEFENSE_INTERNAL_HEADERS | _FORWARDED_HEADERS


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with httpx.AsyncClient(timeout=30.0) as client:
        app.state.http_client = client
        yield


app = FastAPI(title="RUBY Defense Proxy", lifespan=lifespan)
app.include_router(dashboard_router)


@app.middleware("http")
async def secure_dashboard_responses(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == "/__defense" or request.url.path.startswith("/__defense/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
    return response


def parse_plan(raw: str | None) -> list[dict]:
    if not raw:
        return []
    try:
        plan = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return plan if isinstance(plan, list) else []


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
    headers["x-forwarded-for"] = request.headers.get("x-forwarded-for") or (
        request.client.host if request.client else "unknown"
    )
    headers["x-forwarded-host"] = request.headers.get("x-forwarded-host") or request.headers.get(
        "host", ""
    )
    headers["x-forwarded-proto"] = request.headers.get("x-forwarded-proto") or request.url.scheme
    for key, value in extra.items():
        if key.lower() in _HOP_BY_HOP:
            continue
        headers[key] = _header_value(value)
    return headers


def _public_origin(request: Request) -> str:
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme).split(",", 1)[0].strip()
    host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    return f"{scheme}://{host}" if host else ""


def _rewrite_response_header(key: str, value: str, request: Request | None) -> str:
    if request is None:
        return value
    if key.lower() == "location":
        target = BENCHMARK_TARGET_URL.rstrip("/")
        if value == target or value.startswith(f"{target}/"):
            return f"{_public_origin(request)}{value[len(target):]}"
    if key.lower() == "set-cookie":
        return re.sub(r";\s*Domain=[^;]+", "", value, flags=re.IGNORECASE)
    return value


def proxy_response(upstream: httpx.Response, request: Request | None = None) -> Response:
    response = Response(content=upstream.content, status_code=upstream.status_code)
    for key, value in upstream.headers.multi_items():
        if key.lower() in _RESPONSE_SKIP:
            continue
        response.raw_headers.append(
            (
                key.encode("latin-1"),
                _rewrite_response_header(key, _header_value(value), request).encode("latin-1"),
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


async def _stream_body(upstream: httpx.Response):
    try:
        async for chunk in upstream.aiter_raw():
            yield chunk
    finally:
        await upstream.aclose()


def streaming_proxy_response(upstream: httpx.Response, request: Request) -> StreamingResponse:
    response = StreamingResponse(_stream_body(upstream), status_code=upstream.status_code)
    for key, value in upstream.headers.multi_items():
        if key.lower() in _STREAM_RESPONSE_SKIP:
            continue
        response.raw_headers.append(
            (
                key.encode("latin-1"),
                _rewrite_response_header(key, _header_value(value), request).encode("latin-1"),
            )
        )
    return response


def _websocket_target(full_path: str, query: str) -> str:
    target = urlsplit(BENCHMARK_TARGET_URL)
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
    headers["x-forwarded-for"] = websocket.headers.get("x-forwarded-for") or (
        websocket.client.host if websocket.client else "unknown"
    )
    headers["x-forwarded-host"] = websocket.headers.get("x-forwarded-host") or websocket.headers.get(
        "host", ""
    )
    headers["x-forwarded-proto"] = websocket.headers.get("x-forwarded-proto") or (
        "https" if websocket.url.scheme == "wss" else "http"
    )
    headers.update(extra)
    return headers


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "defense"}


@app.websocket("/{full_path:path}")
async def websocket_proxy(websocket: WebSocket, full_path: str):
    started_at = time.perf_counter()
    plan = parse_plan(websocket.headers.get("x-defense-plan"))
    applied_names: list[str] = []
    extra_headers: dict[str, str] = {}

    for step in plan:
        name = step.get("name")
        strategy_impl = STRATEGY_REGISTRY.get(name)
        if strategy_impl is None:
            continue
        result = await strategy_impl.apply(websocket, step.get("params") or {})
        applied_names.append(name)
        extra_headers.update(result.extra_headers)
        if result.short_circuit is not None:
            await websocket.close(code=1008, reason="request blocked by defense policy")
            return

    extra_headers["X-Defense-Applied"] = ",".join(applied_names) or "none"
    requested_protocols = [
        protocol.strip()
        for protocol in websocket.headers.get("sec-websocket-protocol", "").split(",")
        if protocol.strip()
    ]
    status = 101
    outcome = "forwarded"
    try:
        async with websockets.connect(
            _websocket_target(full_path, websocket.url.query),
            extra_headers=_websocket_headers(websocket, extra_headers),
            subprotocols=requested_protocols or None,
            max_size=None,
        ) as upstream:
            await websocket.accept(subprotocol=upstream.subprotocol)

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
    except (WebSocketDisconnect, ConnectionClosed):
        pass
    except Exception:
        status = 502
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
            strategies=applied_names,
            outcome=outcome,
            duration_ms=(time.perf_counter() - started_at) * 1000,
            client_id=websocket.headers.get("x-client-id"),
        )


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def catch_all(request: Request, full_path: str):
    gate = None
    if TOKEN_GATE.mode != "off":
        gate = token_gate.evaluate(
            request.method, request.url.path, request.headers,
            request.cookies.get(token_gate.COOKIE_NAME), time.time(), TOKEN_GATE,
        )

    started_at = time.perf_counter()
    plan = parse_plan(request.headers.get("x-defense-plan"))
    applied_names: list[str] = []
    extra_headers: dict[str, str] = {}

    for step in plan:
        name = step.get("name")
        strategy_impl = STRATEGY_REGISTRY.get(name)
        if strategy_impl is None:
            continue

        result = await strategy_impl.apply(request, step.get("params") or {})
        applied_names.append(name)
        extra_headers.update(result.extra_headers)

        if result.short_circuit is not None:
            for key, value in extra_headers.items():
                result.short_circuit.headers[key] = value
            result.short_circuit.headers["X-Defense-Applied"] = ",".join(applied_names)
            _log_gate(request, gate)
            event_store.record(
                method=request.method,
                path=request.url.path,
                status=result.short_circuit.status_code,
                strategies=applied_names,
                outcome="blocked",
                duration_ms=(time.perf_counter() - started_at) * 1000,
                client_id=request.headers.get("x-client-id"),
            )
            return result.short_circuit

    extra_headers["X-Defense-Applied"] = ",".join(applied_names) or "none"
    headers = build_upstream_headers(request, extra_headers)

    try:
        upstream_request = request.app.state.http_client.build_request(
            method=request.method,
            url=f"{BENCHMARK_TARGET_URL.rstrip('/')}/{full_path}",
            headers=headers,
            content=request.stream() if request.method not in {"GET", "HEAD"} else None,
            params=list(request.query_params.multi_items()),
        )
        upstream = await request.app.state.http_client.send(upstream_request, stream=True)
    except httpx.RequestError as exc:
        _log_gate(request, gate)
        event_store.record(
            method=request.method,
            path=request.url.path,
            status=502,
            strategies=applied_names,
            outcome="error",
            duration_ms=(time.perf_counter() - started_at) * 1000,
            client_id=request.headers.get("x-client-id"),
        )
        return Response(content=str(exc).encode(), status_code=502)

    event_store.record(
        method=request.method,
        path=request.url.path,
        status=upstream.status_code,
        strategies=applied_names,
        outcome="forwarded",
        duration_ms=(time.perf_counter() - started_at) * 1000,
        client_id=request.headers.get("x-client-id"),
    )
    response = streaming_proxy_response(upstream, request)
    if gate is not None and gate.issue_cookie and not 500 <= upstream.status_code < 600:
        response.raw_headers.append(
            (b"set-cookie", token_gate.build_set_cookie(TOKEN_GATE, time.time()).encode("latin-1"))
        )
        response.headers["cache-control"] = "no-store"
    _log_gate(request, gate, upstream.status_code, upstream.headers.get("content-type", ""))
    return response
