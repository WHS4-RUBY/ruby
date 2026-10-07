"""RUBY Defense proxy."""

from contextlib import asynccontextmanager
import asyncio
import json
import os
import re
import time
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import httpx
import websockets
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from starlette.responses import Response, StreamingResponse
from websockets.exceptions import ConnectionClosed

from .dashboard import router as dashboard_router
from .monitoring import event_store
from .strategies.registry import STRATEGY_REGISTRY
from . import path_alias, token_gate

TOKEN_GATE = token_gate.TokenGateConfig.from_env()
PATH_ALIAS = path_alias.PathAliasConfig.from_env()
PATH_ALIAS_TABLE = path_alias.PathAliasTable(PATH_ALIAS)

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
# Cached copies of a rewritten body would carry expired aliases.
_CONDITIONAL_REQUEST_HEADERS = {"if-none-match", "if-modified-since"}
_REWRITTEN_RESPONSE_SKIP = _RESPONSE_SKIP | {"etag", "last-modified", "cache-control"}
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


def streaming_proxy_response(upstream: httpx.Response, request: Request, body=None) -> StreamingResponse:
    response = StreamingResponse(body or _stream_body(upstream), status_code=upstream.status_code)
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


async def _replay_body(consumed: list[bytes], rest, upstream: httpx.Response):
    try:
        for chunk in consumed:
            yield chunk
        async for chunk in rest:
            yield chunk
    finally:
        await upstream.aclose()


async def alias_proxy_response(upstream: httpx.Response, request: Request,
                               alias_client: str | None) -> tuple[Response, int, str | None]:
    """Serve an upstream response with configured routes replaced by this client's aliases."""
    rewrites, skipped = 0, None
    client_id = alias_client or path_alias.new_client_id()
    if not path_alias.rewritable(upstream.headers.get("content-type", ""),
                                 upstream.headers.get("content-encoding", ""),
                                 upstream.status_code, request.method):
        response = streaming_proxy_response(upstream, request)
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
            response = streaming_proxy_response(upstream, request, _replay_body(consumed, stream, upstream))
        else:
            await upstream.aclose()
            body, rewrites = await _alias_db(PATH_ALIAS_TABLE.rewrite_body, b"".join(consumed),
                                             time.time(), client_id)
            skip = _REWRITTEN_RESPONSE_SKIP if rewrites else _RESPONSE_SKIP
            response = Response(content=body, status_code=upstream.status_code)
            for key, value in upstream.headers.multi_items():
                if key.lower() in skip:
                    continue
                response.raw_headers.append(
                    (
                        key.encode("latin-1"),
                        _rewrite_response_header(key, _header_value(value), request).encode("latin-1"),
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
    return response, rewrites, skipped


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
    # Defense stage 1: path aliases run before every other strategy, so later stages see the
    # real path and the alias rewrite is the last change to the outgoing response (README).
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

    started_at = time.perf_counter()
    if alias_decision == "block":
        _log_gate(request, gate)
        _log_alias(request, alias, alias_decision, alias_client=alias_client, rotation=rotation)
        event_store.record(
            method=request.method,
            path=record_path,
            status=404,
            strategies=["path_alias"],
            outcome="blocked",
            duration_ms=(time.perf_counter() - started_at) * 1000,
            client_id=request.headers.get("x-client-id"),
        )
        return _alias_not_found()

    plan = parse_plan(request.headers.get("x-defense-plan"))
    applied_names: list[str] = ["path_alias"] if alias.kind != "other" else []
    extra_headers: dict[str, str] = {}
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

    for step in plan:
        name = step.get("name")
        strategy_impl = STRATEGY_REGISTRY.get(name)
        if strategy_impl is None:
            continue

        result = await strategy_impl.apply(strategy_request, step.get("params") or {})
        applied_names.append(name)
        extra_headers.update(result.extra_headers)

        if result.short_circuit is not None:
            for key, value in extra_headers.items():
                result.short_circuit.headers[key] = value
            result.short_circuit.headers["X-Defense-Applied"] = ",".join(applied_names)
            _log_gate(request, gate)
            event_store.record(
                method=request.method,
                path=record_path,
                status=result.short_circuit.status_code,
                strategies=applied_names,
                outcome="blocked",
                duration_ms=(time.perf_counter() - started_at) * 1000,
                client_id=request.headers.get("x-client-id"),
            )
            return result.short_circuit

    extra_headers["X-Defense-Applied"] = ",".join(applied_names) or "none"
    headers = build_upstream_headers(request, extra_headers)
    if PATH_ALIAS.mode != "off":
        headers = {key: value for key, value in headers.items()
                   if key.lower() not in _CONDITIONAL_REQUEST_HEADERS}
    upstream_path = alias.upstream_path.lstrip("/") if translated else full_path

    try:
        # Query values can themselves be paths (or signed URLs). Rebuilding them through
        # QueryParams changes escaping, empty values, and sometimes the app's routing.
        upstream_url = httpx.URL(f"{BENCHMARK_TARGET_URL.rstrip('/')}/{upstream_path}")
        raw_query = strategy_request.scope.get("query_string", b"")
        if raw_query:
            upstream_url = upstream_url.copy_with(query=raw_query)
        upstream_request = request.app.state.http_client.build_request(
            method=request.method,
            url=str(upstream_url),
            headers=headers,
            content=strategy_request.stream() if request.method not in {"GET", "HEAD"} else None,
        )
        upstream = await request.app.state.http_client.send(upstream_request, stream=True)
    except httpx.RequestError as exc:
        _log_gate(request, gate)
        _log_alias(request, alias, alias_decision, alias_client=alias_client, rotation=rotation)
        event_store.record(
            method=request.method,
            path=record_path,
            status=502,
            strategies=applied_names,
            outcome="error",
            duration_ms=(time.perf_counter() - started_at) * 1000,
            client_id=request.headers.get("x-client-id"),
        )
        return Response(content=str(exc).encode(), status_code=502)

    event_store.record(
        method=request.method,
        path=record_path,
        status=upstream.status_code,
        strategies=applied_names,
        outcome="forwarded",
        duration_ms=(time.perf_counter() - started_at) * 1000,
        client_id=request.headers.get("x-client-id"),
    )
    if PATH_ALIAS.mode != "off":
        response, rewrites, skipped = await alias_proxy_response(upstream, request, alias_client)
    else:
        response, rewrites, skipped = streaming_proxy_response(upstream, request), 0, None
    if gate is not None and gate.issue_cookie and not 500 <= upstream.status_code < 600:
        response.raw_headers.append(
            (b"set-cookie", token_gate.build_set_cookie(TOKEN_GATE, time.time()).encode("latin-1"))
        )
        response.headers["cache-control"] = "no-store"
    _log_gate(request, gate, upstream.status_code, upstream.headers.get("content-type", ""))
    _log_alias(request, alias, alias_decision, upstream.status_code, rewrites, skipped,
               alias_client=alias_client, rotation=rotation)
    return response
