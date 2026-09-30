"""
Defense Proxy - 스텁 버전.
Policy Engine이 X-Defense-Plan 헤더로 넘긴 방어 전략 계획을 실제로 실행하고
(delay 재우기, rate_limit 차단 등), 이후 최종 백엔드로 요청을 전달한다.

TODO: strategy별 실제 요청/응답 변형 로직 구현.
"""
import json
import os
import time

import httpx
from fastapi import FastAPI, Request
from starlette.responses import Response

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
    # Uvicorn이 현재 hop의 값을 생성한다. upstream 값을 전달하면 프록시
    # 계층 수만큼 Date/Server 헤더가 중복된다.
    "date",
    "server",
}
# Policy Engine이 내부 통신용으로 붙인 헤더는 여기서 소비하고, 실제 백엔드에는
# 전달하지 않는다 (백엔드가 몰라도 되는 내부 파이프라인 정보이므로).
_DEFENSE_INTERNAL_HEADERS = {"x-defense-plan"}
_REQUEST_SKIP = _HOP_BY_HOP | {"accept-encoding"} | _DEFENSE_INTERNAL_HEADERS

app = FastAPI(title="Defense Proxy (stub)")


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
    for key, value in extra.items():
        if key.lower() in _HOP_BY_HOP:
            continue
        headers[key] = _header_value(value)
    return headers


def proxy_response(upstream: httpx.Response) -> Response:
    response = Response(content=upstream.content, status_code=upstream.status_code)

    # dict로 변환하면 Set-Cookie처럼 같은 이름을 여러 번 쓰는 헤더가 하나로
    # 합쳐진다. 원본 순서와 중복을 보존해 각 헤더를 ASGI raw_headers에 추가한다.
    for key, value in upstream.headers.multi_items():
        if key.lower() in _RESPONSE_SKIP:
            continue
        response.raw_headers.append(
            (key.encode("latin-1"), _header_value(value).encode("latin-1"))
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


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


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

    plan = parse_plan(request.headers.get("x-defense-plan"))

    applied_names: list[str] = []
    extra_headers: dict[str, str] = {}


    for step in plan:
        name = step.get("name")
        strategy_impl = STRATEGY_REGISTRY.get(name)
        if strategy_impl is None:
            # TODO: registry에 없는 전략 이름이 들어온 경우 처리 정책 확정 (지금은 skip)
            continue

        result = await strategy_impl.apply(request, step.get("params") or {})
        applied_names.append(name)
        extra_headers.update(result.extra_headers)

        if result.short_circuit is not None:
            # rate_limit(429) 등 백엔드까지 갈 필요 없이 여기서 응답 종료
            for k, v in extra_headers.items():
                result.short_circuit.headers[k] = v
            result.short_circuit.headers["X-Defense-Applied"] = ",".join(applied_names)
            _log_gate(request, gate)
            return result.short_circuit

    extra_headers["X-Defense-Applied"] = ",".join(applied_names) or "none"

    body = await request.body()
    headers = build_upstream_headers(request, extra_headers)


    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream = await client.request(
                method=request.method,
                url=f"{BENCHMARK_TARGET_URL.rstrip('/')}/{full_path}",
                headers=headers,
                content=body,
                params=list(request.query_params.multi_items()),
            )
    except httpx.RequestError as exc:
        _log_gate(request, gate)
        return Response(content=str(exc).encode(), status_code=502)

    response = proxy_response(upstream)
    if gate is not None and gate.issue_cookie and not 500 <= upstream.status_code < 600:
        response.raw_headers.append(
            (b"set-cookie", token_gate.build_set_cookie(TOKEN_GATE, time.time()).encode("latin-1"))
        )
        response.headers["cache-control"] = "no-store"
    _log_gate(request, gate, upstream.status_code, upstream.headers.get("content-type", ""))
    return response
