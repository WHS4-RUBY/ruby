"""
Defense Proxy - 스텁 버전.
Policy Engine이 정한 전략(X-Defense-Strategy)을 받아오지만, 아직 실제 방어
동작(지연 주입, 허니팟 전환, 챌린지 삽입 등)은 구현하지 않고 그대로 통과시킴.

TODO: strategy별 실제 요청/응답 변형 로직 구현.
"""
import os

import httpx
from fastapi import FastAPI, Request
from starlette.responses import Response

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
}

app = FastAPI(title="Defense Proxy (stub)")


def apply_defense(strategy: str, request: Request, body: bytes) -> tuple[bytes, dict]:
    # TODO: strategy(challenge/throttle/honeypot 등)에 따라 실제 요청/응답 변형
    return body, {}


def _header_value(value) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    if isinstance(value, str):
        return value
    return str(value)


def build_upstream_headers(request: Request, extra: dict) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        if key.lower() in _HOP_BY_HOP:
            continue
        headers[key] = _header_value(value)
    for key, value in extra.items():
        if key.lower() in _HOP_BY_HOP:
            continue
        headers[key] = _header_value(value)
    return headers


def proxy_response(upstream: httpx.Response) -> Response:
    headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in _RESPONSE_SKIP
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=headers,
    )


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
)
async def catch_all(request: Request, full_path: str):
    strategy = request.headers.get("x-defense-strategy", "passthrough")
    body = await request.body()
    body, extra_headers = apply_defense(strategy, request, body)

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
        return Response(content=str(exc).encode(), status_code=502)

    return proxy_response(upstream)
