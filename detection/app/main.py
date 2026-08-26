"""
Detection Proxy - 스텁 버전.
실제 탐지 로직 없이 '모든 요청을 AI 공격자로 의심'하도록 고정.
Policy Engine / Defense Proxy 파이프라인 배선을 먼저 검증하기 위한 뼈대.

TODO: 여기에 실제 탐지 로직(요청 빈도, 헤더 지문, 세션 지속성 등)을 채워넣는다.
"""
import os

import httpx
from fastapi import FastAPI, Request
from starlette.responses import Response

NEXT_HOP_URL = os.getenv("NEXT_HOP_URL", "http://localhost:8082")

# httpx는 헤더 값이 str/bytes만 허용한다. hop-by-hop·길이 헤더는 재계산해야 한다.
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
# Detection-to-Policy 인터페이스는 탐지 결과로 위험도만 허용한다.
_DETECTION_RESULT_HEADERS = {
    "x-client-id",
    "x-risk-score",
    "x-classification",
}

app = FastAPI(title="Detection Proxy (stub)")


def get_client_id(request: Request) -> str:
    # TODO: X-Forwarded-For 신뢰 여부 처리 등 identity.py 로직 이식
    return request.client.host if request.client else "unknown"


def get_risk_score(request: Request) -> float:
    # TODO: 실제 탐지기(rate, header, session 등)로 교체
    return 1.0


def _header_value(value) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    if isinstance(value, str):
        return value
    return str(value)


def build_upstream_headers(request: Request, extra: dict) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        if key.lower() in _HOP_BY_HOP | _DETECTION_RESULT_HEADERS:
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
    client_id = get_client_id(request)
    risk = get_risk_score(request)

    body = await request.body()
    headers = build_upstream_headers(
        request,
        {
            "X-Client-Id": client_id,
            "X-Risk-Score": risk,
        },
    )

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream = await client.request(
                method=request.method,
                url=f"{NEXT_HOP_URL.rstrip('/')}/{full_path}",
                headers=headers,
                content=body,
                params=list(request.query_params.multi_items()),
            )
    except httpx.RequestError as exc:
        return Response(content=str(exc).encode(), status_code=502)

    return proxy_response(upstream)
