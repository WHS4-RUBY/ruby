import os
import asyncio
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response

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
# httpx가 지원하지 않는 압축 방식(예: Brotli)은 해제하지 못한다. 프록시가
# Content-Encoding을 제거한 응답을 브라우저에 전달해 바이너리가 노출되는 일을
# 막기 위해, 업스트림에는 압축하지 않은 표현을 요청한다.
_REQUEST_SKIP = _HOP_BY_HOP | _DETECTION_RESULT_HEADERS | {"accept-encoding"}

app = FastAPI(title="Detection Proxy (stub)")


def get_client_id(request: Request) -> str:
    # TODO: X-Forwarded-For 신뢰 여부 처리 등 identity.py 로직 이식
    return request.client.host if request.client else "unknown"


class RequestRateTracker:
    """IP(client_id)별 요청 횟수를 세어 N건마다 risk score를 올리는 스텁.

    단일 프로세스 인메모리 구현이라 프로세스 재시작 시 카운트가 초기화되고,
    멀티 워커/멀티 인스턴스 환경에서는 카운트가 인스턴스별로 따로 집계된다.
    실서비스에서는 Redis 등 공유 저장소로 교체 필요.
    """

    def __init__(self, increment: float = 0.1, per_requests: int = 10, cap: float = 1.0):
        self._counts: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._increment = increment
        self._per_requests = per_requests
        self._cap = cap

    async def record_and_score(self, client_id: str) -> float:
        async with self._lock:
            count = self._counts.get(client_id, 0) + 1
            self._counts[client_id] = count

        risk = (count // self._per_requests) * self._increment
        return min(risk, self._cap)


_rate_tracker = RequestRateTracker()


async def get_risk_score(client_id: str) -> float:
    # TODO: rate 외 header, session 등 다른 시그널과 결합해 실제 탐지기로 교체
    return await _rate_tracker.record_and_score(client_id)


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
    risk = await get_risk_score(client_id)

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
