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

app = FastAPI(title="Detection Proxy (stub)")


def get_client_id(request: Request) -> str:
    # TODO: X-Forwarded-For 신뢰 여부 처리 등 identity.py 로직 이식
    return request.client.host if request.client else "unknown"


def get_risk_score(request: Request) -> dict:
    # TODO: 실제 탐지기(rate, header, session 등)로 교체
    return {"risk_score": 1.0}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def catch_all(request: Request, full_path: str):
    client_id = get_client_id(request)
    risk = get_risk_score(request)

    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    headers["X-Client-Id"] = client_id
    headers["X-Risk-Score"] = risk

    async with httpx.AsyncClient() as client:
        upstream = await client.request(
            method=request.method,
            url=f"{NEXT_HOP_URL}/{full_path}",
            headers=headers,
            content=body,
            params=request.query_params,
        )

    return Response(content=upstream.content, status_code=upstream.status_code)
