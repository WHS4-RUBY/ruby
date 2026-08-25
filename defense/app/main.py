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

app = FastAPI(title="Defense Proxy (stub)")


def apply_defense(strategy: str, request: Request, body: bytes) -> tuple[bytes, dict]:
    # TODO: strategy(challenge/throttle/honeypot 등)에 따라 실제 요청/응답 변형
    return body, {}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def catch_all(request: Request, full_path: str):
    strategy = request.headers.get("x-defense-strategy", "passthrough")
    body = await request.body()
    body, extra_headers = apply_defense(strategy, request, body)

    headers = dict(request.headers)
    headers.pop("host", None)
    headers.update(extra_headers)

    async with httpx.AsyncClient() as client:
        upstream = await client.request(
            method=request.method,
            url=f"{BENCHMARK_TARGET_URL}/{full_path}",
            headers=headers,
            content=body,
            params=request.query_params,
        )

    return Response(content=upstream.content, status_code=upstream.status_code)
