"""
Policy Engine - 스텁 버전.
Detection Proxy가 붙인 위험도 헤더를 보고 방어 전략을 정하며, 정책은 config.yaml에서 로드.
지연 방어는 아직 스텁: risk_score 0.1당 delay_ms_per_step만큼 응답을 늦춘다.

TODO: risk_score/classification -> defense strategy 매핑 규칙을 구체화.
"""
import asyncio
import os

import httpx
import yaml
from fastapi import FastAPI, Request
from starlette.responses import Response

NEXT_HOP_URL = os.getenv("NEXT_HOP_URL", "http://localhost:8080")
CONFIG_PATH = os.getenv("POLICY_CONFIG_PATH", "config.yaml")

app = FastAPI(title="Policy Engine (stub)")


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


config = load_config(CONFIG_PATH)


def compute_delay_seconds(risk_score: float) -> float:
    step = config["delay"]["step"]
    delay_ms_per_step = config["delay"]["delay_ms_per_step"]
    steps = risk_score / step
    return (steps * delay_ms_per_step) / 1000


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def catch_all(request: Request, full_path: str):
    risk_score = float(request.headers.get("x-risk-score", "0"))
    delay_seconds = compute_delay_seconds(risk_score)

    await asyncio.sleep(delay_seconds)

    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    headers["X-Defense-Delay-Ms"] = str(int(delay_seconds * 1000))

    async with httpx.AsyncClient() as client:
        upstream = await client.request(
            method=request.method,
            url=f"{NEXT_HOP_URL}/{full_path}",
            headers=headers,
            content=body,
            params=request.query_params,
        )

    return Response(content=upstream.content, status_code=upstream.status_code)
