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

app = FastAPI(title="Policy Engine (stub)")


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


config = load_config(CONFIG_PATH)


def parse_risk_score(raw: str | None) -> float:
    if raw is None or raw == "":
        return 0.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def compute_delay_seconds(risk_score: float) -> float:
    step = float(config["delay"]["step"])
    delay_ms_per_step = float(config["delay"]["delay_ms_per_step"])
    if step <= 0:
        return 0.0
    steps = risk_score / step
    return (steps * delay_ms_per_step) / 1000


def select_strategy(risk_score: float) -> str:
    strategies = config.get("strategies") or {}
    if risk_score >= 0.7:
        return str(strategies.get("likely_ai", "challenge"))
    if risk_score >= 0.3:
        return str(strategies.get("suspicious", "throttle"))
    return str(strategies.get("human", "passthrough"))


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
    risk_score = parse_risk_score(request.headers.get("x-risk-score"))
    strategy = select_strategy(risk_score)
    delay_seconds = compute_delay_seconds(risk_score)

    await asyncio.sleep(delay_seconds)

    body = await request.body()
    headers = build_upstream_headers(
        request,
        {
            "X-Defense-Strategy": strategy,
            "X-Defense-Delay-Ms": str(int(delay_seconds * 1000)),
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
