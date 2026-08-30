"""
Policy Engine - 스텁 버전.
Detection Proxy가 붙인 위험도 헤더를 보고 config.yaml의 rules에 따라
방어 전략(들)을 순서대로 적용한다. 실제 실행은 defense/ 패키지에 위임하고,
이 파일은 "어떤 전략을 어떤 순서로 적용할지" 결정 및 오케스트레이션만 담당한다.
"""
import json
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
# 프록시는 압축을 풀어 다시 쓰는 역할을 하지 않는다. 지원하지 않는 압축 형식의
# 본문과 Content-Encoding 헤더가 어긋나지 않도록 업스트림 압축을 비활성화한다.
_REQUEST_SKIP = _HOP_BY_HOP | {"accept-encoding"}

app = FastAPI(title="Policy Engine (stub)")


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


config = load_config(CONFIG_PATH)
_RULES: list[dict] = config.get("defense", {}).get("rules") or []


def select_strategies(risk_score: float) -> list[dict]:
    # rules는 [min_score, max_score). 순서대로 훑어 첫 매칭 규칙을 쓴다.
    # TODO: 겹치는 구간/구멍난 구간에 대한 config validation 추가.
    for rule in _RULES:
        if rule["min_score"] <= risk_score < rule["max_score"]:
            return rule.get("strategies") or []
    return []


def parse_risk_score(raw: str | None) -> float:
    if raw is None or raw == "":
        return 0.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


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
    risk_score = parse_risk_score(request.headers.get("x-risk-score"))
    strategies = select_strategies(risk_score)

    body = await request.body()
    headers = build_upstream_headers(
        request,
        {
            "X-Defense-Plan": json.dumps(strategies, ensure_ascii=False),
            "X-Risk-Score": str(risk_score),
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