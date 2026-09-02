#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx
from fastapi import FastAPI, Request
from starlette.responses import Response

# 로그/에러 출력이 파일로 리다이렉트돼도 한글이 안 깨지도록 표준 출력을 UTF-8로 고정
# (Windows print 기본값은 OS 로캘 인코딩=cp949).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# 프록시가 종단해야 하는 hop-by-hop 헤더 (RFC 9110 §7.6.1).
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}
# 클라이언트로 되돌려줄 때 제외할 응답 헤더.
#  - content-length   : 본문 길이는 Starlette가 재계산(훅이 본문을 늘릴 수 있음)
#  - content-encoding : accept-encoding: identity로 요청하므로 항상 비압축본
# server/Set-Cookie/Location/보안 헤더 등은 전부 보존한다.
_RESPONSE_SKIP = _HOP_BY_HOP | {"content-length", "content-encoding"}
# 백엔드로 넘길 때 제외할 요청 헤더. host/content-length는 httpx가 다시 채운다.
_REQUEST_SKIP = _HOP_BY_HOP | {"host", "content-length", "accept-encoding"}


@dataclass
class ProxyContext:
    """요청 1건이 프록시를 통과하는 동안의 가변 상태. 훅들이 공유한다."""

    request: Request
    trace_id: str
    method: str
    path: str

    # --- 요청 측 (on_request 에서 수정 가능) ---
    body: bytes
    forward_headers: dict[str, str]
    target_url: str
    query_params: list[tuple[str, str]]

    # --- 응답 측 (백엔드 응답 후 채워짐, on_response 에서 수정 가능) ---
    upstream: Optional[httpx.Response] = None
    response_status: Optional[int] = None
    response_headers: Optional[list[tuple[str, str]]] = None
    response_body: Optional[bytes] = None

    # 훅 간 공유 스크래치 (sid, risk_score, classification, error ...)
    meta: dict = field(default_factory=dict)

    short_circuited: bool = False
    started_at: float = field(default_factory=time.monotonic)

    @property
    def elapsed_ms(self) -> float:
        return (time.monotonic() - self.started_at) * 1000

    def content_type(self, which: str = "response") -> Optional[str]:
        """'request' 또는 'response' 의 Content-Type 값."""
        if which == "request":
            return self.request.headers.get("content-type")
        for key, value in self.response_headers or []:
            if key.lower() == "content-type":
                return value
        return None


class ProxyHook:
    """계층별 로직을 꽂는 지점. 필요한 메서드만 오버라이드한다."""

    async def on_request(self, ctx: ProxyContext) -> Optional[Response]:
        return None

    async def on_response(self, ctx: ProxyContext) -> None:
        return None

    async def on_error(self, ctx: ProxyContext, exc: Exception) -> Optional[Response]:
        return None


def _response_from(ctx: ProxyContext) -> Response:
    """ctx 의 응답 상태로 최종 starlette Response 를 조립한다."""
    resp = Response(content=ctx.response_body or b"", status_code=ctx.response_status or 200)
    for key, value in ctx.response_headers or []:
        try:
            resp.raw_headers.append((key.encode("latin-1"), value.encode("latin-1")))
        except UnicodeEncodeError:
            resp.raw_headers.append((key.encode("utf-8"), value.encode("utf-8")))
    return resp


def _adopt_short_circuit(ctx: ProxyContext, resp: Response) -> None:
    """훅이 반환한 Response 를 ctx 응답 상태로 흡수한다(이후 on_response 도 볼 수 있게)."""
    ctx.short_circuited = True
    ctx.response_status = resp.status_code
    ctx.response_body = bytes(getattr(resp, "body", b"") or b"")
    ctx.response_headers = [
        (k.decode("latin-1"), v.decode("latin-1"))
        for k, v in resp.raw_headers
        if k.decode("latin-1").lower() not in _RESPONSE_SKIP
    ]


def create_app(
    hooks: Optional[list[ProxyHook]] = None,
    *,
    backend: Optional[str] = None,
    title: str = "proxy-core",
    timeout: float = 15.0,
    before_catchall: Optional[Callable[[FastAPI], None]] = None,
) -> FastAPI:
    """훅 리스트를 받아 프록시 FastAPI 앱을 만든다.

    backend        : 백엔드 origin. 생략 시 환경변수 ``REAL_BACKEND``,
                     그것도 없으면 ``http://127.0.0.1:3000``.
    before_catchall: ``fn(app)`` — 캐치올 프록시 라우트보다 먼저 등록할 전용
                     라우트(트랩 엔드포인트 등)를 여기서 ``@app.get(...)`` 로 붙인다.
    """
    hook_list = list(hooks or [])
    backend_url = (backend or os.environ.get("REAL_BACKEND", "http://127.0.0.1:3000")).rstrip("/")

    app = FastAPI(title=title)

    # 전용 라우트를 캐치올보다 먼저 등록 — Starlette 는 등록 순서대로 매칭한다.
    if before_catchall is not None:
        before_catchall(app)

    @app.api_route("/{full_path:path}", methods=_METHODS)
    async def _proxy(request: Request, full_path: str) -> Response:
        forward_headers: dict[str, str] = {}
        for key, value in request.headers.items():
            if key.lower() in _REQUEST_SKIP:
                continue
            value = value.strip()
            if value:
                forward_headers[key] = value
        forward_headers["accept-encoding"] = "identity"

        ctx = ProxyContext(
            request=request,
            trace_id=uuid.uuid4().hex[:8],
            method=request.method,
            path=full_path,
            body=await request.body(),
            forward_headers=forward_headers,
            target_url=f"{backend_url}/{full_path}",
            query_params=list(request.query_params.multi_items()),
        )

        # 1. on_request 훅 — Response 반환 시 백엔드를 건너뛴다.
        for hook in hook_list:
            early = await hook.on_request(ctx)
            if early is not None:
                _adopt_short_circuit(ctx, early)
                break

        # 2. 백엔드로 전달 (단축되지 않았을 때만)
        if not ctx.short_circuited:
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    upstream = await client.request(
                        method=ctx.method,
                        url=ctx.target_url,
                        headers=ctx.forward_headers,
                        content=ctx.body,
                        params=ctx.query_params,
                    )
            except httpx.HTTPError as exc:
                ctx.meta["error"] = repr(exc)
                for hook in hook_list:
                    override = await hook.on_error(ctx, exc)
                    if override is not None:
                        _adopt_short_circuit(ctx, override)
                        break
                if not ctx.short_circuited:
                    ctx.response_status = 502
                    ctx.response_body = b"Bad Gateway"
                    ctx.response_headers = []
            else:
                ctx.upstream = upstream
                ctx.response_status = upstream.status_code
                ctx.response_body = upstream.content
                ctx.response_headers = [
                    (k, v) for k, v in upstream.headers.multi_items()
                    if k.lower() not in _RESPONSE_SKIP
                ]

        # 3. on_response 훅 — 단축·에러 응답도 관찰·변조 가능.
        for hook in hook_list:
            await hook.on_response(ctx)

        return _response_from(ctx)

    return app
