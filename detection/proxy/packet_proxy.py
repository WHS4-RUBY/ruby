#!/usr/bin/env python3
"""패킷 로깅 프록시 = proxy_core + LoggingHook.

    uvicorn packet_proxy:app --host 127.0.0.1 --port 3002 --no-server-header

클라이언트 ↔ 백엔드 간 요청/응답 패킷(메서드·URL·헤더·본문)을 그대로 터미널에
로깅하는 관찰 전용 프록시입니다. 제어 로직은 전혀 없습니다.

탐지(위험도 산정)·방어(차단·변환·지연·기만) 는 [`proxy_core.create_app`](proxy_core.py) 에
각 계층의 ``ProxyHook`` 을 넘겨 별도 앱으로 구성합니다(연결 지점은 proxy_core 모듈 docstring 참고).
"""
import os
from datetime import datetime

from proxy_core import ProxyContext, ProxyHook, create_app

# stdout 을 UTF-8 로 고정하는 건 proxy_core import 시점에 이미 처리됨.

# 로그에 남길 본문 최대 바이트. 0 이하이면 전체 출력.
MAX_BODY_LOG = int(os.environ.get("MAX_BODY_LOG", "2000"))

_TEXTUAL_HINTS = ("text/", "json", "xml", "javascript", "html",
                  "x-www-form-urlencoded", "+json", "+xml")
_BINARY_HINTS = ("image/", "video/", "audio/", "font/",
                 "application/octet-stream", "application/pdf",
                 "application/zip", "application/gzip", "application/x-protobuf")


def _looks_textual(content_type: str, body: bytes) -> bool:
    ct = (content_type or "").lower()
    if any(hint in ct for hint in _TEXTUAL_HINTS):
        return True
    if any(ct.startswith(hint) for hint in _BINARY_HINTS):
        return False
    try:
        body[:2048].decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _format_body(content_type: str, body: bytes) -> str:
    if not body:
        return ""
    if not _looks_textual(content_type, body):
        return f"<Binary Data: {len(body)} bytes, Content-Type: {content_type or 'unknown'}>"
    text = body.decode("utf-8", errors="replace")
    if 0 < MAX_BODY_LOG < len(body):
        return f"{text[:MAX_BODY_LOG]}\n... (truncated, total {len(body)} bytes)"
    return text


class LoggingHook(ProxyHook):
    """요청/응답 패킷을 한 번의 write 로 stdout 에 출력한다(동시 요청 시 라인 섞임 방지)."""

    async def on_request(self, ctx: ProxyContext):
        ts = datetime.now().astimezone().isoformat(timespec="milliseconds")
        lines = ["", "=" * 80,
                 f"▶ [{ts}] [{ctx.trace_id}] REQUEST  {ctx.method} {ctx.request.url}",
                 "-" * 80, "[Headers]"]
        lines += [f"  {k}: {v}" for k, v in ctx.request.headers.items()]
        body = _format_body(ctx.content_type("request"), ctx.body)
        if body:
            lines += ["[Body]", body]
        lines.append("=" * 80)
        print("\n".join(lines), flush=True)
        return None

    async def on_response(self, ctx: ProxyContext):
        ts = datetime.now().astimezone().isoformat(timespec="milliseconds")
        if ctx.meta.get("error"):
            print(f"\n[ERROR] [{ctx.trace_id}] 백엔드 연결 실패: {ctx.meta['error']}", flush=True)
        tag = ""
        if ctx.short_circuited and not ctx.meta.get("error"):
            reason = ctx.meta.get("defense") or "hook"
            tag = f" (short-circuit: {reason})"
        lines = ["", "=" * 80,
                 f"◀ [{ts}] [{ctx.trace_id}] RESPONSE {ctx.response_status}{tag}  "
                 f"{ctx.method} {ctx.target_url}",
                 "-" * 80, "[Headers]"]
        lines += [f"  {k}: {v}" for k, v in ctx.response_headers or []]
        body = _format_body(ctx.content_type("response"), ctx.response_body or b"")
        if body:
            lines += ["[Body]", body]
        lines.append("=" * 80)
        print("\n".join(lines), flush=True)


app = create_app([LoggingHook()], title="패킷 로깅 프록시")
