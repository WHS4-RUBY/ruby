import os
import asyncio

from fastapi import FastAPI, Request
from .proxy.proxy_core import ProxyContext, ProxyHook, create_app

NEXT_HOP_URL = os.getenv("NEXT_HOP_URL", "http://localhost:8082")


# Detection-to-Policy 인터페이스는 탐지 결과로 위험도만 허용한다.
# 클라이언트가 이 헤더들을 직접 주입해 탐지 결과를 위조하지 못하도록
# on_request 에서 먼저 제거한다.
_DETECTION_RESULT_HEADERS = {
    "x-client-id",
    "x-risk-score",
    "x-classification",
}
 

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


class DetectionHook(ProxyHook):
    """client_id 산정 + rate 기반 risk score 계산 → forward_headers 에 실어 백엔드로 전달.
 
    TODO: rate 외 header, session 등 다른 시그널과 결합해 실제 탐지기로 교체.
    """
 
    def __init__(self):
        self._tracker = RequestRateTracker()
 
    async def on_request(self, ctx: ProxyContext):
        # 탐지 결과 헤더 위조 방지: 클라이언트가 보낸 값은 무시하고 제거.
        for header in _DETECTION_RESULT_HEADERS:
            ctx.forward_headers.pop(header, None)
 
        client_id = get_client_id(ctx.request)
        risk = await self._tracker.record_and_score(client_id)
 
        # 다른 훅(로깅 등)이 참고할 수 있도록 meta 에도 남긴다.
        ctx.meta["client_id"] = client_id
        ctx.meta["risk_score"] = risk
 
        ctx.forward_headers["X-Client-Id"] = client_id
        ctx.forward_headers["X-Risk-Score"] = str(risk)
        return None
 
 
def _register_healthz(app: FastAPI) -> None:
    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}
 
 
app = create_app(
    [DetectionHook()],
    backend=NEXT_HOP_URL,
    title="Detection Proxy (stub)",
    before_catchall=_register_healthz,
)
 