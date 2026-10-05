"""
방어 전략 공통 인터페이스.

- apply()는 요청을 보고 (a) 헤더에 남길 정보, (b) 즉시 응답을 끊어야 하는지를
  DefenseResult로 반환한다.
- short_circuit이 세팅되면 이후 전략은 실행하지 않고 그 응답을 그대로 반환한다
  (captcha, block처럼 업스트림까지 갈 필요가 없는 경우).
"""
from abc import ABC, abstractmethod

from starlette.requests import Request
from starlette.responses import Response


class DefenseResult:
    def __init__(
        self,
        short_circuit: Response | None = None,
        extra_headers: dict[str, str] | None = None,
    ):
        self.short_circuit = short_circuit
        self.extra_headers = extra_headers or {}


class DefenseStrategy(ABC):
    name: str

    @abstractmethod
    async def apply(self, request: Request, params: dict) -> DefenseResult:
        ...