"""Defense strategy contract for request and response phases."""

from abc import ABC, abstractmethod
from collections.abc import Callable

from starlette.requests import Request
from starlette.responses import Response


class DefenseResult:
    def __init__(
        self,
        short_circuit: Response | None = None,
        extra_headers: dict[str, str] | None = None,
        response_transform: Callable[[Response], Response] | None = None,
        state_update: dict | None = None,
    ):
        self.short_circuit = short_circuit
        self.extra_headers = extra_headers or {}
        self.response_transform = response_transform
        self.state_update = state_update


class DefenseStrategy(ABC):
    name: str
    # Stateless strategies avoid allocating one state entry per normal request.
    uses_state = True

    @abstractmethod
    async def apply(self, request: Request, params: dict, state: dict) -> DefenseResult:
        """Return effects for this request and an optional replacement client state."""
        ...
