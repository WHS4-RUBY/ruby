"""전략 이름 -> 인스턴스 매핑. 새 전략은 여기에 등록만 하면 config에서 바로 쓸 수 있다."""
from .base import DefenseStrategy
from .delay import DelayStrategy
from .rate_limit import RateLimitStrictStrategy

STRATEGY_REGISTRY: dict[str, DefenseStrategy] = {
    DelayStrategy.name: DelayStrategy(),
    RateLimitStrictStrategy.name: RateLimitStrictStrategy(),
}