from dataclasses import dataclass, field
import os
from pathlib import Path
import math
import re
import tomllib
from .site_profile import SiteProfile, default_site_profile, load_site_profile


@dataclass(frozen=True)
class Limits:
    request_bytes: int = 65_536
    response_bytes: int = 8_388_608
    url_bytes: int = 2_048
    header_bytes: int = 16_384
    concurrent: int = 32
    session_concurrent: int = 1
    peer_rpm: int = 180
    global_rpm: int = 3_600
    max_peers: int = 4_096
    max_sessions: int = 2_048
    session_ttl: int = 21_600
    session_requests: int = 1_000
    session_bytes: int = 67_108_864
    session_delay_ms: int = 5_000
    request_seconds: float = 8.0
    audit_rows: int = 50_000


@dataclass(frozen=True)
class EngagementConfig:
    rounds: int = 8
    stages: int = 4
    candidates: int = 3


@dataclass(frozen=True)
class CycleConfig:
    candidates: int = 3
    history: int = 3


@dataclass(frozen=True)
class Settings:
    modules: tuple[str, ...] = ("cycle",)
    origin_policy: str = "sealed"
    origin: str = ""  # Embedded decoy has no origin client; overlay.py owns the fixed upstream.
    static_paths: tuple[str, ...] = ()
    site_adapter: str = "juice_shop"
    profile: SiteProfile = field(default_factory=default_site_profile)
    frontend_dir: str = ""
    secure_cookie: bool = False
    run_id: str = "local"
    audit_path: str = "state/events.sqlite3"
    detector_required: bool = False
    limits: Limits = field(default_factory=Limits)
    engagement: EngagementConfig = field(default_factory=EngagementConfig)
    cycle: CycleConfig = field(default_factory=CycleConfig)

    def __post_init__(self):
        if self.modules not in {('unified',), ('cycle',)}:
            raise ValueError('Choose exactly one account policy: unified (V1) or cycle (V2)')
        if self.limits.session_requests > 1_000_000:
            raise ValueError('A finite session request budget <= 1000000 is required')
        c = self.cycle
        if any(type(v) is not int for v in vars(c).values()) or not 2 <= c.candidates <= 5 or not 0 <= c.history <= 16:
            raise ValueError("cycle bounds: integer candidates 2..5, history 0..16")
        e = self.engagement
        if any(type(v) is not int for v in vars(e).values()):
            raise ValueError("engagement settings must be integers")
        if not 1 <= e.rounds <= 16 or not 3 <= e.stages <= 8 or not 2 <= e.candidates <= 5:
            raise ValueError("engagement bounds: rounds 1..16, stages 3..8, candidates 2..5")
        if self.origin_policy != "sealed" or self.origin or self.static_paths:
            raise ValueError("Only sealed isolation is supported; origin/static forwarding was removed")
        if self.site_adapter not in {'juice_shop', 'generic'}:
            raise ValueError('Unknown site adapter')
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", self.run_id):
            raise ValueError("invalid run_id")
        if any(type(v) is not bool for v in (self.secure_cookie, self.detector_required)):
            raise ValueError("cookie/detector flags must be boolean")
        for name, value in vars(self.limits).items():
            if type(value) not in {int, float} or not math.isfinite(value) or value <= 0:
                raise ValueError(f"limits.{name} must be finite and positive")
            if name != "request_seconds" and type(value) is not int:
                raise ValueError(f"limits.{name} must be an integer")
        ceilings = {"request_bytes": 1_048_576, "response_bytes": 8_388_608,
                    "concurrent": 128, "max_sessions": 10_000, "max_peers": 20_000,
                    "audit_rows": 100_000, "request_seconds": 30, "session_delay_ms": 30_000}
        for name, ceiling in ceilings.items():
            if getattr(self.limits, name) > ceiling:
                raise ValueError(f"limits.{name} exceeds hard ceiling {ceiling}")
        if self.limits.session_concurrent > self.limits.concurrent:
            raise ValueError('session_concurrent exceeds global concurrent limit')
        if self.limits.response_bytes < 4096 or self.limits.session_bytes < self.limits.response_bytes:
            raise ValueError("response_bytes >= 4096 and session_bytes >= response_bytes required")


def load(path: str) -> Settings:
    source = Path(path).resolve()
    data = tomllib.loads(source.read_text())
    if profile_path := data.pop('site_profile', None):
        profile_path = Path(profile_path)
        data['profile'] = load_site_profile(str(profile_path if profile_path.is_absolute()
                                                else source.parent / profile_path))
    # 감사·미끼 링이 공유하는 텔레메트리 DB. 보안 저장소와는 파일을 공유하지 않는다.
    telemetry = os.environ.get('DEFENSE_TELEMETRY_DB', '').strip()
    if telemetry:
        data['audit_path'] = telemetry
    # TLS 게이트웨이 뒤에서는 가짜 세션 쿠키도 Secure 여야 한다. 예전에는 이 한 값
    # 때문에 decoy-server-v1/v2 와 overlay-server-v1/v2 네 파일이 따로 있었다.
    secure = os.environ.get('OVERLAY_SECURE_COOKIE', '').strip().lower()
    if secure in {'true', '1', 'yes'}:
        data['secure_cookie'] = True
    elif secure in {'false', '0', 'no'}:
        data['secure_cookie'] = False
    elif secure:
        raise ValueError('OVERLAY_SECURE_COOKIE must be true or false')
    data["limits"] = Limits(**data.get("limits", {}))
    data["engagement"] = EngagementConfig(**data.get("engagement", {}))
    data["cycle"] = CycleConfig(**data.get("cycle", {}))
    for key in ("modules", "static_paths"):
        if key in data:
            data[key] = tuple(data[key])
    return Settings(**data)
