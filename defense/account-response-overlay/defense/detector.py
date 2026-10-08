"""Authenticated metadata from a defender-owned detector; never trust a bare label."""
import hashlib
import hmac
import re
import secrets
import time
import math
from dataclasses import dataclass

from .security_store import SecurityStore


@dataclass(frozen=True)
class RouteDecision:
    route: str
    headers: dict[str, str]


class BotScoreRouter:
    """Embed in the trusted detector gateway, with stable server-side actor identities.

    Larger scores mean more likely Agent. Threshold is supplied by the detection team.
    A normal decision is routed by that gateway; this package never forwards normal traffic.
    Actor identities must remain stable across requests and worker restarts. Their
    database keys are HMACs, not raw identifiers. The store is key-scoped: key
    rotation fails closed until an explicit migration preserves existing records.
    """
    def __init__(self, secret: bytes, threshold: float, *, store_path: str, ttl=None,
                 max_actors=2048, now=time.time):
        if (not isinstance(secret, bytes) or len(secret) < 32 or not math.isfinite(threshold)
                or ttl is not None or not isinstance(max_actors, int) or max_actors <= 0):
            raise ValueError('invalid detector router configuration')
        self.secret, self.threshold, self.max_actors, self.now = secret, threshold, max_actors, now
        self.store = SecurityStore(store_path, secret)

    def decide(self, actor: str, score: float, method: str, raw_target: str, body: bytes = b'') -> RouteDecision:
        if not re.fullmatch('[A-Za-z0-9_-]{1,96}', actor):
            raise ValueError('actor must be an opaque, stable detector identity')
        actor_hash = hmac.new(self.secret, b'defense-store:actor:v1\0' + actor.encode(), hashlib.sha256).hexdigest()
        isolate = self.store.should_isolate(
            actor_hash, not math.isfinite(score) or score >= self.threshold,
            max_actors=self.max_actors, now=self.now())
        if isolate:
            return RouteDecision('isolation', sign_headers(self.secret, actor, method, raw_target, body))
        return RouteDecision('normal', {})


def sign_headers(secret: bytes, actor: str, method: str, raw_target: str, body: bytes = b'',
                 *, timestamp: int | None = None, nonce: str | None = None,
                 risk: str | None = None) -> dict[str, str]:
    """Sign a sticky Agent decision; high risk is bound into the HMAC."""
    if risk not in {None, 'high'}:
        raise ValueError('unsupported signed risk tier')
    timestamp = int(time.time()) if timestamp is None else timestamp
    nonce = secrets.token_hex(16) if nonce is None else nonce
    fields = ['agent', actor, str(timestamp), nonce, method.upper(), raw_target,
              hashlib.sha256(body).hexdigest()]
    if risk:
        fields.append(risk)
    signature = hmac.new(secret, '\n'.join(fields).encode(), hashlib.sha256).hexdigest()
    headers = {'x-defense-class': 'agent', 'x-defense-actor': actor,
            'x-defense-timestamp': str(timestamp), 'x-defense-nonce': nonce,
            'x-defense-signature': signature}
    if risk:
        headers['x-defense-risk'] = risk
    return headers


class DetectorVerifier:
    def __init__(self, secret: bytes, *, store_path: str):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError('detector secret must contain at least 32 bytes')
        self.secret = secret
        self.store = SecurityStore(store_path, secret)

    def _high_marker(self, actor: str) -> str:
        digest = hmac.new(self.secret, b'defense-store:high-risk:v1\0' + actor.encode(),
                          hashlib.sha256).hexdigest()
        return 'high:' + digest

    def mark_high_risk(self, actor: str) -> None:
        self.store.mark_high_risk(self._high_marker(actor), now=time.time())

    def is_high_risk(self, actor: str) -> bool:
        return self.store.is_high_risk(self._high_marker(actor))

    def verify(self, request, body: bytes, *, required_risk: str | None = None) -> str | None:
        # A signed field must occur exactly once; merged/first-header semantics
        # must not let two intermediaries authenticate different metadata.
        required = ('class', 'actor', 'timestamp', 'nonce', 'signature')
        h = {}
        for key in required:
            name = 'x-defense-' + key
            values = [value for header, value in request.scope.get('headers', [])
                      if header.lower() == name.encode('ascii')]
            if len(values) != 1:
                return None
            h[name] = values[0].decode('latin-1')
        risks = [value for header, value in request.scope.get('headers', [])
                 if header.lower() == b'x-defense-risk']
        if required_risk not in {None, 'high'}:
            raise ValueError('unsupported required risk tier')
        if required_risk is None and risks:
            return None
        if required_risk == 'high' and (len(risks) != 1 or risks[0] != b'high'):
            return None
        actor, timestamp, nonce = (h.get('x-defense-' + key, '') for key in ('actor', 'timestamp', 'nonce'))
        signature = h.get('x-defense-signature', '')
        now = time.time()
        if (h.get('x-defense-class') != 'agent' or not re.fullmatch('[A-Za-z0-9_-]{1,96}', actor)
                or not re.fullmatch('[0-9]{10,12}', timestamp) or not re.fullmatch('[0-9a-f]{32}', nonce)
                or not re.fullmatch('[0-9a-f]{64}', signature) or abs(now - int(timestamp)) > 30):
            return None
        try:
            target = request.scope['raw_path'].decode('ascii')
            if request.scope.get('query_string'):
                target += '?' + request.scope['query_string'].decode('ascii', errors='strict')
        except (KeyError, UnicodeError):
            return None
        expected = sign_headers(self.secret, actor, request.method, target, body,
                                timestamp=int(timestamp), nonce=nonce,
                                risk=required_risk)['x-defense-signature']
        if not hmac.compare_digest(signature, expected):
            return None
        nonce_hash = hmac.new(self.secret, b'defense-store:nonce:v1\0' + nonce.encode(), hashlib.sha256).hexdigest()
        if not self.store.consume_nonce(nonce_hash, now=now):
            return None
        return actor
