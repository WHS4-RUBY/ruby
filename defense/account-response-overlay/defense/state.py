from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import hmac
import secrets
import time
import re
from .journey import JourneyState
from .cycle import CycleState


class CapacityError(Exception):
    pass


@dataclass
class Session:
    sid: str
    created: float
    requests: int = 0
    bytes_sent: int = 0
    delay_ms: int = 0
    active: int = 0
    policy: tuple[str, ...] | None = None
    authenticated: bool = False
    login_completed: bool = False
    auth_token: str = ""
    journey: JourneyState = field(default_factory=JourneyState)
    cycle: CycleState = field(default_factory=CycleState)

    def stable(self, label: str) -> str:
        return hmac.new(self.sid.encode(), label.encode(), hashlib.sha256).hexdigest()


class State:
    """Single worker. Admission updates have no awaits; active sessions cannot be evicted."""
    def __init__(self, secret: bytes, limits, now=time.monotonic):
        self.secret, self.limits, self.now = secret, limits, now
        self.sessions: OrderedDict[str, Session] = OrderedDict()
        self.peers: OrderedDict[str, tuple[float, int]] = OrderedDict()
        self.global_window = (now(), 0)
        self.inflight = 0

    def sign(self, sid: str) -> str:
        return sid + '.' + hmac.new(self.secret, sid.encode(), hashlib.sha256).hexdigest()

    def get_session(self, cookie: str | None, actor: str | None = None) -> Session:
        now = self.now()
        # Fixed absolute lifetime, checked on every request, including active old sessions.
        for sid, session in list(self.sessions.items()):
            if now - session.created >= self.limits.session_ttl and not session.active:
                del self.sessions[sid]
        if actor is not None:
            sid = hmac.new(self.secret, ('detector:' + actor).encode(), hashlib.sha256).hexdigest()[:32]
            if sid in self.sessions:
                if now - self.sessions[sid].created >= self.limits.session_ttl:
                    raise CapacityError('expired session still completing a request')
                return self.sessions[sid]
            if len(self.sessions) >= self.limits.max_sessions:
                raise CapacityError('session capacity')
            session = Session(sid, now)
            self.sessions[sid] = session
            return session
        if cookie and re.fullmatch(r"[0-9a-f]{32}\.[0-9a-f]{64}", cookie):
            sid = cookie[:32]
            if hmac.compare_digest(cookie, self.sign(sid)):
                session = self.sessions.get(sid)
                if session and now - session.created < self.limits.session_ttl:
                    return session
        if len(self.sessions) >= self.limits.max_sessions:
            raise CapacityError("session capacity")
        session = Session(secrets.token_hex(16), now)
        self.sessions[session.sid] = session
        return session

    def admit_peer(self, peer: str) -> bool:
        now = self.now()
        start, count = self.global_window
        if now - start >= 60:
            start, count = now, 0
        self.global_window = start, count + 1
        if count >= self.limits.global_rpm:
            return False
        while self.peers and now - next(iter(self.peers.values()))[0] >= 60:
            self.peers.popitem(last=False)
        key = hmac.new(self.secret, peer.encode(), hashlib.sha256).hexdigest()
        if key not in self.peers and len(self.peers) >= self.limits.max_peers:
            return False
        start, count = self.peers.get(key, (now, 0))
        if now - start >= 60:
            del self.peers[key]
            start, count = now, 0
        self.peers[key] = start, count + 1
        return count < self.limits.peer_rpm
