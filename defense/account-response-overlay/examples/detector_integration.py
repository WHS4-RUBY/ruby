"""Routing contract for the detection team's existing reverse proxy.

This example plans routing and headers. The gateway supplies HTTP transport and
must send the exact method, raw target and body it signed.
"""
from dataclasses import dataclass
from defense.detector import BotScoreRouter, sign_headers
from defense.gateway_contract import overlay_headers


@dataclass(frozen=True)
class UpstreamPlan:
    upstream: str
    route: str
    headers: list[tuple[str, str]]


def plan_overlay_request(router: BotScoreRouter, *, actor: str, score: float,
                         method: str, raw_target: str, body: bytes,
                         client_headers: list[tuple[str, str]],
                         origin_upstream: str, overlay_upstream: str) -> UpstreamPlan:
    """Route sticky Agent traffic to the response overlay, not sealed isolation."""
    decision = router.decide(actor, score, method, raw_target, body)
    if decision.route == 'isolation':
        return UpstreamPlan(overlay_upstream, 'overlay',
                            overlay_headers(client_headers, decision.headers))
    # The normal gateway must still perform its established header hygiene and
    # authorization checks; this is only a routing example.
    headers = [(k, v) for k, v in client_headers if not k.lower().startswith('x-defense-')]
    return UpstreamPlan(origin_upstream, 'normal', headers)


def plan_high_risk_request(*, secret: bytes, actor: str, method: str,
                           raw_target: str, body: bytes,
                           client_headers: list[tuple[str, str]],
                           overlay_upstream: str) -> UpstreamPlan:
    """Trusted detector's confirmed high-risk branch; same proxy, sealed handler."""
    signed = sign_headers(secret, actor, method, raw_target, body, risk='high')
    return UpstreamPlan(overlay_upstream, 'high_isolation',
                        overlay_headers(client_headers, signed))
