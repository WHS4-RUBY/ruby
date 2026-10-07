"""Local-only gateway: treat every request as an already detected Agent.

Do not deploy this on a public interface or use it as a real detection service.
The dedicated Compose stack publishes it only on 127.0.0.1.
"""
from pathlib import Path
import os
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from starlette.responses import Response

from .core import METHODS
from .detector import sign_headers
from .gateway_contract import overlay_headers

HOP_HEADERS = frozenset({'connection', 'proxy-connection', 'keep-alive', 'proxy-authenticate',
                         'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade'})


def create_lab_gateway(*, overlay_url: str, detector_secret: bytes,
                       actor: str = 'live-lab-agent',
                       risk: str = 'medium',
                       transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    parsed = urlsplit(overlay_url)
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username
            or parsed.password or parsed.path not in {'', '/'} or parsed.query or parsed.fragment):
        raise ValueError('overlay_url must be a fixed HTTP(S) origin')
    if len(detector_secret) < 32:
        raise ValueError('detector secret must contain at least 32 bytes')
    if risk not in {'medium', 'high'}:
        raise ValueError('risk must be medium or high')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None,
                  redirect_slashes=False)

    @app.api_route('/{path:path}', methods=sorted(METHODS))
    async def already_detected_agent(request: Request, path: str):
        try:
            raw_path = request.scope['raw_path'].decode('ascii')
            raw_query = request.scope.get('query_string', b'').decode('ascii')
        except UnicodeError:
            return Response('Invalid target', status_code=400)
        target = raw_path + ('?' + raw_query if raw_query else '')
        body = await request.body()
        if len(body) > 1_048_576:
            return Response('Request too large', status_code=413)
        signed = sign_headers(detector_secret, actor, request.method, target, body,
                              risk='high' if risk == 'high' else None)
        client_headers = [(key.decode('latin-1'), value.decode('latin-1'))
                          for key, value in request.scope.get('headers', [])]
        forwarded = overlay_headers(client_headers, signed)
        url = httpx.URL(overlay_url).copy_with(raw_path=target.encode('ascii'))
        try:
            async with httpx.AsyncClient(transport=transport, trust_env=False,
                                         follow_redirects=False, timeout=15) as client:
                async with client.stream(request.method, url, headers=forwarded,
                                         content=body) as upstream:
                    chunks, size = [], 0
                    async for chunk in upstream.aiter_raw():
                        size += len(chunk)
                        if size > 16_777_216:
                            return Response('Upstream response too large', status_code=502)
                        chunks.append(chunk)
                    response = Response(content=b'' if request.method == 'HEAD' else b''.join(chunks),
                                        status_code=upstream.status_code)
                    connection_tokens = {item.strip().lower()
                                         for value in upstream.headers.get_list('connection')
                                         for item in value.split(',')}
                    response.raw_headers = [(key, value) for key, value in upstream.headers.raw
                                            if key.decode('latin-1').lower()
                                            not in HOP_HEADERS | connection_tokens]
                    return response
        except (httpx.HTTPError, OSError):
            return Response('Overlay unavailable', status_code=502)

    return app


def app_factory() -> FastAPI:
    return create_lab_gateway(
        overlay_url=os.environ.get('LIVE_LAB_OVERLAY_URL', 'http://response-overlay:8080'),
        detector_secret=Path(os.environ.get('DEFENSE_DETECTOR_SECRET_FILE',
                                            '/app/state/detector.key')).read_bytes(),
        actor=os.environ.get('LIVE_LAB_ACTOR', 'live-lab-agent'),
        risk=os.environ.get('LIVE_LAB_RISK', 'medium'),
    )
