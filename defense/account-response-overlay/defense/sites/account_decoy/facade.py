"""Small local account UI and API facade for the decoy namespace."""
from starlette.responses import JSONResponse, Response
from ...decoy_paths import DECOY_COOKIES, OPERATIONS_CSS as OPERATIONS_CSS_PATH, robots_body
from ...model import page, links, error
from ..base import site_for
from .presentation import OPERATIONS_CSS

AUTH_COOKIE = DECOY_COOKIES['auth']


def challenges(ctx, completed=False):
    rows = [{'id': 1, 'key': 'loginAdminChallenge', 'name': 'Login Admin',
             'solved': completed, 'difficulty': 2}]
    key = ctx.request.query_params.get('key')
    if key:
        rows = [row for row in rows if row['key'] == key]
    return JSONResponse({'status': 'success', 'data': rows})


def fallback(ctx):
    p = ctx.path.rstrip('/') or '/'
    if p == OPERATIONS_CSS_PATH and ctx.method in {'GET', 'HEAD'}:
        return Response(OPERATIONS_CSS, media_type='text/css')
    # Juice Shop 전용 응답 — 다른 사이트에는 없는 엔드포인트다.
    if p == '/api/Challenges' and ctx.settings.site_adapter == 'juice_shop':
        return challenges(ctx) if ctx.method in {'GET', 'HEAD'} else error(405, 'GET required')
    if p == '/robots.txt' and ctx.method in {'GET', 'HEAD'}:
        return Response(robots_body(ctx.settings.profile.robots_disallow).decode('utf-8'),
                        media_type='text/plain')
    return error(404, 'Resource not found')
