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
    # 프로파일이 선언한 사이트에만 있는 엔드포인트. 선언이 없으면 404 로 떨어진다 —
    # 없는 엔드포인트를 만들어 주지 않는다.
    challenge_api = ctx.settings.profile.challenge_api
    if challenge_api and p == challenge_api:
        return challenges(ctx) if ctx.method in {'GET', 'HEAD'} else error(405, 'GET required')
    if p == '/robots.txt' and ctx.method in {'GET', 'HEAD'}:
        return Response(robots_body(ctx.settings.profile.robots_disallow).decode('utf-8'),
                        media_type='text/plain')
    return error(404, 'Resource not found')
