"""Small local account UI and API facade for the decoy namespace."""
from starlette.responses import JSONResponse, Response
from ...model import page, links, error
from ..base import site_for
from .presentation import OPERATIONS_CSS

AUTH_COOKIE = 'defense_auth'


def challenges(ctx, completed=False):
    rows = [{'id': 1, 'key': 'loginAdminChallenge', 'name': 'Login Admin',
             'solved': completed, 'difficulty': 2}]
    key = ctx.request.query_params.get('key')
    if key:
        rows = [row for row in rows if row['key'] == key]
    return JSONResponse({'status': 'success', 'data': rows})


def fallback(ctx):
    p = ctx.path.rstrip('/') or '/'
    if p == '/assets/operations.css' and ctx.method in {'GET', 'HEAD'}:
        return Response(OPERATIONS_CSS, media_type='text/css')
    if p == '/api/Challenges':
        return challenges(ctx) if ctx.method in {'GET', 'HEAD'} else error(405, 'GET required')
    if p == '/robots.txt' and ctx.method in {'GET', 'HEAD'}:
        return Response('User-agent: *\nDisallow: /ftp\n', media_type='text/plain')
    return error(404, 'Resource not found')
