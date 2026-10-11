"""V1's account outcome, called only after the unified prerequisite gate."""
import base64
import hmac
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from starlette.responses import JSONResponse
from ...model import ProxyHook, error
from .facade import AUTH_COOKIE, challenges


# 프로파일의 synthetic_success 가 고를 수 있는 응답 종류. 프로파일은 "어느 경로에 어느
# 종류" 만 고르고 본문은 여기서 만든다 — 응답 본문을 TOML 에 적으면 설정이 코드가 된다.
# 이 집합이 site_profile.SYNTHETIC_RESPONSE_KINDS 와 같은지는 테스트가 강제한다.
SYNTHETIC_RESPONSES = {
    'ack': lambda hook, ctx: {'status': 'success'},
    'deluxe_denied': lambda hook, ctx: {'status': 'success', 'data': False},
    'empty_basket': lambda hook, ctx: {'status': 'success',
                                       'data': {'id': hook.uid, 'Products': []}},
    'user_list': lambda hook, ctx: {'status': 'success', 'data': [hook.user(ctx)]},
    'user_object': lambda hook, ctx: {'status': 'success', 'data': hook.user(ctx)},
}


class FalseSuccess(ProxyHook):
    uid = 1

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def user(self, ctx):
        return {'id': self.uid, 'email': ctx.settings.profile.decoy_admin_email, 'role': 'admin',
                'username': '', 'profileImage': ctx.settings.profile.decoy_profile_image}

    def token(self, ctx, ttl):
        def encode(data):
            return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).rstrip(b'=')
        now = int(time.time())
        message = encode({'alg': 'RS256', 'typ': 'JWT'}) + b'.' + encode(
            {'iss': 'sealed-account-defense', 'status': 'success', 'data': self.user(ctx),
             'bid': self.uid, 'iat': now, 'exp': now + ttl})
        signature = self.key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return (message + b'.' + base64.urlsafe_b64encode(signature).rstrip(b'=')).decode()

    async def on_request(self, ctx):
        s, p, method = ctx.session, ctx.path.rstrip('/'), ctx.method
        profile = ctx.settings.profile
        account_root = profile.login_path.rsplit('/', 1)[0]
        # 프로파일이 선언한 것만 가로챈다. 선언이 없는 사이트에서는 로그인 경로에서
        # 파생되는 네 라우트만 미끼가 응답한다 — 없는 엔드포인트를 만들어 주지 않는다.
        synthetic = dict(profile.synthetic_success)
        routes = {profile.login_path, account_root + '/whoami',
                  account_root + '/logout', account_root + '/authentication-details'}
        routes.update(synthetic)
        if profile.challenge_api:
            routes.add(profile.challenge_api)
        if p not in routes:
            return None
        header = ctx.request.headers.get('authorization', '').encode('utf-8')
        cookie = ctx.request.cookies.get(AUTH_COOKIE, '').encode('utf-8')
        frontend_token = ctx.request.cookies.get('token', '').encode('utf-8')
        authenticated = bool(s.authenticated and s.auth_token and (
            hmac.compare_digest(header, ('Bearer ' + s.auth_token).encode()) or
            (hmac.compare_digest(cookie, s.auth_token.encode()) and
             hmac.compare_digest(frontend_token, s.auth_token.encode()))))
        if p == profile.login_path:
            # UnifiedDefense already checks all completed stages and exact issued credentials.
            if method != 'POST':
                return error(405, 'POST required')
            s.authenticated = True
            s.auth_token = s.auth_token or self.token(ctx, ctx.settings.limits.session_ttl)
            ctx.meta['synthetic_result'] = {'goal': 'admin_login', 'state': 'authenticated'}
            response = JSONResponse({'authentication': {'token': s.auth_token, 'bid': self.uid,
                                                        'umail': self.user(ctx)['email']}})
            # Distinct namespace lets the gateway strip production Authorization/cookies.
            response.set_cookie(AUTH_COOKIE, s.auth_token, httponly=True, samesite='strict',
                                secure=ctx.settings.secure_cookie, path='/',
                                max_age=ctx.settings.limits.session_ttl)
            response.set_cookie('token', s.auth_token, httponly=False, samesite='strict',
                                secure=ctx.settings.secure_cookie, path='/',
                                max_age=ctx.settings.limits.session_ttl)
            return response
        if p == account_root + '/logout':
            if method != 'POST':
                return error(405, 'POST required')
            s.authenticated, s.auth_token = False, ''
            response = JSONResponse({'status': 'logged_out'})
            response.delete_cookie(AUTH_COOKIE, path='/', secure=ctx.settings.secure_cookie,
                                   httponly=True, samesite='strict')
            response.delete_cookie('token', path='/', secure=ctx.settings.secure_cookie, samesite='strict')
            return response
        if method not in {'GET', 'HEAD'}:
            return error(405, 'GET required')
        if p == account_root + '/whoami':
            return JSONResponse({'user': self.user(ctx) if authenticated else {}})
        # 챌린지 응답은 인증 검사보다 **먼저** 처리된다 — 원본 앱에서도 인증 없이
        # 조회되는 엔드포인트라 미끼가 거기서 401 을 주면 위장이 깨진다.
        if profile.challenge_api and p == profile.challenge_api:
            return challenges(ctx, s.login_completed)
        if not authenticated:
            return error(401, 'Authentication required')
        # 로그인 경로에서 파생되는 이 라우트는 프로파일이 선언하지 않는다. 리팩토링
        # 이전에는 분기 끝의 catch-all 이 사용자 목록을 돌려줬으므로 그 모양을 유지한다.
        if p == account_root + '/authentication-details':
            return JSONResponse(SYNTHETIC_RESPONSES['user_list'](self, ctx))
        return JSONResponse(SYNTHETIC_RESPONSES[synthetic[p]](self, ctx))

    async def on_response(self, ctx):
        if ctx.meta.get('synthetic_result', {}).get('goal') == 'admin_login':
            ctx.session.login_completed = True
