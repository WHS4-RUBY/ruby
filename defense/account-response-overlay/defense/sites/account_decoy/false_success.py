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
        account_root = ctx.settings.profile.login_path.rsplit('/', 1)[0]
        routes = {ctx.settings.profile.login_path, account_root + '/whoami',
                  account_root + '/logout', account_root + '/authentication-details'}
        if ctx.settings.site_adapter == 'juice_shop':
            routes.update({'/api/Users', '/api/Users/1', '/api/Challenges',
                           '/rest/saveLoginIp', '/rest/deluxe-membership', '/rest/basket/1'})
        if p not in routes:
            return None
        header = ctx.request.headers.get('authorization', '').encode('utf-8')
        cookie = ctx.request.cookies.get(AUTH_COOKIE, '').encode('utf-8')
        frontend_token = ctx.request.cookies.get('token', '').encode('utf-8')
        authenticated = bool(s.authenticated and s.auth_token and (
            hmac.compare_digest(header, ('Bearer ' + s.auth_token).encode()) or
            (hmac.compare_digest(cookie, s.auth_token.encode()) and
             hmac.compare_digest(frontend_token, s.auth_token.encode()))))
        if p == ctx.settings.profile.login_path:
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
        if p == '/api/Challenges':
            return challenges(ctx, s.login_completed)
        if not authenticated:
            return error(401, 'Authentication required')
        if p == '/rest/basket/1':
            return JSONResponse({'status': 'success', 'data': {'id': 1, 'Products': []}})
        if p == '/rest/deluxe-membership':
            return JSONResponse({'status': 'success', 'data': False})
        if p == '/rest/saveLoginIp':
            return JSONResponse({'status': 'success'})
        return JSONResponse({'status': 'success', 'data': self.user(ctx) if p == '/api/Users/1' else [self.user(ctx)]})

    async def on_response(self, ctx):
        if ctx.meta.get('synthetic_result', {}).get('goal') == 'admin_login':
            ctx.session.login_completed = True
