"""Small detector-side header contract; this module never sends a request."""
from http.cookies import SimpleCookie, CookieError

ISOLATION_COOKIES = frozenset({'defense_session', 'defense_auth', 'token'})


def overlay_headers(client_headers, signed_headers):
    """Carry normal browser context to the Agent overlay, with trusted labels.

    Unlike isolation_headers, this intentionally keeps origin credentials. The
    overlay forwards them to the real site on non-decoy paths. Its inner decoy
    call uses isolation_headers so those credentials never reach fake records.
    """
    blocked = {'host', 'connection', 'keep-alive', 'proxy-authenticate',
               'proxy-authorization', 'te', 'trailer', 'transfer-encoding',
               'upgrade', 'content-length'}
    result = [(name, value) for name, value in client_headers
              if name.lower() not in blocked and not name.lower().startswith(('x-defense-', 'x-forwarded-'))]
    result.extend(signed_headers.items())
    return result


def isolation_headers(client_headers, signed_headers):
    """Allow only response-format metadata and this decoy's cookies to isolation.

    The gateway must pass the same method, raw target and body it signed. Host is
    generated from the fixed isolation upstream. Never reuse an HTTP client's
    cross-actor cookie jar. Caller handles failures with an error, not origin.
    Production Authorization, other cookies, forwarding headers and client-supplied
    detector labels are intentionally excluded. V1's defense_auth cookie lets its
    synthetic session work without forwarding a production bearer token.
    """
    result, seen, cookie_parts = {}, set(), []
    for name, value in client_headers:
        name = name.lower()
        if name in {'accept', 'content-type'}:
            if name in seen:
                raise ValueError('Duplicate representation header')
            seen.add(name)
            result[name] = value
        elif name == 'cookie':
            cookie_parts.append(value)
    cookies = SimpleCookie()
    try:
        # Parse each selected pair separately to detect duplicate decoy cookies.
        for part in ';'.join(cookie_parts).split(';'):
            name, separator, value = part.strip().partition('=')
            if name not in ISOLATION_COOKIES:
                continue
            if not separator or name in cookies:
                raise ValueError('Ambiguous isolation cookie')
            parsed = SimpleCookie()
            parsed.load(part.strip())
            if name not in parsed:
                raise ValueError('Malformed isolation cookie')
            cookies[name] = parsed[name].value
    except CookieError as exc:
        raise ValueError('Malformed isolation cookie') from exc
    # Angular removes its readable token cookie when logging out. Forward it only
    # when it matches the decoy-issued HttpOnly credential, never an origin token.
    if 'token' in cookies and ('defense_auth' not in cookies or
                               cookies['token'].value != cookies['defense_auth'].value):
        del cookies['token']
    if cookies:
        result['cookie'] = '; '.join(m.OutputString() for m in cookies.values())
    result.update(signed_headers)
    result['accept-encoding'] = 'identity'
    return result
