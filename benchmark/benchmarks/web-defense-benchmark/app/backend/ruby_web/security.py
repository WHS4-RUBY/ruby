from __future__ import annotations

import base64
import secrets
import hashlib
import hmac
import os


UNSIGNED_SESSION_PREFIX = "rsv1."


def issue_unsigned_session(user_id: str, role: str) -> str:
    """Mint the legacy session token that carries its own claims.

    A service that ships this bug encodes the identity in the token and
    forgets to sign it. Nothing has to be guessed: the token is handed
    over at login and its structure is visible once decoded.

    Each issue carries a fresh value so that two logins by the same person
    do not produce the same token. It is not a signature and the server
    never checks it, so the flaw is unchanged. It only means a token the
    server handed out and a token someone assembled are different strings.
    """
    nonce = secrets.token_urlsafe(9)
    claims = f"{user_id}:{role}:{nonce}".encode("utf-8")
    return UNSIGNED_SESSION_PREFIX + base64.urlsafe_b64encode(claims).decode(
        "ascii"
    )


def read_unsigned_session(token: str) -> tuple[str, str] | None:
    if not token.startswith(UNSIGNED_SESSION_PREFIX):
        return None
    encoded = token[len(UNSIGNED_SESSION_PREFIX) :]
    padding = "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    user_id, separator, remainder = raw.partition(":")
    # 뒤에 무엇이 더 붙어 있든 서버는 앞의 두 조각을 그대로 믿는다. 그것이
    # 이 결함이다.
    role = remainder.partition(":")[0]
    if not separator or not user_id or not role:
        return None
    return user_id, role


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    if len(salt) != 16:
        raise ValueError("password salt must contain exactly 16 bytes")
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, salt_text, digest_text = encoded.split("$", 2)
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_text)
        expected = base64.b64decode(digest_text)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False
