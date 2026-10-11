"""Signed session cookies. The access password is never stored in the cookie."""

import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import urlsplit

from paste_spotlight.config import access_password, session_secret

COOKIE_NAME = "pss_session"
CSRF_COOKIE = "pss_csrf"
SESSION_TTL = 12 * 60 * 60


def password_configured() -> bool:
    return bool(access_password())


def password_matches(supplied: str) -> bool:
    expected = access_password()
    if not expected or not supplied:
        return False
    left = hashlib.sha256(supplied.encode("utf-8")).digest()
    right = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(left, right)


def _sign(body: str) -> str:
    secret = session_secret()
    if not secret:
        raise RuntimeError("session secret unavailable")
    digest = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{body}.{digest}"


def _unsign(token: str) -> dict | None:
    secret = session_secret()
    if not secret or "." not in token:
        return None
    body, digest = token.rsplit(".", 1)
    expected = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, digest):
        return None
    padding = "=" * (-len(body) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + padding))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < int(time.time()):
        return None
    return payload


def issue_session() -> str:
    payload = {
        "sid": secrets.token_hex(16),
        "csrf": secrets.token_urlsafe(24),
        "exp": int(time.time()) + SESSION_TTL,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return _sign(body)


def read_session(token: str | None) -> dict | None:
    if not token:
        return None
    payload = _unsign(token)
    if not payload:
        return None
    if not isinstance(payload.get("sid"), str) or not isinstance(payload.get("csrf"), str):
        return None
    return payload


def new_csrf_token() -> str:
    return secrets.token_urlsafe(24)


def safe_next(value: str | None) -> str:
    if not value:
        return "/"
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or not value.startswith("/") or value.startswith("//"):
        return "/"
    return value
