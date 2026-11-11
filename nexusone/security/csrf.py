"""Session-bound CSRF token helpers."""

import secrets
from collections.abc import MutableMapping
from hmac import compare_digest

_SESSION_KEY = "_nexusone_csrf_token"


def issue_csrf_token(session: MutableMapping[str, object]) -> str:
    token = session.get(_SESSION_KEY)
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        session[_SESSION_KEY] = token
    return token


def verify_csrf_token(session: MutableMapping[str, object], supplied: object) -> bool:
    expected = session.get(_SESSION_KEY)
    if not isinstance(expected, str) or not isinstance(supplied, str):
        return False
    return bool(expected and supplied and compare_digest(expected, supplied))
