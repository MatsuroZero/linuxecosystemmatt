"""Same-origin WSGI gateway for mounting NexusOne inside the legacy dashboard.

The legacy dashboard keeps ownership of its existing routes and login page.
NexusOne is mounted at /nexusone, while its API is mounted at /nexusone-api.
Both apps share the dashboard's signed session cookie and signing key.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from typing import Any

from flask import Flask

_UI_PREFIX = "/nexusone"
_API_PREFIX = "/nexusone-api"
_HTML_INJECT = (
    '<script>(function(){'
    'const nativeFetch=window.fetch.bind(window);'
    'window.fetch=function(input,init){'
    'if(typeof input==="string"&&input.startsWith("/api/"))'
    'input="/nexusone-api"+input;'
    'return nativeFetch(input,init);'
    '};'
    '})();</script>'
)


def _is_loopback(remote_addr: str | None) -> bool:
    try:
        return ipaddress.ip_address(remote_addr or "").is_loopback
    except ValueError:
        return False


class NexusOneGateway:
    """Dispatch NexusOne UI/API paths without changing legacy route behavior."""

    def __init__(
        self,
        legacy_wsgi: Callable,
        nexusone_wsgi: Callable,
        *,
        allow_lan: bool = False,
    ):
        self.legacy_wsgi = legacy_wsgi
        self.nexusone_wsgi = nexusone_wsgi
        self.allow_lan = allow_lan

    @staticmethod
    def _mount(environ: dict[str, Any], prefix: str) -> dict[str, Any]:
        mounted = environ.copy()
        path = str(mounted.get("PATH_INFO", "/"))
        remainder = path[len(prefix):]
        mounted["SCRIPT_NAME"] = str(mounted.get("SCRIPT_NAME", "")) + prefix
        mounted["PATH_INFO"] = remainder or "/"
        return mounted

    @staticmethod
    def _rewrite_html(body: bytes, headers: list[tuple[str, str]]) -> tuple[bytes, list[tuple[str, str]]]:
        try:
            html = body.decode("utf-8")
        except UnicodeDecodeError:
            return body, headers

        # The UI templates use root-relative links. Keep them inside the UI mount.
        html = re.sub(
            r'href="/(?!nexusone(?:/|"))',
            'href="/nexusone/',
            html,
        )
        if "<meta charset=\"utf-8\">" in html:
            html = html.replace(
                '<meta charset="utf-8">',
                '<meta charset="utf-8">' + _HTML_INJECT,
                1,
            )
        rewritten = html.encode("utf-8")
        filtered = [
            (key, value) for key, value in headers
            if key.lower() not in {"content-length", "etag", "content-md5"}
        ]
        filtered.append(("Content-Length", str(len(rewritten))))
        return rewritten, filtered

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        path = str(environ.get("PATH_INFO", "/"))
        if path == _UI_PREFIX or path.startswith(_UI_PREFIX + "/"):
            prefix = _UI_PREFIX
            ui = True
        elif path == _API_PREFIX or path.startswith(_API_PREFIX + "/"):
            prefix = _API_PREFIX
            ui = False
        else:
            return self.legacy_wsgi(environ, start_response)

        remote = environ.get("REMOTE_ADDR")
        scheme = str(environ.get("wsgi.url_scheme", "http"))
        if not _is_loopback(str(remote or "")):
            if not self.allow_lan:
                body = b"NexusOne is available on this machine only."
                start_response("403 Forbidden", [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    ("Content-Length", str(len(body))),
                    ("Cache-Control", "no-store"),
                ])
                return [body]
            if scheme != "https":
                body = b"HTTPS is required for LAN access to NexusOne."
                start_response("403 Forbidden", [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    ("Content-Length", str(len(body))),
                    ("Cache-Control", "no-store"),
                ])
                return [body]

        mounted = self._mount(environ, prefix)
        if not ui:
            return self.nexusone_wsgi(mounted, start_response)

        captured: dict[str, Any] = {}
        writes: list[bytes] = []

        def capture_start_response(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = list(headers)
            return writes.append

        iterable = self.nexusone_wsgi(mounted, capture_start_response)
        try:
            body = b"".join([*writes, *iterable])
        finally:
            close = getattr(iterable, "close", None)
            if close:
                close()

        headers = captured.get("headers", [])
        content_type = next(
            (value for key, value in headers if key.lower() == "content-type"), ""
        )
        if content_type.lower().startswith("text/html"):
            body, headers = self._rewrite_html(body, headers)
        start_response(captured.get("status", "500 Internal Server Error"), headers)
        return [body]


def install_nexusone_gateway(
    legacy_app: Flask,
    config: dict[str, Any] | None = None,
    *,
    allow_lan: bool = False,
) -> Flask:
    """Create and mount NexusOne, requiring the legacy auth DB path explicitly.

    Pass the legacy app's SECRET_KEY and actual dashboard auth database path.
    This avoids silently trusting a signed session without checking the live
    dashboard account database.
    """
    from nexusone.app import create_app

    settings = dict(config or {})
    settings.setdefault("SECRET_KEY", legacy_app.secret_key)
    settings.setdefault(
        "SESSION_COOKIE_NAME",
        legacy_app.config.get("SESSION_COOKIE_NAME", "session"),
    )
    if not settings.get("DASHBOARD_AUTH_DB"):
        raise RuntimeError(
            "DASHBOARD_AUTH_DB must point to the legacy dashboard's users database"
        )
    nexusone_app = create_app(settings)
    legacy_app.wsgi_app = NexusOneGateway(
        legacy_app.wsgi_app,
        nexusone_app.wsgi_app,
        allow_lan=allow_lan,
    )
    legacy_app.extensions["nexusone_app"] = nexusone_app
    return nexusone_app
