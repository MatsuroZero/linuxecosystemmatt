"""Minimal Flask app with NexusOne's shared security defaults."""

import os
import secrets

from flask import Flask, abort, jsonify, request, session

from nexusone.security.csrf import issue_csrf_token, verify_csrf_token
from nexusone.security.rate_limit import RateLimiter

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def resolve_bind_host(environ=None) -> str:
    values = os.environ if environ is None else environ
    if values.get("NEXUSONE_ALLOW_LAN", "").strip().lower() not in {"1", "true", "yes"}:
        return "127.0.0.1"
    return values.get("NEXUSONE_BIND_HOST", "0.0.0.0").strip() or "0.0.0.0"


def create_app(config=None) -> Flask:
    app = Flask(__name__)
    supplied = dict(config or {})
    secret = supplied.pop("SECRET_KEY", None) or os.environ.get("NEXUSONE_SECRET_KEY")
    if not secret:
        if os.environ.get("NEXUSONE_ENV", "development").lower() == "production":
            raise RuntimeError("NEXUSONE_SECRET_KEY must be configured in production")
        secret = secrets.token_hex(32)

    app.config.update(
        SECRET_KEY=secret, MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("NEXUSONE_COOKIE_SECURE", "1") != "0",
        TRUSTED_ORIGINS=(), RATE_LIMIT=120, RATE_WINDOW_SECONDS=60,
    )
    app.config.update(supplied)
    limiter = RateLimiter(int(app.config["RATE_LIMIT"]), float(app.config["RATE_WINDOW_SECONDS"]))

    @app.before_request
    def enforce_request_security():
        if not limiter.allow(request.remote_addr or "unknown"):
            abort(429, description="Too many requests")
        if request.method not in _MUTATING:
            return
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            if origin.rstrip("/") not in set(app.config["TRUSTED_ORIGINS"]):
                abort(403, description="Untrusted request origin")
        if not verify_csrf_token(session, request.headers.get("X-CSRF-Token")):
            abort(403, description="CSRF validation failed")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy",
                                    "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        return response

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="Request body is too large"), 413

    @app.errorhandler(429)
    def rate_limited(_error):
        return jsonify(error="Too many requests"), 429

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify(error=getattr(error, "description", "Forbidden")), 403

    @app.get("/api/health")
    def health():
        return jsonify(ok=True, service="nexusone")

    @app.get("/api/security/csrf")
    def csrf():
        return jsonify(token=issue_csrf_token(session))

    return app


def main():
    app = create_app()
    host = resolve_bind_host()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        app.logger.warning("LAN binding is enabled; use HTTPS, firewall restrictions, and strong authentication.")
    app.run(host=host, port=int(os.environ.get("NEXUSONE_PORT", "7171")), debug=False)


if __name__ == "__main__":
    main()
