import pytest

from nexusone.app import create_app, resolve_bind_host


def test_health_and_security_headers():
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False})
    response = app.test_client().get("/api/health")
    assert response.status_code == 200
    assert response.json == {"ok": True, "service": "nexusone"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert app.config["MAX_CONTENT_LENGTH"] == 2 * 1024 * 1024


def test_mutations_require_session_csrf_token():
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False})
    app.add_url_rule("/api/test-mutation", "test_mutation", lambda: {"ok": True}, methods=["POST"])
    client = app.test_client()
    assert client.post("/api/test-mutation").status_code == 403
    token = client.get("/api/security/csrf").json["token"]
    assert client.post("/api/test-mutation", headers={"X-CSRF-Token": token}).status_code == 200


def test_untrusted_origin_is_rejected():
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False})
    app.add_url_rule("/api/test-mutation", "test_mutation", lambda: {"ok": True}, methods=["POST"])
    client = app.test_client()
    token = client.get("/api/security/csrf").json["token"]
    response = client.post("/api/test-mutation", headers={
        "X-CSRF-Token": token, "Origin": "https://attacker.example"
    })
    assert response.status_code == 403


def test_loopback_is_default_and_lan_requires_opt_in():
    assert resolve_bind_host({}) == "127.0.0.1"
    assert resolve_bind_host({"NEXUSONE_ALLOW_LAN": "1"}) == "0.0.0.0"
    assert resolve_bind_host({"NEXUSONE_ALLOW_LAN": "0"}) == "127.0.0.1"


def test_production_requires_stable_secret(monkeypatch):
    monkeypatch.setenv("NEXUSONE_ENV", "production")
    monkeypatch.delenv("NEXUSONE_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app()

\n\ndef test_rate_limit_returns_429_after_configured_budget():
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret",
        "SESSION_COOKIE_SECURE": False, "RATE_LIMIT": 1,
    })
    client = app.test_client()
    assert client.get("/api/health").status_code == 200
    response = client.get("/api/health")
    assert response.status_code == 429
    assert response.json == {"error": "Too many requests"}
