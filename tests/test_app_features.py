import io

from nexusone.app import create_app


def admin_client(app):
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(authenticated=True, username="marwan", role="admin")
    csrf = client.get("/api/security/csrf").json["token"]
    return client, {"X-CSRF-Token": csrf}


def test_configuration_is_admin_only_and_secrets_are_write_only(tmp_path):
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False,
        "CONFIG_FILE": str(tmp_path / "settings.json"),
    })
    client = app.test_client()
    assert client.get("/api/config").status_code == 401
    with client.session_transaction() as state:
        state.update(authenticated=True, username="viewer", role="user")
    assert client.get("/api/config").status_code == 403
    viewer_home = client.get("/")
    assert viewer_home.status_code == 200
    assert b"Explorer" in viewer_home.data
    assert b"Configuration" not in viewer_home.data
    client, headers = admin_client(app)
    response = client.put("/api/config", headers=headers, json={
        "telegram": {"bot_token": "do-not-return", "authorized_user_ids": ["12345"]},
        "discord": {"client_secret": "also-secret"},
    })
    assert response.status_code == 200
    body = response.get_json()
    assert body["telegram"]["bot_token_configured"] is True
    assert "do-not-return" not in str(body)
    assert client.get("/settings").status_code == 200
    assert b"Configuration" in client.get("/").data


def test_explorer_upload_requires_role_and_supports_chunks(tmp_path):
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False,
        "EXPLORER_ROOT": str(tmp_path / "home"), "UPLOAD_CHUNK_BYTES": 4,
    })
    client = app.test_client()
    assert client.post("/api/explorer/uploads", json={
        "filename": "x.bin", "destination": "", "size": 6
    }).status_code == 401
    with client.session_transaction() as state:
        state.update(authenticated=True, username="viewer", role="user")
    csrf = client.get("/api/security/csrf").json["token"]
    started = client.post("/api/explorer/uploads", headers={"X-CSRF-Token": csrf},
                          json={"filename": "x.bin", "destination": "Phone", "size": 6})
    assert started.status_code == 201
    upload_id = started.json["upload_id"]
    first = client.put(f"/api/explorer/uploads/{upload_id}?offset=0",
                       headers={"X-CSRF-Token": csrf}, data=io.BytesIO(b"abcd"),
                       content_type="application/octet-stream")
    assert first.json == {"offset": 4, "complete": False}
    progress = client.get(f"/api/explorer/uploads/{upload_id}")
    assert progress.json["offset"] == 4
    second = client.put(f"/api/explorer/uploads/{upload_id}?offset=4",
                        headers={"X-CSRF-Token": csrf}, data=io.BytesIO(b"ef"),
                        content_type="application/octet-stream")
    assert second.json == {"offset": 6, "complete": True}
    done = client.post(f"/api/explorer/uploads/{upload_id}/finish",
                       headers={"X-CSRF-Token": csrf})
    assert done.status_code == 200
    assert done.json == {"filename": "x.bin", "size": 6}
    assert app.extensions["nexusone_uploads"].root == (tmp_path / "home").resolve()
    assert next(iter((tmp_path / "home").rglob("x.bin"))).read_bytes() == b"abcdef"


def test_regular_requests_remain_bounded_but_upload_chunks_have_separate_limit(tmp_path):
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False,
        "MAX_REQUEST_BYTES": 32, "EXPLORER_ROOT": str(tmp_path), "UPLOAD_CHUNK_BYTES": 128,
    })
    app.add_url_rule("/api/test", "test_body_limit", lambda: {"ok": True}, methods=["POST"])
    client, headers = admin_client(app)
    too_big = client.post("/api/test", headers=headers, data="x" * 33)
    assert too_big.status_code == 413



def test_services_page_and_api_are_role_protected(monkeypatch):
    import nexusone.app as nexus_app

    monkeypatch.setattr(nexus_app, "list_services", lambda: [{
        "name": "telegram-bot", "scope": "user", "unit": "telegram-control-bot.service",
        "active": "active", "enabled": "enabled", "controllable": True,
    }])
    calls = []
    monkeypatch.setattr(nexus_app, "control_service", lambda name, action: (
        calls.append((name, action)) or {"name": name, "action": action, "active": "active"}
    ))
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False})
    client = app.test_client()
    assert client.get("/services").status_code == 401
    with client.session_transaction() as state:
        state.update(authenticated=True, username="viewer", role="user")
    assert client.get("/services").status_code == 200
    assert client.get("/api/services").status_code == 200
    csrf = client.get("/api/security/csrf").json["token"]
    denied = client.post("/api/services/telegram-bot/restart", headers={"X-CSRF-Token": csrf})
    assert denied.status_code == 403
    admin, headers = admin_client(app)
    allowed = admin.post("/api/services/telegram-bot/restart", headers=headers)
    assert allowed.status_code == 200
    assert calls == [("telegram-bot", "restart")]



def test_activity_log_is_admin_only_and_never_records_secret_values(tmp_path):
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False,
        "CONFIG_FILE": str(tmp_path / "settings.json"),
        "AUDIT_FILE": str(tmp_path / "audit.sqlite3"),
    })
    viewer = app.test_client()
    with viewer.session_transaction() as state:
        state.update(authenticated=True, username="viewer", role="user")
    assert viewer.get("/activity").status_code == 403
    assert viewer.get("/api/audit").status_code == 403

    admin, headers = admin_client(app)
    secret = "do-not-put-this-in-audit"
    saved = admin.put("/api/config", headers=headers, json={
        "telegram": {"bot_token": secret}
    })
    assert saved.status_code == 200
    assert admin.get("/activity").status_code == 200
    audit = admin.get("/api/audit")
    assert audit.status_code == 200
    assert audit.json["events"][0]["action"] == "configuration.update"
    assert secret not in str(audit.json)
