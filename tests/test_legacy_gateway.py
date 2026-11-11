from flask import Flask, jsonify, session
from werkzeug.test import Client
from werkzeug.wrappers import Response

from nexusone.app import create_app
from nexusone.legacy_gateway import NexusOneGateway


def make_gateway(tmp_path, *, allow_lan=False):
    legacy = Flask("legacy-dashboard")
    legacy.secret_key = "shared-test-secret"
    legacy.config["SESSION_COOKIE_NAME"] = "session"

    @legacy.get("/login")
    def login():
        session.update(authenticated=True, username="viewer", role="user")
        return "signed in"

    @legacy.get("/api/files")
    def legacy_files():
        return jsonify(source="legacy")

    root = tmp_path / "workspace"
    root.mkdir()
    (root / "hello.txt").write_text("hello", encoding="utf-8")
    auth_db = tmp_path / "dashboard-users.sqlite3"
    nexusone = create_app({
        "TESTING": True,
        "SECRET_KEY": legacy.secret_key,
        "SESSION_COOKIE_NAME": "session",
        "SESSION_COOKIE_SECURE": False,
        "DASHBOARD_AUTH_DB": str(auth_db),
        "EXPLORER_ROOT": str(root),
        "CONFIG_FILE": str(tmp_path / "settings.json"),
        "AUDIT_FILE": str(tmp_path / "audit.sqlite3"),
    })
    legacy.wsgi_app = NexusOneGateway(
        legacy.wsgi_app, nexusone.wsgi_app, allow_lan=allow_lan
    )
    return Client(legacy, Response)


def test_gateway_keeps_legacy_routes_and_mounts_nexusone_same_origin(tmp_path):
    client = make_gateway(tmp_path)
    client.get("/login")

    legacy_response = client.get("/api/files")
    assert legacy_response.json == {"source": "legacy"}

    page = client.get("/nexusone/explorer")
    assert page.status_code == 200
    assert b'href="/nexusone/' in page.data
    assert b'/nexusone-api' in page.data

    files = client.get("/nexusone-api/api/files")
    assert files.status_code == 200
    assert files.json["entries"][0]["name"] == "hello.txt"

    settings = client.get("/nexusone/settings")
    assert settings.status_code == 403


def test_gateway_csrf_and_shared_session_work_through_api_mount(tmp_path):
    client = make_gateway(tmp_path)
    client.get("/login")

    token = client.get("/nexusone-api/api/security/csrf").json["token"]
    created = client.post(
        "/nexusone-api/api/files/folder",
        json={"path": ".", "name": "from-phone"},
        headers={"X-CSRF-Token": token},
    )
    assert created.status_code == 200


def test_gateway_blocks_remote_access_unless_https_lan_mode_is_explicit(tmp_path):
    client = make_gateway(tmp_path)
    client.environ_base["REMOTE_ADDR"] = "192.168.1.50"
    denied = client.get("/nexusone/")
    assert denied.status_code == 403

    secure_client = make_gateway(tmp_path, allow_lan=True)
    secure_client.environ_base["REMOTE_ADDR"] = "192.168.1.50"
    http_denied = secure_client.get("/nexusone/")
    assert http_denied.status_code == 403
    https_allowed = secure_client.get("/nexusone/", environ_overrides={"wsgi.url_scheme": "https"})
    assert https_allowed.status_code == 401
