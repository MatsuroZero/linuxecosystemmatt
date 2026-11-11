import re
import shutil
import sqlite3
import subprocess

from flask import Flask, jsonify, session

from nexusone.legacy_security import install_legacy_security


def make_legacy_app(tmp_path):
    auth_db = tmp_path / "dashboard-users.sqlite3"
    with sqlite3.connect(auth_db) as db:
        db.execute(
            "CREATE TABLE users (username TEXT PRIMARY KEY, role TEXT NOT NULL)"
        )
        db.execute(
            "INSERT INTO users(username, role) VALUES (?, ?)",
            ("viewer-one", "user"),
        )

    app = Flask("legacy-security-test")
    app.secret_key = "test-signing-key"

    @app.before_request
    def legacy_login_gate():
        from flask import request

        if request.endpoint != "login" and not session.get("authenticated"):
            return jsonify(error="Authentication required"), 401
        return None

    @app.get("/")
    def dashboard():
        return "<html><head></head><body>Dashboard</body></html>"

    @app.route("/api/files", methods=["GET", "POST"])
    def files():
        return jsonify(ok=True, route="files")

    @app.route("/api/terminal", methods=["GET", "POST"])
    def terminal():
        return jsonify(ok=True, route="terminal")

    install_legacy_security(app, auth_db_path=auth_db)
    return app, auth_db


def signed_in(client, *, username="viewer-one", role="user"):
    with client.session_transaction() as state:
        state.update(authenticated=True, username=username, role=role)


def csrf_token(page):
    match = re.search(
        rb'name="nexusone-csrf-token" content="([^"]+)"',
        page.data,
    )
    assert match, "CSRF token meta tag was not injected"
    return match.group(1).decode("ascii")


def test_legacy_html_bootstraps_csrf_header_for_fetch(tmp_path):
    app, _ = make_legacy_app(tmp_path)
    client = app.test_client()
    signed_in(client)

    page = client.get("/")
    assert page.status_code == 200
    assert b"nexusone-csrf-token" in page.data
    assert b"X-CSRF-Token" in page.data
    assert b'nexusone-admin" content="false"' in page.data
    assert b"nexusone-explorer-link" in page.data
    assert b"nexusone-settings-link" in page.data
    assert b'nav.className="tabs"' in page.data
    assert b'addFrame("nexusone-explorer","/nexusone/explorer"' in page.data
    assert b'if(admin)addFrame("nexusone-settings","/nexusone/settings"' in page.data
    assert b"const entries=admin?[" in page.data
    assert b':[["stats","\xf0\x9f\x93\x8a Overview"],["files","\xf0\x9f\x93\x82 Files"]' in page.data
    assert csrf_token(page)


def test_legacy_mutations_require_same_origin_and_csrf(tmp_path):
    app, _ = make_legacy_app(tmp_path)
    client = app.test_client()
    signed_in(client)
    token = csrf_token(client.get("/"))

    missing = client.post(
        "/api/files",
        json={},
        headers={"Origin": "http://localhost"},
    )
    assert missing.status_code == 403

    cross_origin = client.post(
        "/api/files",
        json={},
        headers={
            "Origin": "https://attacker.example",
            "X-CSRF-Token": token,
        },
    )
    assert cross_origin.status_code == 403

    accepted = client.post(
        "/api/files",
        json={},
        headers={
            "Origin": "http://localhost",
            "X-CSRF-Token": token,
        },
    )
    assert accepted.status_code == 200


def test_legacy_terminal_is_admin_only_but_explorer_remains_available(tmp_path):
    app, _ = make_legacy_app(tmp_path)
    client = app.test_client()
    signed_in(client)

    assert client.get("/api/terminal").status_code == 403
    assert client.get("/api/files").status_code == 200


def test_reserved_dashboard_admin_can_use_terminal(tmp_path):
    app, _ = make_legacy_app(tmp_path)
    client = app.test_client()
    signed_in(client, username="marwan", role="user")

    page = client.get("/")
    assert b'nexusone-admin" content="true"' in page.data
    response = client.get("/api/terminal")
    assert response.status_code == 200
    assert response.json == {"ok": True, "route": "terminal"}


def test_deleted_legacy_account_is_rejected_even_with_a_signed_cookie(tmp_path):
    app, auth_db = make_legacy_app(tmp_path)
    client = app.test_client()
    signed_in(client)

    with sqlite3.connect(auth_db) as db:
        db.execute("DELETE FROM users WHERE username = ?", ("viewer-one",))

    response = client.get("/api/files")
    assert response.status_code == 401


def test_legacy_security_bootstrap_javascript_parses_when_node_is_available(tmp_path):
    node = shutil.which("node")
    if node is None:
        import pytest

        pytest.skip("Node.js is not installed")

    app, _ = make_legacy_app(tmp_path)
    client = app.test_client()
    signed_in(client)
    page = client.get("/")
    match = re.search(rb"<script>([\s\S]*?)</script>", page.data)
    assert match, "CSRF bootstrap script was not injected"

    script = tmp_path / "legacy-security-bootstrap.js"
    script.write_bytes(match.group(1))
    result = subprocess.run(
        [node, "--check", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
