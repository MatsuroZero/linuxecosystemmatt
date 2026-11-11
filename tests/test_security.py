from nexusone.security.csrf import issue_csrf_token, verify_csrf_token
from nexusone.security.rate_limit import RateLimiter
from nexusone.security.rbac import Capability, Role, has_capability, normalize_role


def test_unknown_roles_fail_closed_and_admin_has_control_capabilities():
    assert normalize_role("admin") is Role.ADMIN
    assert normalize_role("root") is None
    assert has_capability("admin", Capability.POWER_CONTROL)
    assert not has_capability("viewer", Capability.POWER_CONTROL)
    assert not has_capability("viewer", "terminal:access")
    assert not has_capability(None, Capability.DASHBOARD_READ)


def test_explorer_is_preserved_without_granting_machine_control():
    assert has_capability(Role.VIEWER, Capability.EXPLORER_READ)
    assert has_capability(Role.VIEWER, Capability.EXPLORER_WRITE)
    assert not has_capability(Role.VIEWER, Capability.COMMANDS_EXECUTE)


def test_csrf_token_is_session_bound():
    state = {}
    token = issue_csrf_token(state)
    assert len(token) >= 32
    assert issue_csrf_token(state) == token
    assert verify_csrf_token(state, token)
    assert not verify_csrf_token({}, token)
    assert not verify_csrf_token(state, "wrong")
    assert not verify_csrf_token(state, None)


def test_rate_limiter_enforces_window_and_expires_old_events():
    now = [100.0]
    limiter = RateLimiter(2, 10, clock=lambda: now[0])
    assert limiter.allow("client")
    assert limiter.allow("client")
    assert not limiter.allow("client")
    now[0] = 111.0
    assert limiter.allow("client")


def test_rate_limiter_bounds_client_key_growth():
    now = [10.0]
    limiter = RateLimiter(5, 10, clock=lambda: now[0], max_keys=1)
    assert limiter.allow("first")
    assert not limiter.allow("second")
    now[0] = 21.0
    assert limiter.allow("second")



def test_legacy_dashboard_role_revocation_takes_effect_immediately(tmp_path):
    import sqlite3

    auth_db = tmp_path / "dashboard-users.sqlite3"
    with sqlite3.connect(auth_db) as db:
        db.execute("CREATE TABLE users (username TEXT PRIMARY KEY, role TEXT NOT NULL)")
        db.execute("INSERT INTO users(username, role) VALUES (?, ?)", ("operator1", "user"))

    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False,
        "DASHBOARD_AUTH_DB": str(auth_db), "CONFIG_FILE": str(tmp_path / "settings.json"),
        "EXPLORER_ROOT": str(tmp_path / "workspace"),
    })
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(authenticated=True, username="operator1", role="admin")

    # A stale signed cookie claiming admin must be reduced to the current DB role.
    assert client.get("/settings").status_code == 403
    assert client.get("/explorer").status_code == 200

    with sqlite3.connect(auth_db) as db:
        db.execute("DELETE FROM users WHERE username = ?", ("operator1",))
    assert client.get("/explorer").status_code == 401


def test_dashboard_admin_role_is_recomputed_from_reserved_identity(tmp_path):
    import sqlite3

    auth_db = tmp_path / "dashboard-users.sqlite3"
    with sqlite3.connect(auth_db) as db:
        db.execute("CREATE TABLE users (username TEXT PRIMARY KEY, role TEXT NOT NULL)")
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False,
        "DASHBOARD_AUTH_DB": str(auth_db), "CONFIG_FILE": str(tmp_path / "settings.json"),
    })
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(authenticated=True, username="marwan", role="viewer")
    assert client.get("/settings").status_code == 200
