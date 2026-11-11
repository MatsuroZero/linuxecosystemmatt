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
