from nexusone.app import create_app


def test_ui_shell_wraps_authenticated_pages_and_serves_theme_assets(tmp_path):
    palette = tmp_path / "matugen.css"
    palette.write_text(":root { --md-sys-color-primary: #ff7755; }", encoding="utf-8")
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "SESSION_COOKIE_SECURE": False,
        "MATUGEN_CSS_FILE": str(palette),
    })
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(authenticated=True, username="marwan", role="admin")

    page = client.get("/")
    assert page.status_code == 200
    assert b'name="n1-shell-config"' in page.data
    assert b"/theme/shell.css" in page.data
    assert b"/theme/shell.js" in page.data
    assert b"Integrations" in page.data

    services = client.get("/services")
    assert services.status_code == 200
    nonce_header = services.headers["Content-Security-Policy"]
    assert "script-src 'self' 'nonce-" in nonce_header
    assert b'<script nonce="' in services.data
    assert b'<style nonce="' in services.data

    stylesheet = client.get("/theme/shell.css")
    assert stylesheet.status_code == 200
    assert b"--md-sys-color-primary" in stylesheet.data

    script = client.get("/theme/shell.js")
    assert script.status_code == 200
    assert b"n1-sidebar" in script.data

    matugen = client.get("/theme/matugen.css")
    assert matugen.status_code == 200
    assert b"#ff7755" in matugen.data


def test_ui_shell_hides_admin_navigation_for_viewers():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "SESSION_COOKIE_SECURE": False,
    })
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(authenticated=True, username="viewer", role="viewer")

    page = client.get("/")
    assert page.status_code == 200
    assert b'name="n1-shell-config"' in page.data
    assert b'&quot;href&quot;: &quot;/settings&quot;' not in page.data
    assert b'&quot;href&quot;: &quot;/activity&quot;' not in page.data
