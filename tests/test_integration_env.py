from nexusone.integration_env import render_telegram_environment, write_telegram_environment


def test_telegram_environment_contains_only_audited_keys_and_escapes_values(tmp_path):
    settings = {
        "bot_token": "123:token",
        "authorized_user_ids": ["111", "222"],
        "links_pin": "7171",
        "system_dashboard_username": "mat user",
        "system_dashboard_password": 'p"ass\\word',
        "gemini_api_key": "gemini-key",
        "activity_origin": "not-a-telegram-setting",
    }
    rendered = render_telegram_environment(settings)
    assert 'TELEGRAM_BOT_TOKEN="123:token"' in rendered
    assert 'TELEGRAM_ALLOWED_USER_ID="111"' in rendered
    assert 'TELEGRAM_ALLOWED_USER_IDS="111,222"' in rendered
    assert 'LINKS_PIN="7171"' in rendered
    assert 'SYSTEM_DASHBOARD_USERNAME="mat user"' in rendered
    assert 'SYSTEM_DASHBOARD_PASSWORD="p\\"ass\\\\word"' in rendered
    assert "not-a-telegram-setting" not in rendered

    result = write_telegram_environment(settings, tmp_path / "private" / "telegram.env")
    target = tmp_path / "private" / "telegram.env"
    assert result["variables_written"] == len(rendered.splitlines())
    assert target.read_text(encoding="utf-8") == rendered
    assert target.stat().st_mode & 0o777 == 0o600
    assert target.parent.stat().st_mode & 0o777 == 0o700
