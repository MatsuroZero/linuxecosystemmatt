from nexusone.integration_env import (
    render_discord_environment,
    render_telegram_environment,
    write_discord_environment,
    write_telegram_environment,
)


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



def test_discord_environment_exports_audited_keys_and_allowlist(tmp_path):
    shared = {
        "system_dashboard_url": "http://localhost:7171/",
        "system_dashboard_username": "mat",
        "system_dashboard_password": "dashboard-pass",
        "ollama_base_url": "http://127.0.0.1:11434",
        "gemini_api_key": "gemini-value",
    }
    discord = {
        "application_id": "123456789012345678",
        "client_secret": "client-secret-value",
        "bot_token": "bot-token-value",
        "bridge_secret": "bridge-value",
        "redirect_uri": "https://activity.example.com/callback",
        "activity_origin": "https://activity.example.com",
        "allowed_origins": "https://activity.example.com,http://localhost:3000",
        "authorized_user_ids": ["11111111111111111", "22222222222222222"],
        "links_pin": "longer-pin",
    }
    rendered = render_discord_environment(shared, discord)
    assert 'HOST="127.0.0.1"' in rendered
    assert 'PORT="8787"' in rendered
    assert 'DISCORD_APPLICATION_ID="123456789012345678"' in rendered
    assert 'DISCORD_ALLOWED_USER_ID="11111111111111111"' in rendered
    assert 'DISCORD_ALLOWED_USER_IDS="11111111111111111,22222222222222222"' in rendered
    assert 'DISCORD_ALLOWED_ORIGINS="https://activity.example.com,http://localhost:3000"' in rendered
    assert 'LINKS_PIN="longer-pin"' in rendered
    assert "client-secret-value" in rendered

    result = write_discord_environment(shared, discord, tmp_path / "private" / "discord.env")
    target = tmp_path / "private" / "discord.env"
    assert result["variables_written"] == len(rendered.splitlines())
    assert target.read_text(encoding="utf-8") == rendered
    assert target.stat().st_mode & 0o777 == 0o600
    assert target.parent.stat().st_mode & 0o777 == 0o700
