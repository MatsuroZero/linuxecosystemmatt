import json
import os

import pytest

from nexusone.config_store import ConfigStore, ConfigurationError


def test_secret_values_are_never_returned_and_blank_does_not_clear(tmp_path):
    store = ConfigStore(tmp_path / "private" / "settings.json")
    public = store.update({
        "telegram": {"bot_token": "secret-token", "authorized_user_ids": ["123", "123"]},
        "discord": {"client_secret": "client-secret", "guild_ids": ["456"]},
    })
    assert public["telegram"]["bot_token_configured"] is True
    assert "bot_token" not in public["telegram"]
    assert "secret-token" not in json.dumps(public)
    store.update({"telegram": {"bot_token": ""}, "discord": {"client_secret": ""}})
    assert store.public_view()["telegram"]["bot_token_configured"] is True
    assert store.public_view()["discord"]["client_secret_configured"] is True
    assert os.stat(store.path).st_mode & 0o777 == 0o600
    assert os.stat(store.path.parent).st_mode & 0o777 == 0o700


def test_secret_can_be_explicitly_cleared(tmp_path):
    store = ConfigStore(tmp_path / "settings.json")
    store.update({"telegram": {"bot_token": "secret"}})
    assert store.public_view()["telegram"]["bot_token_configured"]
    store.update({"telegram": {"bot_token": None}})
    assert not store.public_view()["telegram"]["bot_token_configured"]


def test_invalid_user_ids_are_rejected(tmp_path):
    store = ConfigStore(tmp_path / "settings.json")
    with pytest.raises(ConfigurationError):
        store.update({"discord": {"authorized_user_ids": ["123; DROP TABLE"]}})



def test_telegram_group_chat_ids_may_be_negative(tmp_path):
    store = ConfigStore(tmp_path / "settings.json")
    public = store.update({"telegram": {"chat_ids": ["-1001234567890"]}})
    assert public["telegram"]["chat_ids"] == ["-1001234567890"]
    with pytest.raises(ConfigurationError):
        store.update({"telegram": {"authorized_user_ids": ["-12345"]}})



def test_discord_ids_and_activity_origin_are_validated(tmp_path):
    store = ConfigStore(tmp_path / "settings.json")
    with pytest.raises(ConfigurationError):
        store.update({"discord": {"application_id": "not-an-id"}})
    with pytest.raises(ConfigurationError):
        store.update({"discord": {"activity_origin": "http://example.com"}})
    with pytest.raises(ConfigurationError):
        store.update({"discord": {"activity_origin": "https://example.com/path"}})
    with pytest.raises(ConfigurationError):
        store.update({"discord": {"activity_origin": "https://[invalid"}})
    saved = store.update({"discord": {
        "application_id": "123456789012345678",
        "client_id": "123456789012345678",
        "activity_origin": "https://activity.example.com",
    }})
    assert saved["discord"]["activity_origin"] == "https://activity.example.com"
