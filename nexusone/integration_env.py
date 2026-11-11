"""Render the legacy Telegram bot's environment file outside the repository."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any


def _quote(value: Any) -> str:
    text = str(value)
    if any(char in text for char in "\r\n\x00"):
        raise ValueError("Environment values cannot contain newlines or NUL bytes")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_telegram_environment(settings: dict[str, Any]) -> str:
    """Return only the known environment variables consumed by the audited bot."""
    values: dict[str, str] = {}

    def add(env_name: str, config_name: str) -> None:
        value = settings.get(config_name)
        if value is not None and str(value).strip():
            values[env_name] = str(value).strip()

    add("TELEGRAM_BOT_TOKEN", "bot_token")
    add("LINKS_PIN", "links_pin")
    add("SYSTEM_DASHBOARD_USERNAME", "system_dashboard_username")
    add("SYSTEM_DASHBOARD_PASSWORD", "system_dashboard_password")
    add("ODYSSEUS_USERNAME", "odysseus_username")
    add("ODYSSEUS_PASSWORD", "odysseus_password")
    add("JELLYFIN_USERNAME", "jellyfin_username")
    add("JELLYFIN_PASSWORD", "jellyfin_password")
    add("UPTIME_KUMA_USERNAME", "uptime_kuma_username")
    add("UPTIME_KUMA_PASSWORD", "uptime_kuma_password")
    add("GEMINI_API_KEY", "gemini_api_key")
    add("GEMINI_BASE_URL", "gemini_base_url")
    add("GEMINI_TIMEOUT", "gemini_timeout")
    add("OLLAMA_BASE_URL", "ollama_base_url")
    add("OLLAMA_TIMEOUT", "ollama_timeout")
    add("OLLAMA_MEMORY_MODEL", "ollama_memory_model")
    add("OLLAMA_MEMORY_PATH", "ollama_memory_path")

    user_ids = settings.get("authorized_user_ids", [])
    if isinstance(user_ids, list) and user_ids:
        normalized = [str(item).strip() for item in user_ids if str(item).strip().isdigit()]
        if normalized:
            # The legacy bot currently reads one ID. Preserve a plural variable
            # for the multi-user adapter migration while remaining compatible.
            values["TELEGRAM_ALLOWED_USER_ID"] = normalized[0]
            values["TELEGRAM_ALLOWED_USER_IDS"] = ",".join(normalized)

    return "".join(f"{key}={_quote(value)}\n" for key, value in sorted(values.items()))


def write_telegram_environment(settings: dict[str, Any], path: str | Path) -> dict:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target.parent, 0o700)
    content = render_telegram_environment(settings)
    fd, temporary_name = tempfile.mkstemp(prefix=".telegram-env-", dir=target.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, 0o600)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    return {"path": str(target), "variables_written": len(content.splitlines())}



def render_discord_environment(
    telegram_settings: dict[str, Any], discord_settings: dict[str, Any]
) -> str:
    """Render only the environment variables used by the audited Discord Activity."""
    values: dict[str, str] = {"HOST": "127.0.0.1", "PORT": str(discord_settings.get("port") or "8787"), "REQUEST_RATE_LIMIT": "180"}

    def add(target: dict[str, str], env_name: str, settings: dict[str, Any], config_name: str) -> None:
        value = settings.get(config_name)
        if value is not None and str(value).strip():
            target[env_name] = str(value).strip()

    add(values, "DISCORD_APPLICATION_ID", discord_settings, "application_id")
    if "DISCORD_APPLICATION_ID" not in values:
        add(values, "DISCORD_APPLICATION_ID", discord_settings, "client_id")
    add(values, "DISCORD_CLIENT_SECRET", discord_settings, "client_secret")
    add(values, "DISCORD_REDIRECT_URI", discord_settings, "redirect_uri")
    add(values, "DISCORD_BOT_TOKEN", discord_settings, "bot_token")
    add(values, "CONTROL_BRIDGE_SECRET", discord_settings, "bridge_secret")
    add(values, "DISCORD_ACTIVITY_ORIGIN", discord_settings, "activity_origin")
    add(values, "DISCORD_ALLOWED_ORIGINS", discord_settings, "allowed_origins")
    add(values, "LINKS_PIN", discord_settings, "links_pin")

    user_ids = discord_settings.get("authorized_user_ids", [])
    if isinstance(user_ids, list):
        normalized = [str(item).strip() for item in user_ids if str(item).strip().isdigit()]
        if normalized:
            values["DISCORD_ALLOWED_USER_ID"] = normalized[0]
            values["DISCORD_ALLOWED_USER_IDS"] = ",".join(normalized)

    shared_mapping = {
        "SYSTEM_DASHBOARD_URL": "system_dashboard_url",
        "ODYSSEUS_URL": "odysseus_url",
        "JELLYFIN_URL": "jellyfin_url",
        "UPTIME_KUMA_URL": "uptime_kuma_url",
        "SYSTEM_DASHBOARD_USERNAME": "system_dashboard_username",
        "SYSTEM_DASHBOARD_PASSWORD": "system_dashboard_password",
        "ODYSSEUS_USERNAME": "odysseus_username",
        "ODYSSEUS_PASSWORD": "odysseus_password",
        "JELLYFIN_USERNAME": "jellyfin_username",
        "JELLYFIN_PASSWORD": "jellyfin_password",
        "UPTIME_KUMA_USERNAME": "uptime_kuma_username",
        "UPTIME_KUMA_PASSWORD": "uptime_kuma_password",
        "OLLAMA_BASE_URL": "ollama_base_url",
        "GEMINI_API_KEY": "gemini_api_key",
        "OLLAMA_MEMORY_PATH": "ollama_memory_path",
        "NEXUS_REGISTRY_PATH": "nexus_registry_path",
        "SYSTEM_DASHBOARD_HEALTH_URL": "system_dashboard_health_url",
        "JELLYFIN_HEALTH_URL": "jellyfin_health_url",
        "OLLAMA_HEALTH_URL": "ollama_health_url",
        "UPTIME_KUMA_HEALTH_URL": "uptime_kuma_health_url",
    }
    for env_name, config_name in shared_mapping.items():
        add(values, env_name, telegram_settings, config_name)

    return "".join(f"{key}={_quote(value)}\n" for key, value in sorted(values.items()))


def write_discord_environment(
    telegram_settings: dict[str, Any], discord_settings: dict[str, Any], path: str | Path
) -> dict:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target.parent, 0o700)
    content = render_discord_environment(telegram_settings, discord_settings)
    fd, temporary_name = tempfile.mkstemp(prefix=".discord-env-", dir=target.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, 0o600)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    return {"path": str(target), "variables_written": len(content.splitlines())}
