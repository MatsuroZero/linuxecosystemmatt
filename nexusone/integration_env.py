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
