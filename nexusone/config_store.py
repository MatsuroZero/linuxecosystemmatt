"""Private, atomic storage for integration configuration.

Secrets are write-only at the API boundary. This file must live outside the
repository and is created with owner-only permissions.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlsplit

_SECRET_FIELDS = {
    "telegram": {"bot_token", "links_pin"},
    "discord": {"bot_token", "client_secret", "bridge_secret"},
}
_LIST_FIELDS = {
    "telegram": {"authorized_user_ids", "chat_ids"},
    "discord": {"authorized_user_ids", "guild_ids", "channel_ids"},
}
_TEXT_FIELDS = {
    "telegram": {"enabled"},
    "discord": {"enabled", "application_id", "client_id", "activity_origin"},
}


class ConfigurationError(ValueError):
    pass


class ConfigStore:
    """JSON settings store with atomic writes and restrictive permissions."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self._lock = RLock()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"telegram": {}, "discord": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError("Configuration file cannot be read") from exc
        if not isinstance(data, dict):
            raise ConfigurationError("Configuration root must be an object")
        return {name: data.get(name, {}) for name in ("telegram", "discord")}

    @staticmethod
    def _validate_ids(values: Any, field: str, allow_negative: bool = False) -> list[str]:
        if not isinstance(values, list):
            raise ConfigurationError(f"{field} must be a list")
        normalized = []
        for value in values:
            item = str(value).strip()
            numeric = item[1:] if allow_negative and item.startswith("-") else item
            if not numeric.isdigit() or len(item) > 24:
                raise ConfigurationError(f"{field} contains an invalid numeric ID")
            if item not in normalized:
                normalized.append(item)
        return normalized

    def public_view(self) -> dict[str, Any]:
        with self._lock:
            data = self._read()
        result: dict[str, Any] = {}
        for integration, values in data.items():
            values = values if isinstance(values, dict) else {}
            visible = {key + "_configured": bool(values.get(key)) for key in _SECRET_FIELDS[integration]}
            for key, value in values.items():
                if key in _SECRET_FIELDS[integration]:
                    visible[key + "_configured"] = bool(value)
                else:
                    visible[key] = value
            result[integration] = visible
        return result

    def update(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ConfigurationError("Configuration payload must be an object")
        with self._lock:
            data = self._read()
            for integration in ("telegram", "discord"):
                patch = payload.get(integration, {})
                if not isinstance(patch, dict):
                    raise ConfigurationError(f"{integration} settings must be an object")
                allowed = _SECRET_FIELDS[integration] | _LIST_FIELDS[integration] | _TEXT_FIELDS[integration]
                unknown = set(patch) - allowed
                if unknown:
                    raise ConfigurationError(f"Unsupported {integration} setting: {min(unknown)}")
                current = data.setdefault(integration, {})
                for key, value in patch.items():
                    if key in _SECRET_FIELDS[integration]:
                        if value is None:
                            current.pop(key, None)
                        elif isinstance(value, str):
                            if value.strip():
                                normalized = value.strip()
                                if key == "links_pin" and (
                                    not normalized.isdigit() or not 4 <= len(normalized) <= 12
                                ):
                                    raise ConfigurationError("links_pin must contain 4 to 12 digits")
                                current[key] = normalized
                        else:
                            raise ConfigurationError(f"{key} must be text")
                    elif key in _LIST_FIELDS[integration]:
                        current[key] = self._validate_ids(value, key, allow_negative=(key == "chat_ids"))
                    elif key == "enabled":
                        if not isinstance(value, bool):
                            raise ConfigurationError("enabled must be boolean")
                        current[key] = value
                    elif isinstance(value, str) and len(value) <= 500:
                        normalized = value.strip()
                        if key in {"application_id", "client_id"} and normalized and (
                            not normalized.isdigit() or len(normalized) > 24
                        ):
                            raise ConfigurationError(f"{key} must be a numeric Discord ID")
                        if key == "activity_origin" and normalized:
                            try:
                                parsed = urlsplit(normalized)
                                hostname = parsed.hostname
                                port = parsed.port
                            except ValueError as exc:
                                raise ConfigurationError("activity_origin is not a valid URL") from exc
                            if (
                                parsed.scheme != "https" or not hostname
                                or (port is not None and not 1 <= port <= 65535)
                                or parsed.username or parsed.password
                                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                            ):
                                raise ConfigurationError(
                                    "activity_origin must be an HTTPS origin without path, query, or credentials"
                                )
                        current[key] = normalized
                    else:
                        raise ConfigurationError(f"{key} must be text up to 500 characters")
            self._write(data)
        return self.public_view()

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        fd, temp_name = tempfile.mkstemp(prefix=".nexusone-config-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
            os.chmod(self.path, 0o600)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
