"""Allowlisted systemd service discovery and safe user-service controls.

System-scope services are observable but deliberately not controllable here:
they require an explicit polkit helper, never implicit sudo from the web app.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class Service:
    name: str
    scope: str
    unit: str
    controllable: bool = False


SERVICES = (
    Service("jellyfin", "system", "jellyfin.service"),
    Service("docker", "system", "docker.service"),
    Service("ollama", "system", "ollama.service"),
    Service("localnexus", "user", "localnexus.service", True),
    Service("telegram-bot", "user", "telegram-control-bot.service", True),
    Service("dashboard", "system", "system-dashboard.service"),
    Service("dashboard-ydotool", "system", "system-dashboard-ydotool.service"),
    Service("sunshine", "user", "sunshine.service", True),
)

_ALLOWED_ACTIONS = frozenset({"start", "stop", "restart"})


def _run(argv: list[str], timeout: float = 8) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(argv, 1, "", str(exc))


def _systemctl(service: Service, *args: str) -> list[str]:
    argv = ["systemctl"]
    if service.scope == "user":
        argv.append("--user")
    return argv + list(args)


def _state(service: Service, command: str) -> str:
    result = _run(_systemctl(service, command, service.unit), timeout=2)
    value = result.stdout.strip()
    return value[:80] if value else "unknown"


def list_services() -> list[dict]:
    results = []
    for service in SERVICES:
        results.append({
            "name": service.name,
            "scope": service.scope,
            "unit": service.unit,
            "active": _state(service, "is-active"),
            "enabled": _state(service, "is-enabled"),
            "controllable": service.controllable,
        })
    return results


def control_service(name: str, action: str) -> dict:
    service = next((item for item in SERVICES if item.name == name), None)
    if service is None:
        raise ValueError("Unknown service")
    if action not in _ALLOWED_ACTIONS:
        raise ValueError("Unsupported service action")
    if not service.controllable or service.scope != "user":
        raise PermissionError(
            "This system service is status-only until a narrow polkit helper is configured"
        )
    result = _run(_systemctl(service, action, service.unit), timeout=30)
    if result.returncode:
        detail = (result.stderr or result.stdout or "systemctl action failed").strip()
        raise RuntimeError(detail[:500])
    return {
        "name": service.name,
        "action": action,
        "active": _state(service, "is-active"),
    }
