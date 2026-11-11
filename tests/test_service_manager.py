from types import SimpleNamespace

import pytest

from nexusone import service_manager


def test_service_discovery_uses_fixed_allowlist_and_no_shell(monkeypatch):
    calls = []

    def fake_run(argv, timeout=8):
        calls.append((argv, timeout))
        return SimpleNamespace(stdout="active\n", stderr="", returncode=0)

    monkeypatch.setattr(service_manager, "_run", fake_run)
    services = service_manager.list_services()
    assert {item["name"] for item in services} == {
        "jellyfin", "docker", "ollama", "localnexus", "telegram-bot",
        "discord-activity", "dashboard", "dashboard-ydotool", "sunshine",
    }
    assert all(item["active"] == "active" for item in services)
    assert all("sudo" not in argv and "shell" not in argv for argv, _ in calls)


def test_only_allowlisted_user_services_can_be_controlled(monkeypatch):
    calls = []

    def fake_run(argv, timeout=8):
        calls.append(argv)
        return SimpleNamespace(stdout="active\n", stderr="", returncode=0)

    monkeypatch.setattr(service_manager, "_run", fake_run)
    result = service_manager.control_service("telegram-bot", "restart")
    assert result["name"] == "telegram-bot"
    assert result["action"] == "restart"
    assert calls[0] == ["systemctl", "--user", "restart", "telegram-control-bot.service"]
    assert calls[1] == ["systemctl", "--user", "is-active", "telegram-control-bot.service"]

    calls.clear()
    result = service_manager.control_service("discord-activity", "restart")
    assert result["name"] == "discord-activity"
    assert result["action"] == "restart"
    assert calls[0] == ["systemctl", "--user", "restart", "discord-control-activity.service"]
    assert calls[1] == ["systemctl", "--user", "is-active", "discord-control-activity.service"]


def test_system_services_are_status_only(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("system-scope controls must never invoke systemctl")

    monkeypatch.setattr(service_manager, "_run", fail_if_called)
    with pytest.raises(PermissionError, match="polkit helper"):
        service_manager.control_service("docker", "restart")
    with pytest.raises(ValueError, match="Unknown service"):
        service_manager.control_service("unknown-service", "restart")
    with pytest.raises(ValueError, match="Unsupported"):
        service_manager.control_service("telegram-bot", "enable")
