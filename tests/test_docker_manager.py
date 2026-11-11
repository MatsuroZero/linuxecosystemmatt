import json
from types import SimpleNamespace

import pytest

from nexusone import docker_manager


def test_project_status_uses_configured_fixed_compose_file_and_filters_fields(tmp_path, monkeypatch):
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}", encoding="utf-8")
    calls = []

    def fake_run(argv, timeout=20):
        calls.append(argv)
        return SimpleNamespace(
            stdout=json.dumps([{
                "Name": "odysseus-searxng-1", "Service": "searxng",
                "State": "running", "Status": "Up", "Image": "searxng:latest",
                "Config": {"Env": ["SECRET=do-not-return"]},
            }]),
            stderr="", returncode=0,
        )

    monkeypatch.setattr(docker_manager, "_run", fake_run)
    result = docker_manager.project_status(compose)
    assert result["project"] == "odysseus"
    assert result["count"] == 1
    assert result["containers"][0]["Name"] == "odysseus-searxng-1"
    assert "Config" not in str(result)
    assert "do-not-return" not in str(result)
    assert calls[0][:4] == ["docker", "compose", "-p", "odysseus"]


def test_project_actions_are_fixed_and_do_not_use_shell(tmp_path, monkeypatch):
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}", encoding="utf-8")
    calls = []

    def fake_run(argv, timeout=20):
        calls.append(argv)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(docker_manager, "_run", fake_run)
    assert docker_manager.control_project(compose, "start")["action"] == "start"
    assert docker_manager.control_project(compose, "stop")["action"] == "stop"
    assert docker_manager.control_project(compose, "restart")["action"] == "restart"
    assert calls[0][-2:] == ["up", "-d"]
    assert calls[1][-1] == "down"
    assert calls[2][-1] == "restart"
    with pytest.raises(ValueError):
        docker_manager.control_project(compose, "exec")


def test_project_status_rejects_missing_compose_file(tmp_path):
    with pytest.raises(RuntimeError, match="not found"):
        docker_manager.project_status(tmp_path / "missing.yaml")
