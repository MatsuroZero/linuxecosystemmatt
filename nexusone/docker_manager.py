"""Fixed-project Docker Compose adapter. No user-supplied command or project path is accepted."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

_ALLOWED_ACTIONS = {"start", "stop", "restart"}


def _run(argv: list[str], timeout: float = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(argv, 1, "", str(exc))


def _base(compose_file: str | Path) -> list[str]:
    path = Path(compose_file).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError("Odysseus Compose file was not found")
    return ["docker", "compose", "-p", "odysseus", "-f", str(path)]


def _safe_container(row: dict) -> dict:
    return {
        key: str(row.get(key, ""))[:500]
        for key in ("Name", "Service", "State", "Status", "Health", "Image", "Publishers")
        if row.get(key) is not None
    }


def project_status(compose_file: str | Path) -> dict:
    argv = _base(compose_file) + ["ps", "--all", "--format", "json"]
    result = _run(argv)
    if result.returncode:
        detail = (result.stderr or result.stdout or "Docker Compose status failed").strip()
        raise RuntimeError(detail[:500])
    output = result.stdout.strip()
    containers = []
    if output:
        try:
            parsed = json.loads(output)
            rows = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            try:
                rows = [json.loads(line) for line in output.splitlines() if line.strip()]
            except json.JSONDecodeError as exc:
                raise RuntimeError("Docker Compose returned malformed status data") from exc
        containers = [_safe_container(row) for row in rows if isinstance(row, dict)]
    return {"project": "odysseus", "containers": containers, "count": len(containers)}


def control_project(compose_file: str | Path, action: str) -> dict:
    if action not in _ALLOWED_ACTIONS:
        raise ValueError("Unsupported Docker project action")
    argv = _base(compose_file)
    if action == "start":
        argv += ["up", "-d"]
    elif action == "stop":
        argv += ["down"]
    else:
        argv += ["restart"]
    result = _run(argv, timeout=120)
    if result.returncode:
        detail = (result.stderr or result.stdout or "Docker Compose action failed").strip()
        raise RuntimeError(detail[:500])
    return {"project": "odysseus", "action": action, "message": "Docker Compose action completed"}
