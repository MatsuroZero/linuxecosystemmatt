"""Safe, reversible source integration for the legacy System Dashboard."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from datetime import datetime
from pathlib import Path

_INTEGRATION_BLOCK = '''# NexusOne integration: keep this block after all dashboard routes.
import os as _nexusone_os
from nexusone.legacy_gateway import install_nexusone_gateway

install_nexusone_gateway(
    app,
    {
        "DASHBOARD_AUTH_DB": str(DASHBOARD_AUTH_DB),
        "EXPLORER_ROOT": str(_SHARING_HOME),
    },
    allow_lan=(
        _nexusone_os.environ.get("NEXUSONE_ALLOW_LAN", "").strip().lower()
        in {"1", "true", "yes"}
    ),
)
'''

_MAIN_GUARD = 'if __name__ == "__main__":'


def _timestamped_backup(target: Path, label: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return target.with_name(f"{target.name}.{label}-{stamp}.bak")


def _atomic_write(target: Path, content: str, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent
    )
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, mode)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def install_dashboard_gateway(
    app_path: str | Path, *, backup_path: str | Path | None = None
) -> Path:
    """Insert the local-only gateway before the dashboard's main entry point.

    The original source is copied with metadata before any write. The operation
    refuses ambiguous or already-integrated source rather than guessing.
    """
    target = Path(app_path).expanduser()
    if target.is_symlink() or not target.is_file():
        raise ValueError("Dashboard app path must be an existing regular, non-symlink file")

    source = target.read_text(encoding="utf-8")
    if "install_nexusone_gateway" in source:
        raise ValueError("NexusOne gateway code already appears in the dashboard source")
    if source.count(_MAIN_GUARD) != 1:
        raise ValueError('Expected exactly one if __name__ == "__main__": entry point')
    insertion = source.index(_MAIN_GUARD)
    module_source = source[:insertion]
    if "app = Flask(" not in module_source:
        raise ValueError("Dashboard Flask app must be initialized before its main entry point")
    has_auth_db = "DASHBOARD_AUTH_DB =" in module_source
    has_sharing_root = "_SHARING_HOME =" in module_source
    if not (has_auth_db and has_sharing_root):
        if "DASHBOARD_AUTH_DB =" in source and "_SHARING_HOME =" in source:
            raise ValueError(
                "Dashboard auth DB and sharing-root variables must be defined before its main entry point"
            )
        raise ValueError("Dashboard source is missing the audited auth DB or sharing-root variables")

    backup = Path(backup_path).expanduser() if backup_path else _timestamped_backup(
        target, "pre-nexusone"
    )
    if backup.exists() or backup.is_symlink():
        raise FileExistsError(f"Refusing to overwrite existing backup: {backup}")
    if backup.resolve() == target.resolve():
        raise ValueError("Backup path must differ from the dashboard source path")

    updated = source[:insertion].rstrip() + "\n\n" + _INTEGRATION_BLOCK + "\n" + source[insertion:]
    mode = stat.S_IMODE(target.stat().st_mode)

    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target, backup)
    _atomic_write(target, updated, mode)
    return backup


def restore_dashboard_backup(
    app_path: str | Path,
    backup_path: str | Path,
    *,
    recovery_backup_path: str | Path | None = None,
) -> Path:
    """Restore a selected backup while preserving the current source first."""
    target = Path(app_path).expanduser()
    backup = Path(backup_path).expanduser()
    if target.is_symlink() or not target.is_file():
        raise ValueError("Dashboard app path must be an existing regular, non-symlink file")
    if backup.is_symlink() or not backup.is_file():
        raise ValueError("Restore backup must be an existing regular, non-symlink file")
    if target.resolve() == backup.resolve():
        raise ValueError("Restore backup must differ from the dashboard source path")

    recovery = Path(recovery_backup_path).expanduser() if recovery_backup_path else (
        _timestamped_backup(target, "before-restore")
    )
    if recovery.exists() or recovery.is_symlink():
        raise FileExistsError(f"Refusing to overwrite recovery backup: {recovery}")

    restored = backup.read_text(encoding="utf-8")
    mode = stat.S_IMODE(backup.stat().st_mode)
    recovery.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target, recovery)
    _atomic_write(target, restored, mode)
    return recovery
