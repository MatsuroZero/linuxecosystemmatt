"""Small append-only SQLite audit log; never store credential values or request bodies."""
from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self._lock = RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    source_ip TEXT NOT NULL
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(id DESC)")
        os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def record(
        self, actor: str, action: str, target: str = "",
        outcome: str = "success", source_ip: str = "",
    ) -> None:
        values = (
            datetime.now(UTC).isoformat(timespec="seconds"),
            str(actor)[:128], str(action)[:128], str(target)[:255],
            str(outcome)[:40], str(source_ip)[:64],
        )
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO audit_events
                   (created_at, actor, action, target, outcome, source_ip)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                values,
            )
        os.chmod(self.path, 0o600)

    def recent(self, limit: int = 100) -> list[dict]:
        bounded = max(1, min(int(limit), 250))
        with self._lock, self._connect() as db:
            rows = db.execute(
                """SELECT id, created_at, actor, action, target, outcome, source_ip
                   FROM audit_events ORDER BY id DESC LIMIT ?""",
                (bounded,),
            ).fetchall()
        return [dict(row) for row in rows]
