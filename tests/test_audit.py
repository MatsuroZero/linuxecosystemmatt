import sqlite3

from nexusone.audit import AuditLog


def test_audit_log_is_private_and_bounds_recent_queries(tmp_path):
    path = tmp_path / "state" / "audit.sqlite3"
    audit = AuditLog(path)
    audit.record("mat", "configuration.update", "telegram,discord")
    audit.record("mat", "service.restart", "telegram-bot", outcome="success", source_ip="127.0.0.1")
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert len(audit.recent(1)) == 1
    event = audit.recent(1)[0]
    assert event["action"] == "service.restart"
    assert event["target"] == "telegram-bot"
    with sqlite3.connect(path) as db:
        count = db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    assert count == 2
