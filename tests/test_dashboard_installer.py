import pytest

from nexusone.dashboard_installer import (
    install_dashboard_gateway,
    restore_dashboard_backup,
)


def dashboard_source() -> str:
    return (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "DASHBOARD_AUTH_DB = Path('/tmp/users.sqlite3')\n"
        "_SHARING_HOME = Path('/tmp')\n"
        "@app.get('/')\n"
        "def home():\n"
        "    return 'ok'\n\n"
        "if __name__ == \"__main__\":\n"
        "    app.run(host='127.0.0.1', port=7171)\n"
    )


def test_installer_backs_up_and_inserts_gateway_before_main_guard(tmp_path):
    app = tmp_path / "app.py"
    backup = tmp_path / "app.py.original.bak"
    original = dashboard_source()
    app.write_text(original, encoding="utf-8")
    app.chmod(0o750)

    result = install_dashboard_gateway(app, backup_path=backup)

    updated = app.read_text(encoding="utf-8")
    compile(updated, str(app), "exec")
    assert result == backup
    assert backup.read_text(encoding="utf-8") == original
    assert updated.index("install_nexusone_gateway") < updated.index(
        'if __name__ == "__main__":'
    )
    assert '"DASHBOARD_AUTH_DB": str(DASHBOARD_AUTH_DB)' in updated
    assert '"EXPLORER_ROOT": str(_SHARING_HOME)' in updated
    assert app.stat().st_mode & 0o777 == 0o750


def test_installer_refuses_duplicate_or_ambiguous_source(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(dashboard_source(), encoding="utf-8")
    backup = tmp_path / "backup.bak"
    backup.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        install_dashboard_gateway(app, backup_path=backup)
    assert app.read_text(encoding="utf-8") == dashboard_source()

    app.write_text(
        dashboard_source().replace(
            'if __name__ == "__main__":',
            'install_nexusone_gateway(app, {})\n\nif __name__ == "__main__":',
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="already appears"):
        install_dashboard_gateway(app)


def test_installer_requires_expected_dashboard_variables(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        'app = object()\nif __name__ == "__main__":\n    pass\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="auth DB or sharing-root"):
        install_dashboard_gateway(app)


def test_installer_rejects_dashboard_symbols_defined_after_main_guard(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        'app = Flask(__name__)\n'
        'if __name__ == "__main__":\n'
        '    pass\n'
        'DASHBOARD_AUTH_DB = Path("/tmp/users.sqlite3")\n'
        '_SHARING_HOME = Path("/tmp")\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="before its main entry point"):
        install_dashboard_gateway(app)


def test_restore_keeps_a_recovery_copy_of_current_source(tmp_path):
    app = tmp_path / "app.py"
    backup = tmp_path / "original.bak"
    backup.write_text(dashboard_source(), encoding="utf-8")
    app.write_text("modified source", encoding="utf-8")

    recovery = restore_dashboard_backup(app, backup)

    assert app.read_text(encoding="utf-8") == dashboard_source()
    assert recovery.read_text(encoding="utf-8") == "modified source"


def test_installer_rejects_symlinked_dashboard_source(tmp_path):
    actual = tmp_path / "actual.py"
    actual.write_text(dashboard_source(), encoding="utf-8")
    link = tmp_path / "app.py"
    link.symlink_to(actual)

    with pytest.raises(ValueError, match="regular, non-symlink"):
        install_dashboard_gateway(link)
