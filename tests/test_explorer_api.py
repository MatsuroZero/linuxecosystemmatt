import os

from nexusone.app import create_app


def signed_in_client(app, role="user", username="mat"):
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(authenticated=True, username=username, role=role)
    token = client.get("/api/security/csrf").json["token"]
    return client, {"X-CSRF-Token": token}


def test_explorer_lists_creates_renames_and_downloads(tmp_path):
    root = tmp_path / "workspace"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "hello.txt").write_text("hello", encoding="utf-8")
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False,
        "EXPLORER_ROOT": str(root), "CONFIG_FILE": str(tmp_path / "settings.json"),
    })
    client, headers = signed_in_client(app)
    assert client.get("/explorer").status_code == 200
    listing = client.get("/api/files?path=docs")
    assert listing.status_code == 200
    assert listing.json["entries"][0]["name"] == "hello.txt"
    renamed = client.post("/api/files/rename", headers=headers,
                          json={"path": "docs/hello.txt", "name": "renamed.txt"})
    assert renamed.status_code == 200
    download = client.get("/api/files/download?path=docs/renamed.txt")
    assert download.status_code == 200
    assert download.data == b"hello"


def test_explorer_copy_paste_and_delete(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "source.txt").write_text("copy me", encoding="utf-8")
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False,
        "EXPLORER_ROOT": str(root), "CONFIG_FILE": str(tmp_path / "settings.json"),
    })
    client, headers = signed_in_client(app)
    folder = client.post("/api/files/folder", headers=headers, json={"path": ".", "name": "target"})
    assert folder.status_code == 200
    clip = client.post("/api/files/clipboard", headers=headers,
                       json={"paths": ["source.txt"], "mode": "copy"})
    assert clip.status_code == 200
    pasted = client.post("/api/files/paste", headers=headers, json={"path": "target"})
    assert pasted.status_code == 200
    assert (root / "target" / "source.txt").read_text(encoding="utf-8") == "copy me"
    deleted = client.post("/api/files/delete", headers=headers, json={"paths": ["target/source.txt"]})
    assert deleted.status_code == 200
    assert not (root / "target" / "source.txt").exists()


def test_explorer_rejects_paths_outside_workspace(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    try:
        (root / "escape").symlink_to(outside)
    except OSError:
        return
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "SESSION_COOKIE_SECURE": False,
        "EXPLORER_ROOT": str(root), "CONFIG_FILE": str(tmp_path / "settings.json"),
    })
    client, _ = signed_in_client(app)
    response = client.get("/api/files?path=escape")
    assert response.status_code == 400
