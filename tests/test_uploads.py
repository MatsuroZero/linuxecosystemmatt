import io

import pytest

from nexusone.uploads import UploadError, UploadManager


def test_streamed_upload_is_finalized_atomically(tmp_path):
    manager = UploadManager(tmp_path, chunk_limit=4, min_free_bytes=0)
    started = manager.start("phone-photo.jpg", "Incoming", 6)
    upload_id = started["upload_id"]
    assert manager.append(upload_id, 0, io.BytesIO(b"abcd")) == {"offset": 4, "complete": False}
    assert manager.append(upload_id, 4, io.BytesIO(b"ef")) == {"offset": 6, "complete": True}
    assert manager.finish(upload_id) == {"filename": "phone-photo.jpg", "size": 6}
    assert (tmp_path / "Incoming" / "phone-photo.jpg").read_bytes() == b"abcdef"


def test_offset_and_chunk_limits_are_enforced(tmp_path):
    manager = UploadManager(tmp_path, chunk_limit=4, min_free_bytes=0)
    upload_id = manager.start("file.bin", "", 8)["upload_id"]
    with pytest.raises(UploadError):
        manager.append(upload_id, 1, io.BytesIO(b"abcd"))
    with pytest.raises(UploadError):
        manager.append(upload_id, 0, io.BytesIO(b"12345"))


def test_traversal_and_implicit_overwrite_are_rejected(tmp_path):
    manager = UploadManager(tmp_path, min_free_bytes=0)
    with pytest.raises(UploadError):
        manager.start("file.txt", "../outside", 1)
    first = manager.start("file.txt", "", 1)["upload_id"]
    manager.append(first, 0, io.BytesIO(b"x"))
    manager.finish(first)
    second = manager.start("file.txt", "", 1)["upload_id"]
    manager.append(second, 0, io.BytesIO(b"y"))
    with pytest.raises(UploadError):
        manager.finish(second)


def test_cancel_removes_staging_file(tmp_path):
    manager = UploadManager(tmp_path, min_free_bytes=0)
    upload_id = manager.start("file.bin", "", 10)["upload_id"]
    manager.cancel(upload_id)
    with pytest.raises(UploadError):
        manager.append(upload_id, 0, io.BytesIO(b"x"))



def test_upload_session_survives_restart_and_is_user_scoped(tmp_path):
    first = UploadManager(tmp_path, chunk_limit=4, min_free_bytes=0)
    upload_id = first.start("backup.bin", "Phone", 8, owner="matty")["upload_id"]
    first.append(upload_id, 0, io.BytesIO(b"abcd"), owner="matty")

    restarted = UploadManager(tmp_path, chunk_limit=4, min_free_bytes=0)
    with pytest.raises(UploadError):
        restarted.status(upload_id, owner="someone-else")
    assert restarted.status(upload_id, owner="matty")["offset"] == 4
    restarted.append(upload_id, 4, io.BytesIO(b"efgh"), owner="matty")
    restarted.finish(upload_id, owner="matty")
    assert (tmp_path / "Phone" / "backup.bin").read_bytes() == b"abcdefgh"
