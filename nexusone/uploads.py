"""Streaming, resumable Explorer uploads confined to one workspace."""
from __future__ import annotations

import os
import re
import shutil
import uuid
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import BinaryIO


class UploadError(ValueError):
    pass


class UploadManager:
    """Sequential chunk receiver; upload state is held in-process.

    Chunks are streamed to a private staging directory. A completed file is
    atomically moved into the workspace only after the declared size matches.
    """

    def __init__(self, root: str | Path, chunk_limit: int = 8 * 1024 * 1024,
                 max_active: int = 3, min_free_bytes: int = 32 * 1024 * 1024):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.staging = self.root / ".nexusone-upload-tmp"
        self.staging.mkdir(mode=0o700, exist_ok=True)
        self.chunk_limit = chunk_limit
        self.max_active = max_active
        self.min_free_bytes = min_free_bytes
        self._sessions: dict[str, dict] = {}
        self._lock = RLock()

    def _destination(self, relative: str) -> Path:
        if not isinstance(relative, str) or not relative or "\x00" in relative:
            raise UploadError("Invalid destination")
        rel = PurePosixPath(relative)
        if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
            raise UploadError("Destination must be a relative workspace path")
        if any(part.startswith(".nexusone-upload-") for part in rel.parts):
            raise UploadError("Reserved destination name")
        target = self.root.joinpath(*rel.parts)
        parent = target.parent
        parent.mkdir(parents=True, exist_ok=True)
        resolved_parent = parent.resolve()
        if self.root != resolved_parent and self.root not in resolved_parent.parents:
            raise UploadError("Destination escapes workspace")
        # Reject symlinks in existing path components.
        cursor = self.root
        for part in rel.parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise UploadError("Symlink destinations are not allowed")
        if target.is_symlink():
            raise UploadError("Cannot overwrite a symlink")
        return target

    def start(self, filename: str, destination: str, total_size: int) -> dict:
        if not isinstance(filename, str) or not filename.strip() or len(filename) > 255:
            raise UploadError("Invalid filename")
        filename = filename.replace("/", "_").replace("\\", "_").strip()
        filename = re.sub(r"[\\x00-\\x1f]", "_", filename)
        if filename in {"", ".", ".."}:
            raise UploadError("Invalid filename")
        if not isinstance(total_size, int) or total_size < 0:
            raise UploadError("Invalid total size")
        target = self._destination(str(PurePosixPath(destination) / filename))
        with self._lock:
            if len(self._sessions) >= self.max_active:
                raise UploadError("Too many active uploads")
            if shutil.disk_usage(self.root).free - total_size < self.min_free_bytes:
                raise UploadError("Insufficient free disk space for upload")
            upload_id = uuid.uuid4().hex
            temp_path = self.staging / upload_id
            fd = os.open(temp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            self._sessions[upload_id] = {
                "path": temp_path, "target": target, "size": total_size,
                "offset": 0, "filename": filename,
            }
        return {"upload_id": upload_id, "offset": 0, "chunk_limit": self.chunk_limit}

    def append(self, upload_id: str, offset: int, stream: BinaryIO) -> dict:
        with self._lock:
            state = self._sessions.get(upload_id)
            if state is None:
                raise UploadError("Unknown or expired upload")
            if offset != state["offset"]:
                raise UploadError("Chunk offset does not match upload state")
            remaining = state["size"] - state["offset"]
            written = 0
            with state["path"].open("ab") as output:
                while written <= self.chunk_limit:
                    block = stream.read(min(1024 * 1024, self.chunk_limit + 1 - written))
                    if not block:
                        break
                    written += len(block)
                    if written > self.chunk_limit or written > remaining:
                        raise UploadError("Chunk exceeds allowed size")
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            state["offset"] += written
            if state["offset"] > state["size"]:
                raise UploadError("Upload exceeds declared size")
            return {"offset": state["offset"], "complete": state["offset"] == state["size"]}

    def finish(self, upload_id: str) -> dict:
        with self._lock:
            state = self._sessions.get(upload_id)
            if state is None:
                raise UploadError("Unknown or expired upload")
            if state["offset"] != state["size"]:
                raise UploadError("Upload is incomplete")
            target = state["target"]
            if target.exists():
                raise UploadError("Destination already exists; overwrite is not implicit")
            os.replace(state["path"], target)
            del self._sessions[upload_id]
            return {"filename": state["filename"], "size": state["size"]}

    def cancel(self, upload_id: str) -> None:
        with self._lock:
            state = self._sessions.pop(upload_id, None)
            if state:
                state["path"].unlink(missing_ok=True)
