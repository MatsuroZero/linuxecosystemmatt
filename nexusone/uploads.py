"""Streaming, resumable Explorer uploads confined to one workspace."""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import BinaryIO


class UploadError(ValueError):
    pass


class UploadManager:
    """Sequential chunk receiver with restart-persistent session metadata.

    Chunks are streamed to private staging files. A completed file is linked
    atomically into the workspace without replacing an existing destination.
    """

    def __init__(
        self,
        root: str | Path,
        chunk_limit: int = 8 * 1024 * 1024,
        max_active: int = 3,
        min_free_bytes: int = 32 * 1024 * 1024,
        session_ttl_seconds: int = 24 * 60 * 60,
    ):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.staging = self.root / ".nexusone-upload-tmp"
        self.staging.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.staging, 0o700)
        self.chunk_limit = chunk_limit
        self.max_active = max_active
        self.min_free_bytes = min_free_bytes
        self.session_ttl_seconds = session_ttl_seconds
        self._sessions: dict[str, dict] = {}
        self._lock = RLock()
        self._load_sessions()

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
        cursor = self.root
        for part in rel.parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise UploadError("Symlink destinations are not allowed")
        if target.is_symlink():
            raise UploadError("Cannot overwrite a symlink")
        return target

    def _metadata_path(self, upload_id: str) -> Path:
        return self.staging / f"{upload_id}.json"

    def _persist(self, upload_id: str, state: dict) -> None:
        relative_target = state["target"].relative_to(self.root).as_posix()
        metadata = {
            "filename": state["filename"],
            "target": relative_target,
            "size": state["size"],
            "offset": state["offset"],
            "created_at": state["created_at"],
            "owner": state["owner"],
        }
        fd, temp_name = tempfile.mkstemp(prefix=".meta-", dir=self.staging)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(metadata, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self._metadata_path(upload_id))
        finally:
            Path(temp_name).unlink(missing_ok=True)

    def _remove_session_files(self, upload_id: str) -> None:
        (self.staging / upload_id).unlink(missing_ok=True)
        self._metadata_path(upload_id).unlink(missing_ok=True)

    def _load_sessions(self) -> None:
        now = time.time()
        for metadata_path in self.staging.glob("*.json"):
            upload_id = metadata_path.stem
            data_path = self.staging / upload_id
            try:
                if not re.fullmatch(r"[a-f0-9]{32}", upload_id):
                    raise ValueError("invalid upload id")
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                created = float(metadata["created_at"])
                size = int(metadata["size"])
                offset = int(metadata["offset"])
                if now - created > self.session_ttl_seconds or not 0 <= offset <= size:
                    raise ValueError("expired or invalid upload state")
                if data_path.is_symlink() or not data_path.is_file():
                    raise ValueError("missing staging file")
                if data_path.stat().st_size < offset:
                    raise ValueError("staging file is shorter than recorded offset")
                with data_path.open("r+b") as stream:
                    stream.truncate(offset)
                target = self._destination(str(metadata["target"]))
                if target.exists():
                    raise ValueError("destination already exists")
                self._sessions[upload_id] = {
                    "path": data_path,
                    "target": target,
                    "size": size,
                    "offset": offset,
                    "filename": str(metadata["filename"]),
                    "created_at": created,
                    "owner": str(metadata.get("owner", "")),
                }
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                self._remove_session_files(upload_id)
        # Remove incomplete chunk/metadata temporaries left by a process crash.
        for path in self.staging.glob(".chunk-*"):
            path.unlink(missing_ok=True)
        for path in self.staging.glob(".meta-*"):
            path.unlink(missing_ok=True)

    def _owned(self, state: dict, owner: str | None) -> None:
        if state["owner"] != str(owner or ""):
            raise UploadError("Upload session does not belong to this user")

    def start(
        self, filename: str, destination: str, total_size: int, owner: str | None = None
    ) -> dict:
        if not isinstance(filename, str) or not filename.strip() or len(filename) > 255:
            raise UploadError("Invalid filename")
        filename = filename.replace("/", "_").replace("\\", "_").strip()
        filename = re.sub(r"[\x00-\x1f]", "_", filename)
        if filename in {"", ".", ".."}:
            raise UploadError("Invalid filename")
        if isinstance(total_size, bool) or not isinstance(total_size, int) or total_size < 0:
            raise UploadError("Invalid total size")
        target = self._destination(str(PurePosixPath(destination) / filename))
        owner_id = str(owner or "")
        with self._lock:
            active_for_owner = sum(
                1 for state in self._sessions.values() if state["owner"] == owner_id
            )
            if active_for_owner >= self.max_active:
                raise UploadError("This user already has the maximum number of active uploads")
            if shutil.disk_usage(self.root).free - total_size < self.min_free_bytes:
                raise UploadError("Insufficient free disk space for upload")
            upload_id = uuid.uuid4().hex
            temp_path = self.staging / upload_id
            fd = os.open(temp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            state = {
                "path": temp_path, "target": target, "size": total_size,
                "offset": 0, "filename": filename, "created_at": time.time(),
                "owner": owner_id,
            }
            self._sessions[upload_id] = state
            try:
                self._persist(upload_id, state)
            except OSError:
                self._sessions.pop(upload_id, None)
                self._remove_session_files(upload_id)
                raise
        return {"upload_id": upload_id, "offset": 0, "chunk_limit": self.chunk_limit}

    def append(
        self, upload_id: str, offset: int, stream: BinaryIO, owner: str | None = None
    ) -> dict:
        with self._lock:
            state = self._sessions.get(upload_id)
            if state is None:
                raise UploadError("Unknown or expired upload")
            self._owned(state, owner)
            if offset != state["offset"]:
                raise UploadError("Chunk offset does not match upload state")
            remaining = state["size"] - state["offset"]
            chunk_name = None
            written = 0
            try:
                fd, chunk_name = tempfile.mkstemp(prefix=".chunk-", dir=self.staging)
                with os.fdopen(fd, "wb") as chunk:
                    while written <= self.chunk_limit:
                        block = stream.read(min(1024 * 1024, self.chunk_limit + 1 - written))
                        if not block:
                            break
                        written += len(block)
                        if written > self.chunk_limit or written > remaining:
                            raise UploadError("Chunk exceeds allowed size")
                        chunk.write(block)
                    chunk.flush()
                    os.fsync(chunk.fileno())
                previous_offset = state["offset"]
                with open(chunk_name, "rb") as source, state["path"].open("r+b") as output:
                    output.seek(previous_offset)
                    try:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                        output.flush()
                        os.fsync(output.fileno())
                        state["offset"] += written
                        self._persist(upload_id, state)
                    except OSError:
                        output.truncate(previous_offset)
                        output.flush()
                        os.fsync(output.fileno())
                        state["offset"] = previous_offset
                        raise
                return {"offset": state["offset"], "complete": state["offset"] == state["size"]}
            finally:
                if chunk_name:
                    Path(chunk_name).unlink(missing_ok=True)

    def status(self, upload_id: str, owner: str | None = None) -> dict:
        with self._lock:
            state = self._sessions.get(upload_id)
            if state is None:
                raise UploadError("Unknown or expired upload")
            self._owned(state, owner)
            if time.time() - state["created_at"] > self.session_ttl_seconds:
                self._sessions.pop(upload_id, None)
                self._remove_session_files(upload_id)
                raise UploadError("Upload session expired")
            return {
                "filename": state["filename"], "size": state["size"],
                "offset": state["offset"], "chunk_limit": self.chunk_limit,
            }

    def finish(self, upload_id: str, owner: str | None = None) -> dict:
        with self._lock:
            state = self._sessions.get(upload_id)
            if state is None:
                raise UploadError("Unknown or expired upload")
            self._owned(state, owner)
            if state["offset"] != state["size"]:
                raise UploadError("Upload is incomplete")
            target = state["target"]
            try:
                os.link(state["path"], target, follow_symlinks=False)
            except FileExistsError as exc:
                raise UploadError("Destination already exists; overwrite is not implicit") from exc
            self._sessions.pop(upload_id, None)
            self._remove_session_files(upload_id)
            return {"filename": state["filename"], "size": state["size"]}

    def cancel(self, upload_id: str, owner: str | None = None) -> None:
        with self._lock:
            state = self._sessions.get(upload_id)
            if state is None:
                return
            self._owned(state, owner)
            self._sessions.pop(upload_id, None)
            self._remove_session_files(upload_id)
