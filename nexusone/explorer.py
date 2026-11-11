"""Workspace-confined Explorer API, preserving the legacy dashboard's file operations."""
from __future__ import annotations

import shutil
from pathlib import Path
from threading import RLock

from flask import Blueprint, jsonify, request, send_file, session

from nexusone.security.rbac import Capability, has_capability


def create_explorer_blueprint(root: str | Path) -> Blueprint:
    bp = Blueprint("explorer_api", __name__)
    file_root = Path(root).expanduser().resolve()
    file_root.mkdir(parents=True, exist_ok=True)
    clipboards: dict[str, dict] = {}
    clipboard_lock = RLock()

    def current_user() -> str:
        return str(session.get("username", ""))

    def get_clipboard() -> dict | None:
        with clipboard_lock:
            value = clipboards.get(current_user())
            return dict(value) if value else None

    def save_clipboard(value: dict | None) -> None:
        with clipboard_lock:
            if value:
                clipboards[current_user()] = dict(value)
            else:
                clipboards.pop(current_user(), None)

    def require(capability: Capability) -> None:
        role = session.get("role")
        if role == "user":
            role = "viewer"
        if not has_capability(role, capability):
            from flask import abort
            abort(403, description="Insufficient permissions")

    def safe_path(raw_path: str = ".") -> Path:
        raw = str(raw_path or ".").strip() or "."
        requested = Path(raw).expanduser()
        if any(part == ".nexusone-upload-tmp" or part.startswith(".nexusone-upload-")
               for part in requested.parts):
            raise ValueError("Reserved Explorer path")
        candidate = requested
        if not candidate.is_absolute():
            candidate = file_root / candidate
        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(file_root)
        except (OSError, ValueError) as exc:
            raise ValueError("Path is outside the Explorer workspace") from exc
        return resolved

    def relative(path: Path) -> str:
        try:
            value = path.relative_to(file_root)
        except ValueError:
            return ""
        return "." if str(value) == "." else value.as_posix()

    def entry(path: Path) -> dict:
        stat = path.stat()
        is_dir = path.is_dir()
        return {
            "name": path.name or file_root.name,
            "path": relative(path),
            "type": "directory" if is_dir else "file",
            "size": None if is_dir else stat.st_size,
            "modified": stat.st_mtime,
            "hidden": path.name.startswith("."),
        }

    def clip_paths(value: dict | None) -> list[str]:
        if not value:
            return []
        paths = value.get("paths")
        if isinstance(paths, list):
            return [str(item) for item in paths if item]
        return [str(value["path"])] if value.get("path") else []

    def unique_target(directory: Path, name: str) -> Path:
        candidate = directory / name
        if not candidate.exists():
            return candidate
        source_name = Path(name)
        number = 1
        while True:
            candidate = directory / f"{source_name.stem} ({number}){source_name.suffix}"
            if not candidate.exists():
                return candidate
            number += 1

    @bp.get("/api/files")
    def list_files():
        require(Capability.EXPLORER_READ)
        try:
            directory = safe_path(request.args.get("path", "."))
            if not directory.is_dir():
                return jsonify(ok=False, error="Not a directory"), 400
            entries = []
            for item in directory.iterdir():
                if item == file_root / ".nexusone-upload-tmp":
                    continue
                try:
                    safe_path(item.relative_to(file_root).as_posix())
                    entries.append(entry(item))
                except (OSError, ValueError):
                    continue
            entries.sort(key=lambda item: (item["type"] != "directory", item["name"].lower()))
            parent = None if directory == file_root else relative(directory.parent)
            current_clipboard = get_clipboard()
            return jsonify(
                ok=True, root=str(file_root), path=relative(directory),
                parent=parent, entries=entries, clipboard=current_clipboard,
            )
        except (OSError, ValueError) as exc:
            return jsonify(ok=False, error=str(exc)), 400

    @bp.get("/api/files/download")
    def download_file():
        require(Capability.EXPLORER_READ)
        try:
            path = safe_path(request.args.get("path", ""))
            if not path.is_file():
                return jsonify(ok=False, error="File not found"), 404
            return send_file(path, as_attachment=True, download_name=path.name)
        except (OSError, ValueError) as exc:
            return jsonify(ok=False, error=str(exc)), 400

    @bp.post("/api/files/folder")
    def create_folder():
        require(Capability.EXPLORER_WRITE)
        try:
            payload = request.get_json(silent=True) or {}
            parent = safe_path(payload.get("path", "."))
            name = Path(str(payload.get("name", "")).strip()).name
            if not parent.is_dir() or not name or name in {".", ".."}:
                return jsonify(ok=False, error="Invalid folder name or parent"), 400
            target = safe_path(relative(parent / name))
            target.mkdir()
            return jsonify(ok=True, path=relative(target))
        except FileExistsError:
            return jsonify(ok=False, error="Folder already exists"), 409
        except (OSError, ValueError) as exc:
            return jsonify(ok=False, error=str(exc)), 400

    @bp.post("/api/files/rename")
    def rename_file():
        require(Capability.EXPLORER_WRITE)
        try:
            payload = request.get_json(silent=True) or {}
            source = safe_path(payload.get("path", ""))
            name = Path(str(payload.get("name", "")).strip()).name
            if not source.exists() or not name or name in {".", ".."}:
                return jsonify(ok=False, error="Invalid source or name"), 400
            target = safe_path(relative(source.parent / name))
            if target.exists():
                return jsonify(ok=False, error="A file or folder with that name already exists"), 409
            source.rename(target)
            clip = get_clipboard()
            if clip:
                updated = [relative(target) if safe_path(raw) == source else relative(safe_path(raw))
                           for raw in clip_paths(clip)]
                save_clipboard({"paths": updated, "mode": clip.get("mode"), "count": len(updated)} if updated else None)
            return jsonify(ok=True, path=relative(target))
        except (OSError, ValueError) as exc:
            return jsonify(ok=False, error=str(exc)), 400

    @bp.post("/api/files/delete")
    def delete_files():
        require(Capability.EXPLORER_WRITE)
        nonlocal clipboard
        try:
            payload = request.get_json(silent=True) or {}
            raw_paths = payload.get("paths")
            if raw_paths is None:
                raw_paths = [payload.get("path", "")]
            if not isinstance(raw_paths, list) or not raw_paths:
                return jsonify(ok=False, error="No files selected"), 400
            paths = []
            for raw in raw_paths:
                path = safe_path(raw)
                if path == file_root:
                    return jsonify(ok=False, error="The workspace root cannot be deleted"), 400
                if not path.exists():
                    return jsonify(ok=False, error="File or folder not found"), 404
                paths.append(path)
            unique_paths = sorted(set(paths), key=lambda item: len(item.parts), reverse=True)
            for path in unique_paths:
                if path.is_dir():
                    shutil.rmtree(path)
                elif path.exists():
                    path.unlink()
            clip = get_clipboard()
            if clip:
                remaining = []
                for raw in clip_paths(clip):
                    try:
                        candidate = safe_path(raw)
                    except ValueError:
                        continue
                    if any(candidate == deleted or deleted in candidate.parents for deleted in unique_paths):
                        continue
                    remaining.append(relative(candidate))
                save_clipboard(
                    {"paths": remaining, "mode": clip.get("mode"), "count": len(remaining)}
                    if remaining else None
                )
            current_clipboard = get_clipboard()
            return jsonify(ok=True, clipboard=current_clipboard)
        except (OSError, ValueError) as exc:
            return jsonify(ok=False, error=str(exc)), 400

    @bp.post("/api/files/clipboard")
    def set_clipboard():
        require(Capability.EXPLORER_WRITE)
        nonlocal clipboard
        try:
            payload = request.get_json(silent=True) or {}
            raw_paths = payload.get("paths")
            if raw_paths is None:
                raw_paths = [payload.get("path", "")]
            mode = payload.get("mode")
            if not isinstance(raw_paths, list) or not raw_paths:
                return jsonify(ok=False, error="No files selected"), 400
            if mode not in {"copy", "cut"}:
                return jsonify(ok=False, error="Clipboard mode must be copy or cut"), 400
            paths = []
            for raw in raw_paths:
                path = safe_path(raw)
                if not path.exists():
                    return jsonify(ok=False, error=f"File or folder not found: {relative(path)}"), 404
                rel = relative(path)
                if rel not in paths:
                    paths.append(rel)
            result = {"paths": paths, "mode": mode, "count": len(paths)}
            save_clipboard(result)
            return jsonify(ok=True, clipboard=result, **result)
        except (OSError, ValueError) as exc:
            return jsonify(ok=False, error=str(exc)), 400

    @bp.post("/api/files/paste")
    def paste_files():
        require(Capability.EXPLORER_WRITE)
        nonlocal clipboard
        try:
            payload = request.get_json(silent=True) or {}
            destination = safe_path(payload.get("path", "."))
            conflict_action = str(payload.get("conflict", "ask")).lower()
            if not destination.is_dir():
                return jsonify(ok=False, error="Destination is not a directory"), 400
            if conflict_action not in {"ask", "replace", "rename"}:
                return jsonify(ok=False, error="Invalid conflict action"), 400
            current = get_clipboard()
            if not current:
                return jsonify(ok=False, error="Clipboard is empty"), 400
            sources = []
            missing = []
            for raw in clip_paths(current):
                source = safe_path(raw)
                if not source.exists():
                    missing.append(raw)
                else:
                    sources.append(source)
            if missing:
                save_clipboard(None)
                return jsonify(ok=False, error="Clipboard source no longer exists", missing=missing), 404
            plans, conflicts = [], []
            for source in sources:
                target = safe_path(relative(destination / source.name))
                if target == source or source == destination or source in destination.parents:
                    return jsonify(ok=False, error="Cannot paste a folder into itself"), 400
                if target.exists():
                    conflicts.append({"name": source.name, "path": relative(target), "mode": current.get("mode")})
                plans.append((source, target))
            if conflicts and conflict_action == "ask":
                return jsonify(
                    ok=False, conflict=True, conflicts=conflicts, count=len(conflicts),
                    mode=current.get("mode"), message="One or more selected items already exist here.",
                ), 409
            results = []
            mode = current.get("mode")
            for source, target in plans:
                if target.exists() and conflict_action == "replace":
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                elif target.exists() and conflict_action == "rename":
                    target = unique_target(destination, source.name)
                if mode == "copy":
                    if source.is_dir():
                        shutil.copytree(source, target)
                    else:
                        shutil.copy2(source, target)
                elif mode == "cut":
                    shutil.move(str(source), str(target))
                else:
                    return jsonify(ok=False, error="Invalid clipboard mode"), 400
                results.append(relative(target))
            if mode == "cut":
                save_clipboard(None)
            current_clipboard = get_clipboard()
            return jsonify(ok=True, paths=results, count=len(results), mode=mode, clipboard=current_clipboard)
        except (OSError, ValueError, shutil.Error) as exc:
            return jsonify(ok=False, error=str(exc)), 400

    return bp
