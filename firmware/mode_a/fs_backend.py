"""Explicit UBIFS metadata transport for the native filesystem helper.

The payload directory contains numbered ordinary files only. Linux paths,
symlink targets, permissions, ownership and times travel in the inventory;
host filesystem metadata is never substituted for device metadata.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import stat

SCHEMA = "ascent.ubifs.inventory.v1"


def _integer(value, name, maximum=0xffffffff):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"Invalid {name} in filesystem inventory")
    return value


def _timestamp(value, name):
    if not isinstance(value, (tuple, list)) or len(value) != 2:
        raise ValueError(f"Invalid {name} in filesystem inventory")
    return [_integer(value[0], name, 0x7fffffffffffffff),
            _integer(value[1], name, 999999999)]


def export_inventory(inventory, directory):
    """Write a fresh helper input without chmod/chown or host symlinks.

    Unsupported inode kinds and hardlinks refuse before any payload is written.
    Existing output directories are not reused, avoiding stale helper inputs.
    """
    entries = inventory.get("entries")
    if not isinstance(entries, dict) or "/" not in entries:
        raise ValueError("Filesystem inventory must include its root")
    rows, blobs = [], []
    for path, entry in sorted(entries.items()):
        if (not isinstance(path, str) or not path.startswith("/")
                or "\x00" in path or "\\" in path
                or str(PurePosixPath(path)) != path
                or any(part in (".", "..") for part in path.split("/"))):
            raise ValueError("Invalid device path in filesystem inventory")
        path.encode("utf-8", errors="strict")
        mode = _integer(entry.get("mode"), "mode")
        kind = stat.S_IFMT(mode)
        types = {stat.S_IFDIR: "directory", stat.S_IFREG: "file", stat.S_IFLNK: "symlink"}
        if kind not in types:
            raise ValueError("Unsupported inode type in filesystem inventory")
        row = {"path": path, "type": types[kind], "mode": mode,
               "uid": _integer(entry.get("uid"), "uid"),
               "gid": _integer(entry.get("gid"), "gid"),
               "nlink": _integer(entry.get("nlink"), "nlink"),
               "flags": _integer(entry.get("flags"), "flags"),
               "size": _integer(entry.get("size"), "size", 0x7fffffffffffffff),
               "atime": _timestamp(entry.get("atime"), "atime"),
               "mtime": _timestamp(entry.get("mtime"), "mtime")}
        if row["nlink"] < 1:
            raise ValueError("Invalid link count in filesystem inventory")
        if path == "/" and kind != stat.S_IFDIR:
            raise ValueError("Filesystem root must be a directory")
        if path != "/":
            parent = str(PurePosixPath(path).parent)
            if parent not in entries or stat.S_IFMT(entries[parent]["mode"]) != stat.S_IFDIR:
                raise ValueError("Missing parent directory in filesystem inventory")
        if kind == stat.S_IFREG:
            data = entry.get("content")
            if row["nlink"] != 1:
                raise ValueError("Hardlinks require a separately qualified backend")
            if not isinstance(data, bytes) or len(data) != row["size"]:
                raise ValueError("Missing or mismatched file content in filesystem inventory")
            if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
                raise ValueError("File content hash differs from filesystem inventory")
            row["content_file"] = f"{len(blobs):08d}.bin"
            blobs.append((row["content_file"], data))
        elif kind == stat.S_IFLNK:
            target = entry.get("target")
            if not isinstance(target, str) or "\x00" in target:
                raise ValueError("Invalid symlink target in filesystem inventory")
            if len(target.encode("utf-8", errors="strict")) != row["size"]:
                raise ValueError("Symlink size differs from filesystem inventory")
            row["target"] = target
        rows.append(row)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    payload = directory / "payload"
    payload.mkdir()
    for name, data in blobs:
        (payload / name).write_bytes(data)
    manifest = directory / "inventory.json"
    manifest.write_text(json.dumps({"schema": SCHEMA, "entries": rows},
                                   ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return manifest, payload
