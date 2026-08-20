from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from .base import Analyzer

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def _windows_attributes(path: Path) -> dict | None:
    try:
        st = path.stat()
    except OSError:
        return None
    value = getattr(st, "st_file_attributes", None)
    if value is None:
        return None
    names = []
    mapping = {
        0x1: "readonly",
        0x2: "hidden",
        0x4: "system",
        0x20: "archive",
        0x400: "reparse_point",
        0x800: "compressed",
        0x1000: "offline",
        0x4000: "encrypted",
    }
    for bit, label in mapping.items():
        if value & bit:
            names.append(label)
    return {"value": value, "flags": names}


class FilesystemAnalyzer(Analyzer):
    name = "filesystem"
    title = "Filesystem metadata"

    def analyze(self, ctx):
        details: dict = {
            "source": ctx.source,
            "name": ctx.name,
            "size": ctx.size,
            "analyzed_bytes": len(ctx.data),
        }
        extra = ctx.extra or {}
        snapshot = extra.get("filesystem_snapshot")
        if snapshot:
            details.update(snapshot)
            return self.result(details=details)
        if ctx.path is None:
            if "last_modified_ms" in extra:
                details["client_last_modified"] = _iso(extra["last_modified_ms"] / 1000)
            details["note"] = (
                "No filesystem path was available. Browser uploads typically expose "
                "only the file name, size, and last-modified time."
            )
            return self.result(details=details)

        path = ctx.path
        try:
            st = path.stat()
        except OSError as exc:
            return self.failure(exc)

        details.update(
            {
                "path": str(path),
                "absolute_path": str(path.resolve()),
                "created": _iso(getattr(st, "st_ctime", None)),
                "modified": _iso(getattr(st, "st_mtime", None)),
                "accessed": _iso(getattr(st, "st_atime", None)),
                "mode": oct(st.st_mode),
                "uid": getattr(st, "st_uid", None),
                "gid": getattr(st, "st_gid", None),
            }
        )
        win = _windows_attributes(path)
        if win:
            details["windows_attributes"] = win
        return self.result(details=details)
