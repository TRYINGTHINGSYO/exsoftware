"""Parent-side snapshots so analyzer children do not need the original path."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..analyzers.hashes import _digest_path
from ..context import AnalysisContext

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def filesystem_snapshot(path: Path) -> dict[str, Any] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    details: dict[str, Any] = {
        "created": _iso(getattr(st, "st_ctime", None)),
        "modified": _iso(getattr(st, "st_mtime", None)),
        "accessed": _iso(getattr(st, "st_atime", None)),
        "mode": oct(st.st_mode),
        "uid": getattr(st, "st_uid", None),
        "gid": getattr(st, "st_gid", None),
        "path_withheld_from_analyzer_process": True,
    }
    value = getattr(st, "st_file_attributes", None)
    if value is not None:
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
        details["windows_attributes"] = {"value": value, "flags": names}
    return details


def parent_context_extra(
    ctx: AnalysisContext,
    *,
    test_mode: bool = False,
    allowed_test_keys: frozenset[str] | None = None,
) -> dict[str, Any]:
    extra: dict[str, Any] = {}
    src = ctx.extra or {}
    for key in (
        "parent_artifact_id",
        "member_name",
        "last_modified_ms",
        "client_last_modified",
        "last_modified_header",
    ):
        if key in src:
            extra[key] = src[key]
    if test_mode:
        for key in allowed_test_keys or ():
            if key in src:
                extra[key] = src[key]
    if ctx.path is not None:
        snap = filesystem_snapshot(ctx.path)
        if snap:
            extra["filesystem_snapshot"] = snap
        if ctx.truncated:
            extra["full_file_hashes"] = _digest_path(ctx.path)
            extra["hash_coverage"] = "full-file"
        else:
            extra["hash_coverage"] = "full-file"
    return extra


def identity_for_child(identity: Any) -> dict[str, Any]:
    data = identity.to_dict() if identity is not None else {}
    data["path"] = None
    return data
