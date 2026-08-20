from __future__ import annotations

from datetime import datetime, timezone

from ..models import Evidence, Finding
from .base import Analyzer

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc

HAS_LINK_TARGET_ID_LIST = 1 << 0
HAS_LINK_INFO = 1 << 1
HAS_NAME = 1 << 2
HAS_RELATIVE_PATH = 1 << 3
HAS_WORKING_DIR = 1 << 4
HAS_ARGUMENTS = 1 << 5
HAS_ICON_LOCATION = 1 << 6
IS_UNICODE = 1 << 7


class LnkAnalyzer(Analyzer):
    name = "lnk"
    title = "Windows shortcut"
    detected_types = frozenset({"lnk"})

    def analyze(self, ctx):
        data = ctx.data
        if len(data) < 0x4C:
            return self.failure(ValueError("Truncated LNK header"))
        header_size = int.from_bytes(data[0:4], "little")
        flags = int.from_bytes(data[0x14:0x18], "little")
        file_attrs = int.from_bytes(data[0x18:0x1C], "little")
        created = _filetime(data[0x1C:0x24])
        accessed = _filetime(data[0x24:0x2C])
        written = _filetime(data[0x2C:0x34])
        file_size = int.from_bytes(data[0x34:0x38], "little")
        show_command = int.from_bytes(data[0x3C:0x40], "little")
        parsed = _parse_lnk(data)
        findings = [
            Finding(
                id="lnk.target",
                title="Windows shortcut",
                summary=_lnk_summary(parsed),
                category="shortcut",
                severity="info",
                confidence="medium" if parsed.get("error") else "high",
                analyzer=self.name,
                tags=["lnk"],
                evidence=[
                    Evidence(kind="field", summary=key, analyzer=self.name, value=str(value)[:400])
                    for key, value in parsed.items()
                    if value and key in {"local_path", "relative_path", "arguments", "working_dir", "name", "icon_location"}
                ],
            )
        ]
        if parsed.get("arguments"):
            findings.append(
                Finding(
                    id="lnk.arguments",
                    title="Shortcut arguments",
                    summary="The LNK stores command-line arguments for the target.",
                    category="shortcut",
                    severity="low",
                    confidence="high",
                    analyzer=self.name,
                    tags=["arguments"],
                    evidence=[
                        Evidence(kind="string", summary="Arguments", analyzer=self.name, value=str(parsed["arguments"])[:500])
                    ],
                )
            )
        details = {
            "header_size": header_size,
            "flags": flags,
            "file_attributes": file_attrs,
            "created": created,
            "accessed": accessed,
            "written": written,
            "file_size": file_size,
            "show_command": show_command,
            **parsed,
        }
        return self.result(details=details, findings=findings)


def _parse_lnk(data: bytes) -> dict:
    flags = int.from_bytes(data[0x14:0x18], "little")
    unicode = bool(flags & IS_UNICODE)
    offset = int.from_bytes(data[0:4], "little")
    out: dict = {}
    try:
        if flags & HAS_LINK_TARGET_ID_LIST:
            idlist_size = int.from_bytes(data[offset : offset + 2], "little")
            offset += 2 + idlist_size
        if flags & HAS_LINK_INFO:
            info_size = int.from_bytes(data[offset : offset + 4], "little")
            out["local_path"] = _link_info_path(data[offset : offset + info_size])
            offset += info_size
        for bit, key in (
            (HAS_NAME, "name"),
            (HAS_RELATIVE_PATH, "relative_path"),
            (HAS_WORKING_DIR, "working_dir"),
            (HAS_ARGUMENTS, "arguments"),
            (HAS_ICON_LOCATION, "icon_location"),
        ):
            if flags & bit:
                value, offset = _read_string(data, offset, unicode)
                out[key] = value
    except Exception as exc:
        out["error"] = str(exc)
    return out


def _link_info_path(info: bytes) -> str | None:
    if len(info) < 16:
        return None
    link_info_flags = int.from_bytes(info[8:12], "little")
    local_base_path_offset = int.from_bytes(info[16:20], "little")
    if link_info_flags & 1 and 0 < local_base_path_offset < len(info):
        raw = info[local_base_path_offset:].split(b"\x00", 1)[0]
        return raw.decode("latin-1", "replace")
    return None


def _read_string(data: bytes, offset: int, unicode: bool) -> tuple[str, int]:
    if offset + 2 > len(data):
        raise ValueError("Truncated string count")
    count = int.from_bytes(data[offset : offset + 2], "little")
    offset += 2
    if unicode:
        nbytes = count * 2
        raw = data[offset : offset + nbytes]
        text = raw.decode("utf-16le", "replace")
        return text.rstrip("\x00"), offset + nbytes
    raw = data[offset : offset + count]
    return raw.decode("latin-1", "replace"), offset + count


def _filetime(raw: bytes) -> str | None:
    if len(raw) != 8:
        return None
    value = int.from_bytes(raw, "little")
    if value == 0:
        return None
    # FILETIME is 100-ns intervals since 1601.
    try:
        ts = value / 10_000_000 - 11644473600
        return datetime.fromtimestamp(ts, tz=UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return str(value)


def _lnk_summary(parsed: dict) -> str:
    target = parsed.get("local_path") or parsed.get("relative_path") or parsed.get("name") or "an unspecified target"
    args = parsed.get("arguments")
    if args:
        return f"This shortcut points at {target} with arguments {args!r}."
    return f"This shortcut points at {target}."
