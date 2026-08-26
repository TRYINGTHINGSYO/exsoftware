"""Child-side OLE stream enumeration.

Runs only inside the isolated worker. Uses olefile on hostile bytes.
Validates input.bin against the request size and SHA-256 before parsing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..content import digest_bytes


def run_refine(request: dict[str, Any], workdir: Path) -> dict[str, Any]:
    input_spec = request["input"]
    input_path = Path(input_spec["path"])
    if not input_path.is_absolute():
        input_path = workdir / input_path
    data = input_path.read_bytes()

    expected_size = input_spec.get("size")
    if expected_size is None:
        return _fail("input_size_missing", "OLE request input.size is required")
    try:
        expected_size_int = int(expected_size)
    except (TypeError, ValueError):
        return _fail("input_size_invalid", "OLE request input.size is not an integer")
    if expected_size_int != len(data):
        return _fail(
            "input_size_mismatch",
            f"input.bin size {len(data)} did not match request size {expected_size_int}",
        )

    expected_hash = input_spec.get("sha256")
    if not expected_hash or not isinstance(expected_hash, str):
        return _fail("input_hash_missing", "OLE request input.sha256 is required")
    digest = digest_bytes(data)
    if digest["sha256"] != expected_hash:
        return _fail(
            "input_hash_mismatch",
            "input.bin SHA-256 did not match the request",
        )

    try:
        import olefile
    except ImportError as exc:
        return _fail("missing_dependency", str(exc) or "olefile not installed")
    try:
        if not olefile.isOleFile(data):
            return {
                "status": "completed",
                "is_ole": False,
                "streams": [],
                "errors": [],
            }
        with olefile.OleFileIO(data) as ole:
            streams = sorted({"/" + "/".join(parts) for parts in ole.listdir()})
        return {
            "status": "completed",
            "is_ole": True,
            "streams": streams,
            "errors": [],
        }
    except Exception as exc:
        return _fail("ole_parse_error", str(exc) or exc.__class__.__name__)


def _fail(code: str, message: str) -> dict[str, Any]:
    return {
        "status": "failed",
        "is_ole": False,
        "streams": [],
        "errors": [{"code": code, "message": message}],
    }
