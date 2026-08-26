"""Child-side OLE stream enumeration.

Runs only inside the isolated worker. Uses olefile on hostile bytes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def run_refine(request: dict[str, Any], workdir: Path) -> dict[str, Any]:
    input_spec = request["input"]
    input_path = Path(input_spec["path"])
    if not input_path.is_absolute():
        input_path = workdir / input_path
    data = input_path.read_bytes()
    try:
        import olefile
    except ImportError as exc:
        return {
            "status": "failed",
            "is_ole": False,
            "streams": [],
            "errors": [{"code": "missing_dependency", "message": str(exc) or "olefile not installed"}],
        }
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
        return {
            "status": "failed",
            "is_ole": False,
            "streams": [],
            "errors": [{"code": "ole_parse_error", "message": str(exc) or exc.__class__.__name__}],
        }
