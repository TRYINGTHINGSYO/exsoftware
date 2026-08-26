"""OLE identity-refinement protocol.

Child output is hostile. The parent never uses child-supplied filesystem paths.
Stream names are metadata strings used only for subtype classification.
"""

from __future__ import annotations

from typing import Any

from .validate import ProtocolError

OLE_PROTOCOL = "exsoftware.ole"
OLE_PROTOCOL_VERSION = 1
OPERATION_REFINE = "refine"

OLE_SUBTYPES = frozenset({"ole", "doc", "xls", "ppt", "msi", "msg"})
MAX_STREAM_CHARS = 4096
MAX_STREAMS = 4096


def validate_ole_request(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProtocolError("ole request is not an object")
    if data.get("protocol") != OLE_PROTOCOL:
        raise ProtocolError("unsupported ole protocol name")
    if data.get("protocol_version") != OLE_PROTOCOL_VERSION:
        raise ProtocolError("unsupported ole protocol version")
    if data.get("operation") != OPERATION_REFINE:
        raise ProtocolError("unsupported ole operation")
    for key in ("artifact_id", "input", "limits"):
        if key not in data:
            raise ProtocolError(f"missing ole request field {key}")
    if not isinstance(data["input"], dict) or data["input"].get("path") != "input.bin":
        raise ProtocolError("ole input.path must be input.bin")
    if not isinstance(data["limits"], dict):
        raise ProtocolError("limits must be an object")
    return data


def validate_ole_response(data: Any, *, artifact_id: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProtocolError("ole response is not an object")
    if data.get("protocol") != OLE_PROTOCOL:
        raise ProtocolError("unsupported ole protocol name")
    if data.get("protocol_version") != OLE_PROTOCOL_VERSION:
        raise ProtocolError("unsupported ole protocol version")
    if data.get("operation") != OPERATION_REFINE:
        raise ProtocolError("unsupported ole operation")
    if data.get("artifact_id") != artifact_id:
        raise ProtocolError("ole artifact_id does not match the request")
    status = data.get("status")
    if status not in {"completed", "failed", "timeout", "terminated"}:
        raise ProtocolError("ole status is not allowed")
    streams = data.get("streams")
    if streams is None:
        streams = []
    if not isinstance(streams, list):
        raise ProtocolError("streams must be a list")
    if len(streams) > MAX_STREAMS:
        raise ProtocolError("streams list exceeds parent cap")
    cleaned: list[str] = []
    for item in streams:
        if not isinstance(item, str):
            raise ProtocolError("stream name must be a string")
        if len(item) > MAX_STREAM_CHARS:
            raise ProtocolError("stream name exceeds length cap")
        cleaned.append(item)
    out = dict(data)
    out["streams"] = cleaned
    if "is_ole" in out and not isinstance(out["is_ole"], bool):
        raise ProtocolError("is_ole must be a boolean")
    return out


def request_template(
    *,
    artifact_id: str,
    input_sha256: str,
    input_size: int,
    limits: dict[str, Any],
) -> dict[str, Any]:
    return {
        "protocol": OLE_PROTOCOL,
        "protocol_version": OLE_PROTOCOL_VERSION,
        "operation": OPERATION_REFINE,
        "artifact_id": artifact_id,
        "input": {
            "kind": "file",
            "path": "input.bin",
            "sha256": input_sha256,
            "size": input_size,
        },
        "limits": dict(limits),
    }
