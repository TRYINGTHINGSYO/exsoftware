"""Container inspection protocol.

Child output is hostile. The parent never uses child-supplied filesystem paths.
Blob slots are parent-computed: blobs/NNNNNN.bin
"""

from __future__ import annotations

from typing import Any

from .validate import ProtocolError

CONTAINER_PROTOCOL = "exsoftware.container"
CONTAINER_PROTOCOL_VERSION = 1
OPERATION_EXTRACT = "extract"

EXTRACTION_STATUSES = frozenset(
    {
        "extracted",
        "directory",
        "encrypted",
        "path_traversal",
        "malformed",
        "rejected_size_limit",
        "rejected_ratio",
        "rejected_workspace_budget",
        "not_processed_member_limit",
        "not_processed_list_cap",
        "skipped",
    }
)
ZIP_SUBTYPES = frozenset({"zip", "jar", "apk", "wheel", "docx", "xlsx", "pptx"})
MAX_NAME_CHARS = 4096
BLOB_DIR = "blobs"


def slot_name(index: int) -> str:
    if index < 1 or index > 999999:
        raise ValueError("slot index out of range")
    return f"{index:06d}"


def validate_container_request(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProtocolError("container request is not an object")
    if data.get("protocol") != CONTAINER_PROTOCOL:
        raise ProtocolError("unsupported container protocol name")
    if data.get("protocol_version") != CONTAINER_PROTOCOL_VERSION:
        raise ProtocolError("unsupported container protocol version")
    if data.get("operation") != OPERATION_EXTRACT:
        raise ProtocolError("unsupported container operation")
    for key in ("container_artifact_id", "container_type", "input", "limits"):
        if key not in data:
            raise ProtocolError(f"missing container request field {key}")
    if not isinstance(data["input"], dict) or data["input"].get("path") != "input.bin":
        raise ProtocolError("container input.path must be input.bin")
    if not isinstance(data["limits"], dict):
        raise ProtocolError("limits must be an object")
    return data


def validate_container_response(data: Any, *, artifact_id: str, max_members: int) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProtocolError("container response is not an object")
    if data.get("protocol") != CONTAINER_PROTOCOL:
        raise ProtocolError("unsupported container protocol name")
    if data.get("protocol_version") != CONTAINER_PROTOCOL_VERSION:
        raise ProtocolError("unsupported container protocol version")
    if data.get("operation") != OPERATION_EXTRACT:
        raise ProtocolError("unsupported container operation")
    if data.get("container_artifact_id") != artifact_id:
        raise ProtocolError("container_artifact_id does not match the request")
    status = data.get("status")
    if status not in {"completed", "failed", "timeout", "terminated"}:
        raise ProtocolError("container status is not allowed")
    members = data.get("members")
    if members is None:
        members = []
    if not isinstance(members, list):
        raise ProtocolError("members must be a list")
    if len(members) > max_members:
        raise ProtocolError("members list exceeds parent cap")
    cleaned: list[dict[str, Any]] = []
    extracted_slots = 0
    for item in members:
        cleaned.append(_validate_member(item, extracted_slots_before=extracted_slots))
        if cleaned[-1].get("extraction_status") == "extracted":
            extracted_slots += 1
    data = dict(data)
    data["members"] = cleaned
    subtype = data.get("zip_subtype")
    if subtype is not None and subtype not in ZIP_SUBTYPES:
        raise ProtocolError("zip_subtype is not allowed")
    return data


def _validate_member(item: Any, *, extracted_slots_before: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ProtocolError("member is not an object")
    status = item.get("extraction_status")
    if status not in EXTRACTION_STATUSES:
        raise ProtocolError("extraction_status is not allowed")
    name = item.get("original_name")
    if not isinstance(name, str) or not name or len(name) > MAX_NAME_CHARS:
        raise ProtocolError("original_name is missing or too long")
    if "\x00" in name:
        raise ProtocolError("original_name contains NUL")
    index = item.get("index")
    if not isinstance(index, int) or index < 1:
        raise ProtocolError("member index must be a positive integer")
    out = {
        "index": index,
        "original_name": name,
        "display_name": name.replace("\\", "/"),
        "is_directory": bool(item.get("is_directory")),
        "encrypted": bool(item.get("encrypted")),
        "declared_size": _nonneg_int(item.get("declared_size"), "declared_size"),
        "compressed_size": _nonneg_int(item.get("compressed_size"), "compressed_size"),
        "compression_method": item.get("compression_method") if isinstance(item.get("compression_method"), int) else None,
        "crc": item.get("crc") if isinstance(item.get("crc"), str) else None,
        "flags": item.get("flags") if isinstance(item.get("flags"), int) else None,
        "actual_size": _nonneg_int(item.get("actual_size"), "actual_size") if item.get("actual_size") is not None else None,
        "extraction_status": status,
        "error": item.get("error") if isinstance(item.get("error"), str) else None,
        "slot": None,
    }
    if status == "extracted":
        expected = f"{extracted_slots_before + 1:06d}"
        slot = item.get("slot")
        if slot != expected:
            raise ProtocolError("extracted member slot does not match parent-assigned sequence")
        out["slot"] = expected
    elif item.get("slot") not in {None, ""}:
        raise ProtocolError("non-extracted member must not carry a blob slot")
    return out


def _nonneg_int(value: Any, field: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtocolError(f"{field} must be a non-negative integer")
    return value


def request_template(
    *,
    artifact_id: str,
    container_type: str,
    input_sha256: str,
    input_size: int,
    limits: dict[str, Any],
    test_hook: str | None = None,
    extract_contents: bool = True,
) -> dict[str, Any]:
    payload = {
        "protocol": CONTAINER_PROTOCOL,
        "protocol_version": CONTAINER_PROTOCOL_VERSION,
        "operation": OPERATION_EXTRACT,
        "container_artifact_id": artifact_id,
        "container_type": container_type,
        "input": {"kind": "file", "path": "input.bin", "sha256": input_sha256, "size": input_size},
        "limits": limits,
        "extract_contents": bool(extract_contents),
    }
    if test_hook:
        payload["test_hook"] = test_hook
    return payload
