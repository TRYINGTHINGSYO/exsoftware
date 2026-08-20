"""ZIP-family enumeration and extraction. Runs only in the isolated child.

The trusted parent must not import zipfile against submitted bytes. This module
is loaded by the worker process.
"""

from __future__ import annotations

import os
import time
import zipfile
from pathlib import Path
from typing import Any

from ..identify import refine_zip_type_from_names
from .container_protocol import BLOB_DIR, slot_name

RECURSE_TYPES = {"zip", "jar", "apk", "wheel"}


def _is_traversal(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return True
    return ".." in normalized.split("/")


def run_extract(request: dict[str, Any], workdir: Path) -> dict[str, Any]:
    hook = request.get("test_hook") if os.environ.get("EXSOFTWARE_ISOLATE_TEST") == "1" else None
    if hook == "hang":
        while True:
            time.sleep(60)
    if hook == "abort":
        os.abort()
    if hook == "exception":
        raise RuntimeError("synthetic container parser exception")

    limits = request.get("limits") or {}
    max_list = int(limits.get("max_list_entries") or 400)
    max_members = int(limits.get("max_members") or 64)
    max_member_bytes = int(limits.get("max_member_bytes") or 8 * 1024 * 1024)
    max_total = int(limits.get("max_total_expanded_bytes") or 32 * 1024 * 1024)
    max_workspace = int(limits.get("max_workspace_bytes") or max_total)
    max_blobs = int(limits.get("max_blobs") or max_members)
    max_ratio = float(limits.get("max_compression_ratio") or 100.0)
    extract_cap = min(max_members, max_blobs)

    input_path = workdir / "input.bin"
    try:
        archive = zipfile.ZipFile(input_path)
    except zipfile.BadZipFile as exc:
        return {
            "status": "failed",
            "zip_subtype": "zip",
            "listed_count": 0,
            "truncated_listing": False,
            "members": [],
            "errors": [{"code": "bad_zip", "message": str(exc)}],
            "limits_hit": [],
        }

    blob_root = workdir / BLOB_DIR
    blob_root.mkdir(parents=True, exist_ok=True)

    members: list[dict[str, Any]] = []
    infos_by_index: dict[int, zipfile.ZipInfo] = {}
    limits_hit: list[str] = []
    names: list[str] = []

    with archive:
        infos = archive.infolist()
        listed_count = len(infos)
        truncated_listing = listed_count > max_list
        if truncated_listing:
            limits_hit.append("list_cap")
        for position, info in enumerate(infos[:max_list], start=1):
            names.append(info.filename)
            infos_by_index[position] = info
            members.append(_row(index=position, info=info, status="skipped"))

        subtype = refine_zip_type_from_names(names)[0]
        extract_contents = bool(request.get("extract_contents", True))
        if (not extract_contents) or subtype not in RECURSE_TYPES:
            for row in members:
                if row["extraction_status"] == "skipped":
                    if row["is_directory"]:
                        row["extraction_status"] = "directory"
                    elif row["encrypted"]:
                        row["extraction_status"] = "encrypted"
                    elif _is_traversal(row["original_name"]):
                        row["extraction_status"] = "path_traversal"
                    else:
                        row["extraction_status"] = "skipped"
            return _done(subtype, listed_count, truncated_listing, members, limits_hit)

        extracted_bytes = 0
        extracted_count = 0
        next_slot = 1
        hit_member_limit = False
        for row in members:
            info = infos_by_index.get(row["index"])
            if info is None:
                continue
            if row["is_directory"]:
                row["extraction_status"] = "directory"
                continue
            if row["encrypted"]:
                row["extraction_status"] = "encrypted"
                continue
            if _is_traversal(row["original_name"]):
                row["extraction_status"] = "path_traversal"
                continue
            if hit_member_limit:
                row["extraction_status"] = "not_processed_member_limit"
                continue
            if extracted_count >= extract_cap:
                row["extraction_status"] = "not_processed_member_limit"
                limits_hit.append("member_count")
                hit_member_limit = True
                continue
            remaining = min(max_total, max_workspace) - extracted_bytes
            if remaining <= 0:
                row["extraction_status"] = "rejected_workspace_budget"
                limits_hit.append("workspace_budget")
                continue
            slot = slot_name(next_slot)
            dest = blob_root / f"{slot}.bin"
            try:
                written, status = _bounded_extract(
                    archive,
                    info,
                    dest,
                    max_member_bytes=max_member_bytes,
                    remaining_budget=remaining,
                )
            except Exception as exc:
                row["extraction_status"] = "malformed"
                row["error"] = f"{exc.__class__.__name__}: {exc}"
                dest.unlink(missing_ok=True)
                continue
            row["actual_size"] = written
            if status != "extracted":
                row["extraction_status"] = status
                dest.unlink(missing_ok=True)
                limits_hit.append(
                    {
                        "rejected_size_limit": "member_size",
                        "rejected_workspace_budget": "workspace_budget",
                    }.get(status, status)
                )
                continue
            compressed = max(int(row["compressed_size"] or 0), 1)
            if written / compressed > max_ratio:
                row["extraction_status"] = "rejected_ratio"
                dest.unlink(missing_ok=True)
                limits_hit.append("ratio")
                continue
            row["extraction_status"] = "extracted"
            row["slot"] = slot
            next_slot += 1
            extracted_count += 1
            extracted_bytes += written

    return _done(subtype, listed_count, truncated_listing, members, limits_hit)


def _row(*, index: int, info: zipfile.ZipInfo, status: str) -> dict[str, Any]:
    name = info.filename
    return {
        "index": index,
        "original_name": name,
        "display_name": name.replace("\\", "/"),
        "is_directory": bool(info.is_dir() or name.endswith("/")),
        "encrypted": bool(info.flag_bits & 0x1),
        "declared_size": int(info.file_size or 0),
        "compressed_size": int(info.compress_size or 0),
        "compression_method": int(info.compress_type),
        "crc": hex(info.CRC),
        "flags": int(info.flag_bits),
        "actual_size": None,
        "extraction_status": status,
        "slot": None,
        "error": None,
    }


def _done(subtype, listed_count, truncated_listing, members, limits_hit):
    return {
        "status": "completed",
        "zip_subtype": subtype,
        "listed_count": listed_count,
        "truncated_listing": truncated_listing,
        "members": members,
        "errors": [],
        "limits_hit": sorted({item for item in limits_hit if isinstance(item, str)}),
    }


def _bounded_extract(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    dest: Path,
    *,
    max_member_bytes: int,
    remaining_budget: int,
) -> tuple[int, str]:
    written = 0
    with archive.open(info, "r") as src, dest.open("wb") as dst:
        while True:
            chunk = src.read(65536)
            if not chunk:
                break
            written += len(chunk)
            if written > max_member_bytes:
                return written, "rejected_size_limit"
            if written > remaining_budget:
                return written, "rejected_workspace_budget"
            dst.write(chunk)
    return written, "extracted"
