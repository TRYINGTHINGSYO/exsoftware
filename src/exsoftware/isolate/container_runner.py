"""Parent broker for contained ZIP-family inspection.

Child JSON and blob contents are hostile. The parent assigns blob slot names,
opens them with no-follow, and hashes bytes itself.
"""

from __future__ import annotations

import json
import os
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Any

from ..content import digest_fd
from ..identify import refine_zip_type_from_names
from ..limits import RecursionLimits
from .bootstrap import attach_bootstrap_ack
from .container_protocol import (
    CONTAINER_PROTOCOL,
    CONTAINER_PROTOCOL_VERSION,
    request_template,
    validate_container_request,
    validate_container_response,
)
from .output import BoundedStream, finish_streams
from .policy import IsolationPolicy
from .process import child_env, close_job, create_output_streams, spawn_worker, terminate_tree, wait_or_timeout
from .protocol import (
    REASON_CHILD_CRASH,
    REASON_CHILD_EXIT,
    REASON_EMPTY_RESPONSE,
    REASON_INVALID_RESPONSE,
    REASON_OVERSIZED,
    REASON_SPAWN_FAILED,
    REASON_TIMEOUT,
    TEST_ENV,
)
from .validate import ProtocolError
from .workspace import OversizedWorkspaceFile, create_workspace, open_blob_slot, read_workspace_file, rmtree_retry

INPUT_NAME = "input.bin"
REQUEST_NAME = "request.json"
RESPONSE_NAME = "response.json"


@dataclass
class ExtractedBlob:
    slot: str
    original_name: str
    display_name: str
    index: int
    size: int
    hashes: dict[str, str]
    compressed_size: int
    compression_method: int | None
    crc: str | None
    encrypted: bool
    declared_size: int
    extraction_status: str
    data: bytes


@dataclass
class ListedMember:
    index: int
    original_name: str
    display_name: str
    is_directory: bool
    encrypted: bool
    declared_size: int
    compressed_size: int
    compression_method: int | None
    crc: str | None
    flags: int | None
    actual_size: int | None
    extraction_status: str
    error: str | None
    slot: str | None
    blob: ExtractedBlob | None = None


@dataclass
class ContainerResult:
    status: str
    reason: str | None
    zip_subtype: str
    listed_count: int
    truncated_listing: bool
    members: list[ListedMember] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    limits_hit: list[str] = field(default_factory=list)
    isolation: dict[str, Any] = field(default_factory=dict)
    message: str | None = None


class IsolatedContainerRunner:
    def __init__(self, limits: RecursionLimits | None = None) -> None:
        self.limits = limits or RecursionLimits()

    def extract(
        self,
        data: bytes,
        *,
        artifact_id: str,
        container_type: str = "zip",
        timeout: float | None = None,
        test_hook: str | None = None,
        extract_contents: bool = True,
    ) -> ContainerResult:
        timeout = float(timeout if timeout is not None else self.limits.analyzer_timeout_seconds)
        policy = IsolationPolicy.from_limits(self.limits)
        policy.timeout_seconds = timeout
        workdir: Path | None = None
        proc = None
        stdout: BoundedStream | None = None
        stderr: BoundedStream | None = None
        isolation: dict[str, Any] = {
            "mode": "subprocess",
            "protocol": CONTAINER_PROTOCOL,
            "protocol_version": CONTAINER_PROTOCOL_VERSION,
            "operation": "extract",
            "sandbox": False,
            "containment": "static-parser",
        }
        started = perf_counter()
        try:
            try:
                workdir = create_workspace()
            except Exception as exc:
                policy.fail("temporary_storage", f"Isolated workspace setup failed: {exc}")
                raise
            policy.establish(
                "temporary_storage",
                "Isolated workspace created and access restrictions applied",
            )
            isolation["workdir"] = str(workdir)
            (workdir / INPUT_NAME).write_bytes(data)
            from ..content import sha256_hex

            request = request_template(
                artifact_id=artifact_id,
                container_type=container_type,
                input_sha256=sha256_hex(data),
                input_size=len(data),
                limits={
                    "timeout_seconds": timeout,
                    "max_result_bytes": self.limits.max_result_bytes,
                    "max_memory_bytes": self.limits.max_child_memory_bytes,
                    "max_cpu_seconds": self.limits.max_child_cpu_seconds if self.limits.max_child_cpu_seconds is not None else timeout,
                    "max_child_processes": self.limits.max_child_processes,
                    "max_members": self.limits.max_member_count,
                    "max_list_entries": self.limits.max_zip_list_entries,
                    "max_member_bytes": self.limits.max_member_bytes,
                    "max_total_expanded_bytes": self.limits.max_total_expanded_bytes,
                    "max_workspace_bytes": self.limits.max_workspace_bytes,
                    "max_blobs": self.limits.max_blobs,
                    "max_compression_ratio": self.limits.max_compression_ratio,
                },
                test_hook=test_hook,
                extract_contents=extract_contents,
            )
            validate_container_request(request)
            (workdir / REQUEST_NAME).write_text(json.dumps(request), encoding="utf-8")
            test_mode = os.environ.get(TEST_ENV) == "1" or bool(test_hook)
            env = child_env(test_mode=test_mode, workdir=workdir)
            stdout, stderr = create_output_streams(policy)
            proc, spawn_meta = spawn_worker(
                workdir=workdir,
                env=env,
                policy=policy,
                stdout=stdout,
                stderr=stderr,
            )
            isolation.update(spawn_meta)
            isolation["capabilities"] = policy.capabilities()
            isolation["mechanism"] = policy.mechanism
            isolation["policy"] = policy.to_dict()
            rc = wait_or_timeout(proc, timeout)
            if rc is None:
                isolation["termination"] = terminate_tree(proc)
                isolation["stdio"] = finish_streams(stdout, stderr)
                attach_bootstrap_ack(
                    isolation,
                    policy,
                    workdir,
                    timed_out=True,
                    returncode=proc.returncode,
                )
                isolation["duration_ms"] = (perf_counter() - started) * 1000
                return ContainerResult(
                    status="timeout",
                    reason=REASON_TIMEOUT,
                    zip_subtype="zip",
                    listed_count=0,
                    truncated_listing=False,
                    isolation=isolation,
                    message=f"Container worker exceeded {timeout} seconds and was terminated.",
                )
            isolation["returncode"] = rc
            isolation["stdio"] = finish_streams(stdout, stderr)
            attach_bootstrap_ack(
                isolation,
                policy,
                workdir,
                timed_out=False,
                returncode=rc,
            )
            return self._ingest(workdir, artifact_id, isolation, rc, started)
        except Exception as exc:
            isolation["spawn_error"] = str(exc)
            isolation["traceback"] = traceback.format_exc()
            isolation["capabilities"] = policy.capabilities()
            isolation["mechanism"] = policy.mechanism
            isolation["policy"] = policy.to_dict()
            isolation["stdio"] = finish_streams(stdout, stderr)
            return ContainerResult(
                status="failed",
                reason=REASON_SPAWN_FAILED,
                zip_subtype="zip",
                listed_count=0,
                truncated_listing=False,
                isolation=isolation,
                message=str(exc) or exc.__class__.__name__,
            )
        finally:
            if proc is not None:
                if proc.poll() is None:
                    terminate_tree(proc)
                close_job(proc)
            if workdir is not None:
                isolation["workdir_removed"] = rmtree_retry(workdir)

    def _ingest(
        self,
        workdir: Path,
        artifact_id: str,
        isolation: dict[str, Any],
        returncode: int,
        started: float,
    ) -> ContainerResult:
        isolation["duration_ms"] = (perf_counter() - started) * 1000
        try:
            raw = read_workspace_file(workdir, RESPONSE_NAME, max_bytes=self.limits.max_result_bytes)
        except OversizedWorkspaceFile as exc:
            return ContainerResult(
                status="failed",
                reason=REASON_OVERSIZED,
                zip_subtype="zip",
                listed_count=0,
                truncated_listing=False,
                isolation=isolation,
                message=str(exc),
            )
        except OSError as exc:
            message = str(exc)
            if "reparse" in message or "symlink" in message or "escaped" in message:
                return ContainerResult(
                    status="failed",
                    reason=REASON_INVALID_RESPONSE,
                    zip_subtype="zip",
                    listed_count=0,
                    truncated_listing=False,
                    isolation=isolation,
                    message=f"Refused to read container response: {exc}",
                )
            reason = REASON_CHILD_CRASH if _looks_like_crash(returncode) else REASON_CHILD_EXIT
            return ContainerResult(
                status="failed",
                reason=reason,
                zip_subtype="zip",
                listed_count=0,
                truncated_listing=False,
                isolation=isolation,
                message=f"Container child exited without a readable response (returncode={returncode}).",
            )
        if not raw:
            return ContainerResult(
                status="failed",
                reason=REASON_EMPTY_RESPONSE,
                zip_subtype="zip",
                listed_count=0,
                truncated_listing=False,
                isolation=isolation,
                message="Container child wrote an empty response.",
            )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            return ContainerResult(
                status="failed",
                reason=REASON_INVALID_RESPONSE,
                zip_subtype="zip",
                listed_count=0,
                truncated_listing=False,
                isolation=isolation,
                message=f"Container response was not valid JSON ({exc}).",
            )
        cap = self.limits.max_zip_list_entries + 8
        try:
            payload = validate_container_response(payload, artifact_id=artifact_id, max_members=cap)
        except ProtocolError as exc:
            return ContainerResult(
                status="failed",
                reason=exc.code,
                zip_subtype="zip",
                listed_count=0,
                truncated_listing=False,
                isolation=isolation,
                message=str(exc),
            )
        if payload.get("status") != "completed":
            return ContainerResult(
                status="failed",
                reason=payload.get("errors") and payload["errors"][0].get("code") or "container_failed",
                zip_subtype="zip",
                listed_count=int(payload.get("listed_count") or 0),
                truncated_listing=bool(payload.get("truncated_listing")),
                errors=list(payload.get("errors") or []),
                isolation=isolation,
                message=(payload.get("errors") or [{}])[0].get("message") if payload.get("errors") else "container worker failed",
            )
        names = [item["original_name"] for item in payload.get("members") or []]
        zip_subtype = refine_zip_type_from_names(names)[0]
        members: list[ListedMember] = []
        budget = 0
        for item in payload.get("members") or []:
            listed = ListedMember(
                index=item["index"],
                original_name=item["original_name"],
                display_name=item["display_name"],
                is_directory=item["is_directory"],
                encrypted=item["encrypted"],
                declared_size=item["declared_size"],
                compressed_size=item["compressed_size"],
                compression_method=item.get("compression_method"),
                crc=item.get("crc"),
                flags=item.get("flags"),
                actual_size=item.get("actual_size"),
                extraction_status=item["extraction_status"],
                error=item.get("error"),
                slot=item.get("slot"),
            )
            if listed.extraction_status == "extracted" and listed.slot:
                try:
                    blob = _read_blob(workdir, listed, self.limits)
                except OSError as exc:
                    listed.extraction_status = "malformed"
                    listed.error = str(exc)
                    listed.slot = None
                    members.append(listed)
                    continue
                budget += blob.size
                if budget > self.limits.max_workspace_bytes or budget > self.limits.max_total_expanded_bytes:
                    listed.extraction_status = "rejected_workspace_budget"
                    listed.slot = None
                    listed.blob = None
                    members.append(listed)
                    continue
                listed.blob = blob
                listed.actual_size = blob.size
            members.append(listed)
        return ContainerResult(
            status="completed",
            reason=None,
            zip_subtype=zip_subtype,
            listed_count=int(payload.get("listed_count") or len(members)),
            truncated_listing=bool(payload.get("truncated_listing")),
            members=members,
            errors=list(payload.get("errors") or []),
            limits_hit=list(payload.get("limits_hit") or []),
            isolation=isolation,
        )


def _read_blob(workdir: Path, listed: ListedMember, limits: RecursionLimits) -> ExtractedBlob:
    assert listed.slot is not None
    fd = open_blob_slot(workdir, listed.slot)
    try:
        size = os.fstat(fd).st_size
        if size > limits.max_member_bytes:
            raise OSError(f"blob exceeds max_member_bytes ({size})")
        hashes = digest_fd(fd)
        data = os.read(fd, limits.max_member_bytes + 1)
        if len(data) > limits.max_member_bytes:
            raise OSError("blob exceeded max_member_bytes while reading")
        if len(data) != size:
            raise OSError("blob size changed during read")
    finally:
        os.close(fd)
    return ExtractedBlob(
        slot=listed.slot,
        original_name=listed.original_name,
        display_name=listed.display_name,
        index=listed.index,
        size=len(data),
        hashes=hashes,
        compressed_size=listed.compressed_size,
        compression_method=listed.compression_method,
        crc=listed.crc,
        encrypted=listed.encrypted,
        declared_size=listed.declared_size,
        extraction_status="extracted",
        data=data,
    )


def _looks_like_crash(returncode: int | None) -> bool:
    if returncode is None:
        return False
    if returncode < 0:
        return True
    unsigned = returncode & 0xFFFFFFFF
    return unsigned >= 0xC0000000
