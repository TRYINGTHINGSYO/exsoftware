"""Parent broker for contained OLE identity refinement.

Child JSON is hostile. The parent classifies subtype from validated stream
name strings only. olefile never runs in this process.
"""

from __future__ import annotations

import json
import os
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Any

from ..content import sha256_hex
from ..limits import RecursionLimits
from .ole_protocol import (
    OLE_PROTOCOL,
    OLE_PROTOCOL_VERSION,
    request_template,
    validate_ole_request,
    validate_ole_response,
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
from .workspace import OversizedWorkspaceFile, create_workspace, read_workspace_file, rmtree_retry

INPUT_NAME = "input.bin"
REQUEST_NAME = "request.json"
RESPONSE_NAME = "response.json"


@dataclass
class OleRefineResult:
    status: str
    reason: str | None
    is_ole: bool
    streams: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    isolation: dict[str, Any] = field(default_factory=dict)
    message: str | None = None


class IsolatedOleRunner:
    def __init__(self, limits: RecursionLimits | None = None) -> None:
        self.limits = limits or RecursionLimits()

    def refine(
        self,
        data: bytes,
        *,
        artifact_id: str,
        timeout: float | None = None,
    ) -> OleRefineResult:
        timeout = float(timeout if timeout is not None else self.limits.analyzer_timeout_seconds)
        policy = IsolationPolicy.from_limits(self.limits)
        policy.timeout_seconds = timeout
        workdir: Path | None = None
        proc = None
        stdout: BoundedStream | None = None
        stderr: BoundedStream | None = None
        isolation: dict[str, Any] = {
            "mode": "subprocess",
            "protocol": OLE_PROTOCOL,
            "protocol_version": OLE_PROTOCOL_VERSION,
            "operation": "refine",
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
            request = request_template(
                artifact_id=artifact_id,
                input_sha256=sha256_hex(data),
                input_size=len(data),
                limits={
                    "timeout_seconds": timeout,
                    "max_result_bytes": self.limits.max_result_bytes,
                    "max_memory_bytes": self.limits.max_child_memory_bytes,
                    "max_cpu_seconds": self.limits.max_child_cpu_seconds
                    if self.limits.max_child_cpu_seconds is not None
                    else timeout,
                    "max_child_processes": self.limits.max_child_processes,
                },
            )
            validate_ole_request(request)
            (workdir / REQUEST_NAME).write_text(json.dumps(request), encoding="utf-8")
            test_mode = os.environ.get(TEST_ENV) == "1"
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
                isolation["duration_ms"] = (perf_counter() - started) * 1000
                return OleRefineResult(
                    status="timeout",
                    reason=REASON_TIMEOUT,
                    is_ole=False,
                    isolation=isolation,
                    message=f"OLE worker exceeded {timeout} seconds and was terminated.",
                )
            isolation["returncode"] = rc
            isolation["stdio"] = finish_streams(stdout, stderr)
            return self._ingest(workdir, artifact_id, isolation, rc, started)
        except Exception as exc:
            isolation["spawn_error"] = str(exc)
            isolation["traceback"] = traceback.format_exc()
            isolation["capabilities"] = policy.capabilities()
            isolation["mechanism"] = policy.mechanism
            isolation["policy"] = policy.to_dict()
            isolation["stdio"] = finish_streams(stdout, stderr)
            return OleRefineResult(
                status="failed",
                reason=REASON_SPAWN_FAILED,
                is_ole=False,
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
    ) -> OleRefineResult:
        isolation["duration_ms"] = (perf_counter() - started) * 1000
        try:
            raw = read_workspace_file(workdir, RESPONSE_NAME, max_bytes=self.limits.max_result_bytes)
        except OversizedWorkspaceFile as exc:
            return OleRefineResult(
                status="failed",
                reason=REASON_OVERSIZED,
                is_ole=False,
                isolation=isolation,
                message=str(exc),
            )
        except OSError as exc:
            message = str(exc)
            if "reparse" in message or "symlink" in message or "escaped" in message:
                return OleRefineResult(
                    status="failed",
                    reason=REASON_INVALID_RESPONSE,
                    is_ole=False,
                    isolation=isolation,
                    message=f"Refused to read OLE response: {exc}",
                )
            reason = REASON_CHILD_CRASH if _looks_like_crash(returncode) else REASON_CHILD_EXIT
            return OleRefineResult(
                status="failed",
                reason=reason,
                is_ole=False,
                isolation=isolation,
                message=f"OLE child exited without a readable response (returncode={returncode}).",
            )
        if not raw:
            return OleRefineResult(
                status="failed",
                reason=REASON_EMPTY_RESPONSE,
                is_ole=False,
                isolation=isolation,
                message="OLE child wrote an empty response.",
            )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            return OleRefineResult(
                status="failed",
                reason=REASON_INVALID_RESPONSE,
                is_ole=False,
                isolation=isolation,
                message=f"OLE response was not valid JSON ({exc}).",
            )
        try:
            payload = validate_ole_response(payload, artifact_id=artifact_id)
        except ProtocolError as exc:
            return OleRefineResult(
                status="failed",
                reason=exc.code,
                is_ole=False,
                isolation=isolation,
                message=str(exc),
            )
        if payload.get("status") != "completed":
            return OleRefineResult(
                status="failed",
                reason=(payload.get("errors") or [{}])[0].get("code") or "ole_failed",
                is_ole=False,
                streams=list(payload.get("streams") or []),
                errors=list(payload.get("errors") or []),
                isolation=isolation,
                message=(payload.get("errors") or [{}])[0].get("message")
                if payload.get("errors")
                else "OLE worker failed",
            )
        return OleRefineResult(
            status="completed",
            reason=None,
            is_ole=bool(payload.get("is_ole")),
            streams=list(payload.get("streams") or []),
            errors=list(payload.get("errors") or []),
            isolation=isolation,
        )


def _looks_like_crash(returncode: int | None) -> bool:
    if returncode is None:
        return False
    if returncode < 0:
        return True
    unsigned = returncode & 0xFFFFFFFF
    return unsigned >= 0xC0000000
