"""Run one analyzer in an isolated child process and validate its response."""

from __future__ import annotations

import json
import os
import traceback
from pathlib import Path
from time import perf_counter
from typing import Any

from ..content import digest_bytes
from ..context import AnalysisContext
from ..limits import RecursionLimits
from ..models import AnalyzerError, AnalyzerResult
from .output import BoundedStream
from .policy import IsolationPolicy
from .process import child_env, close_job, pid_alive, spawn_worker, terminate_tree, wait_or_timeout
from .protocol import (
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    REASON_CHILD_CRASH,
    REASON_CHILD_EXIT,
    REASON_EMPTY_RESPONSE,
    REASON_INVALID_RESPONSE,
    REASON_OVERSIZED,
    REASON_SPAWN_FAILED,
    REASON_TIMEOUT,
    TEST_ENV,
    request_template,
)
from .snapshot import identity_for_child, parent_context_extra
from .validate import ProtocolError, result_from_payload, validate_response
from .workspace import OversizedWorkspaceFile, create_workspace, read_workspace_file, rmtree_retry

INPUT_NAME = "input.bin"
REQUEST_NAME = "request.json"
RESPONSE_NAME = "response.json"

TEST_EXTRA_KEYS = frozenset(
    {
        "pid_file",
        "sentinel_read",
        "sentinel_write",
        "probe_host",
        "probe_port",
        "probe_host_v6",
        "probe_port_v6",
        "listen_accept_seconds",
    }
)


class IsolatedAnalyzerRunner:
    def __init__(self, limits: RecursionLimits | None = None) -> None:
        self.limits = limits or RecursionLimits()
        self.policy_template = IsolationPolicy.from_limits(self.limits)

    def run(self, analyzer: Any, ctx: AnalysisContext, *, timeout: float) -> AnalyzerResult:
        spec = _analyzer_handle(analyzer)
        started = perf_counter()
        policy = IsolationPolicy.from_limits(self.limits)
        policy.timeout_seconds = timeout
        workdir: Path | None = None
        proc = None
        stdout = BoundedStream(limit=policy.max_output_bytes)
        stderr = BoundedStream(limit=policy.max_output_bytes)
        isolation: dict[str, Any] = {
            "mode": "subprocess",
            "protocol": PROTOCOL_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "input": INPUT_NAME,
            "sandbox": False,
            "containment": "static-parser",
        }
        try:
            workdir = create_workspace()
            isolation["workdir"] = str(workdir)
            (workdir / INPUT_NAME).write_bytes(ctx.data)
            digest = digest_bytes(ctx.data)
            test_mode = os.environ.get(TEST_ENV) == "1" or str(spec.name).startswith("isolate_test.")
            extra = parent_context_extra(ctx, test_mode=test_mode, allowed_test_keys=TEST_EXTRA_KEYS)
            request = request_template(
                analyzer_id=spec.name,
                analyzer_version=spec.version,
                artifact_id=ctx.artifact_id or "",
                input_path=INPUT_NAME,
                input_sha256=digest["sha256"],
                input_size=len(ctx.data),
                identity=identity_for_child(ctx.identity),
                context={
                    "name": ctx.name,
                    "source": ctx.source,
                    "size": ctx.size,
                    "truncated": ctx.truncated,
                    "max_bytes": ctx.max_bytes,
                    "artifact_id": ctx.artifact_id,
                    "depth": ctx.depth,
                    "extra": extra,
                },
                timeout_seconds=timeout,
                max_result_bytes=self.limits.max_result_bytes,
                max_memory_bytes=self.limits.max_child_memory_bytes,
                max_cpu_seconds=self.limits.max_child_cpu_seconds if self.limits.max_child_cpu_seconds is not None else timeout,
                max_child_processes=self.limits.max_child_processes,
            )
            (workdir / REQUEST_NAME).write_text(json.dumps(request, default=str), encoding="utf-8")
            env = child_env(test_mode=test_mode, workdir=workdir)
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
                isolation["still_alive"] = proc.poll() is None
            isolation["stdio"] = {
                "stdout": stdout.finish(),
                "stderr": stderr.finish(),
            }
            if rc is None:
                result = _status_result(
                    spec,
                    status="timeout",
                    reason=REASON_TIMEOUT,
                    message=f"Analyzer exceeded {timeout} seconds and was terminated.",
                    extra={
                        "timeout_seconds": timeout,
                        "result": "not analyzed",
                        "returncode": proc.returncode,
                    },
                )
                return _finish(result, spec, ctx, isolation, started)
            isolation["returncode"] = rc
            return _finish(self._read_response(spec, ctx, workdir, rc), spec, ctx, isolation, started)
        except Exception as exc:
            isolation["spawn_error"] = str(exc)
            isolation["traceback"] = traceback.format_exc()
            isolation.setdefault("capabilities", policy.capabilities())
            try:
                isolation["stdio"] = {"stdout": stdout.finish(), "stderr": stderr.finish()}
            except Exception:
                pass
            result = _status_result(
                spec,
                status="failed",
                reason=REASON_SPAWN_FAILED,
                message=str(exc) or exc.__class__.__name__,
                extra={"exception_type": exc.__class__.__name__},
            )
            return _finish(result, spec, ctx, isolation, started)
        finally:
            if proc is not None:
                if proc.poll() is None:
                    terminate_tree(proc)
                close_job(proc)
            if workdir is not None:
                isolation["workdir_removed"] = rmtree_retry(workdir)

    def _read_response(
        self,
        spec: Any,
        ctx: AnalysisContext,
        workdir: Path,
        returncode: int,
    ) -> AnalyzerResult:
        try:
            raw = read_workspace_file(workdir, RESPONSE_NAME, max_bytes=self.limits.max_result_bytes)
        except OversizedWorkspaceFile as exc:
            return _status_result(
                spec,
                status="failed",
                reason=REASON_OVERSIZED,
                message=str(exc),
                extra={
                    "returncode": returncode,
                    "response_bytes": exc.size,
                    "max_result_bytes": exc.max_bytes,
                },
            )
        except OSError as exc:
            message = str(exc)
            if "reparse" in message or "symlink" in message or "escaped" in message:
                return _status_result(
                    spec,
                    status="failed",
                    reason=REASON_INVALID_RESPONSE,
                    message=f"Refused to read child response: {exc}",
                    extra={"returncode": returncode},
                )
            reason = REASON_CHILD_CRASH if _looks_like_crash(returncode) else REASON_CHILD_EXIT
            return _status_result(
                spec,
                status="failed",
                reason=reason,
                message=f"Analyzer child exited without a readable response (returncode={returncode}).",
                extra={"returncode": returncode},
            )
        if not raw:
            return _status_result(
                spec,
                status="failed",
                reason=REASON_EMPTY_RESPONSE,
                message="Analyzer child wrote an empty response.",
                extra={"returncode": returncode, "response_bytes": 0},
            )
        if len(raw) > self.limits.max_result_bytes:
            return _status_result(
                spec,
                status="failed",
                reason=REASON_OVERSIZED,
                message=f"Analyzer child response was {len(raw)} bytes; limit is {self.limits.max_result_bytes} bytes.",
                extra={"returncode": returncode, "response_bytes": len(raw), "max_result_bytes": self.limits.max_result_bytes},
            )
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            return _status_result(
                spec,
                status="failed",
                reason=REASON_INVALID_RESPONSE,
                message=f"Analyzer child response was not valid JSON ({exc}).",
                extra={"returncode": returncode, "response_bytes": len(raw)},
            )
        try:
            validate_response(
                data,
                analyzer_id=spec.name,
                analyzer_version=spec.version,
                artifact_id=ctx.artifact_id or "",
            )
        except ProtocolError as exc:
            return _status_result(
                spec,
                status="failed",
                reason=exc.code,
                message=str(exc),
                extra={"returncode": returncode, "response_bytes": len(raw)},
            )
        result = result_from_payload(data)
        timing = data.get("timing") or {}
        if timing.get("duration_ms") is not None:
            result.details = {**(result.details or {}), "child_duration_ms": timing.get("duration_ms")}
        return result


def _analyzer_handle(analyzer: Any) -> Any:
    """Normalize AnalyzerSpec, analyzer class, or analyzer instance to a metadata handle."""
    if isinstance(analyzer, type):
        return analyzer
    if callable(getattr(analyzer, "analyze", None)):
        return type(analyzer)
    return analyzer


def _finish(
    result: AnalyzerResult,
    spec: Any,
    ctx: AnalysisContext,
    isolation: dict[str, Any],
    started: float,
) -> AnalyzerResult:
    result.name = spec.name
    result.title = getattr(spec, "title", spec.name)
    result.analyzer_version = spec.version
    result.artifact_id = ctx.artifact_id
    result.duration_ms = (perf_counter() - started) * 1000
    details = dict(result.details or {})
    child_iso = details.get("isolation")
    details["isolation"] = isolation
    if isinstance(child_iso, dict):
        details["isolation"]["child_claimed"] = child_iso
    if spec.name == "filesystem" and ctx.path is not None:
        details.setdefault("path", str(ctx.path))
        details.setdefault("absolute_path", str(ctx.path.resolve()))
    result.details = details
    return result


def _status_result(
    spec: Any,
    *,
    status: str,
    reason: str,
    message: str,
    extra: dict[str, Any] | None = None,
) -> AnalyzerResult:
    details = {"failed": status in {"failed", "timeout", "terminated"}, "reason": reason, **(extra or {})}
    if status == "timeout":
        details.setdefault("result", "not analyzed")
    return AnalyzerResult(
        name=spec.name,
        title=getattr(spec, "title", spec.name),
        applies=True,
        status=status,  # type: ignore[arg-type]
        analyzer_version=spec.version,
        details=details,
        errors=[
            AnalyzerError(
                analyzer=spec.name,
                message=message,
                exception_type={"timeout": "TimeoutError", "terminated": "TerminatedError"}.get(
                    status, "AnalyzerIsolationError"
                ),
            )
        ],
    )


def _looks_like_crash(returncode: int | None) -> bool:
    if returncode is None:
        return False
    if returncode < 0:
        return True
    unsigned = returncode & 0xFFFFFFFF
    return unsigned >= 0xC0000000


def grandchild_alive(pid_file: str | Path, *, wait: float = 0.0) -> bool:
    path = Path(pid_file)
    if wait:
        import time

        time.sleep(wait)
    if not path.is_file():
        return False
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    return pid_alive(pid)
