"""Analyzer child process.

Reads request.json + input.bin from a controlled work directory, runs exactly
one analyzer, writes response.json. Does not ingest into the investigation graph.

On Unix, Landlock / netns / rlimits are applied in a bootstrap phase *before*
any analyzer or third-party parser reads hostile sample bytes. The parent
schema-validates a bounded child ACK from that phase; this process must not
parse samples until that phase has completed.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from time import perf_counter

from ..analyzers.loader import load_analyzer_by_id
from ..content import digest_bytes
from ..context import AnalysisContext
from ..models import AnalyzerError, AnalyzerResult, FileIdentity
from .protocol import (
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    RESPONSE_ENV,
    TEST_ENV,
    WORKDIR_ENV,
)
from .bootstrap import ACK_NAME, BOOTSTRAP_HOOK_ENV, write_bootstrap_ack
from .validate import ProtocolError, validate_request

_UNIX_BOOTSTRAP_COMPLETE = False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exsoftware-isolate-worker")
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args(argv)
    _quiet_windows_errors()
    workdir = Path(args.workdir)
    request_path = workdir / "request.json"
    response_path = workdir / "response.json"
    os_environ_set(RESPONSE_ENV, str(response_path))
    os_environ_set(WORKDIR_ENV, str(workdir))
    started = perf_counter()
    try:
        _run_unix_bootstrap(workdir)
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if request.get("protocol") == "exsoftware.container":
            return _run_container(request, workdir, response_path, started)
        if request.get("protocol") == "exsoftware.ole":
            return _run_ole(request, workdir, response_path, started)
        validate_request(request)
        result = _run(request, workdir)
        status = result.status
        error = None
        if result.errors:
            err = result.errors[0]
            error = {
                "code": (result.details or {}).get("reason") or "analyzer_error",
                "message": err.message,
                "exception_type": err.exception_type,
            }
        write_response(
            response_path,
            analyzer_id=request["analyzer_id"],
            analyzer_version=request["analyzer_version"],
            status=status,
            result=result,
            error=error,
            duration_ms=(perf_counter() - started) * 1000,
        )
        return 0 if status in {"completed", "unsupported", "skipped"} else 1
    except ProtocolError as exc:
        write_failure(
            response_path,
            analyzer_id="unknown",
            analyzer_version="0.0.0",
            status="failed",
            message=str(exc),
            exception_type="ProtocolError",
            reason=exc.code,
            duration_ms=(perf_counter() - started) * 1000,
        )
        return 2
    except Exception as exc:
        write_failure(
            response_path,
            analyzer_id="unknown",
            analyzer_version="0.0.0",
            status="failed",
            message=str(exc) or exc.__class__.__name__,
            exception_type=exc.__class__.__name__,
            reason="exception",
            duration_ms=(perf_counter() - started) * 1000,
            traceback_text=traceback.format_exc(),
        )
        return 1


def _run_container(request: dict, workdir: Path, response_path: Path, started: float) -> int:
    from .container_extract import run_extract
    from .container_protocol import CONTAINER_PROTOCOL, CONTAINER_PROTOCOL_VERSION, validate_container_request

    _ensure_unix_bootstrap_complete()
    artifact_id = request.get("container_artifact_id") or ""
    try:
        validate_container_request(request)
        body = run_extract(request, workdir)
    except ProtocolError as exc:
        body = {
            "status": "failed",
            "zip_subtype": "zip",
            "listed_count": 0,
            "truncated_listing": False,
            "members": [],
            "errors": [{"code": exc.code, "message": str(exc)}],
            "limits_hit": [],
        }
    except Exception as exc:
        body = {
            "status": "failed",
            "zip_subtype": "zip",
            "listed_count": 0,
            "truncated_listing": False,
            "members": [],
            "errors": [{"code": "exception", "message": str(exc) or exc.__class__.__name__}],
            "limits_hit": [],
        }
    payload = {
        "protocol": CONTAINER_PROTOCOL,
        "protocol_version": CONTAINER_PROTOCOL_VERSION,
        "operation": "extract",
        "container_artifact_id": artifact_id,
        "status": body.get("status") or "failed",
        "zip_subtype": body.get("zip_subtype") or "zip",
        "listed_count": body.get("listed_count") or 0,
        "truncated_listing": bool(body.get("truncated_listing")),
        "members": body.get("members") or [],
        "errors": body.get("errors") or [],
        "limits_hit": body.get("limits_hit") or [],
        "timing": {"duration_ms": round((perf_counter() - started) * 1000, 3)},
    }
    _atomic_write(response_path, payload)
    return 0 if payload["status"] == "completed" else 1


def _run_ole(request: dict, workdir: Path, response_path: Path, started: float) -> int:
    from .ole_protocol import OLE_PROTOCOL, OLE_PROTOCOL_VERSION, validate_ole_request
    from .ole_refine import run_refine

    _ensure_unix_bootstrap_complete()
    artifact_id = request.get("artifact_id") or ""
    try:
        validate_ole_request(request)
        body = run_refine(request, workdir)
    except ProtocolError as exc:
        body = {
            "status": "failed",
            "is_ole": False,
            "streams": [],
            "errors": [{"code": exc.code, "message": str(exc)}],
        }
    except Exception as exc:
        body = {
            "status": "failed",
            "is_ole": False,
            "streams": [],
            "errors": [{"code": "exception", "message": str(exc) or exc.__class__.__name__}],
        }
    payload = {
        "protocol": OLE_PROTOCOL,
        "protocol_version": OLE_PROTOCOL_VERSION,
        "operation": "refine",
        "artifact_id": artifact_id,
        "status": body.get("status") or "failed",
        "is_ole": bool(body.get("is_ole")),
        "streams": body.get("streams") or [],
        "errors": body.get("errors") or [],
        "timing": {"duration_ms": round((perf_counter() - started) * 1000, 3)},
    }
    _atomic_write(response_path, payload)
    return 0 if payload["status"] == "completed" else 1


def _run(request: dict, workdir: Path) -> AnalyzerResult:
    _ensure_unix_bootstrap_complete()
    analyzer_id = request["analyzer_id"]
    analyzer_version = request["analyzer_version"]
    cls = resolve_analyzer_class(analyzer_id)
    analyzer = cls()
    if analyzer.version != analyzer_version:
        return AnalyzerResult(
            name=analyzer_id,
            title=analyzer.title,
            applies=True,
            status="failed",
            analyzer_version=analyzer_version,
            details={"reason": "analyzer_version_mismatch", "child_version": analyzer.version},
            errors=[
                AnalyzerError(
                    analyzer=analyzer_id,
                    message=f"Child analyzer version {analyzer.version} != request {analyzer_version}",
                    exception_type="VersionError",
                )
            ],
        )
    input_spec = request["input"]
    input_path = Path(input_spec["path"])
    if not input_path.is_absolute():
        input_path = workdir / input_path
    data = input_path.read_bytes()
    digest = digest_bytes(data)
    expected = input_spec.get("sha256")
    if expected and digest["sha256"] != expected:
        return AnalyzerResult(
            name=analyzer_id,
            title=analyzer.title,
            applies=True,
            status="failed",
            analyzer_version=analyzer_version,
            details={"reason": "input_hash_mismatch"},
            errors=[
                AnalyzerError(
                    analyzer=analyzer_id,
                    message="input.bin SHA-256 did not match the request",
                    exception_type="InputError",
                )
            ],
        )
    identity = FileIdentity.from_dict(request["identity"])
    identity.path = None
    ctx_spec = request["context"]
    ctx = AnalysisContext(
        name=ctx_spec.get("name") or identity.name,
        source=ctx_spec.get("source") or "bytes",
        size=int(ctx_spec.get("size") or len(data)),
        data=data,
        truncated=bool(ctx_spec.get("truncated")),
        max_bytes=int(ctx_spec.get("max_bytes") or len(data)),
        path=None,
        identity=identity,
        extra=dict(ctx_spec.get("extra") or {}),
        artifact_id=request.get("artifact_id"),
        investigation=None,
        depth=int(ctx_spec.get("depth") or 0),
        limits=None,
    )
    if not analyzer.applies(ctx):
        result = analyzer.skipped_result(ctx)
        return result
    try:
        result = analyzer.analyze(ctx)
    except Exception as exc:
        result = analyzer.failure(exc)
        result.details = {**(result.details or {}), "traceback": traceback.format_exc(), "reason": "exception"}
        return result
    if not isinstance(result, AnalyzerResult):
        return analyzer.result(
            status="failed",
            details={"reason": "invalid_analyzer_response"},
            errors=[
                AnalyzerError(
                    analyzer=analyzer_id,
                    message="analyzer.analyze did not return AnalyzerResult",
                    exception_type="TypeError",
                )
            ],
        )
    result.name = analyzer.name
    result.analyzer_version = analyzer.version
    result.artifact_id = request.get("artifact_id")
    return result


def resolve_analyzer_class(analyzer_id: str):
    cls = load_analyzer_by_id(analyzer_id)
    if cls is not None:
        return cls
    if os_environ_get(TEST_ENV) == "1":
        from .test_analyzers import TEST_ANALYZERS

        for item in TEST_ANALYZERS:
            if item.name == analyzer_id:
                return item
    raise KeyError(f"unknown analyzer {analyzer_id!r}")


def result_payload(result: AnalyzerResult) -> dict:
    data = result.to_dict()
    findings = []
    for item in result.findings:
        payload = item.to_dict()
        # to_dict substitutes "derived" when certainty is unset. Child findings
        # usually leave it unset so the parent catalog can assign it.
        if item.certainty is None:
            payload.pop("certainty", None)
        findings.append(payload)
    data["findings"] = findings
    return data


def write_response(
    path: Path,
    *,
    analyzer_id: str,
    analyzer_version: str,
    status: str,
    result: AnalyzerResult,
    error: dict | None,
    duration_ms: float,
) -> None:
    payload = {
        "protocol": PROTOCOL_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer_id": analyzer_id,
        "analyzer_version": analyzer_version,
        "status": status,
        "result": result_payload(result),
        "error": error,
        "timing": {"duration_ms": round(duration_ms, 3)},
    }
    _atomic_write(path, payload)


def write_failure(
    path: Path,
    *,
    analyzer_id: str,
    analyzer_version: str,
    status: str,
    message: str,
    exception_type: str,
    reason: str,
    duration_ms: float,
    traceback_text: str | None = None,
) -> None:
    result = AnalyzerResult(
        name=analyzer_id,
        title=analyzer_id,
        applies=True,
        status=status,  # type: ignore[arg-type]
        analyzer_version=analyzer_version,
        details={"reason": reason, "failed": True, **({"traceback": traceback_text} if traceback_text else {})},
        errors=[AnalyzerError(analyzer=analyzer_id, message=message, exception_type=exception_type)],
    )
    write_response(
        path,
        analyzer_id=analyzer_id,
        analyzer_version=analyzer_version,
        status=status,
        result=result,
        error={"code": reason, "message": message, "exception_type": exception_type},
        duration_ms=duration_ms,
    )


def _atomic_write(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    text = json.dumps(payload, ensure_ascii=False, default=str)
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _run_unix_bootstrap(workdir: Path) -> None:
    """Apply Unix restrictions and write the ACK before hostile-byte work."""
    global _UNIX_BOOTSTRAP_COMPLETE
    if sys.platform == "win32":
        _UNIX_BOOTSTRAP_COMPLETE = True
        return
    import os
    import time

    from .unixcontain import apply_unix_restrictions, unix_runtime_allow_paths

    hook = os.environ.get(BOOTSTRAP_HOOK_ENV) if os.environ.get(TEST_ENV) == "1" else None
    if hook == "crash":
        os.abort()
    if hook == "hang":
        while True:
            time.sleep(60)

    limits = _limits_from_request(workdir)
    results = apply_unix_restrictions(
        workdir=workdir,
        allow_paths=unix_runtime_allow_paths(),
        max_memory_bytes=_optional_int(limits.get("max_memory_bytes")),
        max_cpu_seconds=_optional_float(limits.get("max_cpu_seconds")),
        max_processes=_optional_int(limits.get("max_child_processes")),
    )
    if hook == "unsupported_filesystem":
        results = {**results, "filesystem": "unsupported"}
    if hook == "fail_memory":
        results = {**results, "memory": "failed"}
    if hook == "skip_ack":
        _UNIX_BOOTSTRAP_COMPLETE = True
        return
    if hook == "malformed":
        (workdir / ACK_NAME).write_text(
            '{"protocol":"exsoftware.isolate.bootstrap","protocol_version":1,'
            '"filesystem":"nope","network":"applied","memory":"applied","cpu":"applied","session":"applied"}',
            encoding="utf-8",
        )
        _UNIX_BOOTSTRAP_COMPLETE = True
        return
    if hook == "truncated":
        (workdir / ACK_NAME).write_text(
            '{"protocol":"exsoftware.isolate.bootstrap","protocol_version":1',
            encoding="utf-8",
        )
        _UNIX_BOOTSTRAP_COMPLETE = True
        return
    if hook == "contradict":
        write_bootstrap_ack(workdir, {key: "applied" for key in results})
        _UNIX_BOOTSTRAP_COMPLETE = True
        return
    write_bootstrap_ack(workdir, results)
    _UNIX_BOOTSTRAP_COMPLETE = True


def _ensure_unix_bootstrap_complete() -> None:
    if sys.platform == "win32":
        return
    if not _UNIX_BOOTSTRAP_COMPLETE:
        raise RuntimeError("Unix bootstrap containment has not completed")


def _limits_from_request(workdir: Path) -> dict:
    try:
        data = json.loads((workdir / "request.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    limits = data.get("limits") if isinstance(data, dict) else None
    return limits if isinstance(limits, dict) else {}


def _optional_int(value: object) -> int | None:
    if value is None or value is False:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: object) -> float | None:
    if value is None or value is False:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def os_environ_set(key: str, value: str) -> None:
    import os

    os.environ[key] = value


def os_environ_get(key: str) -> str | None:
    import os

    return os.environ.get(key)


def _quiet_windows_errors() -> None:
    if sys.platform != "win32":
        return
    import ctypes

    # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
    ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)


if __name__ == "__main__":
    raise SystemExit(main())
