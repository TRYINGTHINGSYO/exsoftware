"""Runtime isolation capability report. Facts, not a score."""

from __future__ import annotations

import socket
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from ..context import load_from_bytes
from ..content import content_id_from_bytes
from ..limits import RecursionLimits
from .policy import CAPABILITIES
from .runner import IsolatedAnalyzerRunner
from .test_analyzers import (
    IsolateNetworkAnalyzer,
    IsolateReadOutsideAnalyzer,
    IsolateSpawnAnalyzer,
    IsolateWriteOutsideAnalyzer,
)


def inspect_isolation() -> dict[str, Any]:
    """Probe the live OS boundary. Never reports enforced unless the forbidden op failed."""
    from .unixcontain import describe_unix_support

    report: dict[str, Any] = {
        "sandbox": False,
        "containment": "static-parser",
        "platform": sys.platform,
        "capabilities": {name: "unsupported" for name in CAPABILITIES},
        "reasons": {},
        "observed": {},
        "mechanism": "none",
    }
    report["capabilities"]["wall_clock"] = "enforced"
    report["capabilities"]["output_limit"] = "enforced"
    report["capabilities"]["process_boundary"] = "enforced"
    report["reasons"]["wall_clock"] = "Parent wait + process-tree kill"
    report["reasons"]["output_limit"] = "Bounded stdout/stderr pipes"
    report["reasons"]["process_boundary"] = "Analyzer work runs in a child process"

    with TemporaryDirectory(prefix="exsoftware-status-") as tmp:
        tmp_path = Path(tmp)
        secret = tmp_path / "host-secret.txt"
        secret.write_text("sentinel-secret-value", encoding="utf-8")
        write_target = tmp_path / "host-write.txt"
        host_write_exists = False
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            runner = IsolatedAnalyzerRunner(RecursionLimits(max_child_processes=1, analyzer_timeout_seconds=15))
            ctx = load_from_bytes(b"status", name="status.bin")
            ctx.artifact_id = content_id_from_bytes(ctx.data)

            read = _run(
                runner,
                IsolateReadOutsideAnalyzer,
                ctx,
                extra={"sentinel_read": str(secret)},
            )
            write = _run(
                runner,
                IsolateWriteOutsideAnalyzer,
                ctx,
                extra={"sentinel_write": str(write_target)},
            )
            net = _run(
                runner,
                IsolateNetworkAnalyzer,
                ctx,
                extra={"probe_host": "127.0.0.1", "probe_port": port},
            )
            spawn = _run(runner, IsolateSpawnAnalyzer, ctx, extra={})
            host_write_exists = write_target.exists()
        finally:
            listener.close()

    return _finalize(report, read, write, net, spawn, host_write_exists=host_write_exists)


def _run(runner, cls, ctx, extra: dict[str, Any]) -> dict[str, Any]:
    ctx.extra = dict(extra)
    result = runner.run(cls, ctx, timeout=15)
    iso = (result.details or {}).get("isolation") or {}
    return {
        "status": result.status,
        "details": {
            key: value
            for key, value in (result.details or {}).items()
            if key != "isolation"
        },
        "mechanism": iso.get("mechanism"),
        "capabilities": iso.get("capabilities") or {},
        "reasons": ((iso.get("policy") or {}).get("reasons") or iso.get("reasons") or {}),
    }


def _finalize(report, read, write, net, spawn, *, host_write_exists: bool) -> dict[str, Any]:
    claimed = read.get("capabilities") or {}
    report["mechanism"] = read.get("mechanism") or "none"
    report["capabilities"].update(claimed)
    report["reasons"].update(read.get("reasons") or {})

    read_ok = bool((read.get("details") or {}).get("read_ok"))
    write_ok = bool((write.get("details") or {}).get("write_ok")) or host_write_exists
    connect_ok = bool((net.get("details") or {}).get("connect_ok"))
    listen_ok = bool((net.get("details") or {}).get("listen_ok"))
    spawned = bool((spawn.get("details") or {}).get("spawned"))

    report["observed"]["read_outside_succeeded"] = read_ok
    report["observed"]["write_outside_succeeded"] = write_ok
    report["observed"]["localhost_connect_succeeded"] = connect_ok
    report["observed"]["listen_succeeded"] = listen_ok
    report["observed"]["spawn_succeeded"] = spawned

    report["capabilities"]["filesystem_restriction"] = _observed_state(
        claimed.get("filesystem_restriction", "unsupported"),
        denied=not read_ok and not write_ok,
        succeeded=read_ok or write_ok,
        reason_denied="Host sentinel read and write were denied",
        reason_failed="Child read or wrote a host sentinel while filesystem_restriction was claimed",
        report=report,
        key="filesystem_restriction",
    )
    net_denied = not connect_ok and not listen_ok
    report["capabilities"]["network_restriction"] = _observed_state(
        claimed.get("network_restriction", "unsupported"),
        denied=net_denied,
        succeeded=connect_ok or listen_ok,
        reason_denied="Localhost connect and listen were denied",
        reason_failed="Child opened a socket while network_restriction was claimed enforced",
        report=report,
        key="network_restriction",
        allow_degraded_success=True,
    )
    if listen_ok and not connect_ok:
        report["reasons"]["network_restriction"] = (
            "Connect denied; bind/listen on loopback still succeeded"
        )
    report["capabilities"]["process_creation"] = _observed_state(
        claimed.get("process_creation", "unsupported"),
        denied=not spawned,
        succeeded=spawned,
        reason_denied="CreateProcess/Popen failed in the child",
        reason_failed="Child spawned a process while process_creation was claimed enforced",
        report=report,
        key="process_creation",
        allow_degraded_success=True,
    )
    return report


def _observed_state(
    claimed: str,
    *,
    denied: bool,
    succeeded: bool,
    reason_denied: str,
    reason_failed: str,
    report: dict[str, Any],
    key: str,
    allow_degraded_success: bool = False,
) -> str:
    if claimed == "enforced" and succeeded:
        report["reasons"][key] = reason_failed
        return "failed"
    if denied:
        report["reasons"][key] = reason_denied
        if claimed in {"enforced", "degraded"}:
            return claimed
        return "enforced" if key != "process_creation" else (claimed if claimed != "unsupported" else "degraded")
    if succeeded:
        if claimed == "enforced":
            report["reasons"][key] = reason_failed
            return "failed"
        if claimed == "degraded" and allow_degraded_success:
            report["reasons"][key] = "Operation succeeded; restriction is only partial"
            return "degraded"
        report["reasons"][key] = "Forbidden operation succeeded"
        return "unsupported" if claimed == "unsupported" else "failed"
    return claimed


def format_status(data: dict[str, Any]) -> str:
    lines = [
        "ExSoftware analyzer containment",
        "This is static parser containment. It is not a malware sandbox.",
        f"platform: {data.get('platform')}  mechanism: {data.get('mechanism')}",
        "",
    ]
    for name in CAPABILITIES:
        state = (data.get("capabilities") or {}).get(name, "unsupported")
        reason = (data.get("reasons") or {}).get(name, "")
        suffix = f"  -- {reason}" if reason else ""
        lines.append(f"{name:28} {state}{suffix}")
    obs = data.get("observed") or {}
    lines += [
        "",
        "Observed probe (hostile helper analyzers):",
        f"  host sentinel read succeeded:     {obs.get('read_outside_succeeded')}",
        f"  host sentinel write succeeded:    {obs.get('write_outside_succeeded')}",
        f"  localhost connect succeeded:      {obs.get('localhost_connect_succeeded')}",
        f"  listen succeeded:                 {obs.get('listen_succeeded')}",
        f"  child spawn succeeded:            {obs.get('spawn_succeeded')}",
    ]
    return "\n".join(lines) + "\n"
