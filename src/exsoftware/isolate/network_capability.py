"""Evidence-based network capability evaluation for parser containment.

Distinguish socket API success (bind/listen) from usable network communication
(connect, accept from an outside process, UDP reachability). Capability claims
must follow live probe evidence, not setup-API success alone.
"""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any

from ..content import digest_bytes
from ..context import AnalysisContext
from ..limits import RecursionLimits
from ..models import FileIdentity
from .output import BoundedStream
from .policy import IsolationPolicy
from .process import child_env, close_job, spawn_worker, terminate_tree, wait_or_timeout
from .protocol import request_template
from .snapshot import identity_for_child, parent_context_extra
from .test_analyzers import IsolateNetworkListenAnalyzer
from .workspace import create_workspace, read_workspace_file, rmtree_retry

READY_NAME = "network_listen_ready.json"
INPUT_NAME = "input.bin"
REQUEST_NAME = "request.json"
RESPONSE_NAME = "response.json"


def meaningful_network_success(observed: dict[str, Any]) -> bool:
    """True when the child demonstrated usable network communication."""
    return bool(
        observed.get("localhost_connect_succeeded")
        or observed.get("localhost_connect_v6_succeeded")
        or observed.get("external_connect_succeeded")
        or observed.get("external_connect_v6_succeeded")
        or observed.get("host_to_worker_connect_succeeded")
        or observed.get("udp_send_succeeded")
        or observed.get("udp_send_v6_succeeded")
    )


def evaluate_network_restriction(
    claimed: str,
    observed: dict[str, Any],
) -> tuple[str, str]:
    """Return (state, reason) from claimed policy + live observations.

    Bind/listen API success alone is recorded but does not prove a usable
    network channel and must not by itself prevent an evidence-backed
    ``enforced`` result when communication probes fail.
    """
    claimed = claimed or "unsupported"
    success = meaningful_network_success(observed)
    bind_ok = bool(observed.get("listen_bind_succeeded") or observed.get("listen_bind_v6_succeeded"))

    if claimed == "enforced" and success:
        return (
            "failed",
            "Child achieved usable network communication while network_restriction was claimed enforced",
        )
    if success:
        if claimed == "degraded":
            return (
                "degraded",
                "Partial network restriction; at least one usable network operation succeeded",
            )
        if claimed == "enforced":
            return (
                "failed",
                "Child achieved usable network communication while network_restriction was claimed enforced",
            )
        return ("unsupported" if claimed == "unsupported" else "failed", "Forbidden network operation succeeded")

    # No usable communication observed.
    if bind_ok:
        reason = (
            "Usable connect/accept/UDP probes were denied; bind/listen API still succeeded "
            "(AppContainer loopback isolation may allow bind without host↔worker communication)"
        )
    else:
        reason = "Localhost/external connect, host↔worker accept, and UDP probes were denied"

    if claimed == "enforced":
        return ("enforced", reason)
    if claimed == "degraded":
        # Live evidence of full communication denial may upgrade security-status.
        return ("enforced", reason + "; upgraded from degraded by live probe evidence")
    if claimed == "unsupported":
        # Probes failed but no mechanism claimed; do not invent enforcement.
        return ("unsupported", reason + "; no network isolation mechanism was claimed")
    return (claimed, reason)


def probe_host_to_worker_listen(
    *,
    limits: RecursionLimits | None = None,
    accept_wait_seconds: float = 6.0,
) -> dict[str, Any]:
    """Spawn a listen-helper child, connect from the parent while it accepts.

    Returns observation fields for capability evaluation. Works on any OS that
    can spawn the isolate worker; Windows AppContainer semantics are what this
    is designed to illuminate.
    """
    limits = limits or RecursionLimits(max_child_processes=1, analyzer_timeout_seconds=20)
    policy = IsolationPolicy.from_limits(limits)
    policy.timeout_seconds = float(limits.analyzer_timeout_seconds)
    workdir: Path | None = None
    proc = None
    stdout = BoundedStream(limit=policy.max_output_bytes)
    stderr = BoundedStream(limit=policy.max_output_bytes)
    observed: dict[str, Any] = {
        "listen_bind_succeeded": False,
        "listen_bind_v6_succeeded": False,
        "host_to_worker_connect_succeeded": False,
        "host_to_worker_connect_v6_succeeded": False,
        "child_accept_succeeded": False,
        "ready_endpoints": [],
        "parent_connect_errors": [],
        "mechanism": None,
        "capabilities": {},
        "details": {},
    }
    try:
        workdir = create_workspace()
        payload = b"network-listen-probe"
        (workdir / INPUT_NAME).write_bytes(payload)
        digest = digest_bytes(payload)
        ctx = AnalysisContext(
            name="network-listen-probe.bin",
            source="bytes",
            size=len(payload),
            data=payload,
            truncated=False,
            max_bytes=len(payload),
            identity=FileIdentity(
                name="network-listen-probe.bin",
                path=None,
                source="bytes",
                extension=".bin",
                size=len(payload),
                detected_type="unknown",
                detected_family="unknown",
                detected_mime="application/octet-stream",
                description="network listen probe fixture",
                extension_matches=None,
                magic_offset=0,
                magic_hex="",
            ),
            extra={"listen_accept_seconds": accept_wait_seconds},
            artifact_id="sha256:" + digest["sha256"],
        )
        request = request_template(
            analyzer_id=IsolateNetworkListenAnalyzer.name,
            analyzer_version=IsolateNetworkListenAnalyzer.version,
            artifact_id=ctx.artifact_id or "",
            input_path=INPUT_NAME,
            input_sha256=digest["sha256"],
            input_size=len(payload),
            identity=identity_for_child(ctx.identity),
            context={
                "name": ctx.name,
                "source": ctx.source,
                "size": ctx.size,
                "truncated": False,
                "max_bytes": ctx.max_bytes,
                "artifact_id": ctx.artifact_id,
                "depth": 0,
                "extra": parent_context_extra(
                    ctx,
                    test_mode=True,
                    allowed_test_keys=frozenset({"listen_accept_seconds"}),
                ),
            },
            timeout_seconds=policy.timeout_seconds,
            max_result_bytes=limits.max_result_bytes,
            max_memory_bytes=limits.max_child_memory_bytes,
            max_cpu_seconds=limits.max_child_cpu_seconds
            if limits.max_child_cpu_seconds is not None
            else policy.timeout_seconds,
            max_child_processes=limits.max_child_processes,
        )
        (workdir / REQUEST_NAME).write_text(json.dumps(request, default=str), encoding="utf-8")
        env = child_env(test_mode=True, workdir=workdir)
        proc, spawn_meta = spawn_worker(
            workdir=workdir,
            env=env,
            policy=policy,
            stdout=stdout,
            stderr=stderr,
        )
        observed["mechanism"] = spawn_meta.get("mechanism") or policy.mechanism
        observed["capabilities"] = policy.capabilities()
        ready = _wait_for_ready(workdir, timeout=accept_wait_seconds)
        if ready:
            observed["ready_endpoints"] = list(ready.get("tcp") or [])
            for endpoint in observed["ready_endpoints"]:
                host = endpoint.get("host")
                port = int(endpoint.get("port") or 0)
                family = endpoint.get("family") or "ipv4"
                if family == "ipv4":
                    observed["listen_bind_succeeded"] = True
                elif family == "ipv6":
                    observed["listen_bind_v6_succeeded"] = True
                try:
                    with socket.create_connection((host, port), timeout=2.0) as sock:
                        sock.sendall(b"exsoftware-host-probe")
                    if family == "ipv6":
                        observed["host_to_worker_connect_v6_succeeded"] = True
                    else:
                        observed["host_to_worker_connect_succeeded"] = True
                except OSError as exc:
                    observed["parent_connect_errors"].append(
                        {"family": family, "host": host, "port": port, "error": str(exc)}
                    )
        rc = wait_or_timeout(proc, policy.timeout_seconds)
        if rc is None:
            terminate_tree(proc)
        observed["details"] = _read_listen_details(workdir, limits.max_result_bytes)
        if observed["details"].get("accept_ok"):
            observed["child_accept_succeeded"] = True
            # Child accepted something — treat as host↔worker success if parent also connected,
            # or if accept_ok alone (self-connect). Prefer parent connect flags.
            if not (
                observed["host_to_worker_connect_succeeded"]
                or observed["host_to_worker_connect_v6_succeeded"]
            ):
                # Accept without parent connect may be self-connection inside the container.
                observed["child_accept_without_parent_connect"] = True
        return observed
    except Exception as exc:
        observed["probe_error"] = str(exc) or exc.__class__.__name__
        return observed
    finally:
        if proc is not None:
            if proc.poll() is None:
                terminate_tree(proc)
            close_job(proc)
        if workdir is not None:
            rmtree_retry(workdir)


def _wait_for_ready(workdir: Path, *, timeout: float) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    path = workdir / READY_NAME
    while time.monotonic() < deadline:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeError):
                time.sleep(0.05)
                continue
        time.sleep(0.05)
    return None


def _read_listen_details(workdir: Path, max_bytes: int) -> dict[str, Any]:
    try:
        raw = read_workspace_file(workdir, RESPONSE_NAME, max_bytes=max_bytes)
        data = json.loads(raw.decode("utf-8"))
        result = data.get("result") or {}
        details = result.get("details") or {}
        return details if isinstance(details, dict) else {}
    except Exception:
        return {}
