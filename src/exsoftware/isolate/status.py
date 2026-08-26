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
from .network_capability import (
    assess_network_mechanisms,
    bind_udp_receivers,
    build_probe_completeness,
    classify_connect_outcome,
    drain_udp_receiver,
    evaluate_network_restriction,
    make_udp_tokens,
    probe_host_to_worker_listen,
)
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
    report: dict[str, Any] = {
        "sandbox": False,
        "containment": "static-parser",
        "platform": sys.platform,
        "capabilities": {name: "unsupported" for name in CAPABILITIES},
        "reasons": {},
        "observed": {},
        "mechanism": "none",
        "windows_runtime_verified": sys.platform == "win32",
    }
    report["capabilities"]["wall_clock"] = "enforced"
    report["capabilities"]["output_limit"] = "enforced"
    report["capabilities"]["process_boundary"] = "enforced"
    report["reasons"]["wall_clock"] = "Parent wait + process-tree kill"
    report["reasons"]["output_limit"] = "Bounded stdout/stderr pipes"
    report["reasons"]["process_boundary"] = "Analyzer work runs in a child process"

    listener_v4 = None
    listener_v6 = None
    udp_socks: dict[str, Any] = {}
    with TemporaryDirectory(prefix="exsoftware-status-") as tmp:
        tmp_path = Path(tmp)
        secret = tmp_path / "host-secret.txt"
        secret.write_text("sentinel-secret-value", encoding="utf-8")
        write_target = tmp_path / "host-write.txt"
        host_write_exists = False
        port_v4 = None
        port_v6 = None
        try:
            listener_v4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener_v4.bind(("127.0.0.1", 0))
            listener_v4.listen(1)
            port_v4 = listener_v4.getsockname()[1]
        except OSError as exc:
            report["observed"]["parent_listener_v4_error"] = str(exc)
        try:
            listener_v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            if hasattr(socket, "IPV6_V6ONLY"):
                listener_v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener_v6.bind(("::1", 0))
            listener_v6.listen(1)
            port_v6 = listener_v6.getsockname()[1]
        except OSError as exc:
            report["observed"]["parent_listener_v6_error"] = str(exc)
            listener_v6 = None

        udp_socks = bind_udp_receivers()
        udp_tokens = make_udp_tokens()
        try:
            runner = IsolatedAnalyzerRunner(
                RecursionLimits(max_child_processes=1, analyzer_timeout_seconds=20)
            )
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
            net_extra: dict[str, Any] = {}
            if port_v4 is not None:
                net_extra["probe_host"] = "127.0.0.1"
                net_extra["probe_port"] = port_v4
            if port_v6 is not None:
                net_extra["probe_host_v6"] = "::1"
                net_extra["probe_port_v6"] = port_v6
            if udp_socks.get("udp_port_v4") is not None:
                net_extra["udp_probe_port_v4"] = udp_socks["udp_port_v4"]
                net_extra["udp_probe_token_v4"] = udp_tokens["udp_probe_token_v4"]
            if udp_socks.get("udp_port_v6") is not None:
                net_extra["udp_probe_port_v6"] = udp_socks["udp_port_v6"]
                net_extra["udp_probe_token_v6"] = udp_tokens["udp_probe_token_v6"]
            net = _run(runner, IsolateNetworkAnalyzer, ctx, extra=net_extra)
            spawn = _run(runner, IsolateSpawnAnalyzer, ctx, extra={})
            host_write_exists = write_target.exists()
            listen_comm = probe_host_to_worker_listen(
                limits=RecursionLimits(max_child_processes=1, analyzer_timeout_seconds=20),
                accept_wait_seconds=6.0,
            )
            udp_v4_received = drain_udp_receiver(
                udp_socks.get("udp_v4"),
                expected_token=udp_tokens["udp_probe_token_v4"],
            )
            udp_v6_received = drain_udp_receiver(
                udp_socks.get("udp_v6"),
                expected_token=udp_tokens["udp_probe_token_v6"],
            )
        finally:
            if listener_v4 is not None:
                listener_v4.close()
            if listener_v6 is not None:
                listener_v6.close()
            for key in ("udp_v4", "udp_v6"):
                sock = udp_socks.get(key)
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    return _finalize(
        report,
        read,
        write,
        net,
        spawn,
        listen_comm,
        host_write_exists=host_write_exists,
        parent_listener_v4=port_v4 is not None,
        parent_listener_v6=port_v6 is not None,
        udp_parent_v4=udp_socks.get("udp_port_v4") is not None,
        udp_parent_v6=udp_socks.get("udp_port_v6") is not None,
        udp_v4_received=udp_v4_received,
        udp_v6_received=udp_v6_received,
        udp_bind_errors={
            "udp_v4_error": udp_socks.get("udp_v4_error"),
            "udp_v6_error": udp_socks.get("udp_v6_error"),
        },
    )


def _run(runner, cls, ctx, extra: dict[str, Any]) -> dict[str, Any]:
    ctx.extra = dict(extra)
    result = runner.run(cls, ctx, timeout=20)
    iso = (result.details or {}).get("isolation") or {}
    return {
        "status": result.status,
        "details": {
            key: value
            for key, value in (result.details or {}).items()
            if key != "isolation"
        },
        "mechanism": iso.get("mechanism"),
        "token_is_appcontainer": bool(iso.get("token_is_appcontainer")),
        "capabilities": iso.get("capabilities") or {},
        "reasons": ((iso.get("policy") or {}).get("reasons") or iso.get("reasons") or {}),
    }


def _finalize(
    report,
    read,
    write,
    net,
    spawn,
    listen_comm,
    *,
    host_write_exists: bool,
    parent_listener_v4: bool,
    parent_listener_v6: bool,
    udp_parent_v4: bool,
    udp_parent_v6: bool,
    udp_v4_received: bool,
    udp_v6_received: bool,
    udp_bind_errors: dict[str, Any],
) -> dict[str, Any]:
    claimed = read.get("capabilities") or {}
    report["mechanism"] = (
        net.get("mechanism")
        or listen_comm.get("mechanism")
        or read.get("mechanism")
        or "none"
    )
    report["capabilities"].update(claimed)
    report["reasons"].update(read.get("reasons") or {})

    read_ok = bool((read.get("details") or {}).get("read_ok"))
    write_ok = bool((write.get("details") or {}).get("write_ok")) or host_write_exists
    net_details = net.get("details") or {}
    connect_ok = bool(net_details.get("connect_ok"))
    connect_v6_ok = bool(net_details.get("connect_v6_ok"))
    external_ok = bool(net_details.get("external_connect_ok"))
    external_v6_ok = bool(net_details.get("external_connect_v6_ok"))
    listen_bind_ok = bool(net_details.get("listen_ok")) or bool(listen_comm.get("listen_bind_succeeded"))
    listen_bind_v6_ok = bool(net_details.get("listen_v6_ok")) or bool(
        listen_comm.get("listen_bind_v6_succeeded")
    )
    host_to_worker_v4 = bool(listen_comm.get("host_to_worker_connect_succeeded"))
    host_to_worker_v6 = bool(listen_comm.get("host_to_worker_connect_v6_succeeded"))
    spawned = bool((spawn.get("details") or {}).get("spawned"))

    net_status = str(net.get("status") or "")
    network_analyzer_failed = net_status in {"failed", "timeout", "terminated", "error"} or bool(
        net_details.get("failed")
    )
    network_analyzer_completed = (not network_analyzer_failed) and net_status in {
        "completed",
        "ok",
        "",
    }
    # Empty status with details present still counts as completed when not failed.
    if not network_analyzer_failed and net_details and net_status not in {"failed", "timeout", "terminated"}:
        network_analyzer_completed = True

    localhost_connect_v4_outcome = (
        "unavailable"
        if not parent_listener_v4
        else classify_connect_outcome(
            attempted=True,
            succeeded=connect_ok,
            error=net_details.get("connect_error"),
            probe_complete=network_analyzer_completed and not network_analyzer_failed,
        )
    )
    localhost_connect_v6_outcome = (
        "unavailable"
        if not parent_listener_v6
        else classify_connect_outcome(
            attempted=True,
            succeeded=connect_v6_ok,
            error=net_details.get("connect_v6_error"),
            probe_complete=network_analyzer_completed and not network_analyzer_failed,
        )
    )
    if network_analyzer_failed:
        if parent_listener_v4:
            localhost_connect_v4_outcome = "incomplete"
        if parent_listener_v6:
            localhost_connect_v6_outcome = "incomplete"

    if not udp_parent_v4:
        udp_localhost_v4_outcome = "unavailable"
    elif network_analyzer_failed:
        udp_localhost_v4_outcome = "incomplete"
    elif udp_v4_received:
        udp_localhost_v4_outcome = "succeeded"
    elif net_details.get("udp_localhost_send_error"):
        udp_localhost_v4_outcome = "denied"
    elif net_details.get("udp_localhost_send_ok"):
        # Worker claimed send but parent did not receive — incomplete, not denial.
        udp_localhost_v4_outcome = "incomplete"
    else:
        udp_localhost_v4_outcome = "denied"

    if not udp_parent_v6:
        udp_localhost_v6_outcome = "unavailable"
    elif network_analyzer_failed:
        udp_localhost_v6_outcome = "incomplete"
    elif udp_v6_received:
        udp_localhost_v6_outcome = "succeeded"
    elif net_details.get("udp_localhost_send_v6_error"):
        udp_localhost_v6_outcome = "denied"
    elif net_details.get("udp_localhost_send_v6_ok"):
        udp_localhost_v6_outcome = "incomplete"
    else:
        udp_localhost_v6_outcome = "denied"

    host_to_worker_v4_outcome = listen_comm.get("host_to_worker_v4_outcome") or "incomplete"
    host_to_worker_v6_outcome = listen_comm.get("host_to_worker_v6_outcome") or "unavailable"

    report["observed"]["read_outside_succeeded"] = read_ok
    report["observed"]["write_outside_succeeded"] = write_ok
    report["observed"]["localhost_connect_succeeded"] = connect_ok
    report["observed"]["localhost_connect_v6_succeeded"] = connect_v6_ok
    report["observed"]["external_connect_succeeded"] = external_ok
    report["observed"]["external_connect_v6_succeeded"] = external_v6_ok
    report["observed"]["listen_succeeded"] = listen_bind_ok  # legacy alias: bind/listen API
    report["observed"]["listen_bind_succeeded"] = listen_bind_ok
    report["observed"]["listen_bind_v6_succeeded"] = listen_bind_v6_ok
    report["observed"]["host_to_worker_connect_succeeded"] = host_to_worker_v4
    report["observed"]["host_to_worker_connect_v6_succeeded"] = host_to_worker_v6
    report["observed"]["udp_localhost_received"] = bool(udp_v4_received)
    report["observed"]["udp_localhost_received_v6"] = bool(udp_v6_received)
    report["observed"]["spawn_succeeded"] = spawned
    report["observed"]["localhost_connect_v4_outcome"] = localhost_connect_v4_outcome
    report["observed"]["localhost_connect_v6_outcome"] = localhost_connect_v6_outcome
    report["observed"]["host_to_worker_v4_outcome"] = host_to_worker_v4_outcome
    report["observed"]["host_to_worker_v6_outcome"] = host_to_worker_v6_outcome
    report["observed"]["udp_localhost_v4_outcome"] = udp_localhost_v4_outcome
    report["observed"]["udp_localhost_v6_outcome"] = udp_localhost_v6_outcome
    report["observed"]["network_analyzer_completed"] = network_analyzer_completed
    report["observed"]["network_analyzer_failed"] = network_analyzer_failed
    report["observed"]["listen_comm_completed"] = bool(listen_comm.get("listen_comm_completed"))
    report["observed"]["listen_comm_ready"] = bool(listen_comm.get("listen_comm_ready"))
    report["observed"]["listen_comm_probe_error"] = listen_comm.get("probe_error")
    report["observed"]["ready_validation_error"] = listen_comm.get("ready_validation_error")
    report["observed"]["probe_error"] = listen_comm.get("probe_error")
    report["observed"]["network_probe_errors"] = {
        "connect_error": net_details.get("connect_error"),
        "connect_v6_error": net_details.get("connect_v6_error"),
        "external_connect_error": net_details.get("external_connect_error"),
        "external_connect_v6_error": net_details.get("external_connect_v6_error"),
        "listen_error": net_details.get("listen_error"),
        "listen_v6_error": net_details.get("listen_v6_error"),
        "udp_localhost_send_error": net_details.get("udp_localhost_send_error"),
        "udp_localhost_send_v6_error": net_details.get("udp_localhost_send_v6_error"),
        "parent_connect_errors": listen_comm.get("parent_connect_errors") or [],
        "listen_comm_probe_error": listen_comm.get("probe_error"),
        "udp_bind_errors": udp_bind_errors,
    }
    report["observed"]["listen_communication"] = {
        "ready_endpoints": listen_comm.get("ready_endpoints") or [],
        "child_accept_succeeded": bool(listen_comm.get("child_accept_succeeded")),
        "child_details": listen_comm.get("details") or {},
        "mechanism": listen_comm.get("mechanism"),
        "token_is_appcontainer": bool(listen_comm.get("token_is_appcontainer")),
    }

    mech = assess_network_mechanisms(net, listen_comm)
    report["observed"].update(
        {
            "network_analyzer_mechanism": mech.get("network_analyzer_mechanism"),
            "listen_comm_mechanism": mech.get("listen_comm_mechanism"),
            "network_mechanism_consistent": bool(mech.get("network_mechanism_consistent")),
            "network_mechanism_supports_upgrade": bool(mech.get("network_mechanism_supports_upgrade")),
            "network_mechanism_reason": mech.get("network_mechanism_reason"),
            "network_claim_for_evaluation": mech.get("network_claim_for_evaluation"),
            "read_worker_network_claim": claimed.get("network_restriction"),
        }
    )
    report["observed"]["probe_completeness"] = build_probe_completeness(report["observed"])

    report["capabilities"]["filesystem_restriction"] = _observed_state(
        claimed.get("filesystem_restriction", "unsupported"),
        denied=not read_ok and not write_ok,
        succeeded=read_ok or write_ok,
        reason_denied="Host sentinel read and write were denied",
        reason_failed="Child read or wrote a host sentinel while filesystem_restriction was claimed",
        report=report,
        key="filesystem_restriction",
    )

    # Evaluate from the network workers' claim/mechanism, not the read sentinel alone.
    claimed_net = str(mech.get("network_claim_for_evaluation") or "unsupported")
    net_state, net_reason = evaluate_network_restriction(claimed_net, report["observed"])
    report["capabilities"]["network_restriction"] = net_state
    report["reasons"]["network_restriction"] = net_reason

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
        f"  localhost connect v4 succeeded:   {obs.get('localhost_connect_succeeded')}",
        f"  localhost connect v6 succeeded:   {obs.get('localhost_connect_v6_succeeded')}",
        f"  external connect v4 succeeded:    {obs.get('external_connect_succeeded')}",
        f"  external connect v6 succeeded:    {obs.get('external_connect_v6_succeeded')}",
        f"  listen bind v4 succeeded:         {obs.get('listen_bind_succeeded')}",
        f"  listen bind v6 succeeded:         {obs.get('listen_bind_v6_succeeded')}",
        f"  host→worker connect v4 succeeded: {obs.get('host_to_worker_connect_succeeded')}",
        f"  host→worker connect v6 succeeded: {obs.get('host_to_worker_connect_v6_succeeded')}",
        f"  udp localhost v4 received:        {obs.get('udp_localhost_received')}",
        f"  udp localhost v6 received:        {obs.get('udp_localhost_received_v6')}",
        f"  child spawn succeeded:            {obs.get('spawn_succeeded')}",
    ]
    completeness = obs.get("probe_completeness") or {}
    if completeness:
        lines.append(
            f"  probe complete for upgrade:       {completeness.get('complete_for_upgrade')}"
        )
        if completeness.get("incomplete_reason"):
            lines.append(f"  probe incomplete reason:          {completeness.get('incomplete_reason')}")
    if data.get("windows_runtime_verified") is False:
        lines += [
            "",
            "Note: this process is not running on Windows; AppContainer network",
            "results above are for the local platform only and are not a Windows proof.",
        ]
    return "\n".join(lines) + "\n"
