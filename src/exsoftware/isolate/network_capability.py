"""Evidence-based network capability evaluation for parser containment.

Distinguish socket API success (bind/listen) from usable network communication.
Capability claims follow live probe evidence with explicit completeness gates —
absence of success is never treated as denial when probes did not finish.
"""

from __future__ import annotations

import json
import os
import secrets
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
from .workspace import OversizedWorkspaceFile, create_workspace, read_workspace_file, rmtree_retry

READY_NAME = "network_listen_ready.json"
READY_PROTOCOL = "exsoftware.network_listen_ready"
READY_PROTOCOL_VERSION = 1
READY_MAX_BYTES = 4096
READY_MAX_ENDPOINTS = 4
INPUT_NAME = "input.bin"
REQUEST_NAME = "request.json"
RESPONSE_NAME = "response.json"

PARENT_LOOPBACK = {
    "ipv4": "127.0.0.1",
    "ipv6": "::1",
}
ALLOWED_FAMILIES = frozenset(PARENT_LOOPBACK)


def meaningful_network_success(observed: dict[str, Any]) -> bool:
    """True when the child demonstrated usable network communication."""
    return bool(
        observed.get("localhost_connect_succeeded")
        or observed.get("localhost_connect_v6_succeeded")
        or observed.get("external_connect_succeeded")
        or observed.get("external_connect_v6_succeeded")
        or observed.get("host_to_worker_connect_succeeded")
        or observed.get("host_to_worker_connect_v6_succeeded")
        or observed.get("udp_localhost_received")
        or observed.get("udp_localhost_received_v6")
    )


def probe_evidence_complete(observed: dict[str, Any]) -> tuple[bool, str]:
    """Return whether required probes finished with interpretable outcomes."""
    completeness = observed.get("probe_completeness") or {}
    if completeness.get("complete_for_upgrade"):
        return True, "required probes completed with interpretable results"
    reason = completeness.get("incomplete_reason") or "probe evidence incomplete"
    return False, reason


def network_mechanisms_allow_upgrade(observed: dict[str, Any]) -> tuple[bool, str]:
    """Network workers must share a strong, consistent containment mechanism."""
    if not observed.get("network_mechanism_consistent"):
        return False, observed.get("network_mechanism_reason") or "network probe mechanisms disagree"
    if not observed.get("network_mechanism_supports_upgrade"):
        return False, observed.get("network_mechanism_reason") or "network probe mechanism does not support enforcement"
    return True, "network probes ran under a consistent containment mechanism"


def evaluate_network_restriction(
    claimed: str,
    observed: dict[str, Any],
) -> tuple[str, str]:
    """Return (state, reason) from claimed policy + live observations.

    Bind/listen API success alone is recorded but does not prove a usable
    network channel. Upgrading ``degraded`` → ``enforced`` requires complete,
    interpretable denial evidence from the network workers themselves.
    """
    claimed = claimed or "unsupported"
    observed = dict(observed)
    if "probe_completeness" not in observed:
        observed["probe_completeness"] = build_probe_completeness(observed)
    success = meaningful_network_success(observed)
    complete, complete_reason = probe_evidence_complete(observed)
    mech_ok, mech_reason = network_mechanisms_allow_upgrade(observed)
    bind_ok = bool(observed.get("listen_bind_succeeded") or observed.get("listen_bind_v6_succeeded"))

    if success:
        if claimed == "enforced":
            return (
                "failed",
                "Child achieved usable network communication while network_restriction was claimed enforced",
            )
        if claimed == "degraded":
            return (
                "degraded",
                "Partial network restriction; at least one usable network operation succeeded",
            )
        return ("unsupported" if claimed == "unsupported" else "failed", "Forbidden network operation succeeded")

    if bind_ok:
        denial_reason = (
            "Usable connect/accept/UDP probes were denied; bind/listen API still succeeded "
            "(AppContainer loopback isolation may allow bind without host↔worker communication)"
        )
    else:
        denial_reason = "Localhost connect, host↔worker accept, and localhost UDP probes were denied"

    if claimed == "enforced":
        if not complete:
            return ("degraded", f"claimed enforced but {complete_reason}")
        if not mech_ok:
            return ("degraded", f"claimed enforced but {mech_reason}")
        return ("enforced", denial_reason)

    if claimed == "degraded":
        if not complete:
            return ("degraded", f"Partial claim retained; {complete_reason}")
        if not mech_ok:
            return ("degraded", f"Partial claim retained; {mech_reason}")
        return ("enforced", denial_reason + "; upgraded from degraded by complete live probe evidence")

    if claimed == "unsupported":
        return ("unsupported", denial_reason + "; no network isolation mechanism was claimed")
    return (claimed, denial_reason)


def build_probe_completeness(observed: dict[str, Any]) -> dict[str, Any]:
    """Compute whether upgrade-quality evidence is present."""
    outcomes = {
        "localhost_connect_v4": observed.get("localhost_connect_v4_outcome") or "incomplete",
        "localhost_connect_v6": observed.get("localhost_connect_v6_outcome") or "unavailable",
        "host_to_worker_v4": observed.get("host_to_worker_v4_outcome") or "incomplete",
        "host_to_worker_v6": observed.get("host_to_worker_v6_outcome") or "unavailable",
        "udp_localhost_v4": observed.get("udp_localhost_v4_outcome") or "incomplete",
        "udp_localhost_v6": observed.get("udp_localhost_v6_outcome") or "unavailable",
    }
    info: dict[str, Any] = {
        "outcomes": outcomes,
        "network_analyzer_completed": bool(observed.get("network_analyzer_completed")),
        "listen_comm_completed": bool(observed.get("listen_comm_completed")),
        "listen_comm_ready": bool(observed.get("listen_comm_ready")),
        "complete_for_upgrade": False,
        "incomplete_reason": None,
    }
    if observed.get("listen_comm_probe_error"):
        info["incomplete_reason"] = "listen communication probe errored"
        return info
    if observed.get("network_analyzer_failed"):
        info["incomplete_reason"] = "network analyzer failed or did not complete"
        return info
    if not info["network_analyzer_completed"]:
        info["incomplete_reason"] = "network analyzer did not complete"
        return info
    if not info["listen_comm_completed"]:
        info["incomplete_reason"] = (
            observed.get("probe_error") or "listen communication probe did not complete"
        )
        return info
    if observed.get("ready_validation_error"):
        info["incomplete_reason"] = f"ready file rejected: {observed['ready_validation_error']}"
        return info
    if not info["listen_comm_ready"]:
        info["incomplete_reason"] = "listen helper never became ready"
        return info

    required = ["localhost_connect_v4", "host_to_worker_v4", "udp_localhost_v4"]
    # IPv6 required only when that family was available to the parent.
    for key in ("localhost_connect_v6", "host_to_worker_v6", "udp_localhost_v6"):
        if outcomes[key] != "unavailable":
            required.append(key)

    interpretable = {"succeeded", "denied"}
    for key in required:
        value = outcomes[key]
        if value == "unavailable":
            info["incomplete_reason"] = f"required probe {key} unavailable unexpectedly"
            return info
        if value not in interpretable:
            info["incomplete_reason"] = f"required probe {key} outcome is {value}"
            return info

    info["complete_for_upgrade"] = True
    info["incomplete_reason"] = None
    return info


def assess_network_mechanisms(net: dict[str, Any], listen_comm: dict[str, Any]) -> dict[str, Any]:
    """Compare containment evidence from the network analyzer and listen helper."""
    mech_net = net.get("mechanism") or "none"
    mech_listen = listen_comm.get("mechanism") or "none"
    caps_net = net.get("capabilities") or {}
    caps_listen = listen_comm.get("capabilities") or {}
    token_net = bool(net.get("token_is_appcontainer"))
    token_listen = bool(listen_comm.get("token_is_appcontainer"))
    claim_net = caps_net.get("network_restriction") or "unsupported"
    claim_listen = caps_listen.get("network_restriction") or "unsupported"

    result = {
        "network_analyzer_mechanism": mech_net,
        "listen_comm_mechanism": mech_listen,
        "network_analyzer_network_claim": claim_net,
        "listen_comm_network_claim": claim_listen,
        "network_mechanism_consistent": False,
        "network_mechanism_supports_upgrade": False,
        "network_mechanism_reason": "",
        "network_claim_for_evaluation": "unsupported",
    }
    if mech_net != mech_listen:
        result["network_mechanism_reason"] = (
            f"network probe mechanisms disagree ({mech_net!r} vs {mech_listen!r})"
        )
        return result
    result["network_mechanism_consistent"] = True

    if mech_net == "appcontainer":
        if not (token_net and token_listen):
            result["network_mechanism_reason"] = (
                "AppContainer launch was not confirmed on every network probe "
                f"(analyzer_token={token_net}, listen_token={token_listen})"
            )
            return result
        if claim_net != claim_listen:
            result["network_mechanism_reason"] = (
                f"AppContainer network claims disagree ({claim_net!r} vs {claim_listen!r})"
            )
            return result
        if claim_net not in {"degraded", "enforced"}:
            result["network_mechanism_reason"] = (
                f"AppContainer network claim is {claim_net!r}; cannot upgrade"
            )
            return result
        result["network_mechanism_supports_upgrade"] = True
        result["network_claim_for_evaluation"] = claim_net
        result["network_mechanism_reason"] = "AppContainer confirmed on network probes"
        return result

    if mech_net == "unix-preexec":
        if claim_net != claim_listen:
            result["network_mechanism_reason"] = (
                f"unix-preexec network claims disagree ({claim_net!r} vs {claim_listen!r})"
            )
            return result
        if claim_net not in {"degraded", "enforced"}:
            result["network_mechanism_reason"] = (
                f"unix-preexec network claim is {claim_net!r}; cannot upgrade"
            )
            return result
        result["network_mechanism_supports_upgrade"] = True
        result["network_claim_for_evaluation"] = claim_net
        result["network_mechanism_reason"] = "unix-preexec network probes agree"
        return result

    result["network_mechanism_reason"] = (
        f"mechanism {mech_net!r} is a fallback/unsupported containment path for network enforcement"
    )
    return result


def validate_listen_ready_payload(raw: bytes) -> dict[str, Any]:
    """Validate hostile ready-file bytes. Returns only family+port endpoints."""
    if len(raw) > READY_MAX_BYTES:
        raise ValueError(f"ready file exceeds {READY_MAX_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("ready file is not UTF-8") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("ready file is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("ready file root must be an object")
    if data.get("protocol") != READY_PROTOCOL:
        raise ValueError("ready file protocol name mismatch")
    if data.get("protocol_version") != READY_PROTOCOL_VERSION:
        raise ValueError("ready file protocol version mismatch")
    tcp = data.get("tcp")
    if not isinstance(tcp, list):
        raise ValueError("ready file tcp must be a list")
    if len(tcp) > READY_MAX_ENDPOINTS:
        raise ValueError("ready file tcp list too long")
    cleaned: list[dict[str, Any]] = []
    seen_families: set[str] = set()
    for item in tcp:
        if not isinstance(item, dict):
            raise ValueError("ready endpoint must be an object")
        family = item.get("family")
        if family not in ALLOWED_FAMILIES:
            raise ValueError(f"unsupported address family {family!r}")
        if family in seen_families:
            raise ValueError(f"duplicate address family {family!r}")
        # Hostile children must not supply connect targets. Parent chooses loopback.
        if "host" in item and item.get("host") not in {None, "", PARENT_LOOPBACK[family]}:
            raise ValueError("ready endpoint must not supply a non-parent loopback host")
        port = item.get("port")
        if not isinstance(port, int) or isinstance(port, bool):
            raise ValueError("ready endpoint port must be an int")
        if port < 1 or port > 65535:
            raise ValueError("ready endpoint port out of range")
        seen_families.add(family)
        cleaned.append({"family": family, "port": port})
    return {"tcp": cleaned}


def probe_host_to_worker_listen(
    *,
    limits: RecursionLimits | None = None,
    accept_wait_seconds: float = 6.0,
) -> dict[str, Any]:
    """Spawn a listen-helper child; parent connects only to fixed loopback addresses."""
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
        "host_to_worker_v4_outcome": "incomplete",
        "host_to_worker_v6_outcome": "unavailable",
        "child_accept_succeeded": False,
        "ready_endpoints": [],
        "parent_connect_errors": [],
        "mechanism": None,
        "token_is_appcontainer": False,
        "capabilities": {},
        "details": {},
        "listen_comm_completed": False,
        "listen_comm_ready": False,
        "probe_error": None,
        "ready_validation_error": None,
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
            identity=_probe_identity(len(payload)),
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
        observed["token_is_appcontainer"] = bool(spawn_meta.get("token_is_appcontainer"))
        observed["capabilities"] = policy.capabilities()
        observed["spawn_meta"] = {
            key: spawn_meta.get(key)
            for key in ("mechanism", "token_is_appcontainer", "pid", "job_assigned")
            if key in spawn_meta or key in {"mechanism", "token_is_appcontainer"}
        }

        try:
            ready = _wait_for_ready(workdir, timeout=accept_wait_seconds)
        except OversizedWorkspaceFile as exc:
            observed["ready_validation_error"] = f"ready file exceeds limit ({exc})"
            observed["host_to_worker_v4_outcome"] = "incomplete"
            ready = None
        if ready is None:
            observed["host_to_worker_v4_outcome"] = "incomplete"
            # Ready absence is incomplete evidence, not a denial.
        else:
            try:
                validated = validate_listen_ready_payload(ready)
            except ValueError as exc:
                observed["ready_validation_error"] = str(exc)
                observed["host_to_worker_v4_outcome"] = "incomplete"
            else:
                observed["listen_comm_ready"] = True
                observed["ready_endpoints"] = list(validated.get("tcp") or [])
                families_seen = {item["family"] for item in observed["ready_endpoints"]}
                if "ipv4" not in families_seen:
                    observed["host_to_worker_v4_outcome"] = "incomplete"
                if "ipv6" in families_seen:
                    observed["host_to_worker_v6_outcome"] = "incomplete"
                for endpoint in observed["ready_endpoints"]:
                    family = endpoint["family"]
                    port = int(endpoint["port"])
                    host = PARENT_LOOPBACK[family]
                    if family == "ipv4":
                        observed["listen_bind_succeeded"] = True
                    else:
                        observed["listen_bind_v6_succeeded"] = True
                    try:
                        with socket.create_connection((host, port), timeout=2.0) as sock:
                            sock.sendall(b"exsoftware-host-probe")
                        if family == "ipv6":
                            observed["host_to_worker_connect_v6_succeeded"] = True
                            observed["host_to_worker_v6_outcome"] = "succeeded"
                        else:
                            observed["host_to_worker_connect_succeeded"] = True
                            observed["host_to_worker_v4_outcome"] = "succeeded"
                    except OSError as exc:
                        observed["parent_connect_errors"].append(
                            {"family": family, "host": host, "port": port, "error": str(exc)}
                        )
                        if family == "ipv6":
                            observed["host_to_worker_v6_outcome"] = "denied"
                        else:
                            observed["host_to_worker_v4_outcome"] = "denied"

        rc = wait_or_timeout(proc, policy.timeout_seconds)
        if rc is None:
            terminate_tree(proc)
            observed["probe_error"] = observed.get("probe_error") or "listen helper timed out"
            observed["listen_comm_completed"] = False
        else:
            observed["details"] = _read_listen_details(workdir, limits.max_result_bytes)
            details = observed["details"]
            if details.get("failed") or details.get("reason") == "exception":
                observed["probe_error"] = observed.get("probe_error") or "listen helper crashed"
                observed["listen_comm_completed"] = False
            else:
                observed["listen_comm_completed"] = True
            if details.get("accept_ok") or details.get("accept_v6_ok"):
                observed["child_accept_succeeded"] = True
                if not (
                    observed["host_to_worker_connect_succeeded"]
                    or observed["host_to_worker_connect_v6_succeeded"]
                ):
                    observed["child_accept_without_parent_connect"] = True
        return observed
    except Exception as exc:
        observed["probe_error"] = str(exc) or exc.__class__.__name__
        observed["listen_comm_completed"] = False
        return observed
    finally:
        if proc is not None:
            if proc.poll() is None:
                terminate_tree(proc)
            close_job(proc)
        if workdir is not None:
            rmtree_retry(workdir)


def classify_connect_outcome(*, attempted: bool, succeeded: bool, error: str | None) -> str:
    if not attempted:
        return "unavailable"
    if succeeded:
        return "succeeded"
    if error:
        return "denied"
    return "incomplete"


def _probe_identity(size: int) -> FileIdentity:
    return FileIdentity(
        name="network-listen-probe.bin",
        path=None,
        source="bytes",
        extension=".bin",
        size=size,
        detected_type="unknown",
        detected_family="unknown",
        detected_mime="application/octet-stream",
        description="network listen probe fixture",
        extension_matches=None,
        magic_offset=0,
        magic_hex="",
    )


def _wait_for_ready(workdir: Path, *, timeout: float) -> bytes | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return read_workspace_file(workdir, READY_NAME, max_bytes=READY_MAX_BYTES)
        except OversizedWorkspaceFile:
            raise
        except OSError:
            time.sleep(0.05)
            continue
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


def make_udp_tokens() -> dict[str, str]:
    return {
        "udp_probe_token_v4": secrets.token_hex(16),
        "udp_probe_token_v6": secrets.token_hex(16),
    }


def bind_udp_receivers() -> dict[str, Any]:
    """Bind parent-owned UDP receivers on loopback. Caller must close sockets."""
    out: dict[str, Any] = {
        "udp_v4": None,
        "udp_v6": None,
        "udp_port_v4": None,
        "udp_port_v6": None,
        "udp_v4_error": None,
        "udp_v6_error": None,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.2)
        out["udp_v4"] = sock
        out["udp_port_v4"] = sock.getsockname()[1]
    except OSError as exc:
        out["udp_v4_error"] = str(exc)
    try:
        sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        if hasattr(socket, "IPV6_V6ONLY"):
            sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock6.bind(("::1", 0))
        sock6.settimeout(0.2)
        out["udp_v6"] = sock6
        out["udp_port_v6"] = sock6.getsockname()[1]
    except OSError as exc:
        out["udp_v6_error"] = str(exc)
    return out


def drain_udp_receiver(sock: socket.socket | None, *, expected_token: str, rounds: int = 20) -> bool:
    if sock is None or not expected_token:
        return False
    token = expected_token.encode("utf-8")
    for _ in range(rounds):
        try:
            data, _addr = sock.recvfrom(4096)
        except TimeoutError:
            continue
        except OSError:
            return False
        if data == token:
            return True
    return False
