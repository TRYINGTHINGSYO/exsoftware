"""Unix-family containment: Landlock / network namespace / rlimits.

Session creation is parent-visible (``Popen(start_new_session=True)``).
Landlock, ``CLONE_NEWNET``, and rlimits are applied in the child bootstrap
phase *before* any analyzer or third-party parser reads hostile sample bytes.
The child then writes a bounded ACK. The parent promotes filesystem/network/
memory/cpu only from a schema-validated child attestation that is consistent
with host feature detection. That ACK is not independent proof the restriction
held. Feature detection and a later successful run never create ``enforced``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from .policy import IsolationPolicy


def unix_runtime_allow_paths() -> list[Path]:
    """Interpreter and package paths the Landlock ruleset must still allow."""
    from .process import host_site_package_dirs

    return [
        Path(sys.prefix),
        Path(sys.base_prefix),
        Path(sys.executable).resolve().parent,
        Path(__file__).resolve().parents[2],
        *host_site_package_dirs(),
    ]


def apply_unix_restrictions(
    *,
    workdir: Path,
    allow_paths: list[Path],
    max_memory_bytes: int | None,
    max_cpu_seconds: float | None,
    max_processes: int | None,
) -> dict[str, str]:
    """Apply Unix restrictions in the current process and return ACK result states.

    Must run before hostile sample bytes are parsed. Failures are returned as
    ``failed`` / ``unsupported`` rather than swallowed into a silent success.
    """
    results = {
        "session": _session_result(),
        "network": _apply_unshare_net(),
        "filesystem": _apply_landlock(workdir, allow_paths),
        "memory": _apply_rlimit_as(max_memory_bytes),
        "cpu": _apply_rlimit_cpu(max_cpu_seconds),
    }
    _apply_rlimit_nproc(max_processes)
    return results


def _session_result() -> str:
    getsid = getattr(os, "getsid", None)
    if getsid is None:
        return "unsupported"
    try:
        if getsid(0) == os.getpid():
            return "applied"
        return "failed"
    except OSError:
        return "failed"


def _apply_unshare_net() -> str:
    if sys.platform != "linux":
        return "unsupported"
    flags = getattr(os, "CLONE_NEWNET", None)
    unshare = getattr(os, "unshare", None)
    if flags is None or unshare is None:
        return "unsupported"
    try:
        unshare(flags)
    except OSError:
        return "failed"
    return "applied"


def _apply_landlock(workdir: Path, allow_paths: list[Path]) -> str:
    if sys.platform != "linux":
        return "unsupported"
    try:
        from .landlock import apply_landlock, landlock_available
    except Exception:
        return "unsupported"
    try:
        available = landlock_available()
    except Exception:
        return "unsupported"
    if not available:
        return "unsupported"
    try:
        apply_landlock(workdir, allow_paths)
    except OSError:
        return "failed"
    return "applied"


def _resource_module():
    try:
        import resource
    except ImportError:
        return None
    return resource


def _apply_rlimit_as(memory: int | None) -> str:
    resource = _resource_module()
    if resource is None or not hasattr(resource, "RLIMIT_AS"):
        return "unsupported"
    if not memory:
        return "unsupported"
    value = int(memory)
    try:
        resource.setrlimit(resource.RLIMIT_AS, (value, value))
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    except (ValueError, OSError, AttributeError, resource.error):
        return "failed"
    if soft != value or hard != value:
        return "failed"
    return "applied"


def _apply_rlimit_cpu(cpu: float | None) -> str:
    resource = _resource_module()
    if resource is None or not hasattr(resource, "RLIMIT_CPU"):
        return "unsupported"
    if not cpu:
        return "unsupported"
    value = max(1, int(cpu))
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (value, value))
        soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
    except (ValueError, OSError, AttributeError, resource.error):
        return "failed"
    if soft != value or hard != value:
        return "failed"
    return "applied"


def _apply_rlimit_nproc(nproc: int | None) -> None:
    resource = _resource_module()
    if resource is None or not nproc or not hasattr(resource, "RLIMIT_NPROC"):
        return
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (int(nproc), int(nproc)))
    except (ValueError, OSError, resource.error):
        return


def describe_unix_support() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": sys.platform,
        "unshare_net": False,
        "landlock": False,
        "rlimit": False,
    }
    if sys.platform == "linux" and hasattr(os, "unshare") and hasattr(os, "CLONE_NEWNET"):
        info["unshare_net"] = True
    if sys.platform == "linux":
        try:
            from .landlock import landlock_available

            info["landlock"] = landlock_available()
        except Exception:
            info["landlock"] = False
    try:
        import resource  # noqa: F401

        info["rlimit"] = True
    except ImportError:
        pass
    return info


def apply_unix_policy(
    policy: IsolationPolicy,
    *,
    unshare_applied: bool,
    landlock_applied: bool,
    rlimit_cpu: bool,
    rlimit_as: bool,
    session_established: bool = False,
) -> None:
    """Map parent-visible Unix launch evidence onto capabilities.

    ``landlock_applied`` / ``unshare_applied`` / rlimit flags mean the parent
    detected that the child *will attempt* those applies. They are not proof
    the restriction attached. Only ``session_established`` is parent-visible
    (``Popen(start_new_session=True)`` succeeded) and may be ``enforced``
    before a bootstrap ACK. Filesystem/network/memory/cpu stay degraded or
    unsupported until a validated ACK reports ``applied``.
    """
    if session_established:
        policy.process_tree_limit = "enforced"
        policy.reasons["process_tree_limit"] = (
            "Parent created a new session (start_new_session=True); timeout uses killpg"
        )
    if policy.max_processes <= 1 and sys.platform == "linux":
        policy.process_creation = "degraded"
        policy.reasons["process_creation"] = (
            "RLIMIT_NPROC may deny extra processes; descendants are still killed on timeout"
        )
    else:
        policy.process_creation = "degraded"
        policy.reasons["process_creation"] = (
            "Process creation is not fully prevented; descendants are killed on timeout"
        )
    if landlock_applied:
        policy.filesystem_restriction = "degraded"
        policy.mechanism = "landlock" if not unshare_applied else "landlock+netns"
        policy.reasons["filesystem_restriction"] = (
            "Landlock is available; not enforced until a validated bootstrap ACK reports applied"
        )
    elif sys.platform == "linux":
        policy.filesystem_restriction = "unsupported"
        policy.reasons["filesystem_restriction"] = "Landlock is not available or failed to apply"
    else:
        policy.filesystem_restriction = "unsupported"
        policy.reasons["filesystem_restriction"] = f"{sys.platform} has no Landlock equivalent in this build"
    if unshare_applied:
        policy.network_restriction = "degraded"
        policy.reasons["network_restriction"] = (
            "CLONE_NEWNET is available; not enforced until a validated bootstrap ACK reports applied"
        )
        if policy.mechanism == "none":
            policy.mechanism = "netns"
    elif sys.platform == "linux":
        policy.network_restriction = "unsupported"
        policy.reasons["network_restriction"] = (
            "unshare(CLONE_NEWNET) is not available (often needs user namespaces)"
        )
    else:
        policy.network_restriction = "unsupported"
        policy.reasons["network_restriction"] = (
            f"{sys.platform} network namespace isolation is not implemented"
        )
    if rlimit_as:
        policy.memory_limit = "degraded"
        policy.reasons["memory_limit"] = (
            "RLIMIT_AS is available; not enforced until a validated bootstrap ACK reports applied"
        )
    else:
        policy.memory_limit = "unsupported"
        policy.reasons["memory_limit"] = "RLIMIT_AS is not available on this interpreter"
    if rlimit_cpu:
        policy.cpu_limit = "degraded"
        policy.reasons["cpu_limit"] = (
            "RLIMIT_CPU is available; not enforced until a validated bootstrap ACK reports applied"
        )
    else:
        policy.cpu_limit = "unsupported"
        policy.reasons["cpu_limit"] = "RLIMIT_CPU is not available on this interpreter"
    if policy.mechanism == "none":
        policy.mechanism = "process-group"
