"""Unix-family containment: landlock / network namespace where the kernel allows it."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable

from .policy import IsolationPolicy


def unix_preexec(policy: IsolationPolicy, workdir: Path, allow_paths: list[Path]) -> Callable[[], None]:
    """Return a preexec_fn. Failures are recorded on *policy* after spawn via reasons set here.

    preexec cannot talk to the parent except by surviving. We set env EXSOFTWARE_UNIX_NET
    from the parent based on a probe, and apply landlock/unshare best-effort.
    """

    def _preexec() -> None:
        try:
            os.setsid()
        except OSError:
            pass
        _try_unshare_net()
        _try_landlock(workdir, allow_paths)
        _try_rlimits(policy)

    return _preexec


def _try_unshare_net() -> None:
    if sys.platform != "linux":
        return
    flags = getattr(os, "CLONE_NEWNET", None)
    unshare = getattr(os, "unshare", None)
    if flags is None or unshare is None:
        return
    try:
        unshare(flags)
    except OSError:
        return


def _try_rlimits(policy: IsolationPolicy) -> None:
    try:
        import resource
    except ImportError:
        return
    cpu = policy.max_cpu_seconds
    if cpu:
        value = max(1, int(cpu))
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (value, value))
        except (ValueError, OSError, resource.error):
            pass
    memory = policy.max_memory_bytes
    if memory:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (int(memory), int(memory)))
        except (ValueError, OSError, AttributeError, resource.error):
            pass
    nproc = policy.max_processes
    if nproc and hasattr(resource, "RLIMIT_NPROC"):
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (int(nproc), int(nproc)))
        except (ValueError, OSError, resource.error):
            pass


def _try_landlock(workdir: Path, allow_paths: list[Path]) -> None:
    if sys.platform != "linux":
        return
    try:
        from .landlock import apply_landlock
    except Exception:
        return
    try:
        apply_landlock(workdir, allow_paths)
    except OSError:
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


def apply_unix_policy(policy: IsolationPolicy, *, unshare_applied: bool, landlock_applied: bool, rlimit_cpu: bool, rlimit_as: bool) -> None:
    policy.process_tree_limit = "enforced"
    policy.reasons["process_tree_limit"] = "Child started in a new session; timeout uses killpg"
    if policy.max_processes <= 1 and sys.platform == "linux":
        policy.process_creation = "degraded"
        policy.reasons["process_creation"] = "RLIMIT_NPROC may deny extra processes; descendants are still killed on timeout"
    else:
        policy.process_creation = "degraded"
        policy.reasons["process_creation"] = "Process creation is not fully prevented; descendants are killed on timeout"
    if landlock_applied:
        policy.filesystem_restriction = "enforced"
        policy.mechanism = "landlock" if not unshare_applied else "landlock+netns"
        policy.reasons["filesystem_restriction"] = "Landlock ruleset allows workdir + runtime paths only"
    elif sys.platform == "linux":
        policy.filesystem_restriction = "unsupported"
        policy.reasons["filesystem_restriction"] = "Landlock is not available or failed to apply"
    else:
        policy.filesystem_restriction = "unsupported"
        policy.reasons["filesystem_restriction"] = f"{sys.platform} has no Landlock equivalent in this build"
    if unshare_applied:
        policy.network_restriction = "enforced"
        policy.reasons["network_restriction"] = "CLONE_NEWNET user namespace: empty network namespace"
        if policy.mechanism == "none":
            policy.mechanism = "netns"
    elif sys.platform == "linux":
        policy.network_restriction = "unsupported"
        policy.reasons["network_restriction"] = "unshare(CLONE_NEWNET) is not available (often needs user namespaces)"
    else:
        policy.network_restriction = "unsupported"
        policy.reasons["network_restriction"] = f"{sys.platform} network namespace isolation is not implemented"
    policy.memory_limit = "enforced" if rlimit_as else "unsupported"
    policy.cpu_limit = "enforced" if rlimit_cpu else "unsupported"
    if policy.mechanism == "none":
        policy.mechanism = "process-group"
