"""Portable ACL grant outcomes and success-marker rules.

Windows icacls lives in ``winacl``; this module is imported on every platform so
timeout/failure handling and cache writes can be unit-tested without Win32.
A timed-out or failed grant is never treated as success, and a cache marker is
written only after the grant actually succeeded.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Callable

DEFAULT_ACL_TIMEOUT_SECONDS = 60.0


class AclTimeoutError(OSError):
    """An ACL tool exceeded its time budget. Never treat as success."""


def acl_grant_succeeded(*, returncode: int | None, timed_out: bool = False) -> bool:
    """True only when the ACL tool exited 0 and did not time out."""
    if timed_out or returncode is None:
        return False
    return returncode == 0


def write_acl_success_marker(path: Path, *, succeeded: bool) -> bool:
    """Write ``path`` only when *succeeded* is true. Returns whether it was written."""
    if not succeeded:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("ok", encoding="utf-8")
    return True


def run_acl_command(
    argv: list[str],
    *,
    runner: Callable[..., Any],
    timeout: float = DEFAULT_ACL_TIMEOUT_SECONDS,
    extra_kwargs: dict[str, Any] | None = None,
) -> Any:
    """Run an ACL argv via *runner*. Timeouts become ``AclTimeoutError`` (an OSError)."""
    try:
        return runner(argv, timeout=timeout, **(extra_kwargs or {}))
    except subprocess.TimeoutExpired as exc:
        raise AclTimeoutError(
            f"ACL command timed out after {timeout} seconds: {argv[:3]}"
        ) from exc


class AclBootstrapCache:
    """Remember a failed AppContainer ACL bootstrap for the rest of the process.

    A later probe must not wait through the same expensive failure again.
    """

    def __init__(self) -> None:
        self._failure: BaseException | None = None
        self._success_keys: set[str] = set()

    def raise_if_failed(self) -> None:
        if self._failure is not None:
            raise OSError(
                f"AppContainer ACL bootstrap previously failed: {self._failure}"
            ) from self._failure

    def record_failure(self, exc: BaseException) -> None:
        self._failure = exc

    def record_success(self, key: str) -> None:
        self._success_keys.add(key)

    def has_success(self, key: str) -> bool:
        return key in self._success_keys

    @property
    def failed(self) -> bool:
        return self._failure is not None

    @property
    def failure(self) -> BaseException | None:
        return self._failure

    def clear(self) -> None:
        self._failure = None
        self._success_keys.clear()


# Shared across staging and AppContainer launch so one timeout is not retried
# independently by every security-status probe.
PROCESS_ACL_CACHE = AclBootstrapCache()


def apply_cached_grant(
    *,
    marker: Path,
    grant_fn: Callable[[], bool],
    cache: AclBootstrapCache,
    key: str,
) -> bool:
    """Run *grant_fn* unless a success marker already exists.

    Writes *marker* only after *grant_fn* returns true. Timeouts and false
    results are recorded on *cache* and raised so callers never treat them as
    success.
    """
    cache.raise_if_failed()
    if marker.is_file() or cache.has_success(key):
        cache.record_success(key)
        return True
    try:
        ok = bool(grant_fn())
    except (AclTimeoutError, OSError, subprocess.TimeoutExpired) as exc:
        cache.record_failure(exc)
        raise
    if not ok:
        exc = OSError(f"ACL grant failed for {key}")
        cache.record_failure(exc)
        raise exc
    write_acl_success_marker(marker, succeeded=True)
    cache.record_success(key)
    return True
