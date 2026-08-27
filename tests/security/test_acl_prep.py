"""ACL grant timeout/failure and cache-marker rules. No Win32 required."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from exsoftware.isolate.acl_prep import (
    AclBootstrapCache,
    AclTimeoutError,
    acl_grant_succeeded,
    apply_cached_grant,
    run_acl_command,
    write_acl_success_marker,
)


def test_acl_command_timeout_is_failure_not_success():
    def runner(argv, timeout=None, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    with pytest.raises(AclTimeoutError, match="timed out"):
        run_acl_command(["icacls", r"C:\huge", "/T"], runner=runner, timeout=60)
    assert acl_grant_succeeded(returncode=0, timed_out=True) is False
    assert isinstance(AclTimeoutError("x"), OSError)


def test_failed_acl_grant_is_not_success():
    assert acl_grant_succeeded(returncode=1, timed_out=False) is False
    assert acl_grant_succeeded(returncode=None, timed_out=False) is False
    assert acl_grant_succeeded(returncode=0, timed_out=False) is True


def test_cache_marker_not_written_after_failed_grant(tmp_path: Path):
    marker = tmp_path / "sid-prefix.done"
    assert write_acl_success_marker(marker, succeeded=False) is False
    assert not marker.exists()
    assert write_acl_success_marker(marker, succeeded=acl_grant_succeeded(returncode=5)) is False
    assert not marker.exists()


def test_cache_marker_written_only_after_success(tmp_path: Path):
    marker = tmp_path / "sid-prefix.done"
    assert write_acl_success_marker(marker, succeeded=True) is True
    assert marker.read_text(encoding="utf-8") == "ok"


def test_apply_cached_grant_timeout_does_not_write_marker(tmp_path: Path):
    marker = tmp_path / "cache.done"
    cache = AclBootstrapCache()

    def grant():
        raise AclTimeoutError("icacls timed out after 60 seconds")

    with pytest.raises(AclTimeoutError):
        apply_cached_grant(marker=marker, grant_fn=grant, cache=cache, key="runtime")
    assert not marker.exists()
    assert cache.failed is True


def test_apply_cached_grant_false_does_not_write_marker(tmp_path: Path):
    marker = tmp_path / "cache.done"
    cache = AclBootstrapCache()

    def grant():
        return False

    with pytest.raises(OSError, match="ACL grant failed"):
        apply_cached_grant(marker=marker, grant_fn=grant, cache=cache, key="runtime")
    assert not marker.exists()


def test_bootstrap_failure_is_reused_instead_of_retrying(tmp_path: Path):
    marker = tmp_path / "cache.done"
    cache = AclBootstrapCache()
    calls = {"n": 0}

    def grant():
        calls["n"] += 1
        raise AclTimeoutError("icacls timed out")

    with pytest.raises(AclTimeoutError):
        apply_cached_grant(marker=marker, grant_fn=grant, cache=cache, key="runtime")
    with pytest.raises(OSError, match="previously failed"):
        apply_cached_grant(marker=marker, grant_fn=grant, cache=cache, key="runtime")
    assert calls["n"] == 1
    assert not marker.exists()


def test_successful_grant_writes_marker_and_skips_rerun(tmp_path: Path):
    marker = tmp_path / "cache.done"
    cache = AclBootstrapCache()
    calls = {"n": 0}

    def grant():
        calls["n"] += 1
        return True

    assert apply_cached_grant(marker=marker, grant_fn=grant, cache=cache, key="src") is True
    assert marker.is_file()
    assert apply_cached_grant(marker=marker, grant_fn=grant, cache=cache, key="src") is True
    assert calls["n"] == 1
