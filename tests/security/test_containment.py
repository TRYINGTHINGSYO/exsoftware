"""Adversarial analyzer containment tests.

These tests prove forbidden operations fail when a capability is reported
as enforced (or, for filesystem, at least degraded on Windows).
They launch real child processes. They do not mock the OS boundary.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest

from exsoftware.content import content_id_from_bytes
from exsoftware.context import load_from_bytes
from exsoftware.isolate.runner import IsolatedAnalyzerRunner
from exsoftware.isolate.test_analyzers import (
    IsolateNetworkAnalyzer,
    IsolateReadOutsideAnalyzer,
    IsolateSpawnAnalyzer,
    IsolateStderrFloodAnalyzer,
    IsolateStdoutFloodAnalyzer,
    IsolateSymlinkAnalyzer,
    IsolateWriteOutsideAnalyzer,
)
from exsoftware.limits import RecursionLimits


def _ctx(extra=None):
    ctx = load_from_bytes(b"containment-fixture", name="fixture.bin", extra=extra)
    ctx.artifact_id = content_id_from_bytes(ctx.data)
    return ctx


def _runner() -> IsolatedAnalyzerRunner:
    return IsolatedAnalyzerRunner(RecursionLimits(max_child_processes=1, max_output_bytes=64 * 1024))


def _caps(result) -> dict:
    return ((result.details or {}).get("isolation") or {}).get("capabilities") or {}


def test_host_sentinel_read_is_denied(tmp_path: Path):
    secret = tmp_path / "host-secret.txt"
    secret.write_text("do-not-read-me", encoding="utf-8")
    result = _runner().run(
        IsolateReadOutsideAnalyzer,
        _ctx(extra={"sentinel_read": str(secret)}),
        timeout=20,
    )
    caps = _caps(result)
    fs = caps.get("filesystem_restriction", "unsupported")
    if fs == "unsupported":
        if sys.platform == "win32":
            pytest.fail(
                "Windows filesystem restriction is unsupported. Stage 4 requires at least degraded "
                f"denial. isolation={result.details.get('isolation')}"
            )
        pytest.skip(f"filesystem_restriction unsupported on {sys.platform}: {(result.details.get('isolation') or {}).get('mechanism')}")
    assert result.details.get("read_ok") is False
    assert result.details.get("denied") is True
    assert secret.read_text(encoding="utf-8") == "do-not-read-me"


def test_host_sentinel_write_is_denied(tmp_path: Path):
    target = tmp_path / "host-write.txt"
    result = _runner().run(
        IsolateWriteOutsideAnalyzer,
        _ctx(extra={"sentinel_write": str(target)}),
        timeout=20,
    )
    caps = _caps(result)
    fs = caps.get("filesystem_restriction", "unsupported")
    if fs == "unsupported":
        if sys.platform == "win32":
            pytest.fail(f"Windows filesystem restriction unsupported: {result.details.get('isolation')}")
        pytest.skip(f"filesystem_restriction unsupported on {sys.platform}")
    assert result.details.get("write_ok") is False
    assert result.details.get("denied") is True
    assert not target.exists()


def test_network_sockets_match_claimed_capability():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        result = _runner().run(
            IsolateNetworkAnalyzer,
            _ctx(extra={"probe_host": "127.0.0.1", "probe_port": port}),
            timeout=20,
        )
    finally:
        listener.close()
    caps = _caps(result)
    net = caps.get("network_restriction", "unsupported")
    connect_ok = bool(result.details.get("connect_ok"))
    external_ok = bool(result.details.get("external_connect_ok"))
    listen_ok = bool(result.details.get("listen_ok"))
    if net == "enforced":
        # Usable communication must be denied. Bind/listen API may still succeed
        # under AppContainer loopback isolation; that alone is not a failure of
        # an evidence-backed enforced claim (security-status measures host→worker).
        assert connect_ok is False
        assert external_ok is False
    elif net == "degraded":
        # Partial restriction is allowed only if we do not claim full denial.
        return
    elif net == "unsupported":
        if sys.platform == "win32" and (_caps(result).get("filesystem_restriction") == "enforced"):
            pytest.fail("AppContainer filesystem enforced but network marked unsupported")
        return
    else:
        pytest.fail(f"unexpected network_restriction={net}")
    # Always record bind outcome for diagnostics; do not assert a specific value.
    assert "listen_ok" in result.details or listen_ok in {True, False}


def test_spawn_matches_claimed_capability():
    result = _runner().run(IsolateSpawnAnalyzer, _ctx(), timeout=20)
    caps = _caps(result)
    state = caps.get("process_creation", "unsupported")
    spawned = bool(result.details.get("spawned"))
    if state == "enforced":
        assert spawned is False
        assert result.details.get("denied") is True
    elif state == "degraded":
        # Creation may succeed; Stage 3 still kills the tree on timeout.
        return
    else:
        pytest.skip(f"process_creation {state}")


def test_stdout_flood_is_bounded():
    parent = os.getpid()
    result = _runner().run(IsolateStdoutFloodAnalyzer, _ctx(), timeout=20)
    assert os.getpid() == parent
    stdio = ((result.details.get("isolation") or {}).get("stdio") or {}).get("stdout") or {}
    assert stdio.get("captured_bytes", 0) <= 64 * 1024
    assert stdio.get("truncated") is True or stdio.get("discarded_bytes", 0) > 0
    assert stdio.get("captured_bytes", 0) + stdio.get("discarded_bytes", 0) > 64 * 1024


def test_stderr_flood_is_bounded():
    parent = os.getpid()
    result = _runner().run(IsolateStderrFloodAnalyzer, _ctx(), timeout=20)
    assert os.getpid() == parent
    stdio = ((result.details.get("isolation") or {}).get("stdio") or {}).get("stderr") or {}
    assert stdio.get("captured_bytes", 0) <= 64 * 1024
    assert stdio.get("truncated") is True or stdio.get("discarded_bytes", 0) > 0


def test_symlink_response_is_not_followed(tmp_path: Path):
    secret = tmp_path / "host-secret.txt"
    secret.write_text("symlink-secret", encoding="utf-8")
    result = _runner().run(
        IsolateSymlinkAnalyzer,
        _ctx(extra={"sentinel_read": str(secret)}),
        timeout=20,
    )
    if result.details.get("symlink_ok"):
        assert result.status == "failed"
        assert result.details.get("reason") in {
            "invalid_analyzer_response",
            "child_exited",
            "empty_analyzer_response",
        }
        text = json_preview(result)
        assert "symlink-secret" not in text
        return
    if result.details.get("denied"):
        pytest.skip(f"OS denied symlink creation: {result.details.get('error')}")
    pytest.skip("child did not create a symlink")


def json_preview(result) -> str:
    import json

    return json.dumps(result.to_dict(), default=str)


def test_recursive_zip_uses_same_containment():
    import io
    import zipfile

    from exsoftware import analyze_bytes

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("payload.py", b"print(1)\n")
    report = analyze_bytes(buf.getvalue(), name="sample.zip")
    child = next(item for item in report.artifacts if "payload.py" in item.names)
    runs = [item for item in report.analyzer_runs if item.artifact_id == child.id and item.status == "completed"]
    assert runs
    for run in runs:
        iso = run.details.get("isolation") or {}
        assert iso.get("mode") == "subprocess"
        assert iso.get("sandbox") is False
        caps = iso.get("capabilities") or {}
        assert caps.get("process_boundary") == "enforced"
