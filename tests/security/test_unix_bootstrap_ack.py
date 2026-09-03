"""Parent-validated Unix bootstrap ACK: schema, promotion, and failure modes."""

from __future__ import annotations

import inspect
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

from exsoftware.content import content_id_from_bytes
from exsoftware.context import load_from_bytes
from exsoftware.isolate.bootstrap import (
    ACK_MAX_BYTES,
    ACK_NAME,
    BOOTSTRAP_HOOK_ENV,
    BOOTSTRAP_PROTOCOL,
    ack_contradictions,
    apply_validated_ack,
    attach_bootstrap_ack,
    ingest_unix_bootstrap_ack,
    validate_bootstrap_ack,
)
from exsoftware.isolate.container_runner import IsolatedContainerRunner
from exsoftware.isolate.ole_runner import IsolatedOleRunner
from exsoftware.isolate.policy import IsolationPolicy
from exsoftware.isolate.protocol import TEST_ENV
from exsoftware.isolate.runner import IsolatedAnalyzerRunner
from exsoftware.isolate.test_analyzers import (
    IsolateHangAnalyzer,
    IsolateOkAnalyzer,
    IsolateSegfaultAnalyzer,
)
from exsoftware.isolate.unixcontain import apply_unix_policy
from exsoftware.isolate.worker import main as worker_main
from exsoftware.limits import RecursionLimits
from exsoftware.models import Report

LINUX_SUPPORT = {
    "platform": "linux",
    "landlock": True,
    "unshare_net": True,
    "rlimit": True,
}

PROMOTABLE = (
    "filesystem_restriction",
    "network_restriction",
    "memory_limit",
    "cpu_limit",
)


def _ctx():
    ctx = load_from_bytes(b"bootstrap-ack-fixture", name="fixture.bin")
    ctx.artifact_id = content_id_from_bytes(ctx.data)
    return ctx


def _runner() -> IsolatedAnalyzerRunner:
    return IsolatedAnalyzerRunner(RecursionLimits(max_child_processes=1))


def _isolation(result) -> dict:
    return (result.details or {}).get("isolation") or {}


def _caps(result) -> dict:
    return _isolation(result).get("capabilities") or {}


def _valid_ack(**overrides: str) -> dict:
    payload = {
        "protocol": BOOTSTRAP_PROTOCOL,
        "protocol_version": 1,
        "filesystem": "applied",
        "network": "applied",
        "memory": "applied",
        "cpu": "applied",
        "session": "applied",
    }
    payload.update(overrides)
    return payload


def _spawn_policy() -> IsolationPolicy:
    policy = IsolationPolicy()
    apply_unix_policy(
        policy,
        landlock_applied=True,
        unshare_applied=True,
        rlimit_cpu=True,
        rlimit_as=True,
        session_established=True,
    )
    return policy


def _write_ack(workdir: Path, payload) -> None:
    if isinstance(payload, bytes):
        (workdir / ACK_NAME).write_bytes(payload)
    elif isinstance(payload, str):
        (workdir / ACK_NAME).write_text(payload, encoding="utf-8")
    else:
        (workdir / ACK_NAME).write_text(json.dumps(payload), encoding="utf-8")


def test_validate_bootstrap_ack_accepts_closed_schema():
    results = validate_bootstrap_ack(_valid_ack(network="unsupported"))
    assert results["filesystem"] == "applied"
    assert results["network"] == "unsupported"
    assert results["memory"] == "applied"
    assert results["cpu"] == "applied"
    assert results["session"] == "applied"


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"protocol": BOOTSTRAP_PROTOCOL},
        _valid_ack(filesystem="APPLIED"),
        {**_valid_ack(), "extra": "nope"},
        {**_valid_ack(), "protocol_version": "1"},
        {**_valid_ack(), "protocol": "exsoftware.isolate"},
    ],
)
def test_validate_bootstrap_ack_rejects_malformed(payload):
    with pytest.raises(Exception):
        validate_bootstrap_ack(payload)


def test_applied_without_parent_support_is_contradictory():
    results = validate_bootstrap_ack(_valid_ack())
    problems = ack_contradictions(results, {"landlock": False, "unshare_net": True, "rlimit": True})
    assert problems
    assert any("filesystem" in item for item in problems)


def test_valid_ack_promotes_only_applied_results(tmp_path: Path):
    policy = _spawn_policy()
    _write_ack(tmp_path, _valid_ack(network="unsupported", cpu="failed"))
    evidence = ingest_unix_bootstrap_ack(
        policy,
        tmp_path,
        timed_out=False,
        returncode=0,
        unix_support=LINUX_SUPPORT,
    )
    assert evidence["status"] == "ok"
    assert evidence["promoted"] is True
    assert policy.filesystem_restriction == "enforced"
    assert policy.network_restriction == "unsupported"
    assert policy.memory_limit == "enforced"
    assert policy.cpu_limit == "failed"
    assert policy.process_tree_limit == "enforced"


def test_one_apply_failure_does_not_promote_that_capability(tmp_path: Path):
    policy = _spawn_policy()
    _write_ack(tmp_path, _valid_ack(memory="failed"))
    ingest_unix_bootstrap_ack(
        policy, tmp_path, timed_out=False, returncode=0, unix_support=LINUX_SUPPORT
    )
    assert policy.memory_limit == "failed"
    assert policy.filesystem_restriction == "enforced"
    assert policy.memory_limit != "enforced"


@pytest.mark.parametrize(
    ("payload", "status"),
    [
        (None, "missing"),
        ("", "missing"),
        ("{not-json", "truncated"),
        ('{"protocol":"exsoftware.isolate.bootstrap","protocol_version":1', "truncated"),
        ({**_valid_ack(), "extra": True}, "malformed"),
        (_valid_ack(), "contradictory"),
        (b"A" * (ACK_MAX_BYTES + 8), "oversized"),
    ],
)
def test_invalid_ack_never_promotes(tmp_path: Path, payload, status):
    policy = _spawn_policy()
    if payload is not None:
        if status == "contradictory":
            _write_ack(tmp_path, payload)
            support = {"landlock": False, "unshare_net": False, "rlimit": False}
        else:
            _write_ack(tmp_path, payload)
            support = LINUX_SUPPORT
    else:
        support = LINUX_SUPPORT
    evidence = ingest_unix_bootstrap_ack(
        policy,
        tmp_path,
        timed_out=False,
        returncode=0,
        unix_support=support,
    )
    assert evidence["status"] == status
    assert evidence["promoted"] is False
    for name in PROMOTABLE:
        assert getattr(policy, name) != "enforced"
    assert policy.process_tree_limit == "enforced"


def test_timeout_without_ack_is_timeout_not_enforced(tmp_path: Path):
    policy = _spawn_policy()
    evidence = ingest_unix_bootstrap_ack(
        policy, tmp_path, timed_out=True, returncode=None, unix_support=LINUX_SUPPORT
    )
    assert evidence["status"] == "timeout"
    for name in PROMOTABLE:
        assert getattr(policy, name) != "enforced"


def test_crash_without_ack_is_crash_before_ack(tmp_path: Path):
    policy = _spawn_policy()
    evidence = ingest_unix_bootstrap_ack(
        policy, tmp_path, timed_out=False, returncode=-6, unix_support=LINUX_SUPPORT
    )
    assert evidence["status"] == "crash_before_ack"
    for name in PROMOTABLE:
        assert getattr(policy, name) != "enforced"


def test_successful_child_without_ack_does_not_promote(tmp_path: Path):
    policy = _spawn_policy()
    evidence = ingest_unix_bootstrap_ack(
        policy, tmp_path, timed_out=False, returncode=0, unix_support=LINUX_SUPPORT
    )
    assert evidence["status"] == "missing"
    for name in PROMOTABLE:
        assert getattr(policy, name) == "degraded"


def test_apply_validated_ack_does_not_touch_process_tree():
    policy = _spawn_policy()
    apply_validated_ack(
        policy,
        {
            "filesystem": "applied",
            "network": "applied",
            "memory": "applied",
            "cpu": "applied",
            "session": "failed",
        },
    )
    assert policy.process_tree_limit == "enforced"
    assert policy.filesystem_restriction == "enforced"


def test_attach_bootstrap_ack_is_noop_on_windows(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("exsoftware.isolate.bootstrap.sys.platform", "win32")
    policy = _spawn_policy()
    _write_ack(tmp_path, _valid_ack())
    isolation = {"unix_support": LINUX_SUPPORT, "capabilities": policy.capabilities()}
    attach_bootstrap_ack(isolation, policy, tmp_path, timed_out=False, returncode=0)
    assert "bootstrap_ack" not in isolation
    for name in PROMOTABLE:
        assert getattr(policy, name) == "degraded"


def test_worker_bootstraps_before_hostile_dispatch():
    source = inspect.getsource(worker_main)
    assert source.index("_run_unix_bootstrap") < source.index("_run_container")
    assert source.index("_run_unix_bootstrap") < source.index("_run_ole")
    assert source.index("_run_unix_bootstrap") < source.index("validate_request")


def test_report_without_bootstrap_ack_still_loads():
    restored = Report.from_dict(
        {
            "schema_version": 1,
            "identity": {
                "name": "x",
                "path": None,
                "source": "bytes",
                "extension": "",
                "size": 1,
                "detected_type": "unknown",
                "detected_family": "unknown",
                "detected_mime": "application/octet-stream",
                "description": "unknown",
                "extension_matches": None,
                "magic_offset": 0,
                "magic_hex": "",
            },
            "overview": "",
            "next_steps": [],
            "hashes": {},
            "findings": [],
            "analyzers": [],
            "analyzer_runs": [],
            "limits": {"isolation": {"mechanism": "unix-preexec", "capabilities": {}}},
        }
    )
    assert restored.schema_version == 1


def _assert_ack_backed_caps(isolation: dict) -> None:
    ack = isolation.get("bootstrap_ack") or {}
    caps = isolation.get("capabilities") or {}
    assert caps.get("process_tree_limit") == "enforced"
    if ack.get("status") != "ok":
        for name in PROMOTABLE:
            assert caps.get(name) != "enforced"
        return
    results = ack.get("results") or {}
    mapping = {
        "filesystem": "filesystem_restriction",
        "network": "network_restriction",
        "memory": "memory_limit",
        "cpu": "cpu_limit",
    }
    for ack_key, cap_name in mapping.items():
        state = results.get(ack_key)
        if state == "applied":
            assert caps.get(cap_name) == "enforced"
        elif state == "unsupported":
            assert caps.get(cap_name) == "unsupported"
        elif state == "failed":
            assert caps.get(cap_name) == "failed"
        else:
            assert caps.get(cap_name) != "enforced"


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_all_requested_restrictions_can_be_acknowledged():
    result = _runner().run(IsolateOkAnalyzer, _ctx(), timeout=20)
    isolation = _isolation(result)
    ack = isolation.get("bootstrap_ack") or {}
    caps = isolation.get("capabilities") or {}
    results = ack.get("results") or {}
    support = isolation.get("unix_support") or {}
    assert ack.get("status") == "ok"
    _assert_ack_backed_caps(isolation)
    assert result.status == "completed"
    assert caps.get("process_tree_limit") == "enforced"
    # Hosted Ubuntu may deny CLONE_NEWNET. That is runner policy, not a broken
    # protocol. Rlimits should still attach; Landlock should attach when present.
    if sys.platform.startswith("linux"):
        assert results.get("memory") == "applied"
        assert results.get("cpu") == "applied"
        assert caps.get("memory_limit") == "enforced"
        assert caps.get("cpu_limit") == "enforced"
        if support.get("landlock"):
            assert results.get("filesystem") in {"applied", "failed"}
            if results.get("filesystem") == "applied":
                assert caps.get("filesystem_restriction") == "enforced"
        else:
            assert caps.get("filesystem_restriction") != "enforced"
        assert results.get("network") in {"applied", "unsupported", "failed"}
        if results.get("network") != "applied":
            assert caps.get("network_restriction") != "enforced"


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_one_restriction_unsupported_hook(monkeypatch):
    monkeypatch.setenv(TEST_ENV, "1")
    monkeypatch.setenv(BOOTSTRAP_HOOK_ENV, "unsupported_filesystem")
    result = _runner().run(IsolateOkAnalyzer, _ctx(), timeout=20)
    isolation = _isolation(result)
    assert isolation["bootstrap_ack"]["status"] == "ok"
    assert isolation["bootstrap_ack"]["results"]["filesystem"] == "unsupported"
    assert isolation["capabilities"]["filesystem_restriction"] == "unsupported"
    assert isolation["capabilities"]["filesystem_restriction"] != "enforced"
    _assert_ack_backed_caps(isolation)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_one_restriction_apply_failure_hook(monkeypatch):
    monkeypatch.setenv(TEST_ENV, "1")
    monkeypatch.setenv(BOOTSTRAP_HOOK_ENV, "fail_memory")
    result = _runner().run(IsolateOkAnalyzer, _ctx(), timeout=20)
    isolation = _isolation(result)
    assert isolation["bootstrap_ack"]["status"] == "ok"
    assert isolation["bootstrap_ack"]["results"]["memory"] == "failed"
    assert isolation["capabilities"]["memory_limit"] == "failed"
    assert isolation["capabilities"]["memory_limit"] != "enforced"


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
@pytest.mark.parametrize(
    "hook",
    ["malformed", "truncated", "skip_ack", "contradict"],
)
def test_bad_ack_hooks_never_enforce_ack_capabilities(monkeypatch, hook):
    monkeypatch.setenv(TEST_ENV, "1")
    monkeypatch.setenv(BOOTSTRAP_HOOK_ENV, hook)
    if hook == "contradict":
        monkeypatch.setattr(
            "exsoftware.isolate.unixcontain.describe_unix_support",
            lambda: {"platform": "linux", "landlock": False, "unshare_net": False, "rlimit": False},
        )
    result = _runner().run(IsolateOkAnalyzer, _ctx(), timeout=20)
    isolation = _isolation(result)
    ack = isolation.get("bootstrap_ack") or {}
    if hook == "skip_ack":
        assert ack.get("status") == "missing"
    elif hook == "contradict":
        assert ack.get("status") == "contradictory"
    elif hook == "truncated":
        assert ack.get("status") == "truncated"
    else:
        assert ack.get("status") == "malformed"
    for name in PROMOTABLE:
        assert isolation["capabilities"].get(name) != "enforced"
    assert isolation["capabilities"]["process_tree_limit"] == "enforced"
    assert result.status == "completed"


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_crash_before_ack_never_enforces(monkeypatch):
    monkeypatch.setenv(TEST_ENV, "1")
    monkeypatch.setenv(BOOTSTRAP_HOOK_ENV, "crash")
    result = _runner().run(IsolateOkAnalyzer, _ctx(), timeout=20)
    isolation = _isolation(result)
    assert isolation["bootstrap_ack"]["status"] == "crash_before_ack"
    for name in PROMOTABLE:
        assert isolation["capabilities"].get(name) != "enforced"
    assert isolation["capabilities"]["process_tree_limit"] == "enforced"
    assert result.status == "failed"


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_timeout_before_ack_never_enforces(monkeypatch):
    monkeypatch.setenv(TEST_ENV, "1")
    monkeypatch.setenv(BOOTSTRAP_HOOK_ENV, "hang")
    result = _runner().run(IsolateOkAnalyzer, _ctx(), timeout=1)
    isolation = _isolation(result)
    assert result.status == "timeout"
    assert isolation["bootstrap_ack"]["status"] == "timeout"
    for name in PROMOTABLE:
        assert isolation["capabilities"].get(name) != "enforced"
    assert isolation["capabilities"]["process_tree_limit"] == "enforced"


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_ack_followed_by_analyzer_crash_keeps_validated_promotion():
    result = _runner().run(IsolateSegfaultAnalyzer, _ctx(), timeout=20)
    isolation = _isolation(result)
    assert result.status == "failed"
    assert isolation["bootstrap_ack"]["status"] == "ok"
    _assert_ack_backed_caps(isolation)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_analyzer_hang_after_ack_does_not_drop_session_enforcement():
    result = _runner().run(IsolateHangAnalyzer, _ctx(), timeout=1)
    isolation = _isolation(result)
    assert result.status == "timeout"
    assert isolation["capabilities"]["process_tree_limit"] == "enforced"
    assert isolation["bootstrap_ack"]["status"] == "ok"
    _assert_ack_backed_caps(isolation)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_container_worker_uses_same_bootstrap_ack():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("a.txt", b"hello")
    result = IsolatedContainerRunner(RecursionLimits()).extract(
        buf.getvalue(),
        artifact_id="sha256:container-ack",
        timeout=20,
    )
    assert result.status == "completed"
    assert result.isolation.get("bootstrap_ack", {}).get("status") == "ok"
    _assert_ack_backed_caps(result.isolation)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_ole_worker_uses_same_bootstrap_ack():
    result = IsolatedOleRunner(RecursionLimits()).refine(
        b"not-an-ole-file",
        artifact_id="sha256:ole-ack",
        timeout=20,
    )
    assert result.isolation.get("bootstrap_ack", {}).get("status") == "ok"
    _assert_ack_backed_caps(result.isolation)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix bootstrap ACK worker path")
def test_container_abort_after_ack_does_not_invent_enforcement(monkeypatch):
    monkeypatch.setenv(TEST_ENV, "1")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("a.txt", b"hello")
    result = IsolatedContainerRunner(RecursionLimits()).extract(
        buf.getvalue(),
        artifact_id="sha256:container-abort",
        timeout=20,
        test_hook="abort",
    )
    assert result.status == "failed"
    assert result.isolation.get("bootstrap_ack", {}).get("status") == "ok"
    _assert_ack_backed_caps(result.isolation)
