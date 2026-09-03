"""Unix spawn capability mapping. Deterministic; does not require a Linux kernel."""

from __future__ import annotations

from exsoftware.isolate import process, unixcontain
from exsoftware.isolate.policy import IsolationPolicy
from exsoftware.isolate.unixcontain import apply_unix_policy


class FakeStream:
    child_fd = 7

    def __init__(self) -> None:
        self.write_closed = False

    def close_write(self) -> None:
        self.write_closed = True


class FakeProc:
    pid = 4242

    def __init__(self) -> None:
        self._exsoftware_job = None


def _policy() -> IsolationPolicy:
    policy = IsolationPolicy()
    policy.establish("temporary_storage", "test workspace established")
    policy.establish("output_limit", "test pipes established")
    return policy


def test_apply_unix_policy_does_not_overclaim_unverified_protections():
    policy = IsolationPolicy()
    apply_unix_policy(
        policy,
        landlock_applied=True,
        unshare_applied=True,
        rlimit_cpu=True,
        rlimit_as=True,
    )

    assert policy.process_tree_limit == "unsupported"
    assert policy.filesystem_restriction == "degraded"
    assert policy.network_restriction == "degraded"
    assert policy.memory_limit == "degraded"
    assert policy.cpu_limit == "degraded"
    assert "validated bootstrap ACK" in policy.reasons["filesystem_restriction"]
    assert "validated bootstrap ACK" in policy.reasons["network_restriction"]
    assert "validated bootstrap ACK" in policy.reasons["memory_limit"]
    assert "validated bootstrap ACK" in policy.reasons["cpu_limit"]


def test_apply_unix_policy_enforces_process_tree_only_when_session_established():
    without_session = IsolationPolicy()
    apply_unix_policy(
        without_session,
        landlock_applied=True,
        unshare_applied=True,
        rlimit_cpu=True,
        rlimit_as=True,
        session_established=False,
    )
    assert without_session.process_tree_limit == "unsupported"

    with_session = IsolationPolicy()
    apply_unix_policy(
        with_session,
        landlock_applied=False,
        unshare_applied=False,
        rlimit_cpu=False,
        rlimit_as=False,
        session_established=True,
    )
    assert with_session.process_tree_limit == "enforced"
    assert "start_new_session=True" in with_session.reasons["process_tree_limit"]
    assert with_session.filesystem_restriction == "unsupported"
    assert with_session.network_restriction == "unsupported"
    assert with_session.memory_limit == "unsupported"
    assert with_session.cpu_limit == "unsupported"


def test_spawn_unix_passes_start_new_session_true(monkeypatch, tmp_path):
    captured: dict = {}
    fake = FakeProc()

    def fake_popen(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return fake

    monkeypatch.setattr(process.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        unixcontain,
        "describe_unix_support",
        lambda: {
            "platform": "linux",
            "unshare_net": True,
            "landlock": True,
            "rlimit": True,
        },
    )

    stdout = FakeStream()
    stderr = FakeStream()
    policy = _policy()
    child, meta = process._spawn_unix(
        ["python", "-m", "exsoftware.isolate.worker"],
        tmp_path,
        {},
        policy,
        stdout,
        stderr,
    )

    assert child is fake
    assert captured["kwargs"]["start_new_session"] is True
    assert captured["kwargs"].get("preexec_fn") is None
    assert stdout.write_closed is True
    assert stderr.write_closed is True
    assert meta["start_new_session"] is True
    assert meta["process_group"] is True
    assert policy.process_tree_limit == "enforced"
    assert policy.filesystem_restriction == "degraded"
    assert policy.network_restriction == "degraded"
    assert policy.memory_limit == "degraded"
    assert policy.cpu_limit == "degraded"


def test_feature_complete_unix_support_does_not_enforce_unverified_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(process.subprocess, "Popen", lambda *args, **kwargs: FakeProc())
    monkeypatch.setattr(
        unixcontain,
        "describe_unix_support",
        lambda: {
            "platform": "linux",
            "unshare_net": True,
            "landlock": True,
            "rlimit": True,
        },
    )

    policy = _policy()
    _child, meta = process._spawn_unix(
        ["python"],
        tmp_path,
        {},
        policy,
        FakeStream(),
        FakeStream(),
    )

    assert meta["unix_support"]["landlock"] is True
    assert meta["unix_support"]["unshare_net"] is True
    assert meta["unix_support"]["rlimit"] is True
    assert policy.memory_limit != "enforced"
    assert policy.cpu_limit != "enforced"
    assert policy.filesystem_restriction != "enforced"
    assert policy.network_restriction != "enforced"
    assert policy.process_tree_limit == "enforced"


def test_unix_popen_failure_does_not_claim_process_tree(monkeypatch, tmp_path):
    def fail_popen(*args, **kwargs):
        raise OSError("synthetic start_new_session failure")

    monkeypatch.setattr(process.subprocess, "Popen", fail_popen)
    monkeypatch.setattr(
        unixcontain,
        "describe_unix_support",
        lambda: {"platform": "linux", "unshare_net": True, "landlock": True, "rlimit": True},
    )
    policy = _policy()
    try:
        process._spawn_unix(["python"], tmp_path, {}, policy, FakeStream(), FakeStream())
    except OSError as exc:
        assert "start_new_session" in str(exc)
    else:
        raise AssertionError("expected Popen failure")
    assert policy.process_tree_limit == "unsupported"
    assert policy.memory_limit == "unsupported"
    assert policy.filesystem_restriction == "unsupported"
