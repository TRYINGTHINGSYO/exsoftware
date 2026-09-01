from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows launch mapping")


class FakeStream:
    def __init__(self) -> None:
        self.started = False
        self.write_closed = False

    def start(self) -> None:
        self.started = True

    def child_handle(self) -> int:
        return 101

    def close_write(self) -> None:
        self.write_closed = True


class FakeChild:
    pid = 4321


def _policy():
    from exsoftware.isolate.policy import IsolationPolicy

    policy = IsolationPolicy()
    policy.establish("temporary_storage", "test workspace established")
    return policy


def _job(*, assigned=True, memory=1024, cpu=5.0, active=1):
    return SimpleNamespace(
        assigned=assigned,
        assign_error=None if assigned else 5,
        limits_applied={
            "kill_on_job_close": True,
            "active_process_limit": active,
            "job_memory_bytes": memory,
            "job_cpu_seconds": cpu,
        },
    )


def _spawn(monkeypatch, tmp_path, job):
    from exsoftware.isolate import process, winjob

    monkeypatch.setattr(process, "worker_executable", lambda: sys.executable)
    monkeypatch.setattr(winjob, "WinJob", lambda **kwargs: job)
    stdout = FakeStream()
    stderr = FakeStream()
    policy = _policy()
    child, meta = process.spawn_worker(
        workdir=tmp_path,
        env={},
        policy=policy,
        stdout=stdout,
        stderr=stderr,
    )
    return child, meta, policy


def test_appcontainer_creation_failure_uses_restricted_token_capabilities(monkeypatch, tmp_path):
    from exsoftware.isolate import wincontain

    monkeypatch.setattr(
        wincontain,
        "launch_appcontainer",
        lambda **kwargs: (_ for _ in ()).throw(OSError("synthetic AppContainer failure")),
    )
    monkeypatch.setattr(
        wincontain,
        "launch_restricted_token",
        lambda **kwargs: (FakeChild(), {"mechanism": "restricted_token", "pid": 4321}),
    )

    _, meta, policy = _spawn(monkeypatch, tmp_path, _job())

    assert meta["mechanism"] == "restricted_token"
    assert policy.process_boundary == "enforced"
    assert policy.wall_clock == "enforced"
    assert policy.filesystem_restriction == "degraded"
    assert policy.network_restriction == "unsupported"


def test_restricted_token_failure_uses_job_only_capabilities(monkeypatch, tmp_path):
    from exsoftware.isolate import process, wincontain

    monkeypatch.setattr(
        wincontain,
        "launch_appcontainer",
        lambda **kwargs: (_ for _ in ()).throw(OSError("synthetic AppContainer failure")),
    )
    monkeypatch.setattr(
        wincontain,
        "launch_restricted_token",
        lambda **kwargs: (_ for _ in ()).throw(OSError("synthetic restricted-token failure")),
    )
    monkeypatch.setattr(
        process,
        "_spawn_windows_fallback",
        lambda *args: (FakeChild(), {"mechanism": "job-only", "pid": 4321}),
    )

    _, meta, policy = _spawn(monkeypatch, tmp_path, _job())

    assert meta["mechanism"] == "job-only"
    assert meta["fallback_errors"] == [
        "appcontainer: synthetic AppContainer failure",
        "restricted_token: synthetic restricted-token failure",
    ]
    assert policy.filesystem_restriction == "unsupported"
    assert policy.network_restriction == "unsupported"
    assert policy.process_boundary == "enforced"


def test_job_creation_failure_does_not_claim_job_capabilities(monkeypatch, tmp_path):
    from exsoftware.isolate import process, wincontain, winjob

    monkeypatch.setattr(process, "worker_executable", lambda: sys.executable)
    monkeypatch.setattr(
        winjob,
        "WinJob",
        lambda **kwargs: (_ for _ in ()).throw(OSError("synthetic Job creation failure")),
    )
    monkeypatch.setattr(
        wincontain,
        "launch_appcontainer",
        lambda **kwargs: (FakeChild(), {"mechanism": "appcontainer", "pid": 4321}),
    )
    monkeypatch.setattr(wincontain, "query_child_token", lambda child: {"token_is_appcontainer": True})
    policy = _policy()

    _, meta = process.spawn_worker(
        workdir=tmp_path,
        env={},
        policy=policy,
        stdout=FakeStream(),
        stderr=FakeStream(),
    )

    assert meta["job_assigned"] is False
    assert policy.process_tree_limit == "degraded"
    assert policy.memory_limit == "unsupported"
    assert policy.cpu_limit == "unsupported"
    assert policy.process_creation == "degraded"


def test_workspace_acl_inheritance_failure_is_not_silently_accepted(monkeypatch, tmp_path):
    from exsoftware.isolate import winacl

    monkeypatch.setattr(winacl, "current_user_sid", lambda: "S-1-5-21-test")
    monkeypatch.setattr(
        winacl,
        "_icacls",
        lambda args: SimpleNamespace(returncode=5, stderr=b"synthetic inheritance failure"),
    )

    with pytest.raises(OSError, match="synthetic inheritance failure"):
        winacl.restrict_directory_to_current_user(tmp_path)


def test_job_assignment_failure_does_not_claim_job_capabilities(monkeypatch, tmp_path):
    from exsoftware.isolate import wincontain

    job = _job(assigned=False)
    monkeypatch.setattr(
        wincontain,
        "launch_appcontainer",
        lambda **kwargs: (FakeChild(), {"mechanism": "appcontainer", "pid": 4321}),
    )
    monkeypatch.setattr(wincontain, "query_child_token", lambda child: {"token_is_appcontainer": True})

    _, meta, policy = _spawn(monkeypatch, tmp_path, job)

    assert meta["job_assigned"] is False
    assert meta["job_assign_error"] == 5
    assert policy.process_tree_limit == "degraded"
    assert policy.memory_limit == "unsupported"
    assert policy.cpu_limit == "unsupported"


@pytest.mark.parametrize(
    ("memory", "cpu", "expected_memory", "expected_cpu"),
    [
        (None, 5.0, "unsupported", "enforced"),
        (1024, None, "enforced", "unsupported"),
    ],
)
def test_optional_job_limit_setup_failures_are_not_enforced(
    memory, cpu, expected_memory, expected_cpu
):
    from exsoftware.isolate import wincontain

    policy = _policy()
    wincontain.apply_policy_from_launch(
        policy,
        {"mechanism": "job-only", "pid": 4321},
        _job(memory=memory, cpu=cpu),
    )

    assert policy.memory_limit == expected_memory
    assert policy.cpu_limit == expected_cpu
