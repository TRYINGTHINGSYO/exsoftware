from __future__ import annotations

import sys
from pathlib import Path

import pytest

from exsoftware.analyzers.hashes import HashAnalyzer
from exsoftware.content import content_id_from_bytes
from exsoftware.context import load_from_bytes
from exsoftware.isolate import process, workspace
from exsoftware.isolate.inventory import aggregate_worker_isolation, worker_isolation_record
from exsoftware.isolate.policy import CAPABILITIES, IsolationPolicy
from exsoftware.isolate.runner import IsolatedAnalyzerRunner
from exsoftware.isolate.test_analyzers import IsolateHangAnalyzer
from exsoftware.limits import RecursionLimits


def _ctx():
    ctx = load_from_bytes(b"spawn-lifecycle", name="fixture.bin")
    ctx.artifact_id = content_id_from_bytes(ctx.data)
    return ctx


def _runner() -> IsolatedAnalyzerRunner:
    return IsolatedAnalyzerRunner(RecursionLimits(max_child_processes=1))


def _isolation(result) -> dict:
    return (result.details or {}).get("isolation") or {}


def test_policy_capabilities_begin_non_enforced():
    capabilities = IsolationPolicy().capabilities()

    assert all(state == "unsupported" for state in capabilities.values())


def test_workspace_creation_failure_does_not_claim_unestablished_protections(monkeypatch):
    def fail_workspace():
        raise OSError("synthetic workspace creation failure")

    monkeypatch.setattr("exsoftware.isolate.runner.create_workspace", fail_workspace)

    result = _runner().run(HashAnalyzer, _ctx(), timeout=5)
    isolation = _isolation(result)
    capabilities = isolation["capabilities"]

    assert result.status == "failed"
    assert result.details["reason"] == "spawn_failed"
    assert capabilities["temporary_storage"] == "failed"
    assert capabilities["output_limit"] == "unsupported"
    assert capabilities["process_boundary"] == "unsupported"
    assert capabilities["wall_clock"] == "unsupported"
    assert isolation["mechanism"] == "none"


def test_workspace_permission_failure_is_reported_and_partial_directory_removed(
    monkeypatch, tmp_path: Path
):
    base = tmp_path / "temporary-root"

    def fail_permissions(path: Path):
        raise OSError("synthetic ACL preparation failure")

    monkeypatch.setattr(workspace.tempfile, "gettempdir", lambda: str(base))
    monkeypatch.setattr(workspace, "_restrict_workspace", fail_permissions)

    result = _runner().run(HashAnalyzer, _ctx(), timeout=5)
    isolation = _isolation(result)

    assert result.status == "failed"
    assert isolation["capabilities"]["temporary_storage"] == "failed"
    assert "synthetic ACL preparation failure" in isolation["spawn_error"]
    created = base / "exsoftware-isolate"
    assert not list(created.glob("w-*"))


def test_pipe_creation_failure_preserves_workspace_but_not_output_claim(monkeypatch):
    class BrokenStream:
        def __init__(self, *, limit: int):
            raise OSError(f"synthetic pipe failure at limit {limit}")

    monkeypatch.setattr(process, "BoundedStream", BrokenStream)

    result = _runner().run(HashAnalyzer, _ctx(), timeout=5)
    capabilities = _isolation(result)["capabilities"]

    assert result.status == "failed"
    assert capabilities["temporary_storage"] == "enforced"
    assert capabilities["output_limit"] == "failed"
    assert capabilities["process_boundary"] == "unsupported"
    assert capabilities["wall_clock"] == "unsupported"


def test_process_creation_failure_preserves_parent_protections_only(monkeypatch):
    def fail_spawn(*args, **kwargs):
        raise OSError("synthetic process creation failure")

    target = "_spawn_windows" if sys.platform == "win32" else "_spawn_unix"
    monkeypatch.setattr(process, target, fail_spawn)
    monkeypatch.setattr(process, "worker_executable", lambda: sys.executable)

    result = _runner().run(HashAnalyzer, _ctx(), timeout=5)
    capabilities = _isolation(result)["capabilities"]

    assert result.status == "failed"
    assert capabilities["temporary_storage"] == "enforced"
    assert capabilities["output_limit"] == "enforced"
    assert capabilities["process_boundary"] == "failed"
    assert capabilities["wall_clock"] == "failed"


def test_timeout_retains_protections_established_before_worker_hang():
    result = _runner().run(IsolateHangAnalyzer, _ctx(), timeout=1)
    capabilities = _isolation(result)["capabilities"]

    assert result.status == "timeout"
    assert capabilities["temporary_storage"] == "enforced"
    assert capabilities["output_limit"] == "enforced"
    assert capabilities["process_boundary"] == "enforced"
    assert capabilities["wall_clock"] == "enforced"


def test_normal_launch_retains_parent_enforced_capabilities():
    result = _runner().run(HashAnalyzer, _ctx(), timeout=20)
    capabilities = _isolation(result)["capabilities"]

    assert result.status == "completed"
    assert capabilities["temporary_storage"] == "enforced"
    assert capabilities["output_limit"] == "enforced"
    assert capabilities["process_boundary"] == "enforced"
    assert capabilities["wall_clock"] == "enforced"


def test_failed_worker_downgrades_report_wide_aggregate(monkeypatch):
    monkeypatch.setattr(
        "exsoftware.isolate.runner.create_workspace",
        lambda: (_ for _ in ()).throw(OSError("synthetic workspace failure")),
    )
    result = _runner().run(HashAnalyzer, _ctx(), timeout=5)
    failed_isolation = _isolation(result)
    strong_capabilities = {name: "enforced" for name in CAPABILITIES}
    workers = [
        worker_isolation_record(
            worker_type="analyzer",
            worker_id="strong",
            artifact_id="sha256:strong",
            status="completed",
            isolation={
                "mode": "subprocess",
                "mechanism": "appcontainer",
                "pid": 1234,
                "capabilities": strong_capabilities,
            },
        ),
        worker_isolation_record(
            worker_type="analyzer",
            worker_id="failed",
            artifact_id="sha256:failed",
            status="failed",
            reason="spawn_failed",
            isolation=failed_isolation,
        ),
    ]

    summary = aggregate_worker_isolation(workers)

    assert summary["all_workers_launched"] is False
    assert summary["capabilities"]["temporary_storage"] == "failed"
    assert summary["capabilities"]["process_boundary"] == "unsupported"
    assert workers[1]["capabilities"]["temporary_storage"] == "failed"

