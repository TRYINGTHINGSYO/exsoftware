from __future__ import annotations

import io
import zipfile

from exsoftware import analyze_bytes
from exsoftware.content import digest_bytes
from exsoftware.isolate.container_runner import (
    ContainerResult,
    ExtractedBlob,
    IsolatedContainerRunner,
    ListedMember,
)
from exsoftware.isolate.inventory import (
    aggregate_worker_isolation,
    analyzer_worker_isolation_record,
    worker_isolation_record,
)
from exsoftware.isolate.ole_runner import IsolatedOleRunner, OleRefineResult
from exsoftware.isolate.policy import CAPABILITIES
from exsoftware.models import AnalyzerError, AnalyzerRun, FileIdentity, Report


def _capabilities(state: str = "enforced", **overrides: str) -> dict[str, str]:
    values = {name: state for name in CAPABILITIES}
    values.update(overrides)
    return values


def _isolation(
    mechanism: str | None,
    *,
    state: str = "enforced",
    launched: bool = True,
    **extra,
) -> dict:
    data = {
        "mode": "subprocess",
        "mechanism": mechanism,
        "capabilities": _capabilities(state),
        **extra,
    }
    if launched:
        data["pid"] = 1234
    else:
        data["launched"] = False
    return data


def _worker(
    worker_type: str,
    worker_id: str,
    mechanism: str | None,
    *,
    artifact_id: str = "sha256:fixture",
    state: str = "enforced",
    status: str = "completed",
    launched: bool = True,
    capability_overrides: dict[str, str] | None = None,
    **extra,
) -> dict:
    isolation = _isolation(mechanism, state=state, launched=launched, **extra)
    isolation["capabilities"].update(capability_overrides or {})
    return worker_isolation_record(
        worker_type=worker_type,
        worker_id=worker_id,
        artifact_id=artifact_id,
        status=status,
        isolation=isolation,
        reason="spawn_failed" if not launched else None,
    )


def test_all_workers_appcontainer_and_enforced_are_uniform():
    workers = [
        _worker("analyzer", "identity", "appcontainer"),
        _worker("analyzer", "hashes", "appcontainer"),
        _worker("archive_broker", "zip", "appcontainer"),
        _worker("ole_broker", "ole-refine", "appcontainer"),
    ]

    summary = aggregate_worker_isolation(workers)

    assert summary["mechanism"] == "appcontainer"
    assert summary["mechanisms"] == ["appcontainer"]
    assert summary["mechanism_uniform"] is True
    assert summary["all_workers_launched"] is True
    assert summary["capabilities"] == _capabilities()


def test_mixed_appcontainer_and_job_only_is_not_uniform():
    workers = [
        _worker("analyzer", "identity", "appcontainer"),
        _worker(
            "analyzer",
            "hashes",
            "job-only",
            capability_overrides={
                "filesystem_restriction": "unsupported",
                "network_restriction": "unsupported",
            },
            fallback_errors=["appcontainer: forced failure"],
        ),
    ]

    summary = aggregate_worker_isolation(workers)

    assert summary["mechanism"] == "mixed"
    assert summary["mechanisms"] == ["appcontainer", "job-only"]
    assert summary["mechanism_uniform"] is False
    assert summary["fallback_used"] is True
    assert summary["capabilities"]["filesystem_restriction"] == "unsupported"
    assert summary["capability_counts"]["filesystem_restriction"] == {
        "enforced": 1,
        "unsupported": 1,
    }


def test_multiple_analyzers_with_different_mechanisms_are_explicitly_mixed():
    workers = [
        _worker("analyzer", "identity", "appcontainer"),
        _worker("analyzer", "hashes", "unix-preexec"),
    ]

    summary = aggregate_worker_isolation(workers)

    assert summary["mechanism"] == "mixed"
    assert summary["mechanisms"] == ["appcontainer", "unix-preexec"]
    assert summary["mechanism_counts"] == {"appcontainer": 1, "unix-preexec": 1}


def test_weaker_archive_broker_downgrades_stronger_analyzers():
    workers = [
        _worker("analyzer", "identity", "appcontainer"),
        _worker("analyzer", "hashes", "appcontainer"),
        _worker(
            "archive_broker",
            "zip",
            "job-only",
            capability_overrides={"filesystem_restriction": "unsupported"},
        ),
    ]

    summary = aggregate_worker_isolation(workers)

    assert summary["mechanism"] == "mixed"
    assert summary["capabilities"]["filesystem_restriction"] == "unsupported"
    assert workers[-1]["worker_type"] == "archive_broker"
    assert workers[-1]["weaker_capabilities"]["filesystem_restriction"] == "unsupported"


def test_weaker_ole_broker_downgrades_stronger_analyzers():
    workers = [
        _worker("analyzer", "identity", "appcontainer"),
        _worker(
            "ole_broker",
            "ole-refine",
            "restricted-token",
            capability_overrides={"filesystem_restriction": "degraded"},
        ),
    ]

    summary = aggregate_worker_isolation(workers)

    assert summary["mechanism"] == "mixed"
    assert summary["capabilities"]["filesystem_restriction"] == "degraded"
    assert summary["fallback_used"] is True


def test_broker_launch_failure_is_visible_and_cannot_be_uniform():
    workers = [
        _worker("analyzer", "identity", "appcontainer"),
        _worker(
            "archive_broker",
            "zip",
            None,
            state="failed",
            status="failed",
            launched=False,
            spawn_error="forced broker spawn failure",
        ),
    ]

    summary = aggregate_worker_isolation(workers)

    assert summary["mechanism"] == "mixed"
    assert summary["all_workers_launched"] is False
    assert summary["failed_worker_count"] == 1
    assert summary["mechanism_counts"]["not-launched"] == 1
    assert summary["capabilities"]["process_boundary"] == "failed"
    assert workers[-1]["evidence"]["spawn_error"] == "forced broker spawn failure"


def test_analyzer_launch_failure_is_visible_in_analyzer_inventory():
    run = AnalyzerRun(
        id="run-0001",
        analyzer_id="hashes",
        analyzer_version="1.0.0",
        analyzer_title="Hashes",
        artifact_id="sha256:fixture",
        status="failed",
        details={
            "reason": "spawn_failed",
            "isolation": _isolation(
                None,
                state="failed",
                launched=False,
                spawn_error="forced analyzer spawn failure",
            ),
        },
        errors=[AnalyzerError(analyzer="hashes", message="forced analyzer spawn failure")],
    )

    worker = analyzer_worker_isolation_record(run)
    assert worker is not None
    summary = aggregate_worker_isolation([worker])

    assert worker["launched"] is False
    assert worker["reason"] == "spawn_failed"
    assert worker["message"] == "forced analyzer spawn failure"
    assert summary["mechanism"] == "none"
    assert summary["all_workers_launched"] is False
    assert summary["capabilities"]["process_boundary"] == "failed"


def test_stronger_first_worker_cannot_hide_later_weaker_worker():
    strong = _worker("analyzer", "identity", "appcontainer")
    weak = _worker(
        "analyzer",
        "hashes",
        "job-only",
        capability_overrides={"filesystem_restriction": "unsupported"},
    )

    summary = aggregate_worker_isolation([strong, weak])

    assert summary["mechanism"] == "mixed"
    assert summary["capabilities"]["filesystem_restriction"] == "unsupported"


def test_weaker_first_worker_and_stronger_later_has_same_aggregate():
    strong = _worker("analyzer", "identity", "appcontainer")
    weak = _worker(
        "analyzer",
        "hashes",
        "job-only",
        capability_overrides={"filesystem_restriction": "unsupported"},
    )

    weak_first = aggregate_worker_isolation([weak, strong])
    strong_first = aggregate_worker_isolation([strong, weak])

    assert weak_first == strong_first
    assert weak_first["mechanism"] == "mixed"
    assert weak_first["capabilities"]["filesystem_restriction"] == "unsupported"


def test_pipeline_serializes_archive_broker_inventory_and_round_trips(monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("note.txt", b"hello")

    def fake_extract(*args, **kwargs):
        return ContainerResult(
            status="completed",
            reason=None,
            zip_subtype="zip",
            listed_count=0,
            truncated_listing=False,
            isolation=_isolation(
                "job-only",
                fallback_errors=["appcontainer: forced failure"],
            ),
        )

    monkeypatch.setattr(IsolatedContainerRunner, "extract", fake_extract)
    monkeypatch.setattr("exsoftware.pipeline._run_analyzers", lambda ctx, inv: [])

    report = analyze_bytes(buf.getvalue(), name="sample.zip")
    isolation = report.limits["isolation"]
    workers = isolation["workers"]

    assert len(workers) == 1
    assert workers[0]["worker_type"] == "archive_broker"
    assert workers[0]["worker_id"] == "zip"
    assert workers[0]["mechanism"] == "job-only"
    assert workers[0]["fallback_used"] is True
    assert isolation["mechanism"] == "job-only"
    restored = Report.from_dict(report.to_dict())
    assert restored.limits["isolation"]["workers"] == workers


def test_recursive_archive_brokers_are_accumulated_not_overwritten(monkeypatch):
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w") as archive:
        archive.writestr("note.txt", b"hello")
    inner = inner_buffer.getvalue()

    outer_buffer = io.BytesIO()
    with zipfile.ZipFile(outer_buffer, "w") as archive:
        archive.writestr("inner.zip", inner)

    blob = ExtractedBlob(
        slot="blobs/000000.bin",
        original_name="inner.zip",
        display_name="inner.zip",
        index=0,
        size=len(inner),
        hashes=digest_bytes(inner),
        compressed_size=len(inner),
        compression_method=0,
        crc=None,
        encrypted=False,
        declared_size=len(inner),
        extraction_status="extracted",
        data=inner,
    )
    member = ListedMember(
        index=0,
        original_name="inner.zip",
        display_name="inner.zip",
        is_directory=False,
        encrypted=False,
        declared_size=len(inner),
        compressed_size=len(inner),
        compression_method=0,
        crc=None,
        flags=0,
        actual_size=len(inner),
        extraction_status="extracted",
        error=None,
        slot=blob.slot,
        blob=blob,
    )
    calls = 0

    def fake_extract(*args, **kwargs):
        nonlocal calls
        calls += 1
        return ContainerResult(
            status="completed",
            reason=None,
            zip_subtype="zip",
            listed_count=1 if calls == 1 else 0,
            truncated_listing=False,
            members=[member] if calls == 1 else [],
            isolation=_isolation(
                "appcontainer" if calls == 1 else "job-only",
                fallback_errors=[] if calls == 1 else ["appcontainer: forced failure"],
            ),
        )

    monkeypatch.setattr(IsolatedContainerRunner, "extract", fake_extract)
    monkeypatch.setattr("exsoftware.pipeline._run_analyzers", lambda ctx, inv: [])

    report = analyze_bytes(outer_buffer.getvalue(), name="outer.zip")
    isolation = report.limits["isolation"]
    brokers = [item for item in isolation["workers"] if item["worker_type"] == "archive_broker"]

    assert calls == 2
    assert len(brokers) == 2
    assert {item["mechanism"] for item in brokers} == {"appcontainer", "job-only"}
    assert isolation["mechanism"] == "mixed"


def test_pipeline_serializes_ole_broker_launch_failure(monkeypatch):
    identity = FileIdentity(
        name="memo.doc",
        path=None,
        source="bytes",
        extension=".doc",
        size=8,
        detected_type="ole",
        detected_family="document",
        detected_mime="application/x-ole-storage",
        description="OLE Compound File",
        extension_matches=True,
        magic_offset=0,
        magic_hex="d0cf11e0",
        extra={"ole_subtype_pending": True},
    )

    def fake_refine(*args, **kwargs):
        return OleRefineResult(
            status="failed",
            reason="spawn_failed",
            is_ole=False,
            message="forced OLE launch failure",
            isolation=_isolation(
                None,
                state="failed",
                launched=False,
                spawn_error="forced OLE launch failure",
            ),
        )

    monkeypatch.setattr("exsoftware.context.identify_bytes", lambda *args, **kwargs: identity)
    monkeypatch.setattr(IsolatedOleRunner, "refine", fake_refine)
    monkeypatch.setattr("exsoftware.pipeline._run_analyzers", lambda ctx, inv: [])

    report = analyze_bytes(b"not-real-ole", name="memo.doc")
    isolation = report.limits["isolation"]
    worker = isolation["workers"][0]

    assert worker["worker_type"] == "ole_broker"
    assert worker["status"] == "failed"
    assert worker["launched"] is False
    assert worker["reason"] == "spawn_failed"
    assert worker["evidence"]["spawn_error"] == "forced OLE launch failure"
    assert isolation["mechanism"] == "none"
    assert isolation["all_workers_launched"] is False
