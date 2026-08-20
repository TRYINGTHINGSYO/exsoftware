from __future__ import annotations

import json

from exsoftware import analyze_bytes
from exsoftware.models import Report


def _sound(report: Report) -> None:
    artifact_ids = {item.id for item in report.artifacts}
    evidence_ids = {item.id for item in report.evidence_store}
    observation_ids = {item.id for item in report.observations}
    assert report.root_artifact_id in artifact_ids
    for rel in report.relationships:
        assert rel.source_id in artifact_ids, rel
        assert rel.target_id in artifact_ids, rel
        assert rel.analyzer_id
        assert rel.analyzer_version
        assert rel.certainty in {"observed", "derived", "inferred", "unknown", "not_analyzed"}
    for finding in report.findings:
        assert finding.artifact_id in artifact_ids
        assert finding.rule_id
        assert finding.rule_version
        assert finding.analyzer_version
        assert finding.certainty in {"observed", "derived", "inferred", "unknown", "not_analyzed"}
        for eid in finding.evidence_ids:
            assert eid in evidence_ids
        for oid in finding.observation_ids:
            assert oid in observation_ids
    for evidence in report.evidence_store:
        assert evidence.artifact_id in artifact_ids
        assert evidence.analyzer
    for obs in report.observations:
        assert obs.artifact_id in artifact_ids
        assert obs.certainty in {"observed", "derived", "inferred", "unknown", "not_analyzed"}
        for eid in obs.evidence_ids:
            assert eid in evidence_ids
    for run in report.analyzer_runs:
        assert run.artifact_id in artifact_ids
        assert run.status in {
            "completed",
            "unsupported",
            "skipped",
            "failed",
            "timeout",
            "terminated",
        }
        assert run.analyzer_version


def test_same_bytes_different_names_share_content_id():
    data = b"print('hello')\n"
    first = analyze_bytes(data, name="malware.exe")
    second = analyze_bytes(data, name="cute-cat.jpg")
    assert first.root_artifact_id == second.root_artifact_id
    assert first.root_artifact_id.startswith("sha256:")
    root = next(item for item in first.artifacts if item.id == first.root_artifact_id)
    assert root.content_id == first.root_artifact_id


def test_different_bytes_different_content_id():
    first = analyze_bytes(b"aaa", name="a.txt")
    second = analyze_bytes(b"bbb", name="a.txt")
    assert first.root_artifact_id != second.root_artifact_id


def test_filename_is_metadata_not_identity():
    report = analyze_bytes(b"{}", name="notes.json")
    root = next(item for item in report.artifacts if item.id == report.root_artifact_id)
    assert "notes.json" in root.names
    assert root.id.startswith("sha256:")
    assert root.id != "notes.json"


def test_json_roundtrip_preserves_graph():
    source = b"import subprocess\nsubprocess.run(['true'])\n# https://example.test/x\n"
    report = analyze_bytes(source, name="fetch.py")
    payload = report.to_dict()
    text = json.dumps(payload)
    restored = Report.from_dict(json.loads(text))
    assert restored.schema_version == 1
    assert restored.root_artifact_id == report.root_artifact_id
    assert {item.id for item in restored.artifacts} == {item.id for item in report.artifacts}
    assert {item.id for item in restored.relationships} == {item.id for item in report.relationships}
    assert {item.rule_id for item in restored.findings} == {item.rule_id for item in report.findings}
    assert restored.engine.get("version")
    _sound(restored)


def test_schema_version_is_integer_one():
    report = analyze_bytes(b"hello", name="plain.txt")
    data = report.to_dict()
    assert data["schema_version"] == 1
    assert data["schema"] == "exsoftware.report"
    assert "artifacts" in data
    assert "observations" in data
    assert "evidence" in data
    assert "findings" in data
    assert "relationships" in data
    assert "analyzer_runs" in data


def test_certainty_distinguishes_observed_url_from_inferred_capability():
    source = b"import urllib.request\nurllib.request.urlopen('https://example.test/payload')\n"
    report = analyze_bytes(source, name="fetch.py")
    url_findings = [item for item in report.findings if item.rule_id == "STR.URL.001"]
    assert url_findings
    assert all(item.certainty == "observed" for item in url_findings)
    call_findings = [item for item in report.findings if item.rule_id == "SCRIPT.PY.CALL.001"]
    if call_findings:
        assert all(item.certainty == "derived" for item in call_findings)
    url_rels = [item for item in report.relationships if item.type == "REFERENCES" and item.target_id.startswith("name:url:")]
    assert url_rels
    assert all(item.certainty == "observed" for item in url_rels)
    assert "runtime" not in (url_findings[0].summary.lower())
    _sound(report)


def test_python_imports_are_observed_relationships():
    report = analyze_bytes(b"import subprocess\n", name="tool.py")
    rels = [item for item in report.relationships if item.type == "IMPORTS"]
    assert any(item.target_id.endswith("subprocess") or "subprocess" in item.target_id for item in rels)
    assert all(item.certainty == "observed" for item in rels)
    assert all(item.analyzer_version for item in rels)


def test_failed_analyzer_is_recorded(monkeypatch):
    from exsoftware.analyzers.hashes import HashAnalyzer
    from exsoftware.limits import RecursionLimits

    def boom(self, ctx):
        raise RuntimeError("hash exploded")

    monkeypatch.setattr(HashAnalyzer, "analyze", boom)
    report = analyze_bytes(
        b"hello world",
        name="plain.txt",
        limits=RecursionLimits(isolate_analyzers=False),
    )
    runs = [item for item in report.analyzer_runs if item.analyzer_id == "hashes" and item.artifact_id == report.root_artifact_id]
    assert runs
    assert runs[0].status == "failed"
    assert runs[0].errors
    assert runs[0].errors[0].exception_type == "RuntimeError"
    unsupported = [item for item in report.analyzer_runs if item.status == "unsupported"]
    assert unsupported


def test_analyzer_provenance_on_findings():
    report = analyze_bytes(b"import os\n", name="a.py")
    assert report.findings
    for finding in report.findings:
        assert finding.analyzer
        assert finding.analyzer_version == "1.0.0"
        assert finding.rule_id
        assert finding.rule_version
        assert finding.created_at


def test_unsupported_is_not_skipped_silence():
    report = analyze_bytes(b"import os\n", name="a.py")
    pe_runs = [item for item in report.analyzer_runs if item.analyzer_id == "pe"]
    assert pe_runs
    assert all(item.status == "unsupported" for item in pe_runs)
    assert all(item.skip_reason for item in pe_runs)
