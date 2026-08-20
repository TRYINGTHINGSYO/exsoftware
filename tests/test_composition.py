from __future__ import annotations

import io
import zipfile

from exsoftware import analyze_bytes
from exsoftware.cli import render_text
from exsoftware.models import Report


def test_python_composition_golden():
    source = b"import subprocess\nimport json\nimport requests\nsubprocess.run(['true'])\n"
    report = analyze_bytes(source, name="simple_python.py")
    comp = report.composition
    assert comp is not None
    assert comp["identity"]["category"] == "python_script"
    assert comp["identity"]["sha256"]
    assert any(item["id"] == "CAP.PROCESS.PY_SUBPROCESS.001" for item in comp["capabilities"])
    subprocess_cap = next(item for item in comp["capabilities"] if item["id"] == "CAP.PROCESS.PY_SUBPROCESS.001")
    assert "not" in subprocess_cap["not_established"].lower()
    assert "runtime" in subprocess_cap["not_established"].lower()
    names = {item["name"] for item in comp["dependencies"]}
    assert "subprocess" in names
    assert "json" in names
    groups = {item["name"]: item["group"] for item in comp["dependencies"]}
    assert groups["subprocess"] == "language_runtime"
    assert groups.get("requests") == "application"
    assert any(item["id"] == "GAP.RUNTIME.NOT_OBSERVED.001" for item in comp["gaps"])
    assert comp["completeness"]["executed"] is False
    text = render_text(report)
    assert "What this is" in text
    assert "Python script" in text
    assert "Not established" in text


def test_nested_zip_composition_tree():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("payload.py", b"import os\n")
        archive.writestr("readme.txt", b"hello")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("inner.zip", inner.getvalue())
        archive.writestr("ok.txt", b"x")
    report = analyze_bytes(outer.getvalue(), name="nested_package.zip")
    comp = report.composition
    assert comp["identity"]["category"] == "zip_software_bundle"
    roles = comp["stats"]["by_role"]
    assert roles.get("archive") or roles.get("script") or roles.get("configuration")
    labels = _flatten_labels(comp["component_tree"])
    assert any("inner.zip" in label for label in labels)
    assert any("payload.py" in label for label in labels)
    notable = " ".join(item["label"] for item in comp["notable_components"])
    assert "payload.py" in notable or "inner.zip" in notable
    archive_runs = [
        item
        for item in report.analyzer_runs
        if item.analyzer_id == "archive" and item.artifact_id == report.root_artifact_id
    ]
    assert archive_runs
    assert archive_runs[0].status == "skipped"


def test_extension_mismatch_is_important():
    data = b"import os\n"
    report = analyze_bytes(data, name="cute-cat.jpg")
    ids = {item["id"] for item in report.composition["important_observations"]}
    assert "IMP.ID.EXT_MISMATCH.001" in ids
    assert report.composition["identity"]["extension_agrees"] is False


def test_duplicate_components_counted_once():
    payload = b"print('same')\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("a.py", payload)
        archive.writestr("nested/b.py", payload)
        archive.writestr("c.py", payload)
    report = analyze_bytes(buf.getvalue(), name="dup.zip")
    stats = report.composition["stats"]
    assert stats["duplicate_occurrences"] >= 2
    assert stats["unique_content_artifacts"] >= 1
    py = [item for item in report.artifacts if item.content_id and any(n.endswith(".py") for n in item.names)]
    assert len({item.content_id for item in py}) == 1


def test_encrypted_member_is_a_gap():
    import struct
    import zlib

    def stored_zip(members):
        locals_blob = b""
        central = b""
        for name, payload, flags in members:
            crc = zlib.crc32(payload) & 0xFFFFFFFF
            name_b = name.encode("utf-8")
            offset = len(locals_blob)
            locals_blob += struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50, 20, flags, 0, 0, 0, crc, len(payload), len(payload), len(name_b), 0,
            )
            locals_blob += name_b + payload
            central += struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50, 20, 20, flags, 0, 0, 0, crc, len(payload), len(payload), len(name_b), 0, 0, 0, 0, 0, offset,
            )
            central += name_b
        eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members), len(central), len(locals_blob), 0)
        return locals_blob + central + eocd

    data = stored_zip([("secret.txt", b"classified", 0x1), ("ok.txt", b"hello", 0)])
    report = analyze_bytes(data, name="enc.zip")
    assert report.composition["completeness"]["encrypted_members"] >= 1
    assert any(item["kind"] == "encrypted" for item in report.composition["gaps"])
    assert any(item["id"] == "IMP.MEMBER.ENCRYPTED.001" for item in report.composition["important_observations"])
    assert report.composition["completeness"]["state"] in {"partial", "significantly_incomplete"}


def test_unknown_binary_is_explained():
    report = analyze_bytes(bytes(range(32)), name="blob.dat")
    ident = report.composition["identity"]
    assert ident["category"] == "unknown_binary"
    assert ident["sha256"]
    assert any(item["id"] == "GAP.TYPE.UNKNOWN.001" for item in report.composition["gaps"])
    text = render_text(report)
    assert "Unknown binary" in text


def test_capability_has_evidence_refs():
    source = b"import subprocess\nsubprocess.run(['true'])\n"
    report = analyze_bytes(source, name="proc.py")
    cap = next(item for item in report.composition["capabilities"] if item["id"] == "CAP.PROCESS.PY_SUBPROCESS.001")
    refs = cap["refs"]
    assert refs["artifact_ids"]
    assert refs["relationship_ids"]
    rel_ids = {item.id for item in report.relationships}
    assert refs["relationship_ids"][0] in rel_ids
    assert refs["finding_ids"] or refs["evidence_ids"]
    finding_ids = {item.id for item in report.findings}
    assert all(fid in finding_ids for fid in refs["finding_ids"])


def test_json_exposes_composition_without_breaking_schema():
    report = analyze_bytes(b"print(1)\n", name="a.py")
    payload = report.to_dict()
    assert payload["schema_version"] == 1
    assert "composition" in payload
    assert payload["composition"]["version"] == 1
    restored = Report.from_dict(payload)
    assert restored.composition["identity"]["category"] == "python_script"


def test_composition_is_cheap_relative_to_analysis():
    import time

    source = b"import json\nprint(1)\n"
    started = time.perf_counter()
    report = analyze_bytes(source, name="cheap.py")
    analysis_ms = (time.perf_counter() - started) * 1000
    from exsoftware.composition import compose

    started = time.perf_counter()
    compose(report)
    compose_ms = (time.perf_counter() - started) * 1000
    assert compose_ms < 250
    assert compose_ms < analysis_ms


def _flatten_labels(nodes: list[dict]) -> list[str]:
    out = []
    for node in nodes:
        out.append(node.get("label") or "")
        out.extend(_flatten_labels(node.get("children") or []))
    return out
