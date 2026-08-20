"""Contained ZIP-family extraction tests.

Fixtures are built with zipfile in the test process. That is not parent-side
parsing of submitted archives.
"""

from __future__ import annotations

import io
import os
import struct
import time
import zlib
import zipfile
from pathlib import Path

from exsoftware import analyze_bytes
from exsoftware.isolate.container_protocol import validate_container_response
from exsoftware.isolate.container_runner import IsolatedContainerRunner
from exsoftware.isolate.validate import ProtocolError
from exsoftware.limits import RecursionLimits
from exsoftware.models import Report


def _zip_bytes(members: dict[str, bytes], *, compress=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compress) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buf.getvalue()


def _stored_zip(members: list[tuple[str, bytes, int]]) -> bytes:
    """Build a stored ZIP. *members* is (name, payload, general_purpose_flags)."""
    locals_blob = b""
    central = b""
    for name, payload, flags in members:
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        name_b = name.encode("utf-8")
        offset = len(locals_blob)
        locals_blob += struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            flags,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(name_b),
            0,
        )
        locals_blob += name_b + payload
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            flags,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(name_b),
            0,
            0,
            0,
            0,
            0,
            offset,
        )
        central += name_b
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members), len(central), len(locals_blob), 0)
    return locals_blob + central + eocd


def _zip_lying_uncompressed_size(name: str, payload: bytes, declared: int) -> bytes:
    """Stored ZIP whose central/local uncompressed-size field does not match the payload."""
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    name_b = name.encode("utf-8")
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0,
        0,
        0,
        0,
        crc,
        len(payload),
        declared & 0xFFFFFFFF,
        len(name_b),
        0,
    )
    local += name_b + payload
    cd = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0,
        0,
        0,
        0,
        crc,
        len(payload),
        declared & 0xFFFFFFFF,
        len(name_b),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    cd += name_b
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd), len(local), 0)
    return local + cd + eocd


def _extracted_names(report: Report) -> list[str]:
    names = []
    for rel in report.relationships:
        if rel.type == "CONTAINS" and rel.extra.get("extracted"):
            names.append(rel.extra.get("member_name"))
    return names


def test_parent_never_instantiates_zipfile_on_archives(monkeypatch):
    data = _zip_bytes({"a.py": b"print(1)\n", "b.txt": b"hi"})

    def boom(*args, **kwargs):
        raise AssertionError("trusted parent used zipfile.ZipFile on hostile bytes")

    monkeypatch.setattr(zipfile, "ZipFile", boom)
    report = analyze_bytes(data, name="sample.zip")
    assert "a.py" in _extracted_names(report)
    runs = [item for item in report.analyzer_runs if item.status == "completed"]
    assert runs
    for run in runs:
        iso = run.details.get("isolation") or {}
        if iso.get("mode") == "subprocess":
            assert iso.get("sandbox") is False


def test_nested_archive_parses_inside_containment(monkeypatch):
    inner = _zip_bytes({"payload.py": b"import os\n"})
    data = _zip_bytes({"inner.zip": inner})

    def boom(*args, **kwargs):
        raise AssertionError("trusted parent used zipfile.ZipFile")

    monkeypatch.setattr(zipfile, "ZipFile", boom)
    report = analyze_bytes(data, name="outer.zip")
    names = {name for artifact in report.artifacts for name in artifact.names}
    assert "inner.zip" in names
    assert "payload.py" in names
    child_runs = [
        item
        for item in report.analyzer_runs
        if item.artifact_id != report.root_artifact_id and item.status == "completed"
    ]
    assert child_runs
    for run in child_runs:
        iso = run.details.get("isolation") or {}
        if run.analyzer_id in {"hashes", "script", "identity"}:
            assert iso.get("mode") == "subprocess"


def test_path_traversal_creates_no_host_file(tmp_path: Path):
    sentinel = tmp_path / "evil.txt"
    data = _zip_bytes({"../../evil.txt": b"nope", "ok.txt": b"hello"})
    report = analyze_bytes(data, name="slip.zip")
    assert not sentinel.exists()
    extracted = _extracted_names(report)
    assert "ok.txt" in extracted
    assert "../../evil.txt" not in extracted
    assert any(item.rule_id == "ARC.TRAVERSAL.001" for item in report.findings)


def test_absolute_path_not_extracted():
    data = _zip_bytes(
        {
            r"C:\Windows\Temp\exsoftware-abs.txt": b"nope",
            "/tmp/exsoftware-abs.txt": b"nope",
            "ok.txt": b"hello",
        }
    )
    report = analyze_bytes(data, name="abs.zip")
    extracted = _extracted_names(report)
    assert extracted == ["ok.txt"]
    stubs = [item for item in report.artifacts if item.content_id is None]
    assert stubs


def test_duplicate_members_one_content_id():
    payload = b"print('same')\n"
    data = _zip_bytes({"a.py": payload, "nested/b.py": payload, "c.py": payload})
    report = analyze_bytes(data, name="dup.zip")
    py = [item for item in report.artifacts if any(n.endswith(".py") for n in item.names)]
    content_ids = {item.content_id for item in py if item.content_id}
    assert len(content_ids) == 1
    contains = [
        item for item in report.relationships if item.type == "CONTAINS" and item.target_id == next(iter(content_ids))
    ]
    assert len(contains) == 3


def test_encrypted_member_is_not_extracted():
    data = _stored_zip(
        [
            ("secret.txt", b"classified", 0x1),
            ("ok.txt", b"hello", 0),
        ]
    )
    report = analyze_bytes(data, name="enc.zip")
    extracted = _extracted_names(report)
    assert "ok.txt" in extracted
    assert "secret.txt" not in extracted
    stubs = [item for item in report.artifacts if "secret.txt" in item.names]
    assert stubs
    assert all(item.complete is False for item in stubs)
    assert any(item.rule_id == "ARC.ENCRYPTED.001" for item in report.findings)


def test_member_count_remaining_unprocessed():
    members = {f"f{i}.txt": b"x" for i in range(8)}
    data = _zip_bytes(members)
    report = analyze_bytes(data, name="many.zip", limits=RecursionLimits(max_member_count=3, max_blobs=3))
    extracted = [item for item in report.relationships if item.type == "CONTAINS" and item.extra.get("extracted")]
    assert len(extracted) == 3
    unprocessed = [
        item for item in report.relationships if item.type == "CONTAINS" and item.extra.get("reason") == "member-count"
    ]
    assert unprocessed
    assert any(item.rule_id == "REC.LIMIT.COUNT.001" for item in report.findings)


def test_zip_bomb_stops_on_actual_bytes():
    zeros = b"\x00" * (2 * 1024 * 1024)
    data = _zip_bytes({"zeros.bin": zeros})
    parent = os.getpid()
    report = analyze_bytes(
        data,
        name="bomb.zip",
        limits=RecursionLimits(max_compression_ratio=20, max_member_bytes=8 * 1024 * 1024),
    )
    assert os.getpid() == parent
    extracted = [item for item in report.relationships if item.type == "CONTAINS" and item.extra.get("extracted")]
    assert extracted == []
    assert any(item.rule_id == "REC.LIMIT.RATIO.001" for item in report.findings)


def test_workspace_budget_stops_extraction():
    data = _zip_bytes({"a.bin": b"a" * 80, "b.bin": b"b" * 80, "c.bin": b"c" * 80})
    report = analyze_bytes(
        data,
        name="budget.zip",
        limits=RecursionLimits(
            max_total_expanded_bytes=100,
            max_workspace_bytes=100,
            max_member_bytes=1000,
            max_compression_ratio=1000,
        ),
    )
    extracted = [item for item in report.relationships if item.type == "CONTAINS" and item.extra.get("extracted")]
    total = sum(int(item.extra.get("actual_size") or 0) for item in extracted)
    assert total <= 100
    assert any(item.rule_id in {"REC.LIMIT.BYTES.001", "REC.LIMIT.MEMBER.001"} for item in report.findings)


def test_oversized_member_not_extracted():
    data = _zip_bytes({"big.bin": b"a" * 5000, "ok.txt": b"x"})
    report = analyze_bytes(
        data,
        name="big.zip",
        limits=RecursionLimits(max_member_bytes=100, max_total_expanded_bytes=10_000, max_compression_ratio=1000),
    )
    extracted = _extracted_names(report)
    assert "ok.txt" in extracted
    assert "big.bin" not in extracted
    assert any(item.rule_id == "REC.LIMIT.MEMBER.001" for item in report.findings)


def test_lying_declared_size_does_not_bypass_actual_byte_cap():
    data = _zip_lying_uncompressed_size("lie.bin", b"A" * 5000, declared=10)
    parent = os.getpid()
    report = analyze_bytes(
        data,
        name="lie.zip",
        limits=RecursionLimits(max_member_bytes=100, max_compression_ratio=10_000, max_total_expanded_bytes=10_000),
    )
    assert os.getpid() == parent
    assert "lie.bin" not in _extracted_names(report)
    assert any(
        item.rule_id in {"REC.LIMIT.MEMBER.001", "ARC.PARSE.001", "REC.MEMBER.MALFORMED.001"}
        for item in report.findings
    )


def test_lying_huge_declared_size_does_not_invent_bytes():
    data = _zip_lying_uncompressed_size("ok.bin", b"hello", declared=2_000_000_000)
    report = analyze_bytes(
        data,
        name="huge-declared.zip",
        limits=RecursionLimits(max_member_bytes=1024, max_total_expanded_bytes=1024, max_compression_ratio=10_000),
    )
    extracted = [item for item in report.relationships if item.type == "CONTAINS" and item.extra.get("extracted")]
    if extracted:
        assert extracted[0].extra.get("actual_size") == 5
        assert extracted[0].extra.get("member_name") == "ok.bin"


def test_malformed_archive_parent_survives():
    parent = os.getpid()
    report = analyze_bytes(b"PK\x03\x04this is not a zip", name="broken.zip")
    assert os.getpid() == parent
    assert report.identity.detected_type == "zip"
    assert any(item.rule_id == "ARC.PARSE.001" for item in report.findings)
    assert [item for item in report.relationships if item.type == "CONTAINS"] == []


def test_container_parser_timeout():
    data = _zip_bytes({"a.txt": b"hi"})
    parent = os.getpid()
    started = time.perf_counter()
    result = IsolatedContainerRunner(RecursionLimits()).extract(
        data,
        artifact_id="sha256:test",
        timeout=1.0,
        test_hook="hang",
    )
    elapsed = time.perf_counter() - started
    assert os.getpid() == parent
    assert result.status == "timeout"
    assert elapsed < 20
    assert result.isolation.get("mode") == "subprocess"


def test_container_parser_abort():
    data = _zip_bytes({"a.txt": b"hi"})
    parent = os.getpid()
    result = IsolatedContainerRunner(RecursionLimits()).extract(
        data,
        artifact_id="sha256:test",
        timeout=20,
        test_hook="abort",
    )
    assert os.getpid() == parent
    assert result.status == "failed"
    assert result.members == []


def test_container_parent_hashes_blob_not_child_claim():
    data = _zip_bytes({"ok.txt": b"hello"})
    result = IsolatedContainerRunner(RecursionLimits()).extract(data, artifact_id="sha256:x", timeout=30)
    assert result.status == "completed"
    extracted = [item for item in result.members if item.extraction_status == "extracted"]
    assert extracted
    assert extracted[0].slot == "000001"
    assert extracted[0].blob is not None
    assert extracted[0].blob.data == b"hello"
    from hashlib import sha256

    assert extracted[0].blob.hashes["sha256"] == sha256(b"hello").hexdigest()


def test_manifest_host_path_is_not_opened():
    payload = {
        "protocol": "exsoftware.container",
        "protocol_version": 1,
        "operation": "extract",
        "container_artifact_id": "sha256:x",
        "status": "completed",
        "zip_subtype": "zip",
        "members": [
            {
                "index": 1,
                "original_name": r"C:\Users\secret.txt",
                "extraction_status": "extracted",
                "slot": "000001",
                "path": r"C:\Users\secret.txt",
                "declared_size": 12,
                "compressed_size": 12,
            }
        ],
    }
    cleaned = validate_container_response(payload, artifact_id="sha256:x", max_members=8)
    member = cleaned["members"][0]
    assert member["slot"] == "000001"
    assert "path" not in member
    assert member["original_name"] == r"C:\Users\secret.txt"


def test_manifest_rejects_nonsequential_slot():
    payload = {
        "protocol": "exsoftware.container",
        "protocol_version": 1,
        "operation": "extract",
        "container_artifact_id": "sha256:x",
        "status": "completed",
        "members": [
            {
                "index": 1,
                "original_name": "ok.txt",
                "extraction_status": "extracted",
                "slot": "000007",
                "declared_size": 1,
                "compressed_size": 1,
            }
        ],
    }
    try:
        validate_container_response(payload, artifact_id="sha256:x", max_members=8)
        raise AssertionError("expected ProtocolError")
    except ProtocolError:
        pass


def test_jar_identity_without_exploding_contents():
    data = _zip_bytes(
        {
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
            "com/example/App.class": b"\xca\xfe\xba\xbe" + b"\x00" * 32,
        }
    )
    report = analyze_bytes(data, name="app.jar", limits=RecursionLimits(enable_recursion=False))
    assert report.identity.detected_type == "jar"
    assert [item for item in report.relationships if item.type == "EXTRACTED_FROM"] == []
