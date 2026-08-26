"""Architecture tests for the trusted-core separation.

These prove security properties of the parent process, not merely that a
particular helper was called.
"""

from __future__ import annotations

import ast
import inspect
import struct
import subprocess
import sys

import olefile

from exsoftware import analyze_bytes
from exsoftware.analyzers.eligibility import is_eligible
from exsoftware.analyzers.registry import ANALYZER_REGISTRY, get_spec
from exsoftware.identify import identify_bytes, refine_ole_type_from_streams
from exsoftware.isolate.ole_runner import IsolatedOleRunner


IMPLEMENTATION_MODULES = frozenset(
    {
        "exsoftware.analyzers.identity",
        "exsoftware.analyzers.filesystem",
        "exsoftware.analyzers.hashes",
        "exsoftware.analyzers.entropy",
        "exsoftware.analyzers.strings",
        "exsoftware.analyzers.pe",
        "exsoftware.analyzers.elf",
        "exsoftware.analyzers.macho",
        "exsoftware.analyzers.lnk",
        "exsoftware.analyzers.archive",
        "exsoftware.analyzers.pdf",
        "exsoftware.analyzers.image",
        "exsoftware.analyzers.ole",
        "exsoftware.analyzers.script",
        "exsoftware.analyzers.signature",
        "exsoftware.analyzers.embedded",
    }
)

ALLOWED_ANALYZER_PACKAGE_MODULES = frozenset(
    {
        "exsoftware.analyzers",
        "exsoftware.analyzers.base",
        "exsoftware.analyzers.eligibility",
        "exsoftware.analyzers.registry",
        "exsoftware.analyzers.loader",
    }
)


def _build_ole(streams: dict[str, bytes]) -> bytes:
    """Minimal CFB for tests. Built in the test process, not by the engine parent path."""
    ENDOFCHAIN = 0xFFFFFFFE
    FATSECT = 0xFFFFFFFD
    FREESECT = 0xFFFFFFFF
    sector_size = 512
    names = list(streams.keys())
    payloads = [streams[n] for n in names]
    data_sectors = []
    stream_sector_ids = []
    for payload in payloads:
        stream_sector_ids.append(len(data_sectors))
        data_sectors.append(payload.ljust(sector_size, b"\x00")[:sector_size])
    fat_sector_id = len(data_sectors)
    dir_count = 1 + len(names)
    dir_sector_count = max(1, (dir_count * 128 + sector_size - 1) // sector_size)
    dir_start = fat_sector_id + 1
    fat = [ENDOFCHAIN] * len(data_sectors) + [FATSECT]
    for i in range(dir_sector_count):
        fat.append(ENDOFCHAIN if i == dir_sector_count - 1 else dir_start + i + 1)
    while len(fat) < sector_size // 4:
        fat.append(FREESECT)
    fat_bytes = b"".join(struct.pack("<I", x) for x in fat[: sector_size // 4])

    def dirent(name: str, obj_type: int, child=0xFFFFFFFF, start=0, size=0, left=0xFFFFFFFF, right=0xFFFFFFFF) -> bytes:
        encoded = name.encode("utf-16le") + b"\x00\x00"
        name_buf = encoded.ljust(64, b"\x00")[:64]
        return (
            name_buf
            + struct.pack("<H", len(name.encode("utf-16le")) + 2)
            + struct.pack("<B", obj_type)
            + struct.pack("<B", 1)
            + struct.pack("<III", left, right, child)
            + b"\x00" * 16
            + struct.pack("<I", 0)
            + b"\x00" * 16
            + struct.pack("<I", start)
            + struct.pack("<Q", size)
        )

    dirents = [dirent("Root Entry", 5, child=1 if names else 0xFFFFFFFF, start=ENDOFCHAIN)]
    for i, name in enumerate(names):
        right = (i + 2) if i + 1 < len(names) else 0xFFFFFFFF
        dirents.append(dirent(name, 2, start=stream_sector_ids[i], size=len(payloads[i]), right=right))
    dir_blob = b"".join(dirents).ljust(dir_sector_count * sector_size, b"\x00")
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", header, 0x18, 0x003E)
    struct.pack_into("<H", header, 0x1A, 0x0003)
    struct.pack_into("<H", header, 0x1C, 0xFFFE)
    struct.pack_into("<H", header, 0x1E, 9)
    struct.pack_into("<H", header, 0x20, 6)
    struct.pack_into("<I", header, 0x2C, 1)
    struct.pack_into("<I", header, 0x30, dir_start)
    struct.pack_into("<I", header, 0x38, 4096)
    struct.pack_into("<I", header, 0x3C, ENDOFCHAIN)
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)
    struct.pack_into("<I", header, 0x4C, fat_sector_id)
    for i in range(1, 109):
        struct.pack_into("<I", header, 0x4C + 4 * i, FREESECT)
    out = bytes(header) + b"".join(data_sectors) + fat_bytes + dir_blob
    assert olefile.isOleFile(out)
    return out


def test_trusted_engine_import_does_not_load_analyzer_implementations():
    code = r"""
import sys
import exsoftware
import exsoftware.pipeline
import exsoftware.identify
allowed = {
    "exsoftware.analyzers",
    "exsoftware.analyzers.base",
    "exsoftware.analyzers.eligibility",
    "exsoftware.analyzers.registry",
    "exsoftware.analyzers.loader",
}
loaded = {m for m in sys.modules if m.startswith("exsoftware.analyzers")}
bad = sorted(loaded - allowed)
assert not bad, bad
assert "olefile" not in sys.modules
print("ok")
"""
    import os

    env = os.environ.copy()
    env.pop("EXSOFTWARE_ISOLATE_TEST", None)
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert "ok" in result.stdout


def test_identify_source_does_not_import_olefile():
    import exsoftware.identify as identify

    source = inspect.getsource(identify)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] != "olefile"
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] != "olefile"
    assert "olefile.OleFileIO" not in source
    assert "import olefile" not in source


def test_parent_analyze_does_not_import_olefile_or_analyzer_impls(monkeypatch):
    doc = _build_ole({"WordDocument": b"fixture-doc" * 8})
    # Remove any prior imports from this process so the guard is meaningful.
    for name in list(sys.modules):
        if name == "olefile" or name.startswith("olefile.") or name in IMPLEMENTATION_MODULES:
            sys.modules.pop(name, None)

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

    def guarded(name, globals=None, locals=None, fromlist=(), level=0):
        root = name.split(".")[0]
        if root == "olefile":
            raise AssertionError("trusted parent imported olefile")
        if name in IMPLEMENTATION_MODULES or (
            name.startswith("exsoftware.analyzers.") and name not in ALLOWED_ANALYZER_PACKAGE_MODULES
        ):
            # fromlist-style relative imports use package-relative names; only block absolute impls.
            if name.startswith("exsoftware.analyzers."):
                raise AssertionError(f"trusted parent imported analyzer implementation {name}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr("builtins.__import__", guarded)
    report = analyze_bytes(doc, name="memo.doc")
    assert report.identity.detected_type == "doc"
    assert report.identity.extra.get("ole_refinement", {}).get("status") == "completed"
    assert report.identity.extra.get("ole_refinement", {}).get("fallback") is not True
    for name in IMPLEMENTATION_MODULES:
        assert name not in sys.modules
    assert "olefile" not in sys.modules


def test_eligibility_from_registry_matches_expected_analyzers():
    from types import SimpleNamespace

    pe_id = SimpleNamespace(detected_type="pe", detected_family="executable")
    py_id = SimpleNamespace(detected_type="python", detected_family="script")
    pe_eligible = {spec.name for spec in ANALYZER_REGISTRY if is_eligible(spec, pe_id)}
    py_eligible = {spec.name for spec in ANALYZER_REGISTRY if is_eligible(spec, py_id)}
    assert "pe" in pe_eligible
    assert "signature" in pe_eligible
    assert "pdf" not in pe_eligible
    assert "script" in py_eligible
    assert "pe" not in py_eligible
    always = {"identity", "filesystem", "hashes", "entropy", "strings", "embedded"}
    assert always <= pe_eligible
    assert always <= py_eligible


def test_worker_loads_implementation_only_when_resolving():
    code = r"""
import sys
from exsoftware.analyzers.loader import load_analyzer_by_id
assert "exsoftware.analyzers.pe" not in sys.modules
cls = load_analyzer_by_id("pe")
assert cls is not None
assert cls.name == "pe"
assert "exsoftware.analyzers.pe" in sys.modules
assert "exsoftware.analyzers.pdf" not in sys.modules
print("ok")
"""
    result = subprocess.run([sys.executable, "-c", code], check=True, capture_output=True, text=True)
    assert "ok" in result.stdout


def test_ole_magic_leaves_subtype_pending_without_olefile():
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    for name in list(sys.modules):
        if name == "olefile" or name.startswith("olefile."):
            sys.modules.pop(name, None)
    ident = identify_bytes(data, "blob.bin")
    assert ident.detected_type == "ole"
    assert ident.extra.get("ole_subtype_pending") is True
    assert "olefile" not in sys.modules


def test_ole_refinement_through_containment_classifies_doc():
    doc = _build_ole({"WordDocument": b"fixture-doc" * 8})
    report = analyze_bytes(doc, name="memo.doc")
    assert report.identity.detected_type == "doc"
    assert report.identity.detected_family == "document"
    ole_runs = [item for item in report.analyzer_runs if item.analyzer_id == "ole"]
    assert ole_runs
    assert ole_runs[0].status == "completed"
    assert report.limits["isolation"]["ole_protocol"] == "exsoftware.ole"


def test_ole_refinement_classifies_xls_and_msi():
    xls = _build_ole({"Workbook": b"sheet" * 10})
    msi = _build_ole({"_StringData": b"a" * 20, "_Tables": b"b" * 20})
    assert analyze_bytes(xls, name="book.xls").identity.detected_type == "xls"
    assert analyze_bytes(msi, name="setup.msi").identity.detected_type == "msi"


def test_ole_worker_failure_is_honest_without_parent_fallback(monkeypatch):
    doc = _build_ole({"WordDocument": b"fixture-doc" * 8})

    def boom(*args, **kwargs):
        from exsoftware.isolate.ole_runner import OleRefineResult

        return OleRefineResult(
            status="failed",
            reason="spawn_failed",
            is_ole=False,
            message="forced failure",
            isolation={"mode": "subprocess", "sandbox": False},
        )

    monkeypatch.setattr(IsolatedOleRunner, "refine", boom)
    report = analyze_bytes(doc, name="memo.doc")
    assert report.identity.detected_type == "ole"
    refinement = report.identity.extra.get("ole_refinement") or {}
    assert refinement.get("status") == "failed"
    assert refinement.get("fallback") is False
    assert refinement.get("reason") == "spawn_failed"


def test_refine_ole_type_from_streams_is_parent_side_string_logic():
    assert refine_ole_type_from_streams(["/WordDocument"])[0] == "doc"
    assert refine_ole_type_from_streams(["/Workbook"])[0] == "xls"
    assert refine_ole_type_from_streams(["/_StringData"])[0] == "msi"
    assert refine_ole_type_from_streams([])[0] == "ole"


def test_registry_covers_historical_analyzer_ids():
    names = [spec.name for spec in ANALYZER_REGISTRY]
    assert names == [
        "identity",
        "filesystem",
        "hashes",
        "entropy",
        "strings",
        "pe",
        "elf",
        "macho",
        "lnk",
        "archive",
        "pdf",
        "image",
        "ole",
        "script",
        "signature",
        "embedded",
    ]
    pe = get_spec("pe")
    assert pe is not None
    assert pe.worker_module == "exsoftware.analyzers.pe"
    assert pe.worker_class == "PEAnalyzer"


def test_existing_python_analysis_still_compatible():
    source = b"import subprocess\nsubprocess.run(['true'])\n# https://example.test/x\n"
    report = analyze_bytes(source, name="tool.py")
    assert report.schema_version == 1
    assert report.identity.detected_type == "python"
    assert report.root_artifact_id.startswith("sha256:")
    assert any(item.analyzer_id == "script" and item.status == "completed" for item in report.analyzer_runs)
    assert any(item.status == "unsupported" and item.analyzer_id == "pe" for item in report.analyzer_runs)


def test_ole_refine_rejects_input_size_mismatch(tmp_path):
    from exsoftware.content import sha256_hex
    from exsoftware.isolate.ole_refine import run_refine

    data = _build_ole({"WordDocument": b"fixture-doc" * 8})
    (tmp_path / "input.bin").write_bytes(data)
    request = {
        "input": {
            "kind": "file",
            "path": "input.bin",
            "sha256": sha256_hex(data),
            "size": len(data) + 1,
        }
    }
    body = run_refine(request, tmp_path)
    assert body["status"] == "failed"
    assert body["is_ole"] is False
    assert body["streams"] == []
    assert body["errors"][0]["code"] == "input_size_mismatch"


def test_ole_refine_rejects_input_hash_mismatch(tmp_path):
    from exsoftware.isolate.ole_refine import run_refine

    data = _build_ole({"WordDocument": b"fixture-doc" * 8})
    (tmp_path / "input.bin").write_bytes(data)
    request = {
        "input": {
            "kind": "file",
            "path": "input.bin",
            "sha256": "0" * 64,
            "size": len(data),
        }
    }
    body = run_refine(request, tmp_path)
    assert body["status"] == "failed"
    assert body["is_ole"] is False
    assert body["streams"] == []
    assert body["errors"][0]["code"] == "input_hash_mismatch"


def test_registry_matches_analyzer_implementation_metadata():
    """Maintenance check: registry must not drift from implementation classes.

    This test intentionally imports analyzer implementations. Trusted-parent
    execution still must not.
    """
    from exsoftware.analyzers.loader import load_analyzer_class
    from exsoftware.analyzers.registry import all_specs

    for spec in all_specs():
        cls = load_analyzer_class(spec)
        assert cls.name == spec.name, spec.name
        assert getattr(cls, "version", "1.0.0") == spec.version, spec.name
        assert getattr(cls, "title", cls.name) == spec.title, spec.name
        assert getattr(cls, "detected_types", None) == spec.detected_types, spec.name
        assert getattr(cls, "detected_families", None) == spec.detected_families, spec.name
        assert getattr(cls, "timeout_seconds", None) == spec.timeout_seconds, spec.name
        assert cls.__module__ == spec.worker_module, spec.name
        assert cls.__name__ == spec.worker_class, spec.name
