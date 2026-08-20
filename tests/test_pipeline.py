from pathlib import Path
import zipfile

import pytest
from pypdf import PdfWriter
from PIL import Image

from exsoftware import analyze_bytes, analyze_path
from exsoftware.cli import render_text


def _ids(report) -> set[str]:
    keys: set[str] = set()
    for item in report.findings:
        keys.update({item.id, item.legacy_id or "", item.rule_id or ""})
    return {key for key in keys if key}


def test_python_script_imports_and_url():
    source = b"""import subprocess\nimport urllib.request\n\nsubprocess.run(['true'])\nurllib.request.urlopen('https://example.test/payload')\n"""
    report = analyze_bytes(source, name="fetch.py")
    assert report.identity.detected_type == "python"
    assert report.hashes["sha256"]
    assert "strings.urls" in _ids(report)
    assert any((item.legacy_id or item.rule_id) == "script.python-imports" or item.rule_id == "SCRIPT.PY.IMPORT.001" for item in report.findings)
    text = render_text(report)
    assert "What this is" in text
    assert "Python script" in text
    assert report.limits["executed"] is False


def test_extension_mismatch_zip(tmp_path: Path):
    path = tmp_path / "invoice.pdf"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../evil.txt", "nope")
        archive.writestr("ok.txt", "hello")
    report = analyze_path(path)
    ids = _ids(report)
    assert "identity.extension-mismatch" in ids
    assert "archive.path-traversal" in ids
    assert report.identity.detected_type == "zip"


def test_png_report(tmp_path: Path):
    path = tmp_path / "dot.png"
    Image.new("RGB", (8, 8), color=(12, 24, 36)).save(path)
    report = analyze_path(path)
    assert report.identity.detected_type == "png"
    assert any((item.legacy_id or "") == "image.identity" or item.rule_id == "IMG.FORMAT.001" for item in report.findings)


def test_pdf_metadata(tmp_path: Path):
    path = tmp_path / "doc.pdf"
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    writer.add_metadata({"/Author": "exsoftware-test", "/Title": "Fixture"})
    writer.write(path)
    report = analyze_path(path)
    assert report.identity.detected_type == "pdf"
    pdf = next(section for section in report.sections if section.name == "pdf")
    assert pdf.errors == []
    assert pdf.details.get("metadata")


def test_high_entropy_unknown():
    data = bytes((i * 37 + 11) % 256 for i in range(8192))
    report = analyze_bytes(data, name="blob.bin")
    assert report.identity.detected_type == "unknown"
    assert any((item.legacy_id or item.id).startswith("entropy.") or (item.rule_id or "").startswith("ENT.") for item in report.findings)


def test_analyzer_errors_are_visible(monkeypatch):
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
    hashes = next(section for section in report.sections if section.name == "hashes")
    assert hashes.errors
    assert hashes.errors[0].exception_type == "RuntimeError"
    assert "traceback" in hashes.details


@pytest.mark.skipif(not Path(r"C:\Windows\System32\notepad.exe").is_file(), reason="notepad.exe not present")
def test_notepad_pe():
    report = analyze_path(r"C:\Windows\System32\notepad.exe")
    assert report.identity.detected_type == "pe"
    pe = next(section for section in report.sections if section.name == "pe")
    assert pe.errors == []
    assert pe.details.get("imports")
    assert report.hashes["sha256"]
    assert any((item.legacy_id or "") == "pe.identity" or item.rule_id == "PE.FORMAT.001" for item in report.findings)


@pytest.mark.skipif(not Path(r"C:\Windows\System32\kernel32.dll").is_file(), reason="kernel32.dll not present")
def test_kernel32_dll():
    report = analyze_path(r"C:\Windows\System32\kernel32.dll")
    assert report.identity.detected_type == "pe"
    pe = next(section for section in report.sections if section.name == "pe")
    assert pe.details.get("is_dll") is True
    assert pe.details.get("export_count", 0) > 0
