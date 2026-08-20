from exsoftware import analyze_bytes
from exsoftware.analyzers.hashes import HashAnalyzer
from exsoftware.analyzers.pe import PEAnalyzer


def test_parent_does_not_call_analyzer_owned_applies(monkeypatch):
    def boom(self, ctx):
        raise AssertionError("analyzer-owned applies() executed in the trusted parent")

    monkeypatch.setattr(HashAnalyzer, "applies", boom)
    monkeypatch.setattr(PEAnalyzer, "applies", boom)
    report = analyze_bytes(b"print('x')\n", name="a.py")
    hashes = next(item for item in report.analyzer_runs if item.analyzer_id == "hashes")
    assert hashes.status == "completed"
    pe = next(item for item in report.analyzer_runs if item.analyzer_id == "pe")
    assert pe.status == "unsupported"
    assert pe.details.get("isolation", {}).get("mode") == "not-started"
