from pathlib import Path

from exsoftware import analyze_bytes
from exsoftware.api import STATIC_DIR


def test_analyze_payload_includes_graph_arrays_and_composition_refs():
    source = b"import subprocess\nsubprocess.run(['true'])\n# https://example.test/x\n"
    report = analyze_bytes(source, name="tool.py")
    payload = report.to_dict()
    assert payload["artifacts"]
    assert payload["relationships"]
    assert payload["observations"]
    assert payload["evidence"]
    assert payload["composition"]
    assert payload["composition"]["identity"]["trust_verified"] is False
    caps = payload["composition"]["capabilities"]
    assert caps
    assert "refs" in caps[0]
    important = payload["composition"]["important_observations"]
    assert isinstance(important, list)
    if important:
        assert "refs" in important[0]
    gaps = payload["composition"]["gaps"]
    assert gaps
    assert "refs" in gaps[0]
    deps = payload["composition"]["dependencies"]
    assert deps
    assert deps[0]["relationship_type"] == "IMPORTS"


def test_ui_js_indexes_the_same_graph_keys_the_api_emits():
    js = Path(STATIC_DIR / "app.js").read_text(encoding="utf-8")
    for key in ("artifacts", "relationships", "observations", "evidence", "findings"):
        assert f"{key}:" in js or f"report.{key}" in js
    assert "SIGNED_BY" in js or "crypto_valid" in js
    assert "trust_verified" in js
