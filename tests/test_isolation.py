from __future__ import annotations

import io
import json
import os
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from exsoftware import analyze_bytes
from exsoftware.analyzers.hashes import HashAnalyzer
from exsoftware.analyzers.identity import IdentityAnalyzer
from exsoftware.content import content_id_from_bytes
from exsoftware.context import load_from_bytes
from exsoftware.isolate.process import pid_alive
from exsoftware.isolate.protocol import PROTOCOL_NAME, PROTOCOL_VERSION
from exsoftware.isolate.runner import IsolatedAnalyzerRunner
from exsoftware.isolate.test_analyzers import (
    IsolateExitAnalyzer,
    IsolateHangAnalyzer,
    IsolateInvalidJsonAnalyzer,
    IsolateOversizedAnalyzer,
    IsolateRaiseAnalyzer,
    IsolateSegfaultAnalyzer,
    IsolateSpawnHangAnalyzer,
    IsolateWrongProtocolAnalyzer,
)
from exsoftware.isolate.validate import ProtocolError, validate_response
from exsoftware.limits import RecursionLimits
from exsoftware.models import ANALYZER_STATUSES, Report


def _ctx(data: bytes = b"hello isolation", name: str = "fixture.bin", extra=None):
    ctx = load_from_bytes(data, name=name, extra=extra)
    ctx.artifact_id = content_id_from_bytes(ctx.data)
    return ctx


def _runner(**kwargs) -> IsolatedAnalyzerRunner:
    return IsolatedAnalyzerRunner(RecursionLimits(**kwargs))


def test_isolated_success_matches_in_process():
    ctx = _ctx(b"print('ok')\n")
    in_proc = HashAnalyzer().analyze(ctx)
    isolated = _runner().run(HashAnalyzer(), ctx, timeout=30)
    assert isolated.status == "completed"
    assert isolated.details["hashes"] == in_proc.details["hashes"]
    assert isolated.analyzer_version == HashAnalyzer.version
    assert isolated.details["isolation"]["mode"] == "subprocess"
    assert isolated.details["isolation"]["sandbox"] is False
    assert isolated.details["isolation"].get("workdir_removed") is True
    workdir = isolated.details["isolation"].get("workdir")
    if workdir:
        assert not Path(workdir).exists()


def test_isolated_identity_preserves_type():
    ctx = _ctx(b"import os\n", name="tool.py")
    isolated = _runner().run(IdentityAnalyzer(), ctx, timeout=30)
    in_proc = IdentityAnalyzer().analyze(ctx)
    assert isolated.status == "completed"
    assert isolated.details["detected_type"] == in_proc.details["detected_type"]


def test_parent_survives_child_exception():
    parent = os.getpid()
    result = _runner().run(IsolateRaiseAnalyzer(), _ctx(), timeout=30)
    assert os.getpid() == parent
    assert result.status == "failed"
    assert result.details.get("reason") == "exception"
    assert any("synthetic analyzer exception" in err.message for err in result.errors)
    assert result.details["isolation"]["mode"] == "subprocess"


def test_parent_survives_sys_exit():
    parent = os.getpid()
    result = _runner().run(IsolateExitAnalyzer(), _ctx(), timeout=30)
    assert os.getpid() == parent
    assert result.status == "failed"
    assert result.details.get("reason") in {"child_exited", "child_crashed"}
    assert result.details.get("returncode") not in {None, 0}


def test_hard_timeout_kills_hang():
    parent = os.getpid()
    started = time.perf_counter()
    result = _runner().run(IsolateHangAnalyzer(), _ctx(), timeout=1.0)
    elapsed = time.perf_counter() - started
    assert os.getpid() == parent
    assert result.status == "timeout"
    assert result.details.get("reason") == "timeout"
    assert result.details.get("result") == "not analyzed"
    assert result.details.get("timeout_seconds") == 1.0
    assert elapsed < 20
    assert result.errors
    text = json.dumps(result.to_dict())
    assert "timeout" in text
    assert "No suspicious findings" not in text


def test_invalid_json_is_rejected():
    result = _runner().run(IsolateInvalidJsonAnalyzer(), _ctx(), timeout=30)
    assert result.status == "failed"
    assert result.details.get("reason") == "invalid_analyzer_response"


def test_wrong_protocol_is_rejected():
    result = _runner().run(IsolateWrongProtocolAnalyzer(), _ctx(), timeout=30)
    assert result.status == "failed"
    assert result.details.get("reason") == "invalid_analyzer_response"


def test_oversized_response_is_rejected():
    result = _runner(max_result_bytes=4096).run(IsolateOversizedAnalyzer(), _ctx(), timeout=30)
    assert result.status == "failed"
    assert result.details.get("reason") == "oversized_analyzer_response"
    assert result.details.get("response_bytes", 0) > 4096


def test_native_crash_is_contained():
    parent = os.getpid()
    result = _runner().run(IsolateSegfaultAnalyzer(), _ctx(), timeout=30)
    assert os.getpid() == parent
    assert result.status == "failed"
    assert result.details.get("reason") in {"child_crashed", "child_exited"}


def test_spawned_child_is_killed_on_timeout(tmp_path: Path):
    pid_file = tmp_path / "grandchild.pid"
    ctx = _ctx(extra={"pid_file": str(pid_file)})
    result = _runner().run(IsolateSpawnHangAnalyzer(), ctx, timeout=1.5)
    caps = (result.details.get("isolation") or {}).get("capabilities") or {}
    if result.status == "completed" and result.details.get("spawned") is False:
        assert caps.get("process_creation") in {"enforced", "degraded"}
        return
    assert result.status == "timeout"
    deadline = time.time() + 8
    alive = True
    while time.time() < deadline:
        if not pid_file.is_file():
            alive = False
            break
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
        except ValueError:
            alive = False
            break
        if not pid_alive(pid):
            alive = False
            break
        time.sleep(0.1)
    assert alive is False


def test_temp_dir_cleaned_after_failure():
    result = _runner().run(IsolateRaiseAnalyzer(), _ctx(), timeout=30)
    workdir = result.details["isolation"].get("workdir")
    assert result.details["isolation"].get("workdir_removed") is True
    assert workdir
    assert not Path(workdir).exists()


def test_temp_dir_cleaned_after_timeout():
    result = _runner().run(IsolateHangAnalyzer(), _ctx(), timeout=1.0)
    workdir = result.details["isolation"].get("workdir")
    assert result.details["isolation"].get("workdir_removed") is True
    assert workdir
    assert not Path(workdir).exists()


def test_validate_rejects_graph_injection():
    payload = {
        "protocol": PROTOCOL_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer_id": "hashes",
        "analyzer_version": "1.0.0",
        "status": "completed",
        "result": {
            "name": "hashes",
            "title": "Hashes",
            "applies": True,
            "status": "completed",
            "analyzer_version": "1.0.0",
            "findings": [],
            "artifacts": [{"id": "sha256:deadbeef"}],
        },
    }
    with pytest.raises(ProtocolError):
        validate_response(payload, analyzer_id="hashes", analyzer_version="1.0.0", artifact_id="sha256:abc")


def test_validate_rejects_foreign_artifact_id():
    payload = {
        "protocol": PROTOCOL_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer_id": "hashes",
        "analyzer_version": "1.0.0",
        "status": "completed",
        "result": {
            "name": "hashes",
            "title": "Hashes",
            "applies": True,
            "status": "completed",
            "analyzer_version": "1.0.0",
            "artifact_id": "sha256:someone-else",
            "findings": [],
        },
    }
    with pytest.raises(ProtocolError):
        validate_response(
            payload,
            analyzer_id="hashes",
            analyzer_version="1.0.0",
            artifact_id="sha256:abc",
        )


def test_pipeline_uses_subprocess_isolation():
    report = analyze_bytes(b"print('hello')\n", name="hello.py")
    assert report.limits["sandbox"] is False
    assert report.limits["isolation"]["analyzers"] == "subprocess"
    assert report.schema_version == 1
    hashes = next(run for run in report.analyzer_runs if run.analyzer_id == "hashes")
    assert hashes.status == "completed"
    assert hashes.details["isolation"]["mode"] == "subprocess"
    pe = next(run for run in report.analyzer_runs if run.analyzer_id == "pe")
    assert pe.status == "unsupported"
    assert pe.details["isolation"]["mode"] == "not-started"


def test_recursive_zip_children_use_isolated_path():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("payload.py", b"import subprocess\n")
    report = analyze_bytes(buf.getvalue(), name="sample.zip")
    child = next(item for item in report.artifacts if "payload.py" in item.names)
    child_runs = [item for item in report.analyzer_runs if item.artifact_id == child.id]
    assert child_runs
    started = [item for item in child_runs if item.status not in {"unsupported", "skipped"}]
    assert started
    for run in started:
        assert run.details.get("isolation", {}).get("mode") == "subprocess"
    script = next(item for item in child_runs if item.analyzer_id == "script")
    assert script.status == "completed"
    assert script.analyzer_version


def test_timeout_serializes_in_report():
    # Hang is per-analyzer; inject via isolated runner into a tiny report path
    result = _runner().run(IsolateHangAnalyzer(), _ctx(), timeout=1.0)
    assert result.status == "timeout"
    payload = result.to_dict()
    assert payload["status"] == "timeout"
    restored = Report.from_dict(
        {
            "schema_version": 1,
            "identity": {
                "name": "x",
                "path": None,
                "source": "bytes",
                "extension": "",
                "size": 1,
                "detected_type": "unknown",
                "detected_family": "unknown",
                "detected_mime": "application/octet-stream",
                "description": "unknown",
                "extension_matches": None,
                "magic_offset": 0,
                "magic_hex": "",
            },
            "overview": "",
            "next_steps": [],
            "hashes": {},
            "findings": [],
            "analyzers": [payload],
            "analyzer_runs": [
                {
                    "id": "run-0001",
                    "analyzer_id": result.name,
                    "analyzer_version": result.analyzer_version,
                    "title": result.title,
                    "artifact_id": "sha256:00",
                    "status": "timeout",
                    "details": result.details,
                    "errors": [err.to_dict() for err in result.errors],
                }
            ],
            "limits": {},
        }
    )
    assert restored.analyzer_runs[0].status == "timeout"


def test_concurrent_analyses_do_not_mix_results():
    py_src = b"import os\n"
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as archive:
        archive.writestr("inner.txt", b"hello zip")
    zip_src = zip_buf.getvalue()

    def run_py():
        return analyze_bytes(py_src, name="one.py")

    def run_zip():
        return analyze_bytes(zip_src, name="one.zip")

    with ThreadPoolExecutor(max_workers=2) as pool:
        py_fut = pool.submit(run_py)
        zip_fut = pool.submit(run_zip)
        py_report = py_fut.result()
        zip_report = zip_fut.result()

    assert py_report.identity.detected_type == "python"
    assert zip_report.identity.detected_type == "zip"
    assert py_report.root_artifact_id != zip_report.root_artifact_id
    py_hashes = next(item for item in py_report.sections if item.name == "hashes")
    zip_hashes = next(item for item in zip_report.sections if item.name == "hashes")
    assert py_hashes.details["hashes"]["sha256"] != zip_hashes.details["hashes"]["sha256"]
    assert all(run.artifact_id in {item.id for item in py_report.artifacts} for run in py_report.analyzer_runs)


def test_cli_analyze_still_works(tmp_path: Path):
    path = tmp_path / "hello.py"
    path.write_text("print('cli')\n", encoding="utf-8")
    import subprocess

    completed = subprocess.run(
        [sys.executable, "-m", "exsoftware", "analyze", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "What this is" in completed.stdout
    assert "executed=no" in completed.stdout

    completed_json = subprocess.run(
        [sys.executable, "-m", "exsoftware", "analyze", str(path), "--json"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed_json.returncode == 0, completed_json.stderr
    payload = json.loads(completed_json.stdout)
    assert payload["schema_version"] == 1
    assert payload["limits"]["executed"] is False
    assert payload["limits"]["isolation"]["analyzers"] == "subprocess"
    assert payload["composition"]["identity"]["category"] == "python_script"


def test_api_analyze_still_works():
    from fastapi.testclient import TestClient

    from exsoftware.api import app

    client = TestClient(app)
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["executes_files"] is False
    response = client.post(
        "/api/analyze",
        files={"file": ("note.py", b"import os\n", "text/x-python")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == 1
    assert payload["identity"]["detected_type"] == "python"
    assert payload["composition"]["identity"]["category"] == "python_script"
    assert payload["limits"]["isolation"]["analyzers"] == "subprocess"


def test_status_enum_includes_terminated():
    assert "terminated" in ANALYZER_STATUSES
    assert "timeout" in ANALYZER_STATUSES


def test_timeout_text_report_is_incomplete():
    result = _runner().run(IsolateHangAnalyzer(), _ctx(), timeout=1.0)
    assert result.status == "timeout"
    assert "not analyzed" in (result.details.get("result") or "")
    # Absence of findings on this analyzer must not be phrased as clean.
    assert result.findings == []
    assert result.status != "completed"
