import json
import sys

from exsoftware.cli import main
from exsoftware.isolate.status import inspect_isolation


def test_security_status_probe_is_honest():
    data = inspect_isolation()
    assert data["sandbox"] is False
    assert data["containment"] == "static-parser"
    assert data["capabilities"]["process_boundary"] == "enforced"
    assert data["capabilities"]["wall_clock"] == "enforced"
    assert data["capabilities"]["output_limit"] == "enforced"
    # Never claim enforced if a usable network operation succeeded.
    usable = (
        data["observed"].get("localhost_connect_succeeded")
        or data["observed"].get("localhost_connect_v6_succeeded")
        or data["observed"].get("external_connect_succeeded")
        or data["observed"].get("external_connect_v6_succeeded")
        or data["observed"].get("host_to_worker_connect_succeeded")
        or data["observed"].get("host_to_worker_connect_v6_succeeded")
        or data["observed"].get("udp_localhost_received")
        or data["observed"].get("udp_localhost_received_v6")
    )
    if data["observed"]["read_outside_succeeded"]:
        assert data["capabilities"]["filesystem_restriction"] != "enforced"
    if usable:
        assert data["capabilities"]["network_restriction"] != "enforced"
    if data["observed"]["spawn_succeeded"]:
        assert data["capabilities"]["process_creation"] != "enforced"
    # Never report the dishonest spawn-failure combination.
    if data["mechanism"] in {None, "none"} and not data["observed"].get("any_probe_worker_launched"):
        assert data["capabilities"]["filesystem_restriction"] != "enforced"
        assert data["capabilities"]["network_restriction"] != "enforced"
        assert data["capabilities"]["process_creation"] != "enforced"
    # Legacy listen_succeeded alias remains for older readers.
    assert "listen_succeeded" in data["observed"]
    assert "listen_bind_succeeded" in data["observed"]
    assert "host_to_worker_connect_succeeded" in data["observed"]
    assert "host_to_worker_connect_v6_succeeded" in data["observed"]
    assert "udp_localhost_received" in data["observed"]
    assert "probe_completeness" in data["observed"]


def test_cli_json_does_not_include_progress(monkeypatch, capsys):
    seen = {}

    def fake_inspect(*, progress=None):
        seen["progress"] = progress
        if progress is not None:
            progress("Checking Windows containment...")
            progress("filesystem read...")
        return {
            "sandbox": False,
            "containment": "static-parser",
            "platform": sys.platform,
            "mechanism": "none",
            "capabilities": {},
            "reasons": {},
            "observed": {},
        }

    monkeypatch.setattr("exsoftware.isolate.status.inspect_isolation", fake_inspect)
    assert main(["security-status", "--json"]) == 0
    out, err = capsys.readouterr()
    assert seen["progress"] is None
    payload = json.loads(out)
    assert payload["sandbox"] is False
    assert "Checking" not in out
    assert "filesystem read" not in out
    assert "Checking" not in err
    assert "filesystem read" not in err


def test_cli_human_progress_goes_to_stderr(monkeypatch, capsys):
    def fake_inspect(*, progress=None):
        assert progress is not None
        progress("Checking Windows containment...")
        progress("filesystem read...")
        progress("filesystem write...")
        progress("network...")
        progress("process creation...")
        return {
            "sandbox": False,
            "containment": "static-parser",
            "platform": sys.platform,
            "mechanism": "none",
            "capabilities": {name: "unsupported" for name in (
                "process_boundary",
                "process_tree_limit",
                "filesystem_restriction",
                "network_restriction",
                "memory_limit",
                "cpu_limit",
                "wall_clock",
                "output_limit",
                "temporary_storage",
                "process_creation",
            )},
            "reasons": {},
            "observed": {},
        }

    monkeypatch.setattr("exsoftware.isolate.status.inspect_isolation", fake_inspect)
    assert main(["security-status"]) == 0
    out, err = capsys.readouterr()
    assert "Checking Windows containment..." in err
    assert "filesystem read..." in err
    assert "filesystem write..." in err
    assert "network..." in err
    assert "process creation..." in err
    assert "Checking Windows containment..." not in out
    assert "ExSoftware analyzer containment" in out

