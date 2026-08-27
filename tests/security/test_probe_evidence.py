"""Filesystem/process probe evidence must not treat spawn failure as denial."""

from __future__ import annotations

import json

from exsoftware.isolate.policy import CAPABILITIES, IsolationPolicy
from exsoftware.isolate.probe_evidence import (
    OS_CONTAINMENT_CAPABILITIES,
    assess_filesystem_mechanisms,
    evaluate_filesystem_restriction,
    evaluate_process_boundary,
    evaluate_process_creation,
    reject_os_enforcement_without_mechanism,
)
from exsoftware.isolate.status import _finalize, format_status


def _spawn_failed_probe(**overrides):
    probe = {
        "status": "failed",
        "details": {"reason": "spawn_failed", "failed": True},
        "mechanism": "none",
        "token_is_appcontainer": False,
        "capabilities": IsolationPolicy().capabilities(),
        "reasons": {},
        "worker_launched": False,
        "spawn_error": "icacls timed out after 60 seconds",
        "pid": None,
    }
    probe.update(overrides)
    return probe


def _complete_probe(*, kind: str, mechanism="appcontainer", claimed=None, **detail_overrides):
    policy = IsolationPolicy()
    policy.mechanism = mechanism
    if mechanism == "appcontainer":
        policy.filesystem_restriction = "enforced"
        policy.network_restriction = "degraded"
        policy.process_creation = "enforced"
        policy.process_boundary = "enforced"
    caps = policy.capabilities()
    if claimed:
        caps.update(claimed)
    if kind == "read":
        details = {"read_ok": False, "denied": True, "target": "host-secret.txt"}
    elif kind == "write":
        details = {"write_ok": False, "denied": True, "target": "host-write.txt"}
    elif kind == "spawn":
        details = {"spawned": False, "denied": True}
    else:
        details = {}
    details.update(detail_overrides)
    return {
        "status": "completed",
        "details": details,
        "mechanism": mechanism,
        "token_is_appcontainer": mechanism == "appcontainer",
        "capabilities": caps,
        "reasons": {},
        "worker_launched": True,
        "pid": 4242,
        "spawn_error": None,
    }


def _empty_listen(**overrides):
    data = {
        "mechanism": "none",
        "listen_comm_completed": False,
        "listen_comm_ready": False,
        "probe_error": "probe worker failed before launch",
        "worker_launched": False,
        "host_to_worker_v4_outcome": "incomplete",
        "host_to_worker_v6_outcome": "unavailable",
        "details": {},
        "capabilities": {},
    }
    data.update(overrides)
    return data


def _base_report():
    return {
        "sandbox": False,
        "containment": "static-parser",
        "platform": "win32",
        "capabilities": {name: "unsupported" for name in CAPABILITIES},
        "reasons": {},
        "observed": {},
        "mechanism": "none",
        "windows_runtime_verified": True,
    }


def _finalize_from(read, write, net, spawn, listen=None):
    return _finalize(
        _base_report(),
        read,
        write,
        net,
        spawn,
        listen or _empty_listen(),
        host_write_exists=False,
        parent_listener_v4=False,
        parent_listener_v6=False,
        udp_parent_v4=False,
        udp_parent_v6=False,
        udp_v4_received=False,
        udp_v6_received=False,
        udp_bind_errors={},
    )


def test_spawn_failure_cannot_produce_filesystem_enforced():
    failed = _spawn_failed_probe()
    state, reason = evaluate_filesystem_restriction(
        claimed="unsupported",
        mechanism="none",
        token_is_appcontainer=False,
        read_probe=failed,
        write_probe=failed,
        host_write_exists=False,
    )
    assert state != "enforced"
    assert "launch" in reason.lower() or "mechanism" in reason.lower()

    report = _finalize_from(failed, failed, failed, failed)
    assert report["capabilities"]["filesystem_restriction"] != "enforced"
    assert report["mechanism"] == "none"
    assert report["capabilities"]["process_boundary"] == "unsupported"


def test_spawn_failure_cannot_produce_process_or_network_enforced():
    failed = _spawn_failed_probe()
    proc_state, _ = evaluate_process_creation(
        claimed="unsupported",
        mechanism="none",
        spawn_probe=failed,
    )
    assert proc_state != "enforced"
    boundary, _ = evaluate_process_boundary(any_worker_launched=False)
    assert boundary != "enforced"

    report = _finalize_from(failed, failed, failed, failed)
    assert report["capabilities"]["process_creation"] != "enforced"
    assert report["capabilities"]["network_restriction"] != "enforced"
    assert report["capabilities"]["filesystem_restriction"] != "enforced"
    # The previously observed dishonest combination must never occur.
    assert not (
        report["mechanism"] == "none"
        and report["capabilities"]["process_boundary"] == "unsupported"
        and report["capabilities"]["filesystem_restriction"] == "enforced"
    )


def test_mechanism_none_cannot_yield_os_containment_enforced():
    caps = {
        "filesystem_restriction": "enforced",
        "network_restriction": "enforced",
        "process_creation": "enforced",
        "process_boundary": "unsupported",
    }
    reasons: dict[str, str] = {}
    reject_os_enforcement_without_mechanism(caps, "none", reasons=reasons)
    for key in OS_CONTAINMENT_CAPABILITIES:
        assert caps[key] != "enforced"
        assert key in reasons


def test_read_ok_false_without_launch_is_not_filesystem_denial():
    """read_ok=False and write_ok=False must not mean enforced when the worker never ran."""
    failed = _spawn_failed_probe(
        details={"reason": "spawn_failed", "failed": True, "read_ok": False, "write_ok": False}
    )
    state, _reason = evaluate_filesystem_restriction(
        claimed="unsupported",
        mechanism="none",
        token_is_appcontainer=False,
        read_probe=failed,
        write_probe=failed,
        host_write_exists=False,
    )
    assert state != "enforced"


def test_successful_filesystem_probe_behavior_unchanged():
    read = _complete_probe(kind="read")
    write = _complete_probe(kind="write")
    state, reason = evaluate_filesystem_restriction(
        claimed="enforced",
        mechanism="appcontainer",
        token_is_appcontainer=True,
        read_probe=read,
        write_probe=write,
        host_write_exists=False,
    )
    assert state == "enforced"
    assert "denied" in reason.lower()


def test_successful_process_probe_behavior_unchanged():
    spawn = _complete_probe(kind="spawn")
    state, _reason = evaluate_process_creation(
        claimed="enforced",
        mechanism="appcontainer",
        spawn_probe=spawn,
    )
    assert state == "enforced"


def test_successful_probes_still_fail_claim_when_operation_succeeds():
    read = _complete_probe(kind="read", read_ok=True, denied=False)
    write = _complete_probe(kind="write")
    state, _reason = evaluate_filesystem_restriction(
        claimed="enforced",
        mechanism="appcontainer",
        token_is_appcontainer=True,
        read_probe=read,
        write_probe=write,
        host_write_exists=False,
    )
    assert state == "failed"

    spawn = _complete_probe(kind="spawn", spawned=True, denied=False)
    proc, _ = evaluate_process_creation(
        claimed="enforced",
        mechanism="appcontainer",
        spawn_probe=spawn,
    )
    assert proc == "failed"


def test_finalize_successful_appcontainer_probes_remain_enforced_for_fs():
    read = _complete_probe(kind="read")
    write = _complete_probe(kind="write")
    spawn = _complete_probe(kind="spawn")
    net = _complete_probe(kind="read")
    net["details"] = {
        "connect_ok": False,
        "connect_v6_ok": False,
        "external_connect_ok": False,
        "external_connect_v6_ok": False,
        "listen_ok": True,
        "listen_v6_ok": False,
        "failed": False,
    }
    listen = _empty_listen(
        mechanism="appcontainer",
        token_is_appcontainer=True,
        worker_launched=True,
        listen_comm_completed=True,
        listen_comm_ready=True,
        probe_error=None,
        host_to_worker_connect_succeeded=False,
        host_to_worker_connect_v6_succeeded=False,
        listen_bind_succeeded=True,
        capabilities=read["capabilities"],
        spawn_meta={"pid": 99, "mechanism": "appcontainer"},
        host_to_worker_v4_outcome="denied",
        host_to_worker_v6_outcome="unavailable",
    )
    report = _finalize_from(read, write, net, spawn, listen)
    assert report["mechanism"] == "appcontainer"
    assert report["capabilities"]["filesystem_restriction"] == "enforced"
    assert report["capabilities"]["process_boundary"] == "enforced"


def test_format_status_still_renders_after_spawn_failure():
    failed = _spawn_failed_probe()
    report = _finalize_from(failed, failed, failed, failed)
    text = format_status(report)
    assert "filesystem_restriction" in text
    line = next(item for item in text.splitlines() if item.startswith("filesystem_restriction"))
    assert line.split()[1] != "enforced"


def test_read_appcontainer_spawn_none_process_creation_not_enforced():
    """Aggregate/read AppContainer must not upgrade a spawn probe with mechanism none."""
    read = _complete_probe(kind="read")
    write = _complete_probe(kind="write")
    spawn = _spawn_failed_probe(
        status="completed",
        details={"spawned": False, "denied": True},
        mechanism="none",
        worker_launched=True,
        spawn_error=None,
        pid=99,
        capabilities=_complete_probe(kind="spawn")["capabilities"],
    )
    # Direct evaluator: spawn mechanism is authoritative even if a caller passes AC.
    proc_state, proc_reason = evaluate_process_creation(
        claimed="enforced",
        mechanism="appcontainer",
        spawn_probe=spawn,
    )
    assert proc_state != "enforced"
    assert "mechanism" in proc_reason.lower()

    net = _complete_probe(kind="read")
    net["details"] = {
        "connect_ok": False,
        "connect_v6_ok": False,
        "external_connect_ok": False,
        "external_connect_v6_ok": False,
        "listen_ok": True,
        "listen_v6_ok": False,
        "failed": False,
    }
    report = _finalize_from(read, write, net, spawn)
    assert report["mechanism"] == "appcontainer"
    assert report["capabilities"]["process_creation"] != "enforced"
    assert report["observed"]["spawn_mechanism"] == "none"


def test_read_appcontainer_write_none_filesystem_not_enforced():
    """Filesystem enforced requires both read and write probe mechanisms to agree."""
    read = _complete_probe(kind="read")
    write = _spawn_failed_probe(
        status="completed",
        details={"write_ok": False, "denied": True, "target": "host-write.txt"},
        mechanism="none",
        worker_launched=True,
        spawn_error=None,
        pid=77,
        capabilities=read["capabilities"],
    )
    state, reason = evaluate_filesystem_restriction(
        claimed="enforced",
        read_probe=read,
        write_probe=write,
        host_write_exists=False,
    )
    assert state != "enforced"
    assert "disagree" in reason.lower() or "mechanism" in reason.lower()

    assessed = assess_filesystem_mechanisms(read, write)
    assert assessed["filesystem_mechanism_consistent"] is False
    assert assessed["filesystem_mechanism_supports_enforced"] is False

    spawn = _complete_probe(kind="spawn")
    net = _complete_probe(kind="read")
    net["details"] = {
        "connect_ok": False,
        "connect_v6_ok": False,
        "external_connect_ok": False,
        "external_connect_v6_ok": False,
        "listen_ok": True,
        "listen_v6_ok": False,
        "failed": False,
    }
    report = _finalize_from(read, write, net, spawn)
    assert report["mechanism"] == "appcontainer"
    assert report["capabilities"]["filesystem_restriction"] != "enforced"
    assert report["observed"]["read_mechanism"] == "appcontainer"
    assert report["observed"]["write_mechanism"] == "none"


def test_read_write_appcontainer_with_tokens_filesystem_remains_enforced():
    read = _complete_probe(kind="read")
    write = _complete_probe(kind="write")
    assert read["token_is_appcontainer"] and write["token_is_appcontainer"]
    state, reason = evaluate_filesystem_restriction(
        claimed="enforced",
        read_probe=read,
        write_probe=write,
        host_write_exists=False,
    )
    assert state == "enforced"
    assert "denied" in reason.lower()

    spawn = _complete_probe(kind="spawn")
    net = _complete_probe(kind="read")
    net["details"] = {
        "connect_ok": False,
        "connect_v6_ok": False,
        "external_connect_ok": False,
        "external_connect_v6_ok": False,
        "listen_ok": True,
        "listen_v6_ok": False,
        "failed": False,
    }
    report = _finalize_from(read, write, net, spawn)
    assert report["mechanism"] == "appcontainer"
    assert report["capabilities"]["filesystem_restriction"] == "enforced"
    assert report["observed"]["filesystem_mechanism_consistent"] is True
    assert report["observed"]["filesystem_mechanism_supports_enforced"] is True


def test_spawn_appcontainer_denied_process_creation_preserved():
    spawn = _complete_probe(kind="spawn")
    state, reason = evaluate_process_creation(
        claimed="enforced",
        spawn_probe=spawn,
    )
    assert state == "enforced"
    assert "failed" in reason.lower() or "CreateProcess" in reason or "Popen" in reason

    read = _complete_probe(kind="read")
    write = _complete_probe(kind="write")
    net = _complete_probe(kind="read")
    net["details"] = {
        "connect_ok": False,
        "connect_v6_ok": False,
        "external_connect_ok": False,
        "external_connect_v6_ok": False,
        "listen_ok": True,
        "listen_v6_ok": False,
        "failed": False,
    }
    report = _finalize_from(read, write, net, spawn)
    assert report["capabilities"]["process_creation"] == "enforced"
    assert report["observed"]["spawn_mechanism"] == "appcontainer"


def test_aggregate_report_mechanism_does_not_override_weaker_probe():
    """report['mechanism']=AppContainer must not override a weaker per-probe mechanism."""
    read = _complete_probe(kind="read")
    write = _complete_probe(kind="write")
    # Spawn never got AppContainer; only net/read did.
    spawn = _complete_probe(kind="spawn", mechanism="none")
    spawn["token_is_appcontainer"] = False
    spawn["capabilities"] = dict(spawn["capabilities"])
    spawn["capabilities"]["process_creation"] = "enforced"

    net = _complete_probe(kind="read")
    net["details"] = {
        "connect_ok": False,
        "connect_v6_ok": False,
        "external_connect_ok": False,
        "external_connect_v6_ok": False,
        "listen_ok": True,
        "listen_v6_ok": False,
        "failed": False,
    }
    report = _finalize_from(read, write, net, spawn)
    assert report["mechanism"] == "appcontainer"
    assert report["observed"]["spawn_mechanism"] == "none"
    assert report["capabilities"]["process_creation"] != "enforced"

    # Write weaker than read: filesystem must not be enforced despite aggregate AC.
    weak_write = _complete_probe(kind="write", mechanism="none")
    weak_write["token_is_appcontainer"] = False
    report2 = _finalize_from(read, weak_write, net, _complete_probe(kind="spawn"))
    assert report2["mechanism"] == "appcontainer"
    assert report2["capabilities"]["filesystem_restriction"] != "enforced"


def test_appcontainer_filesystem_requires_tokens_on_both_workers():
    read = _complete_probe(kind="read")
    write = _complete_probe(kind="write")
    write["token_is_appcontainer"] = False
    state, _reason = evaluate_filesystem_restriction(
        claimed="enforced",
        read_probe=read,
        write_probe=write,
        host_write_exists=False,
    )
    assert state != "enforced"
    assessed = assess_filesystem_mechanisms(read, write)
    assert assessed["filesystem_mechanism_consistent"] is True
    assert assessed["filesystem_mechanism_supports_enforced"] is False
