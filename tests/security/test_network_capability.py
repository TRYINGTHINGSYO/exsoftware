"""Evidence-based network capability evaluation unit tests.

These tests do not require Windows. Live AppContainer behavior still needs a
Windows host for runtime proof.
"""

from __future__ import annotations

import json
import sys

import pytest

from exsoftware.isolate.network_capability import (
    assess_network_mechanisms,
    build_probe_completeness,
    evaluate_network_restriction,
    meaningful_network_success,
    validate_listen_ready_payload,
)
from exsoftware.isolate.status import inspect_isolation


def _complete_denial_observed(**overrides):
    observed = {
        "localhost_connect_succeeded": False,
        "localhost_connect_v6_succeeded": False,
        "external_connect_succeeded": False,
        "external_connect_v6_succeeded": False,
        "host_to_worker_connect_succeeded": False,
        "host_to_worker_connect_v6_succeeded": False,
        "udp_localhost_received": False,
        "udp_localhost_received_v6": False,
        "listen_bind_succeeded": True,
        "listen_bind_v6_succeeded": False,
        "localhost_connect_v4_outcome": "denied",
        "localhost_connect_v6_outcome": "unavailable",
        "host_to_worker_v4_outcome": "denied",
        "host_to_worker_v6_outcome": "unavailable",
        "udp_localhost_v4_outcome": "denied",
        "udp_localhost_v6_outcome": "unavailable",
        "network_analyzer_completed": True,
        "listen_comm_completed": True,
        "listen_comm_ready": True,
        "network_mechanism_consistent": True,
        "network_mechanism_supports_upgrade": True,
    }
    observed.update(overrides)
    return observed


def test_bind_alone_is_not_meaningful_network_success():
    observed = {
        "listen_bind_succeeded": True,
        "listen_bind_v6_succeeded": True,
        "localhost_connect_succeeded": False,
        "localhost_connect_v6_succeeded": False,
        "external_connect_succeeded": False,
        "external_connect_v6_succeeded": False,
        "host_to_worker_connect_succeeded": False,
        "host_to_worker_connect_v6_succeeded": False,
        "udp_localhost_received": False,
        "udp_localhost_received_v6": False,
        # Legacy TEST-NET UDP flags must not count as usable communication.
        "udp_send_succeeded": True,
        "udp_send_v6_succeeded": True,
    }
    assert meaningful_network_success(observed) is False


def test_localhost_connect_is_meaningful_success():
    observed = {"localhost_connect_succeeded": True}
    assert meaningful_network_success(observed) is True


def test_host_to_worker_connect_is_meaningful_success():
    observed = {"host_to_worker_connect_succeeded": True}
    assert meaningful_network_success(observed) is True


def test_host_to_worker_connect_v6_is_meaningful_success():
    observed = {"host_to_worker_connect_v6_succeeded": True}
    assert meaningful_network_success(observed) is True


def test_udp_localhost_receipt_is_meaningful_success():
    observed = {"udp_localhost_received": True}
    assert meaningful_network_success(observed) is True


def test_udp_localhost_v6_receipt_is_meaningful_success():
    observed = {"udp_localhost_received_v6": True}
    assert meaningful_network_success(observed) is True


def test_enforced_claim_fails_when_connect_succeeds():
    state, reason = evaluate_network_restriction(
        "enforced",
        _complete_denial_observed(localhost_connect_succeeded=True, localhost_connect_v4_outcome="succeeded"),
    )
    assert state == "failed"
    assert "usable network" in reason.lower() or "communication" in reason.lower()


def test_enforced_claim_fails_when_host_to_worker_succeeds():
    state, _reason = evaluate_network_restriction(
        "enforced",
        _complete_denial_observed(
            host_to_worker_connect_succeeded=True,
            host_to_worker_v4_outcome="succeeded",
            listen_bind_succeeded=True,
        ),
    )
    assert state == "failed"


def test_enforced_claim_fails_when_host_to_worker_v6_succeeds():
    state, _reason = evaluate_network_restriction(
        "enforced",
        _complete_denial_observed(
            host_to_worker_connect_v6_succeeded=True,
            host_to_worker_v6_outcome="succeeded",
            localhost_connect_v6_outcome="denied",
            udp_localhost_v6_outcome="denied",
        ),
    )
    assert state == "failed"


def test_complete_denial_can_upgrade_degraded_to_enforced():
    state, reason = evaluate_network_restriction("degraded", _complete_denial_observed())
    assert state == "enforced"
    assert "upgraded" in reason.lower() or "denied" in reason.lower()


def test_unsupported_claim_does_not_invent_enforcement():
    state, _reason = evaluate_network_restriction(
        "unsupported",
        _complete_denial_observed(network_mechanism_supports_upgrade=False),
    )
    assert state == "unsupported"


def test_listen_probe_error_blocks_upgrade():
    state, reason = evaluate_network_restriction(
        "degraded",
        _complete_denial_observed(
            listen_comm_probe_error="boom",
            listen_comm_completed=False,
            listen_comm_ready=False,
        ),
    )
    assert state == "degraded"
    assert "incomplete" in reason.lower() or "errored" in reason.lower() or "probe" in reason.lower()


def test_helper_never_ready_blocks_upgrade():
    state, reason = evaluate_network_restriction(
        "degraded",
        _complete_denial_observed(
            listen_comm_ready=False,
            host_to_worker_v4_outcome="incomplete",
        ),
    )
    assert state == "degraded"
    assert "never became ready" in reason.lower() or "ready" in reason.lower()


def test_helper_timeout_blocks_upgrade():
    state, reason = evaluate_network_restriction(
        "degraded",
        _complete_denial_observed(
            listen_comm_completed=False,
            probe_error="listen helper timed out",
            listen_comm_ready=True,
            host_to_worker_v4_outcome="incomplete",
        ),
    )
    assert state == "degraded"
    assert "timed out" in reason.lower() or "did not complete" in reason.lower() or "incomplete" in reason.lower()


def test_helper_crash_blocks_upgrade():
    state, reason = evaluate_network_restriction(
        "degraded",
        _complete_denial_observed(
            listen_comm_completed=False,
            probe_error="listen helper crashed",
        ),
    )
    assert state == "degraded"
    assert "crash" in reason.lower() or "did not complete" in reason.lower() or "incomplete" in reason.lower()


def test_network_analyzer_failure_blocks_upgrade():
    state, reason = evaluate_network_restriction(
        "degraded",
        _complete_denial_observed(
            network_analyzer_failed=True,
            network_analyzer_completed=False,
            localhost_connect_v4_outcome="incomplete",
            udp_localhost_v4_outcome="incomplete",
        ),
    )
    assert state == "degraded"
    assert "analyzer" in reason.lower() or "incomplete" in reason.lower()


def test_missing_evidence_blocks_upgrade():
    state, reason = evaluate_network_restriction(
        "degraded",
        {
            "listen_bind_succeeded": True,
            "localhost_connect_succeeded": False,
            "host_to_worker_connect_succeeded": False,
            "udp_localhost_received": False,
            # Outcomes omitted → incomplete.
            "network_analyzer_completed": True,
            "listen_comm_completed": True,
            "listen_comm_ready": True,
            "network_mechanism_consistent": True,
            "network_mechanism_supports_upgrade": True,
        },
    )
    assert state == "degraded"
    assert "incomplete" in reason.lower() or "outcome" in reason.lower()


def test_all_false_without_completeness_does_not_upgrade():
    """Absence of success alone must never upgrade degraded → enforced."""
    state, reason = evaluate_network_restriction(
        "degraded",
        {
            "localhost_connect_succeeded": False,
            "host_to_worker_connect_succeeded": False,
            "udp_localhost_received": False,
            "listen_bind_succeeded": True,
            "network_analyzer_completed": False,
            "listen_comm_completed": False,
            "listen_comm_ready": False,
            "network_mechanism_consistent": True,
            "network_mechanism_supports_upgrade": True,
        },
    )
    assert state == "degraded"
    assert state != "enforced"


def test_mechanism_mismatch_blocks_upgrade():
    state, reason = evaluate_network_restriction(
        "degraded",
        _complete_denial_observed(
            network_mechanism_consistent=False,
            network_mechanism_supports_upgrade=False,
            network_mechanism_reason="network probe mechanisms disagree ('appcontainer' vs 'job_only')",
        ),
    )
    assert state == "degraded"
    assert "disagree" in reason.lower() or "mechanism" in reason.lower()


def test_fallback_mechanism_blocks_upgrade():
    state, reason = evaluate_network_restriction(
        "degraded",
        _complete_denial_observed(
            network_mechanism_consistent=True,
            network_mechanism_supports_upgrade=False,
            network_mechanism_reason="mechanism 'restricted_token' is a fallback/unsupported containment path",
        ),
    )
    assert state == "degraded"
    assert "fallback" in reason.lower() or "support" in reason.lower() or "mechanism" in reason.lower()


def test_assess_network_mechanisms_rejects_mismatch():
    result = assess_network_mechanisms(
        {
            "mechanism": "appcontainer",
            "token_is_appcontainer": True,
            "capabilities": {"network_restriction": "degraded"},
        },
        {
            "mechanism": "job_only",
            "token_is_appcontainer": False,
            "capabilities": {"network_restriction": "unsupported"},
        },
    )
    assert result["network_mechanism_consistent"] is False
    assert result["network_mechanism_supports_upgrade"] is False


def test_assess_network_mechanisms_rejects_fallback():
    result = assess_network_mechanisms(
        {
            "mechanism": "restricted_token",
            "token_is_appcontainer": False,
            "capabilities": {"network_restriction": "unsupported"},
        },
        {
            "mechanism": "restricted_token",
            "token_is_appcontainer": False,
            "capabilities": {"network_restriction": "unsupported"},
        },
    )
    assert result["network_mechanism_consistent"] is True
    assert result["network_mechanism_supports_upgrade"] is False


def test_validate_listen_ready_accepts_family_port_only():
    raw = json.dumps(
        {
            "protocol": "exsoftware.network_listen_ready",
            "protocol_version": 1,
            "tcp": [{"family": "ipv4", "port": 12345}],
        }
    ).encode("utf-8")
    data = validate_listen_ready_payload(raw)
    assert data["tcp"] == [{"family": "ipv4", "port": 12345}]


def test_validate_listen_ready_rejects_arbitrary_host():
    raw = json.dumps(
        {
            "protocol": "exsoftware.network_listen_ready",
            "protocol_version": 1,
            "tcp": [{"family": "ipv4", "host": "8.8.8.8", "port": 53}],
        }
    ).encode("utf-8")
    with pytest.raises(ValueError, match="loopback|host"):
        validate_listen_ready_payload(raw)


def test_validate_listen_ready_rejects_malformed_and_duplicates():
    with pytest.raises(ValueError):
        validate_listen_ready_payload(b"not-json")
    with pytest.raises(ValueError):
        validate_listen_ready_payload(
            json.dumps(
                {
                    "protocol": "exsoftware.network_listen_ready",
                    "protocol_version": 1,
                    "tcp": [
                        {"family": "ipv4", "port": 1},
                        {"family": "ipv4", "port": 2},
                    ],
                }
            ).encode()
        )
    with pytest.raises(ValueError):
        validate_listen_ready_payload(
            json.dumps(
                {
                    "protocol": "exsoftware.network_listen_ready",
                    "protocol_version": 1,
                    "tcp": [{"family": "ipv4", "port": 99999}],
                }
            ).encode()
        )
    with pytest.raises(ValueError):
        validate_listen_ready_payload(
            json.dumps(
                {
                    "protocol": "exsoftware.network_listen_ready",
                    "protocol_version": 1,
                    "tcp": [{"family": "unix", "port": 1}],
                }
            ).encode()
        )


def test_validate_listen_ready_rejects_oversized():
    huge = b"{" + (b"x" * 5000) + b"}"
    with pytest.raises(ValueError, match="exceeds"):
        validate_listen_ready_payload(huge)


def test_build_probe_completeness_marks_incomplete_without_ready():
    info = build_probe_completeness(
        {
            "network_analyzer_completed": True,
            "listen_comm_completed": True,
            "listen_comm_ready": False,
            "localhost_connect_v4_outcome": "denied",
            "host_to_worker_v4_outcome": "incomplete",
            "udp_localhost_v4_outcome": "denied",
        }
    )
    assert info["complete_for_upgrade"] is False
    assert "ready" in (info["incomplete_reason"] or "").lower()


def test_security_status_never_enforces_when_usable_network_succeeds():
    data = inspect_isolation()
    obs = data["observed"]
    usable = (
        obs.get("localhost_connect_succeeded")
        or obs.get("localhost_connect_v6_succeeded")
        or obs.get("external_connect_succeeded")
        or obs.get("external_connect_v6_succeeded")
        or obs.get("host_to_worker_connect_succeeded")
        or obs.get("host_to_worker_connect_v6_succeeded")
        or obs.get("udp_localhost_received")
        or obs.get("udp_localhost_received_v6")
    )
    if usable:
        assert data["capabilities"]["network_restriction"] != "enforced"
    if data["observed"].get("read_outside_succeeded"):
        assert data["capabilities"]["filesystem_restriction"] != "enforced"
    if data["observed"].get("spawn_succeeded"):
        assert data["capabilities"]["process_creation"] != "enforced"
    assert data["sandbox"] is False
    assert data.get("windows_runtime_verified") is (sys.platform == "win32")
    assert "probe_completeness" in obs
    assert "network_mechanism_consistent" in obs
    assert "host_to_worker_connect_v6_succeeded" in obs
    assert "udp_localhost_received" in obs
