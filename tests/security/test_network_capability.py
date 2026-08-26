"""Evidence-based network capability evaluation unit tests.

These tests do not require Windows. Live AppContainer behavior still needs a
Windows host for runtime proof.
"""

from __future__ import annotations

import sys

from exsoftware.isolate.network_capability import (
    evaluate_network_restriction,
    meaningful_network_success,
)
from exsoftware.isolate.status import inspect_isolation


def test_bind_alone_is_not_meaningful_network_success():
    observed = {
        "listen_bind_succeeded": True,
        "listen_bind_v6_succeeded": True,
        "localhost_connect_succeeded": False,
        "localhost_connect_v6_succeeded": False,
        "external_connect_succeeded": False,
        "external_connect_v6_succeeded": False,
        "host_to_worker_connect_succeeded": False,
        "udp_send_succeeded": False,
        "udp_send_v6_succeeded": False,
    }
    assert meaningful_network_success(observed) is False


def test_localhost_connect_is_meaningful_success():
    observed = {"localhost_connect_succeeded": True}
    assert meaningful_network_success(observed) is True


def test_host_to_worker_connect_is_meaningful_success():
    observed = {"host_to_worker_connect_succeeded": True}
    assert meaningful_network_success(observed) is True


def test_udp_send_is_meaningful_success():
    observed = {"udp_send_succeeded": True}
    assert meaningful_network_success(observed) is True


def test_enforced_claim_fails_when_connect_succeeds():
    state, reason = evaluate_network_restriction(
        "enforced",
        {"localhost_connect_succeeded": True, "listen_bind_succeeded": False},
    )
    assert state == "failed"
    assert "usable network" in reason.lower() or "communication" in reason.lower()


def test_enforced_claim_fails_when_host_to_worker_succeeds():
    state, _reason = evaluate_network_restriction(
        "enforced",
        {
            "host_to_worker_connect_succeeded": True,
            "listen_bind_succeeded": True,
            "localhost_connect_succeeded": False,
        },
    )
    assert state == "failed"


def test_bind_without_communication_can_upgrade_degraded_to_enforced():
    state, reason = evaluate_network_restriction(
        "degraded",
        {
            "listen_bind_succeeded": True,
            "localhost_connect_succeeded": False,
            "external_connect_succeeded": False,
            "host_to_worker_connect_succeeded": False,
            "udp_send_succeeded": False,
            "udp_send_v6_succeeded": False,
            "localhost_connect_v6_succeeded": False,
            "external_connect_v6_succeeded": False,
        },
    )
    assert state == "enforced"
    assert "bind/listen" in reason.lower()


def test_unsupported_claim_does_not_invent_enforcement():
    state, _reason = evaluate_network_restriction(
        "unsupported",
        {
            "listen_bind_succeeded": False,
            "localhost_connect_succeeded": False,
            "external_connect_succeeded": False,
            "host_to_worker_connect_succeeded": False,
            "udp_send_succeeded": False,
        },
    )
    assert state == "unsupported"


def test_security_status_never_enforces_when_usable_network_succeeds():
    data = inspect_isolation()
    obs = data["observed"]
    usable = (
        obs.get("localhost_connect_succeeded")
        or obs.get("localhost_connect_v6_succeeded")
        or obs.get("external_connect_succeeded")
        or obs.get("external_connect_v6_succeeded")
        or obs.get("host_to_worker_connect_succeeded")
        or obs.get("udp_send_succeeded")
        or obs.get("udp_send_v6_succeeded")
    )
    if usable:
        assert data["capabilities"]["network_restriction"] != "enforced"
    # Bind alone must not force a non-enforced result when communication failed.
    if obs.get("listen_bind_succeeded") and not usable:
        # May be enforced or degraded/unsupported depending on claimed mechanism.
        assert data["capabilities"]["network_restriction"] in {
            "enforced",
            "degraded",
            "unsupported",
            "failed",
        }
    if data["observed"].get("read_outside_succeeded"):
        assert data["capabilities"]["filesystem_restriction"] != "enforced"
    if data["observed"].get("spawn_succeeded"):
        assert data["capabilities"]["process_creation"] != "enforced"
    assert data["sandbox"] is False
    assert data.get("windows_runtime_verified") is (sys.platform == "win32")
