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
    # Legacy listen_succeeded alias remains for older readers.
    assert "listen_succeeded" in data["observed"]
    assert "listen_bind_succeeded" in data["observed"]
    assert "host_to_worker_connect_succeeded" in data["observed"]
    assert "host_to_worker_connect_v6_succeeded" in data["observed"]
    assert "udp_localhost_received" in data["observed"]
    assert "probe_completeness" in data["observed"]
