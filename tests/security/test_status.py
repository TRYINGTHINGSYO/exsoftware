from exsoftware.isolate.status import inspect_isolation


def test_security_status_probe_is_honest():
    data = inspect_isolation()
    assert data["sandbox"] is False
    assert data["containment"] == "static-parser"
    assert data["capabilities"]["process_boundary"] == "enforced"
    assert data["capabilities"]["wall_clock"] == "enforced"
    assert data["capabilities"]["output_limit"] == "enforced"
    # Never claim enforced if the probe succeeded at the forbidden operation.
    if data["observed"]["read_outside_succeeded"]:
        assert data["capabilities"]["filesystem_restriction"] != "enforced"
    if data["observed"]["localhost_connect_succeeded"] or data["observed"]["listen_succeeded"]:
        assert data["capabilities"]["network_restriction"] != "enforced"
    if data["observed"]["spawn_succeeded"]:
        assert data["capabilities"]["process_creation"] != "enforced"
