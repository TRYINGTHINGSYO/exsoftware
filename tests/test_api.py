from pathlib import Path

from exsoftware.api import STATIC_DIR, app


def test_ui_static_files_exist():
    assert (STATIC_DIR / "index.html").is_file()
    assert (STATIC_DIR / "styles.css").is_file()
    assert (STATIC_DIR / "app.js").is_file()


def test_api_app_registers_routes():
    paths = {getattr(route, "path", None) for route in app.routes}
    assert "/" in paths
    assert "/api/health" in paths
    assert "/api/security-status" in paths
    assert "/api/analyze" in paths
    assert "/api/analyze-path" in paths
