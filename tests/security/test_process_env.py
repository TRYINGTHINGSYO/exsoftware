"""Isolated child must see the same third-party deps the parent installed."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from exsoftware.isolate.process import child_env, host_site_package_dirs, pythonpath_for_child
from exsoftware.isolate.workspace import rmtree_retry


def test_host_site_package_dirs_are_real_directories():
    dirs = host_site_package_dirs()
    assert dirs, "expected at least one host site-packages directory"
    for path in dirs:
        assert path.is_dir()
        # Prefix roots (e.g. hostedtoolcache .../x64) must be normalized away.
        assert path.name.lower() in {"site-packages", "dist-packages"}

@pytest.mark.skipif(sys.platform == "win32", reason="Unix site-packages layout regression")
def test_unix_pythonpath_includes_real_site_packages():
    path = pythonpath_for_child()
    parts = [part for part in path.split(os.pathsep) if part]
    real_dirs = {str(path) for path in host_site_package_dirs()}
    assert real_dirs
    assert any(part in real_dirs for part in parts)
    # Windows-style Lib/site-packages under /usr is usually absent on Linux.
    lib_guess = str(Path(sys.prefix) / "Lib" / "site-packages")
    if not Path(lib_guess).is_dir():
        assert lib_guess not in parts


def test_isolated_child_can_import_runtime_dependencies():
    workdir = Path(tempfile.mkdtemp(prefix="exsoftware-child-env-"))
    try:
        env = child_env(test_mode=True, workdir=workdir)
        code = (
            "import olefile, pypdf, PIL\n"
            "print('ok', olefile.__name__, pypdf.__name__, PIL.__name__)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(workdir),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert "ok" in completed.stdout
    finally:
        rmtree_retry(workdir)
