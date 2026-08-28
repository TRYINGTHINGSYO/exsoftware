"""Isolated child must see the same third-party deps the parent installed."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import exsoftware.isolate.process as process
from exsoftware.isolate.process import (
    child_env,
    host_site_package_dirs,
    pythonpath_for_child,
    windows_child_path_entries,
)
from exsoftware.isolate.winruntime import staged_python_root
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


def test_windows_pythonpath_uses_only_staged_runtime(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(process.sys, "platform", "win32")
    monkeypatch.setenv("TEMP", str(tmp_path / "temp"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "live-src"))

    parts = [part for part in process.pythonpath_for_child().split(os.pathsep) if part]
    assert parts == [str(staged_python_root() / "Lib" / "site-packages")]
    assert str(tmp_path / "live-src") not in parts


def test_windows_child_path_excludes_live_venv_scripts(tmp_path: Path):
    staged_python = tmp_path / "runtime" / "python.exe"
    staged_python.parent.mkdir(parents=True)
    staged_python.write_text("x", encoding="utf-8")
    venv = tmp_path / "venv"

    entries = windows_child_path_entries(staged_python, str(tmp_path / "windows"))

    assert str(venv / "Scripts") not in entries
    assert str(staged_python.parent.resolve()) in entries
