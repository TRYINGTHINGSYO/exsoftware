"""Staged Windows runtime selection. Safe to run on non-Windows hosts."""

from __future__ import annotations

from pathlib import Path

import pytest

from exsoftware.isolate.acl_prep import AclTimeoutError
from exsoftware.isolate.winruntime import (
    RUNTIME_LAYOUT_VERSION,
    SKIP_DIR_NAMES,
    acl_sid_marker_name,
    child_path_entries,
    copy_runtime,
    extra_host_site_packages,
    looks_like_conda_prefix,
    runtime_copy_plan,
    stage_cpython_tree,
)


def _write(path: Path, text: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fake_cpython(root: Path) -> Path:
    _write(root / "python.exe")
    _write(root / "python313.dll")
    _write(root / "vcruntime140.dll")
    _write(root / "zlib.dll")
    _write(root / "ucrtbase.dll")
    _write(root / "DLLs" / "_socket.pyd")
    _write(root / "Lib" / "os.py")
    _write(root / "Lib" / "encodings" / "__init__.py")
    _write(root / "Lib" / "site-packages" / "pefile.py")
    _write(root / "Lib" / "test" / "test_os.py")
    _write(root / "Lib" / "idlelib" / "idle.py")
    return root


def _fake_conda(root: Path) -> Path:
    _fake_cpython(root)
    _write(root / "conda-meta" / "history", "huge-meta")
    _write(root / "pkgs" / "openssl-3.0" / "blob.bin", "GIGABYTE")
    _write(root / "pkgs" / "huge" / "a.bin", "nope")
    _write(root / "envs" / "other" / "python.exe")
    _write(root / "Library" / "bin" / "sqlite3.dll")
    _write(root / "Library" / "lib" / "sqlite3.lib")
    _write(root / "Library" / "include" / "sqlite3.h")
    _write(root / "condabin" / "conda.bat")
    _write(root / "share" / "doc" / "readme.txt")
    return root


def test_conda_style_runtime_path_selection_skips_pkgs_and_envs(tmp_path: Path):
    source = _fake_conda(tmp_path / "miniconda3")
    plan = runtime_copy_plan(source)
    assert plan.conda_prefix is True
    assert looks_like_conda_prefix(source) is True
    copied = set(plan.directories) | set(plan.root_files)
    for name in ("pkgs", "conda-meta", "envs", "condabin", "share"):
        assert name not in copied
        assert not any(str(item).replace("\\", "/").split("/")[0] == name for item in plan.directories)
    assert "python.exe" in plan.root_files
    assert "zlib.dll" in plan.root_files
    assert "ucrtbase.dll" in plan.root_files
    assert "Lib" in plan.directories
    assert "DLLs" in plan.directories
    assert any(Path(item).parts[:2] == ("Library", "bin") or item.replace("\\", "/") == "Library/bin" for item in plan.directories)


def test_staged_runtime_excludes_unrelated_conda_directories(tmp_path: Path):
    source = _fake_conda(tmp_path / "miniconda3")
    dest = tmp_path / "staged"
    dest.mkdir()
    copy_runtime(source, dest)
    assert (dest / "python.exe").is_file()
    assert (dest / "Lib" / "os.py").is_file()
    assert (dest / "Lib" / "site-packages" / "pefile.py").is_file()
    assert (dest / "Lib" / "site-packages" / "exsoftware" / "__init__.py").is_file()
    assert (dest / "zlib.dll").is_file()
    assert (dest / "Library" / "bin" / "sqlite3.dll").is_file()
    assert not (dest / "pkgs").exists()
    assert not (dest / "conda-meta").exists()
    assert not (dest / "envs").exists()
    assert not (dest / "condabin").exists()
    assert not (dest / "share").exists()
    assert not (dest / "Library" / "lib").exists()
    assert not (dest / "Library" / "include").exists()
    assert not (dest / "Lib" / "test").exists()
    assert not (dest / "Lib" / "idlelib").exists()
    for skipped in ("pkgs", "conda-meta", "envs", "docs", "tests"):
        assert skipped in SKIP_DIR_NAMES


def test_python_org_layout_copies_interpreter_and_stdlib(tmp_path: Path):
    source = _fake_cpython(tmp_path / "Python314")
    plan = runtime_copy_plan(source)
    assert plan.conda_prefix is False
    assert not any("Library" in item for item in plan.directories)
    dest = tmp_path / "staged"
    dest.mkdir()
    copy_runtime(source, dest)
    assert (dest / "python.exe").is_file()
    assert (dest / "python313.dll").is_file()
    assert (dest / "vcruntime140.dll").is_file()
    assert (dest / "Lib" / "os.py").is_file()


def test_failed_acl_before_copy_does_not_write_markers(tmp_path: Path):
    source = _fake_cpython(tmp_path / "Python314")
    dest = tmp_path / "runtime"

    def grant(*_args, **_kwargs):
        return False

    with pytest.raises(OSError, match="inheritable AppContainer ACE"):
        stage_cpython_tree(source, dest, appcontainer_sid="S-1-5-64-96", grant_sid_fn=grant)
    assert not dest.exists()
    assert not (tmp_path / "runtime.staging").exists()


def test_acl_timeout_before_copy_does_not_write_markers(tmp_path: Path):
    source = _fake_cpython(tmp_path / "Python314")
    dest = tmp_path / "runtime"

    def grant(*_args, **_kwargs):
        raise AclTimeoutError("icacls timed out after 60 seconds")

    with pytest.raises(AclTimeoutError):
        stage_cpython_tree(source, dest, appcontainer_sid="S-1-5-64-96", grant_sid_fn=grant)
    assert not dest.exists()
    assert not list(tmp_path.glob(".exsoftware-acl-*"))
    assert not (dest / ".exsoftware-runtime-complete").exists()


def test_acl_marker_written_only_after_successful_grant_and_copy(tmp_path: Path):
    source = _fake_cpython(tmp_path / "Python314")
    dest = tmp_path / "runtime"
    granted: list[tuple] = []

    def grant(path, sid, rights, *, recursive=False):
        granted.append((Path(path), sid, rights, recursive))
        assert recursive is False
        assert (path / "python.exe").exists() is False
        return True

    sid = "S-1-5-64-96"
    result = stage_cpython_tree(source, dest, appcontainer_sid=sid, grant_sid_fn=grant)
    assert result == dest
    assert granted, "inheritable ACE must be applied before copy"
    assert (dest / "python.exe").is_file()
    marker = dest / ".exsoftware-runtime-complete"
    assert marker.is_file()
    text = marker.read_text(encoding="utf-8")
    assert f"layout={RUNTIME_LAYOUT_VERSION}" in text
    assert (dest / acl_sid_marker_name(sid)).is_file()


def test_conda_site_packages_under_install_root_are_not_extra_acl_targets(tmp_path: Path, monkeypatch):
    root = tmp_path / "miniconda3"
    site = root / "Lib" / "site-packages"
    site.mkdir(parents=True)
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.prefix", str(root))
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.base_prefix", str(root))
    assert extra_host_site_packages(install_root=root) == []


def test_venv_site_packages_are_extra_acl_targets(tmp_path: Path, monkeypatch):
    base = tmp_path / "Python314"
    base.mkdir()
    venv = tmp_path / "venv"
    site = venv / "Lib" / "site-packages"
    site.mkdir(parents=True)
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.prefix", str(venv))
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.base_prefix", str(base))
    extra = extra_host_site_packages(install_root=base)
    assert site.resolve() in extra


def test_stage_acl_failure_is_reused_without_retry(tmp_path: Path):
    source = _fake_cpython(tmp_path / "Python314")
    dest = tmp_path / "runtime"
    calls = {"n": 0}

    def grant(*_args, **_kwargs):
        calls["n"] += 1
        raise AclTimeoutError("icacls timed out after 60 seconds")

    with pytest.raises(AclTimeoutError):
        stage_cpython_tree(source, dest, appcontainer_sid="S-1-5-64-96", grant_sid_fn=grant)
    with pytest.raises(OSError, match="previously failed"):
        stage_cpython_tree(source, dest, appcontainer_sid="S-1-5-64-96", grant_sid_fn=grant)
    assert calls["n"] == 1
    assert not dest.exists()


def test_venv_does_not_copy_install_site_packages_that_would_shadow(tmp_path: Path, monkeypatch):
    source = _fake_conda(tmp_path / "miniconda3")
    venv = tmp_path / "venv"
    venv_site = venv / "Lib" / "site-packages"
    venv_site.mkdir(parents=True)
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.prefix", str(venv))
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.base_prefix", str(source))
    dest = tmp_path / "staged"
    dest.mkdir()
    copy_runtime(source, dest, include_site_packages=False)
    assert not (dest / "Lib" / "site-packages" / "pefile.py").exists()
    assert (dest / "Lib" / "os.py").is_file()
    assert (dest / "Lib" / "site-packages" / "exsoftware" / "__init__.py").is_file()


def test_child_path_includes_conda_library_bin(tmp_path: Path):
    python_exe = tmp_path / "python.exe"
    python_exe.write_text("x", encoding="utf-8")
    library_bin = tmp_path / "Library" / "bin"
    library_bin.mkdir(parents=True)
    entries = child_path_entries(python_exe)
    assert str(tmp_path.resolve()) in entries
    assert str(library_bin.resolve()) in entries
