"""Staged Windows runtime selection. Safe to run on non-Windows hosts."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from exsoftware.isolate.acl_prep import PROCESS_ACL_CACHE, AclTimeoutError
from exsoftware.isolate.process import host_site_package_dirs
from exsoftware.isolate import winruntime
from exsoftware.isolate.winruntime import (
    REQUIRED_RUNTIME_SITE_ENTRIES,
    RUNTIME_LAYOUT_VERSION,
    SKIP_DIR_NAMES,
    _copy_required_site_packages,
    _runtime_complete,
    acl_sid_marker_name,
    application_package_fingerprint,
    child_path_entries,
    copy_runtime,
    extra_host_site_packages,
    looks_like_conda_prefix,
    path_is_under,
    runtime_copy_plan,
    runtime_site_package_sources,
    stage_cpython_tree,
    staged_python_root,
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
    _write(root / "Lib" / "site-packages" / "ordlookup" / "__init__.py")
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
    _write(root / "Lib" / "site-packages" / "huge_unrelated_package" / "__init__.py")
    _write(root / "Lib" / "site-packages" / "fastapi" / "__init__.py")
    _write(root / "Lib" / "site-packages" / "uvicorn" / "__init__.py")
    _write(root / "Lib" / "site-packages" / "cryptography" / "__init__.py")
    _write(root / "Lib" / "site-packages" / "cryptography" / "hazmat" / "bindings" / "_rust.pyd")
    _write(root / "Lib" / "site-packages" / "cryptography-99.dist-info" / "METADATA")
    _write(root / "Lib" / "site-packages" / "cryptography.libs" / "crypto.dll")
    _write_olefile_package(root / "Lib" / "site-packages")
    _write(root / "Lib" / "site-packages" / "PIL" / "__init__.py")
    _write(root / "Lib" / "site-packages" / "PIL" / "_imaging.pyd")
    _write(root / "Lib" / "site-packages" / "Pillow.libs" / "libpng.dll")
    _write(root / "Lib" / "site-packages" / "_cffi_backend.pyd")
    _write(root / "Lib" / "site-packages" / "cffi" / "__init__.py")
    return root


def _write_olefile_package(site: Path) -> None:
    """Realistic olefile 0.47 layout: a package directory, not olefile.py."""
    _write(site / "olefile" / "__init__.py", "from .olefile import *\n")
    _write(site / "olefile" / "olefile.py", "def isOleFile(filename): return False\n")


@pytest.fixture(autouse=True)
def _isolate_host_user_site(monkeypatch, tmp_path, request):
    """Keep copy_runtime fixtures from ingesting the live pip --user tree."""
    if request.node.name == "test_staged_runtime_imports_worker_dependencies":
        return
    monkeypatch.setattr(
        "site.getusersitepackages",
        lambda: str(tmp_path / "no-user-site" / "site-packages"),
    )


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
    assert (dest / "Lib" / "site-packages" / "ordlookup" / "__init__.py").is_file()
    assert (dest / "Lib" / "site-packages" / "olefile" / "__init__.py").is_file()
    assert (dest / "Lib" / "site-packages" / "olefile" / "olefile.py").is_file()
    assert (dest / "Lib" / "site-packages" / "cryptography" / "__init__.py").is_file()
    assert (dest / "Lib" / "site-packages" / "cryptography" / "hazmat" / "bindings" / "_rust.pyd").is_file()
    assert (dest / "Lib" / "site-packages" / "cryptography-99.dist-info" / "METADATA").is_file()
    assert (dest / "Lib" / "site-packages" / "cryptography.libs" / "crypto.dll").is_file()
    assert (dest / "Lib" / "site-packages" / "PIL" / "__init__.py").is_file()
    assert (dest / "Lib" / "site-packages" / "PIL" / "_imaging.pyd").is_file()
    assert (dest / "Lib" / "site-packages" / "Pillow.libs" / "libpng.dll").is_file()
    assert (dest / "Lib" / "site-packages" / "_cffi_backend.pyd").is_file()
    assert (dest / "Lib" / "site-packages" / "cffi" / "__init__.py").is_file()
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
    assert not (dest / "Lib" / "site-packages" / "huge_unrelated_package").exists()
    assert not (dest / "Lib" / "site-packages" / "fastapi").exists()
    assert not (dest / "Lib" / "site-packages" / "uvicorn").exists()
    for skipped in ("pkgs", "conda-meta", "envs", "docs", "tests"):
        assert skipped in SKIP_DIR_NAMES
    assert "pefile.py" in REQUIRED_RUNTIME_SITE_ENTRIES
    assert "ordlookup" in REQUIRED_RUNTIME_SITE_ENTRIES
    assert "olefile" in REQUIRED_RUNTIME_SITE_ENTRIES
    assert "olefile.py" in REQUIRED_RUNTIME_SITE_ENTRIES


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
    extra = extra_host_site_packages(install_root=root)
    assert site.resolve() not in extra
    assert all(not path_is_under(path, root) for path in extra)


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


def test_user_site_packages_are_selectively_staged(tmp_path: Path, monkeypatch):
    source = _fake_cpython(tmp_path / "Python314")
    user_site = tmp_path / "usersite"
    _write_olefile_package(user_site)
    _write(user_site / "unrelated_user_pkg" / "__init__.py")
    monkeypatch.setattr("site.getusersitepackages", lambda: str(user_site))
    monkeypatch.setattr(winruntime.sys, "prefix", str(source))
    monkeypatch.setattr(winruntime.sys, "base_prefix", str(source))

    dest = tmp_path / "staged"
    dest.mkdir()
    copy_runtime(source, dest)
    staged = dest / "Lib" / "site-packages"
    assert (staged / "olefile" / "__init__.py").is_file()
    assert (staged / "olefile" / "olefile.py").is_file()
    assert not (staged / "unrelated_user_pkg").exists()


def test_runtime_site_package_sources_prioritize_venv(tmp_path: Path, monkeypatch):
    base = _fake_conda(tmp_path / "miniconda3")
    venv = tmp_path / "venv"
    venv_site = venv / "Lib" / "site-packages"
    venv_site.mkdir(parents=True)
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.prefix", str(venv))
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.base_prefix", str(base))
    sources = runtime_site_package_sources(base)
    resolved = [path.resolve() for path in sources]
    assert resolved[0] == venv_site.resolve()
    assert (base / "Lib" / "site-packages").resolve() in resolved


def test_venv_runtime_copies_required_packages_without_base_shadowing(tmp_path: Path, monkeypatch):
    base = _fake_conda(tmp_path / "miniconda3")
    _write(base / "Lib" / "site-packages" / "pefile.py", "base-pefile")
    venv = tmp_path / "venv"
    _write(venv / "Lib" / "site-packages" / "pefile.py", "venv-pefile")
    _write(venv / "Lib" / "site-packages" / "unrelated_big_pkg" / "__init__.py")
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.prefix", str(venv))
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.base_prefix", str(base))

    dest = tmp_path / "staged"
    dest.mkdir()
    copy_runtime(base, dest)
    assert (dest / "Lib" / "site-packages" / "pefile.py").read_text(encoding="utf-8") == "venv-pefile"
    assert not (dest / "Lib" / "site-packages" / "unrelated_big_pkg").exists()


def test_unrelated_runtime_source_is_not_contaminated_by_live_host_packages(
    tmp_path: Path, monkeypatch
):
    """A fake runtime root must not inherit packages from the running interpreter.

    Host PIL/olefile entries share ``_site_entry_key`` with the source copies, so
    mixing live site-packages in first would hide the source's ``_imaging.pyd``
    and legacy ``olefile.py``.
    """
    live = tmp_path / "live-miniconda"
    _write(live / "python.exe")
    live_site = live / "Lib" / "site-packages"
    _write(live_site / "PIL" / "__init__.py", "live-pil-without-imaging")
    _write(live_site / "olefile" / "__init__.py", "live-olefile-package")
    _write(live_site / "pefile.py", "live-pefile")

    source = _fake_cpython(tmp_path / "unrelated-python")
    src_site = source / "Lib" / "site-packages"
    _write(src_site / "PIL" / "__init__.py", "source-pil")
    _write(src_site / "PIL" / "_imaging.pyd")
    _write(src_site / "olefile.py", "legacy-olefile")
    _write(src_site / "pefile.py", "source-pefile")

    monkeypatch.setattr(winruntime.sys, "prefix", str(live))
    monkeypatch.setattr(winruntime.sys, "base_prefix", str(live))
    monkeypatch.setattr(winruntime.sys, "_base_executable", str(live / "python.exe"))

    assert extra_host_site_packages(install_root=source) == []
    resolved_sources = [path.resolve() for path in runtime_site_package_sources(source)]
    assert live_site.resolve() not in resolved_sources
    assert src_site.resolve() in resolved_sources

    dest = tmp_path / "staged"
    dest.mkdir()
    copy_runtime(source, dest)
    staged = dest / "Lib" / "site-packages"
    assert (staged / "PIL" / "__init__.py").read_text(encoding="utf-8") == "source-pil"
    assert (staged / "PIL" / "_imaging.pyd").is_file()
    assert (staged / "olefile.py").read_text(encoding="utf-8") == "legacy-olefile"
    assert not (staged / "olefile").exists()
    assert (staged / "pefile.py").read_text(encoding="utf-8") == "source-pefile"


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


def test_application_source_change_invalidates_staged_runtime(tmp_path: Path, monkeypatch):
    """Staged exsoftware must not be reused after source changes without a version bump."""
    src_root = tmp_path / "src"
    pkg = src_root / "exsoftware"
    _write(pkg / "__init__.py", "version-one")
    _write(pkg / "worker.py", "payload=1\n")
    _write(pkg / "__pycache__" / "worker.cpython-312.pyc", "bytecode")
    monkeypatch.setattr("exsoftware.isolate.winruntime.python_src_root", lambda: src_root)

    source = _fake_cpython(tmp_path / "Python314")
    monkeypatch.setattr("exsoftware.isolate.winruntime.python_install_root", lambda: source)
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.version", "3.14.0-fingerprint-test")
    monkeypatch.setenv("TEMP", str(tmp_path / "temp"))

    fp_before = application_package_fingerprint()
    dest_before = staged_python_root()
    stage_cpython_tree(source, dest_before, appcontainer_sid=None)
    staged_init = dest_before / "Lib" / "site-packages" / "exsoftware" / "__init__.py"
    assert staged_init.read_text(encoding="utf-8") == "version-one"
    assert not (dest_before / "Lib" / "site-packages" / "exsoftware" / "__pycache__").exists()
    marker = dest_before / ".exsoftware-runtime-complete"
    assert _runtime_complete(marker, source, app_fingerprint=fp_before)
    assert f"app={fp_before}" in marker.read_text(encoding="utf-8")

    # Same Python/version/install root; only application source changes.
    _write(pkg / "__init__.py", "version-two")
    fp_after = application_package_fingerprint()
    assert fp_after != fp_before
    dest_after = staged_python_root()
    assert dest_after != dest_before
    assert not _runtime_complete(marker, source, app_fingerprint=fp_after)

    stage_cpython_tree(source, dest_after, appcontainer_sid=None)
    assert (dest_after / "Lib" / "site-packages" / "exsoftware" / "__init__.py").read_text(
        encoding="utf-8"
    ) == "version-two"
    # Old staged tree still has stale code but must not be the selected identity.
    assert staged_init.read_text(encoding="utf-8") == "version-one"


def test_unchanged_application_source_reuses_staged_runtime(tmp_path: Path, monkeypatch):
    src_root = tmp_path / "src"
    pkg = src_root / "exsoftware"
    _write(pkg / "__init__.py", "stable")
    monkeypatch.setattr("exsoftware.isolate.winruntime.python_src_root", lambda: src_root)

    source = _fake_cpython(tmp_path / "Python314")
    monkeypatch.setattr("exsoftware.isolate.winruntime.python_install_root", lambda: source)
    monkeypatch.setattr("exsoftware.isolate.winruntime.sys.version", "3.14.0-reuse-test")
    monkeypatch.setenv("TEMP", str(tmp_path / "temp"))

    dest = staged_python_root()
    first = stage_cpython_tree(source, dest, appcontainer_sid=None)
    marker_mtime = (dest / ".exsoftware-runtime-complete").stat().st_mtime_ns
    second = stage_cpython_tree(source, dest, appcontainer_sid=None)
    assert first == second == dest
    assert staged_python_root() == dest
    assert (dest / ".exsoftware-runtime-complete").stat().st_mtime_ns == marker_mtime


def test_application_fingerprint_ignores_pycache_noise(tmp_path: Path):
    pkg = tmp_path / "exsoftware"
    _write(pkg / "__init__.py", "same")
    fp1 = application_package_fingerprint(pkg)
    _write(pkg / "__pycache__" / "x.pyc", "noise")
    _write(pkg / "module.pyc", "also-noise")
    fp2 = application_package_fingerprint(pkg)
    assert fp1 == fp2


def test_copy_error_does_not_poison_process_acl_cache(tmp_path: Path, monkeypatch):
    source = _fake_cpython(tmp_path / "Python314")
    dest = tmp_path / "runtime"
    grants = {"n": 0}

    def grant(*_args, **_kwargs):
        grants["n"] += 1
        return True

    def boom(*_args, **_kwargs):
        raise OSError("disk full while copying runtime files")

    monkeypatch.setattr("exsoftware.isolate.winruntime.copy_runtime", boom)
    with pytest.raises(OSError, match="disk full"):
        stage_cpython_tree(source, dest, appcontainer_sid="S-1-5-64-96", grant_sid_fn=grant)
    assert PROCESS_ACL_CACHE.failed is False
    assert grants["n"] == 1

    # A later attempt must still be allowed to run (ACL cache was not poisoned).
    monkeypatch.undo()
    source2 = _fake_cpython(tmp_path / "Python315")
    dest2 = tmp_path / "runtime2"
    grants2 = {"n": 0}

    def grant2(*_args, **_kwargs):
        grants2["n"] += 1
        return True

    PROCESS_ACL_CACHE.raise_if_failed()
    result = stage_cpython_tree(source2, dest2, appcontainer_sid="S-1-5-64-96", grant_sid_fn=grant2)
    assert result == dest2
    assert grants2["n"] == 1
    assert (dest2 / "python.exe").is_file()


def test_layout_5_runtime_is_not_reused_after_layout_6(tmp_path: Path, monkeypatch):
    """Selective site-packages staging must not reuse a layout-5 cache directory."""
    assert RUNTIME_LAYOUT_VERSION == "6"
    src_root = tmp_path / "src"
    _write(src_root / "exsoftware" / "__init__.py", "pkg")
    monkeypatch.setattr(winruntime, "python_src_root", lambda: src_root)

    source = _fake_cpython(tmp_path / "Python314")
    monkeypatch.setattr(winruntime, "python_install_root", lambda: source)
    monkeypatch.setattr(winruntime.sys, "version", "3.14.0-layout-bump")
    monkeypatch.setenv("TEMP", str(tmp_path / "temp"))

    monkeypatch.setattr(winruntime, "RUNTIME_LAYOUT_VERSION", "5")
    old_dest = staged_python_root()
    stage_cpython_tree(source, old_dest, appcontainer_sid=None)
    _write(old_dest / "Lib" / "site-packages" / "fastapi" / "__init__.py")
    old_marker = old_dest / ".exsoftware-runtime-complete"
    assert "layout=5" in old_marker.read_text(encoding="utf-8")

    monkeypatch.setattr(winruntime, "RUNTIME_LAYOUT_VERSION", "6")
    new_dest = staged_python_root()
    assert new_dest != old_dest
    assert not _runtime_complete(old_marker, source)
    assert (old_dest / "Lib" / "site-packages" / "fastapi" / "__init__.py").is_file()

    first = stage_cpython_tree(source, new_dest, appcontainer_sid=None)
    assert first == new_dest
    new_marker = new_dest / ".exsoftware-runtime-complete"
    assert "layout=6" in new_marker.read_text(encoding="utf-8")
    assert not (new_dest / "Lib" / "site-packages" / "fastapi").exists()
    assert staged_python_root() == new_dest

    marker_mtime = new_marker.stat().st_mtime_ns
    second = stage_cpython_tree(source, new_dest, appcontainer_sid=None)
    assert second == new_dest
    assert staged_python_root() == new_dest
    assert new_marker.stat().st_mtime_ns == marker_mtime
    # The old layout-5 tree is left in place; identity selection just ignores it.
    assert (old_dest / "python.exe").is_file()
    assert "layout=5" in old_marker.read_text(encoding="utf-8")


def test_olefile_package_layout_is_staged(tmp_path: Path):
    source = _fake_cpython(tmp_path / "Python314")
    site = source / "Lib" / "site-packages"
    _write_olefile_package(site)
    dest = tmp_path / "staged"
    dest.mkdir()
    copy_runtime(source, dest)
    staged = dest / "Lib" / "site-packages" / "olefile"
    assert (staged / "__init__.py").is_file()
    assert (staged / "olefile.py").is_file()
    assert not (dest / "Lib" / "site-packages" / "olefile.py").exists()


def test_legacy_olefile_module_is_still_staged(tmp_path: Path):
    source = _fake_cpython(tmp_path / "Python314")
    _write(source / "Lib" / "site-packages" / "olefile.py", "def isOleFile(filename): return False\n")
    dest = tmp_path / "staged"
    dest.mkdir()
    copy_runtime(source, dest)
    assert (dest / "Lib" / "site-packages" / "olefile.py").is_file()


def test_native_analyzer_support_files_are_staged(tmp_path: Path):
    source = _fake_cpython(tmp_path / "Python314")
    site = source / "Lib" / "site-packages"
    _write(site / "PIL" / "__init__.py")
    _write(site / "PIL" / "_imaging.pyd")
    _write(site / "Pillow.libs" / "libpng.dll")
    _write(site / "PIL.libs" / "libjpeg.dll")
    _write(site / "cryptography" / "__init__.py")
    _write(site / "cryptography" / "hazmat" / "bindings" / "_rust.pyd")
    _write(site / "cryptography.libs" / "crypto.dll")
    _write(site / "_cffi_backend.cp314-win_amd64.pyd")
    _write(site / "cffi" / "__init__.py")
    dest = tmp_path / "staged"
    dest.mkdir()
    copy_runtime(source, dest)
    staged = dest / "Lib" / "site-packages"
    assert (staged / "PIL" / "_imaging.pyd").is_file()
    assert (staged / "Pillow.libs" / "libpng.dll").is_file()
    assert (staged / "PIL.libs" / "libjpeg.dll").is_file()
    assert (staged / "cryptography" / "hazmat" / "bindings" / "_rust.pyd").is_file()
    assert (staged / "cryptography.libs" / "crypto.dll").is_file()
    assert (staged / "_cffi_backend.cp314-win_amd64.pyd").is_file()
    assert (staged / "cffi" / "__init__.py").is_file()


def test_staged_runtime_imports_worker_dependencies(tmp_path: Path, monkeypatch):
    """Import analyzer deps from a selectively staged tree, not the live host site."""
    host_sites = host_site_package_dirs()
    assert host_sites, "expected host site-packages so selective copy has a source"
    monkeypatch.setattr(winruntime, "runtime_site_package_sources", lambda _source: host_sites)

    dest = tmp_path / "staged"
    dest.mkdir()
    _copy_required_site_packages(tmp_path, dest)
    staged_site = dest / "Lib" / "site-packages"
    assert (staged_site / "olefile").is_dir() or (staged_site / "olefile.py").is_file()
    assert not (staged_site / "fastapi").exists()

    code = f"""
import sys
from pathlib import Path
staged = Path({str(staged_site)!r})
kept = [str(staged)]
for item in sys.path:
    name = Path(item).name.lower()
    if name in {{"site-packages", "dist-packages"}}:
        continue
    if item and item not in kept:
        kept.append(item)
sys.path[:] = kept
import pefile
import elftools
import olefile
import pypdf
import PIL
import cryptography
from PIL import Image
from cryptography.hazmat.primitives.serialization import pkcs7
for name, module in (
    ("pefile", pefile),
    ("elftools", elftools),
    ("olefile", olefile),
    ("pypdf", pypdf),
    ("PIL", PIL),
    ("cryptography", cryptography),
):
    location = getattr(module, "__file__", None) or ""
    try:
        Path(location).resolve().relative_to(staged.resolve())
    except (ValueError, OSError):
        raise SystemExit(f"{{name}} loaded from outside staged runtime: {{location}}")
try:
    import fastapi
except ImportError:
    pass
else:
    raise SystemExit("fastapi must not be importable from the staged runtime")
print("ok")
"""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONIOENCODING": "utf-8",
        "SystemRoot": os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows",
        "SYSTEMROOT": os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot") or r"C:\Windows",
    }
    if sys.platform == "win32":
        env["PATHEXT"] = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        env["WINDIR"] = os.environ.get("WINDIR") or env["SystemRoot"]
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "ok" in completed.stdout
