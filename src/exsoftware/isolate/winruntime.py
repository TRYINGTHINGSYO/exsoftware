"""User-owned CPython tree for AppContainer ACL grants.

Machine-wide installs (for example C:\\Python314) are typically owned by
Administrators. A non-elevated parent cannot add the AppContainer ACE to
those files, so python.exe starts and then dies with STATUS_DLL_NOT_FOUND
(0xC0000135) when it cannot load python3xx.dll.

This module copies a **minimal** interpreter into
``%TEMP%\\exsoftware-isolate\\runtime`` where the current user can set ACLs.
It does not execute submitted artifacts.

Conda/Miniconda install roots also contain ``pkgs``, ``conda-meta``, caches,
and unrelated envs. Those are never staged and must not be recursively ACL'd.
When an AppContainer SID is available, the inheritable ACE is applied to the
empty staging directory **before** files are copied so children inherit access
without a recursive ``icacls /T`` over a large tree.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .acl_prep import PROCESS_ACL_CACHE

_LOCK = threading.Lock()

# Bump when the staged layout changes so fat historical copies are rebuilt.
RUNTIME_LAYOUT_VERSION = "4"

# Directory names never copied from any Python install root (any depth).
SKIP_DIR_NAMES = frozenset(
    {
        "doc",
        "docs",
        "include",
        "libs",
        "tcl",
        "tools",
        "test",
        "tests",
        "idlelib",
        "ensurepip",
        "turtledemo",
        "__pycache__",
        ".git",
        "pkgs",
        "conda-meta",
        "conda-bld",
        "envs",
        "condabin",
        "shells",
        "cache",
        ".cache",
        "share",
        "man",
        "info",
        "etc",
        "menu",
        "compiler_compat",
        "var",
        "tmp",
        "wheels",
        "conda-pkgs",
        "pkgs_dirs",
    }
)

CONDA_MARKER_DIRS = frozenset({"conda-meta", "conda-bld", "condabin", "pkgs"})

_ROOT_NAME_EXACT = frozenset({"python.exe", "pythonw.exe"})


@dataclass(frozen=True)
class RuntimeCopyPlan:
    """What to copy from a Windows Python install root."""

    source: Path
    root_files: tuple[str, ...]
    directories: tuple[str, ...]
    skip_dir_names: frozenset[str]
    conda_prefix: bool


def python_install_root() -> Path:
    """Directory that contains the base ``python.exe`` (not a venv launcher)."""
    return Path(getattr(sys, "_base_executable", sys.executable)).resolve().parent


def python_src_root() -> Path:
    """Repository ``src`` directory (parent of the ``exsoftware`` package)."""
    return Path(__file__).resolve().parents[2]


def staged_python_root() -> Path:
    base = python_install_root()
    key = hashlib.sha256(f"{sys.version}|{base}|layout={RUNTIME_LAYOUT_VERSION}".encode("utf-8")).hexdigest()[:16]
    return Path(os.environ.get("TEMP") or os.environ.get("TMP") or os.getenv("LOCALAPPDATA") or ".") / "exsoftware-isolate" / "runtime" / key


def staged_python_executable() -> Path:
    return ensure_staged_cpython() / "python.exe"


def looks_like_conda_prefix(root: Path) -> bool:
    root = Path(root)
    return any((root / name).is_dir() for name in CONDA_MARKER_DIRS)


def path_is_under(path: Path, root: Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def extra_host_site_packages(install_root: Path | None = None) -> list[Path]:
    """site-packages the child must read that are **not** inside the staged install.

    A venv's site-packages lives outside the base CPython tree. Conda
    site-packages sit under the install root and are copied with ``Lib``.
    """
    install_root = (install_root or python_install_root()).resolve()
    found: list[Path] = []
    seen: set[Path] = set()
    for prefix in (Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()):
        site = prefix / "Lib" / "site-packages"
        try:
            resolved = site.resolve()
        except OSError:
            continue
        if resolved in seen or not site.is_dir():
            continue
        if path_is_under(resolved, install_root):
            continue
        seen.add(resolved)
        found.append(resolved)
    return found


def acl_sid_marker_name(sid: str) -> str:
    digest = hashlib.sha256(sid.encode("utf-8")).hexdigest()[:16]
    return f".exsoftware-acl-{digest}"


def child_path_entries(python_exe: Path) -> list[str]:
    """PATH entries the AppContainer child needs next to the staged interpreter."""
    python_dir = Path(python_exe).resolve().parent
    entries = [str(python_dir)]
    library_bin = python_dir / "Library" / "bin"
    if library_bin.is_dir():
        entries.append(str(library_bin))
    return entries


def _is_root_runtime_file(name: str) -> bool:
    lowered = name.lower()
    if lowered in _ROOT_NAME_EXACT:
        return True
    # Conda ships zlib, ucrtbase, api-ms-win-* and VC runtime DLLs next to python.exe.
    # Copying every root *.dll stays tiny compared with pkgs/envs and is required to boot.
    if lowered.endswith((".dll", ".pyd")):
        return True
    return False


def runtime_copy_plan(source: Path) -> RuntimeCopyPlan:
    """Select a minimal interpreter layout. Never includes Conda pkgs/envs/caches."""
    source = Path(source)
    conda = looks_like_conda_prefix(source)
    root_files: list[str] = []
    try:
        names = os.listdir(source)
    except OSError:
        names = []
    for name in names:
        path = source / name
        if path.is_file() and _is_root_runtime_file(name):
            root_files.append(name)
    directories: list[str] = []
    if (source / "DLLs").is_dir():
        directories.append("DLLs")
    if (source / "Lib").is_dir():
        directories.append("Lib")
    library_bin = source / "Library" / "bin"
    if conda and library_bin.is_dir():
        directories.append(str(Path("Library") / "bin"))
    return RuntimeCopyPlan(
        source=source,
        root_files=tuple(sorted(root_files, key=str.lower)),
        directories=tuple(directories),
        skip_dir_names=SKIP_DIR_NAMES,
        conda_prefix=conda,
    )


def _ignore_skipped(directory: str, names: list[str]) -> set[str]:
    skipped: set[str] = set()
    for name in names:
        lowered = name.lower()
        if lowered in SKIP_DIR_NAMES or lowered.endswith((".pyc", ".pdb")):
            skipped.add(name)
    return skipped


def copy_runtime(source: Path, dest: Path, *, include_site_packages: bool | None = None) -> None:
    """Copy only the planned runtime files into *dest* (must already exist).

    When a venv's site-packages lives outside the install root, the install's
    ``Lib/site-packages`` is skipped so a broken Conda copy cannot shadow the
    venv (for example a cp310 Pillow wheel next to Python 3.11).
    """
    source = Path(source)
    dest = Path(dest)
    if include_site_packages is None:
        include_site_packages = True
        try:
            if source.resolve() == python_install_root().resolve() and extra_host_site_packages(
                install_root=source
            ):
                include_site_packages = False
        except OSError:
            include_site_packages = True
    plan = runtime_copy_plan(source)
    dest.mkdir(parents=True, exist_ok=True)
    for name in plan.root_files:
        src_file = source / name
        if src_file.is_file():
            shutil.copy2(src_file, dest / name)
    for relative in plan.directories:
        src_dir = source.joinpath(*Path(relative).parts)
        dst_dir = dest.joinpath(*Path(relative).parts)
        if not src_dir.is_dir():
            continue
        dst_dir.parent.mkdir(parents=True, exist_ok=True)
        ignore = _ignore_skipped
        if (not include_site_packages) and Path(relative).parts == ("Lib",):
            ignore = _ignore_lib_without_site_packages
        shutil.copytree(
            src_dir,
            dst_dir,
            dirs_exist_ok=True,
            ignore=ignore,
            copy_function=shutil.copy2,
        )
    _copy_application_package(dest)
    if not (dest / "python.exe").is_file():
        raise OSError("failed to stage a user-owned python.exe for AppContainer")


def _ignore_lib_without_site_packages(directory: str, names: list[str]) -> set[str]:
    skipped = _ignore_skipped(directory, names)
    if Path(directory).name.lower() == "lib":
        for name in names:
            if name.lower() == "site-packages":
                skipped.add(name)
    return skipped


def _copy_application_package(dest_runtime: Path) -> None:
    """Place exsoftware inside the staged tree so the child does not need the live src ACL."""
    src_pkg = python_src_root() / "exsoftware"
    if not src_pkg.is_dir():
        return
    dest_pkg = dest_runtime / "Lib" / "site-packages" / "exsoftware"
    dest_pkg.parent.mkdir(parents=True, exist_ok=True)
    if dest_pkg.exists():
        shutil.rmtree(dest_pkg)
    shutil.copytree(src_pkg, dest_pkg, ignore=_ignore_skipped, copy_function=shutil.copy2)


def _runtime_complete(marker: Path, source: Path) -> bool:
    if not marker.is_file():
        return False
    try:
        text = marker.read_text(encoding="utf-8")
    except OSError:
        return False
    return str(source) in text and f"layout={RUNTIME_LAYOUT_VERSION}" in text


def _write_runtime_marker(dest: Path, source: Path) -> None:
    (dest / ".exsoftware-runtime-complete").write_text(
        f"{source}\nlayout={RUNTIME_LAYOUT_VERSION}\n",
        encoding="utf-8",
    )


def stage_cpython_tree(
    source: Path,
    dest: Path,
    *,
    appcontainer_sid: str | None = None,
    grant_sid_fn: Callable[..., bool] | None = None,
) -> Path:
    """Stage *source* into *dest*. Apply an inheritable ACE before copy when SID is set.

    *grant_sid_fn(path, sid, rights, recursive=False)* must return True only when
    the grant actually succeeded. A false return or exception leaves no success
    markers and does not publish *dest*.
    """
    source = Path(source)
    dest = Path(dest)
    marker = dest / ".exsoftware-runtime-complete"
    acl_marker = dest / acl_sid_marker_name(appcontainer_sid) if appcontainer_sid else None
    if marker.is_file() and (dest / "python.exe").is_file() and _runtime_complete(marker, source):
        if appcontainer_sid is None or (acl_marker is not None and acl_marker.is_file()):
            return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = dest.parent / f"{dest.name}.staging"
    PROCESS_ACL_CACHE.raise_if_failed()
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    try:
        if appcontainer_sid:
            grant = grant_sid_fn
            if grant is None and sys.platform == "win32":
                from .winacl import grant_sid

                grant = grant_sid
            if grant is None:
                raise OSError("AppContainer SID provided but no ACL grant function is available")
            ok = bool(grant(staging, appcontainer_sid, "(OI)(CI)(RX)", recursive=False))
            if not ok:
                raise OSError("failed to apply inheritable AppContainer ACE before runtime copy")
        copy_runtime(source, staging)
        _write_runtime_marker(staging, source)
        if appcontainer_sid:
            (staging / acl_sid_marker_name(appcontainer_sid)).write_text("ok", encoding="utf-8")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        os.replace(staging, dest)
    except BaseException as exc:
        shutil.rmtree(staging, ignore_errors=True)
        if isinstance(exc, OSError):
            PROCESS_ACL_CACHE.record_failure(exc)
        raise
    return dest


def ensure_staged_cpython(*, appcontainer_sid: str | None = None) -> Path:
    """Return a user-owned copy of the base interpreter directory."""
    dest = staged_python_root()
    source = python_install_root()
    sid = appcontainer_sid
    if sid is None and sys.platform == "win32":
        try:
            from .wincontain import appcontainer_sid as _appcontainer_sid

            sid, _ptr = _appcontainer_sid()
        except OSError:
            sid = None
    marker = dest / ".exsoftware-runtime-complete"
    acl_marker = dest / acl_sid_marker_name(sid) if sid else None
    if marker.is_file() and (dest / "python.exe").is_file() and _runtime_complete(marker, source):
        if sid is None or (acl_marker is not None and acl_marker.is_file()):
            return dest
    with _LOCK:
        if marker.is_file() and (dest / "python.exe").is_file() and _runtime_complete(marker, source):
            if sid is None or (acl_marker is not None and acl_marker.is_file()):
                return dest
        return stage_cpython_tree(source, dest, appcontainer_sid=sid)
