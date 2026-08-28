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
# Layout 5: identity includes a fingerprint of staged exsoftware package contents.
RUNTIME_LAYOUT_VERSION = "5"

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

# Third-party packages that isolated workers may import while analyzing files.
# Server-only dependencies (FastAPI/Uvicorn/python-multipart) are intentionally
# omitted: AppContainer workers run analyzer modules, not the HTTP server.
REQUIRED_RUNTIME_SITE_ENTRIES = (
    "pefile.py",
    "elftools",
    "olefile.py",
    "pypdf",
    "PIL",
    "cryptography",
    "cffi",
    "pycparser",
    "_cffi_backend",
    "typing_extensions.py",
)
REQUIRED_RUNTIME_DIST_PREFIXES = (
    "pefile",
    "pyelftools",
    "olefile",
    "pypdf",
    "pillow",
    "cryptography",
    "cffi",
    "pycparser",
    "typing_extensions",
)


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


def application_package_root() -> Path:
    return python_src_root() / "exsoftware"


def _package_entry_ignored(name: str) -> bool:
    """Match copy_runtime ignore rules for fingerprinting staged application files."""
    lowered = name.lower()
    return lowered in SKIP_DIR_NAMES or lowered.endswith((".pyc", ".pdb"))


def iter_application_package_files(package_root: Path | None = None) -> list[Path]:
    """Runtime-relevant files under the exsoftware package, stable relative order."""
    root = Path(package_root) if package_root is not None else application_package_root()
    if not root.is_dir():
        return []
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if not _package_entry_ignored(name))
        for name in sorted(filenames):
            if _package_entry_ignored(name):
                continue
            files.append(Path(dirpath) / name)
    files.sort(key=lambda path: path.relative_to(root).as_posix())
    return files


def application_package_fingerprint(package_root: Path | None = None) -> str:
    """Deterministic fingerprint of staged application sources (paths + contents).

    Editable/development checkouts can change without a package version bump, so
    the staged runtime identity must hash the files that ``_copy_application_package``
    would install — not ``exsoftware.__version__`` alone.
    """
    root = Path(package_root) if package_root is not None else application_package_root()
    digest = hashlib.sha256()
    if not root.is_dir():
        digest.update(b"missing\0")
        return digest.hexdigest()
    for path in iter_application_package_files(root):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError as exc:
            digest.update(f"unreadable:{exc}".encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def staged_python_root() -> Path:
    base = python_install_root()
    app = application_package_fingerprint()
    key_material = (
        f"{sys.version}|{base}|layout={RUNTIME_LAYOUT_VERSION}|app={app}"
    )
    key = hashlib.sha256(key_material.encode("utf-8")).hexdigest()[:16]
    return (
        Path(os.environ.get("TEMP") or os.environ.get("TMP") or os.getenv("LOCALAPPDATA") or ".")
        / "exsoftware-isolate"
        / "runtime"
        / key
    )


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
    """Active site-packages outside the base install that can feed staging.

    A venv's site-packages lives outside the base CPython tree. It is copied
    selectively into the staged runtime, not granted to the child wholesale.
    Conda site-packages sit under the install root and are handled separately.
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

    ``Lib/site-packages`` is never copied wholesale. Conda/venv environments can
    contain many unrelated packages, caches, and tests; staging only the known
    analyzer runtime imports keeps the AppContainer read ACL narrow and avoids
    recursive ACL work over a large environment.
    """
    source = Path(source)
    dest = Path(dest)
    if include_site_packages is None:
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
        if Path(relative).parts == ("Lib",):
            ignore = _ignore_lib_without_site_packages
        shutil.copytree(
            src_dir,
            dst_dir,
            dirs_exist_ok=True,
            ignore=ignore,
            copy_function=shutil.copy2,
        )
    if include_site_packages:
        _copy_required_site_packages(source, dest)
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


def runtime_site_package_sources(source: Path) -> list[Path]:
    """Candidate site-packages roots, highest priority first.

    A virtualenv's site-packages should win over its base interpreter. For a
    Conda/base install, ``extra_host_site_packages`` returns nothing and the
    install root's own site-packages is used selectively.
    """
    source = Path(source)
    candidates = [*extra_host_site_packages(install_root=source), source / "Lib" / "site-packages"]
    found: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen or not candidate.is_dir():
            continue
        seen.add(resolved)
        found.append(candidate)
    return found


def _copy_required_site_packages(source: Path, dest_runtime: Path) -> None:
    dest_site = dest_runtime / "Lib" / "site-packages"
    copied_keys: set[str] = set()
    for site in runtime_site_package_sources(source):
        for entry in _iter_required_site_entries(site):
            key = _site_entry_key(entry)
            if key in copied_keys:
                continue
            _copy_site_entry(entry, dest_site / entry.name)
            copied_keys.add(key)


def _iter_required_site_entries(site: Path) -> list[Path]:
    try:
        names = sorted(os.listdir(site), key=str.lower)
    except OSError:
        return []
    selected: list[Path] = []
    required = {name.lower() for name in REQUIRED_RUNTIME_SITE_ENTRIES}
    dist_prefixes = tuple(prefix.lower().replace("-", "_") for prefix in REQUIRED_RUNTIME_DIST_PREFIXES)
    for name in names:
        lowered = name.lower()
        normalized = lowered.replace("-", "_")
        path = site / name
        if lowered in required:
            selected.append(path)
            continue
        if lowered.startswith("_cffi_backend") and lowered.endswith((".pyd", ".dll", ".so")):
            selected.append(path)
            continue
        if lowered.endswith((".dist-info", ".egg-info", ".libs")) and normalized.startswith(dist_prefixes):
            selected.append(path)
    return selected


def _site_entry_key(path: Path) -> str:
    name = path.name.lower().replace("-", "_")
    if name.startswith("_cffi_backend"):
        return "_cffi_backend"
    return name


def _copy_site_entry(src: Path, dst: Path) -> None:
    if dst.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, ignore=_ignore_skipped, copy_function=shutil.copy2)
    elif src.is_file():
        shutil.copy2(src, dst)


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


def _runtime_complete(
    marker: Path,
    source: Path,
    *,
    app_fingerprint: str | None = None,
) -> bool:
    if not marker.is_file():
        return False
    try:
        text = marker.read_text(encoding="utf-8")
    except OSError:
        return False
    fingerprint = (
        app_fingerprint
        if app_fingerprint is not None
        else application_package_fingerprint()
    )
    return (
        str(source) in text
        and f"layout={RUNTIME_LAYOUT_VERSION}" in text
        and f"app={fingerprint}" in text
    )


def _write_runtime_marker(
    dest: Path,
    source: Path,
    *,
    app_fingerprint: str | None = None,
) -> None:
    fingerprint = (
        app_fingerprint
        if app_fingerprint is not None
        else application_package_fingerprint()
    )
    (dest / ".exsoftware-runtime-complete").write_text(
        f"{source}\nlayout={RUNTIME_LAYOUT_VERSION}\napp={fingerprint}\n",
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
    app_fingerprint = application_package_fingerprint()
    marker = dest / ".exsoftware-runtime-complete"
    acl_marker = dest / acl_sid_marker_name(appcontainer_sid) if appcontainer_sid else None
    if (
        marker.is_file()
        and (dest / "python.exe").is_file()
        and _runtime_complete(marker, source, app_fingerprint=app_fingerprint)
    ):
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
            try:
                ok = bool(grant(staging, appcontainer_sid, "(OI)(CI)(RX)", recursive=False))
            except OSError as exc:
                # Only ACL bootstrap failures poison the process-wide cache.
                PROCESS_ACL_CACHE.record_failure(exc)
                raise
            if not ok:
                exc = OSError("failed to apply inheritable AppContainer ACE before runtime copy")
                PROCESS_ACL_CACHE.record_failure(exc)
                raise exc
        copy_runtime(source, staging)
        _write_runtime_marker(staging, source, app_fingerprint=app_fingerprint)
        if appcontainer_sid:
            (staging / acl_sid_marker_name(appcontainer_sid)).write_text("ok", encoding="utf-8")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        os.replace(staging, dest)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return dest


def ensure_staged_cpython(*, appcontainer_sid: str | None = None) -> Path:
    """Return a user-owned copy of the base interpreter directory."""
    dest = staged_python_root()
    source = python_install_root()
    app_fingerprint = application_package_fingerprint()
    sid = appcontainer_sid
    if sid is None and sys.platform == "win32":
        try:
            from .wincontain import appcontainer_sid as _appcontainer_sid

            sid, _ptr = _appcontainer_sid()
        except OSError:
            sid = None
    marker = dest / ".exsoftware-runtime-complete"
    acl_marker = dest / acl_sid_marker_name(sid) if sid else None
    if (
        marker.is_file()
        and (dest / "python.exe").is_file()
        and _runtime_complete(marker, source, app_fingerprint=app_fingerprint)
    ):
        if sid is None or (acl_marker is not None and acl_marker.is_file()):
            return dest
    with _LOCK:
        if (
            marker.is_file()
            and (dest / "python.exe").is_file()
            and _runtime_complete(marker, source, app_fingerprint=app_fingerprint)
        ):
            if sid is None or (acl_marker is not None and acl_marker.is_file()):
                return dest
        return stage_cpython_tree(source, dest, appcontainer_sid=sid)
