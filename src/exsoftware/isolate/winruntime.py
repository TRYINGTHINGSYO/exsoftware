"""User-owned CPython tree for AppContainer ACL grants.

Machine-wide installs (for example C:\\Python314) are typically owned by
Administrators. A non-elevated parent cannot add the AppContainer ACE to
those files, so python.exe starts and then dies with STATUS_DLL_NOT_FOUND
(0xC0000135) when it cannot load python3xx.dll.

This module copies a slim interpreter into %TEMP%\\exsoftware-isolate\\runtime
where the current user can set ACLs. It does not execute submitted artifacts.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

CREATE_NO_WINDOW = 0x08000000
_LOCK = threading.Lock()

_SKIP_DIRS = {
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
}


def staged_python_root() -> Path:
    base = Path(getattr(sys, "_base_executable", sys.executable)).resolve().parent
    key = hashlib.sha256(f"{sys.version}|{base}".encode("utf-8")).hexdigest()[:16]
    return Path(os.environ.get("TEMP") or os.environ.get("TMP") or os.getenv("LOCALAPPDATA") or ".") / "exsoftware-isolate" / "runtime" / key


def staged_python_executable() -> Path:
    return ensure_staged_cpython() / "python.exe"


def ensure_staged_cpython() -> Path:
    """Return a user-owned copy of the base interpreter directory."""
    dest = staged_python_root()
    marker = dest / ".exsoftware-runtime-complete"
    if marker.is_file() and (dest / "python.exe").is_file():
        return dest
    source = Path(getattr(sys, "_base_executable", sys.executable)).resolve().parent
    with _LOCK:
        if marker.is_file() and (dest / "python.exe").is_file():
            return dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        staging = dest.parent / f"{dest.name}.staging"
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)
        _copy_runtime(source, staging)
        (staging / ".exsoftware-runtime-complete").write_text(str(source), encoding="utf-8")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        os.replace(staging, dest)
    return dest


def _copy_runtime(source: Path, dest: Path) -> None:
    robocopy = shutil.which("robocopy")
    if robocopy:
        cmd = [
            robocopy,
            str(source),
            str(dest),
            "/E",
            "/COPY:DAT",
            "/R:1",
            "/W:1",
            "/XD",
            *sorted(_SKIP_DIRS),
            "/XF",
            "*.pyc",
            "*.pdb",
            "/NFL",
            "/NDL",
            "/NJH",
            "/NJS",
        ]
        completed = subprocess.run(cmd, capture_output=True, creationflags=CREATE_NO_WINDOW, check=False)
        # robocopy: 0-7 are success / extra files / mismatched extras.
        if completed.returncode < 8 and (dest / "python.exe").is_file():
            return
    shutil.copytree(source, dest, dirs_exist_ok=True, ignore=_ignore, copy_function=shutil.copy2)
    if not (dest / "python.exe").is_file():
        raise OSError("failed to stage a user-owned python.exe for AppContainer")


def _ignore(directory: str, names: list[str]) -> set[str]:
    skipped: set[str] = set()
    for name in names:
        lowered = name.lower()
        if lowered in _SKIP_DIRS or lowered.endswith((".pyc", ".pdb")):
            skipped.add(name)
    return skipped
