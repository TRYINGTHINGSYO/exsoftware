"""Secure analyzer workspaces and no-follow response reads."""

from __future__ import annotations

import os
import stat
import tempfile
import time
from pathlib import Path

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class OversizedWorkspaceFile(OSError):
    def __init__(self, size: int, max_bytes: int) -> None:
        self.size = size
        self.max_bytes = max_bytes
        super().__init__(f"workspace file exceeds max_bytes ({size} > {max_bytes})")


def create_workspace() -> Path:
    """Create a randomly named directory with owner-only access where the OS allows it."""
    base = Path(tempfile.gettempdir()) / "exsoftware-isolate"
    base.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="w-", dir=str(base)))
    _restrict_workspace(path)
    if _is_reparse(path):
        raise OSError("workspace resolved to a reparse point")
    return path


def _restrict_workspace(path: Path) -> None:
    if os.name != "nt":
        os.chmod(path, 0o700)
        return
    try:
        from .winacl import restrict_directory_to_current_user

        restrict_directory_to_current_user(path)
    except OSError:
        pass


def _is_reparse(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0) or 0
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def assert_child_relative(workdir: Path, candidate: Path) -> Path:
    """Resolve *candidate* without trusting child-created links."""
    work = workdir.resolve()
    raw = Path(candidate)
    if raw.is_absolute():
        # Parent always uses its own workdir / filename, never a child-supplied absolute path.
        raise OSError("absolute child path rejected")
    target = work.joinpath(raw.name if raw.parent == Path(".") else raw)
    if _is_reparse(target):
        raise OSError("response path is a reparse point / symlink")
    if target.parent.resolve() != work:
        raise OSError("response path escaped the workspace")
    return target


def read_workspace_file(workdir: Path, name: str, *, max_bytes: int) -> bytes:
    path = assert_child_relative(workdir, Path(name))
    if _is_reparse(path):
        raise OSError("response path is a reparse point / symlink")
    if not path.is_file():
        raise OSError("workspace file missing")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags)
    try:
        size = os.fstat(fd).st_size
        if size > max_bytes:
            raise OversizedWorkspaceFile(size, max_bytes)
        return os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)


def rmtree_retry(path: Path, *, attempts: int = 20, delay: float = 0.05) -> bool:
    import shutil

    if not path.exists():
        return True
    for _ in range(attempts):
        try:
            shutil.rmtree(path)
            return True
        except OSError:
            time.sleep(delay)
    shutil.rmtree(path, ignore_errors=True)
    return not path.exists()


def open_blob_slot(workdir: Path, slot: str) -> int:
    """Open blobs/<slot>.bin without following reparse points. Caller closes the fd.

    *slot* must be six digits. The parent computes this name; child-supplied
    paths are never used.
    """
    import re

    if not re.fullmatch(r"[0-9]{6}", slot):
        raise OSError("invalid blob slot")
    work = workdir.resolve()
    blob_dir = work / "blobs"
    if _is_reparse(blob_dir) or _is_reparse(work):
        raise OSError("blob directory is a reparse point")
    path = blob_dir / f"{slot}.bin"
    if path.parent.resolve() != blob_dir.resolve():
        raise OSError("blob path escaped blobs/")
    if _is_reparse(path):
        raise OSError("blob path is a reparse point / symlink")
    if not path.is_file() or _is_reparse(path):
        raise OSError("blob file missing or is a reparse point")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    return os.open(path, flags)
