"""Windows ACL helpers for analyzer workspaces. Parent-side only."""

from __future__ import annotations

import ctypes
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

from .acl_prep import acl_grant_succeeded, run_acl_command

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("winacl is Windows-only")

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

TOKEN_QUERY = 0x0008
TokenUser = 1
ERROR_INSUFFICIENT_BUFFER = 122
CREATE_NO_WINDOW = 0x08000000


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
advapi32.GetTokenInformation.restype = wintypes.BOOL
advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def current_user_sid() -> str:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TokenUser, buf, needed, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        user = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents
        string_sid = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(string_sid)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return string_sid.value or ""
        finally:
            kernel32.LocalFree(string_sid)
    finally:
        kernel32.CloseHandle(token)


def _icacls(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_acl_command(
        ["icacls", *args],
        runner=subprocess.run,
        extra_kwargs={
            "capture_output": True,
            "creationflags": CREATE_NO_WINDOW,
            "check": False,
        },
    )


def restrict_directory_to_current_user(path: Path) -> None:
    sid = current_user_sid()
    _icacls([str(path), "/inheritance:r", "/Q"])
    for ace in (f"*{sid}:(OI)(CI)(F)", "*S-1-5-18:(OI)(CI)(F)"):
        completed = _icacls([str(path), "/grant:r", ace, "/Q"])
        if completed.returncode != 0:
            raise OSError(completed.returncode, completed.stderr.decode("utf-8", "replace"))


def grant_sid(path: Path, sid: str, rights: str, *, recursive: bool = False) -> bool:
    """Grant an inheritable ACE. *rights* is an icacls mask such as ``(OI)(CI)(RX)``.

    Returns True only when icacls exits 0. Timeouts raise ``AclTimeoutError``
    (an ``OSError``) and must never be treated as success.
    """
    args = [str(path), "/grant", f"*{sid}:{rights}", "/C", "/Q"]
    if recursive:
        args.append("/T")
    completed = _icacls(args)
    return acl_grant_succeeded(returncode=completed.returncode, timed_out=False)
