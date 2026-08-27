"""Windows least-privilege launch for analyzer children.

Primary mechanism: AppContainer with no network capabilities, Job Object,
ACL-scoped workspace.

Fallback: restricted token + Low integrity + Job Object (filesystem is
degraded: user-ACL secrets are denied; Users/Everyone-readable files are not).

This is static parser containment, not a malware sandbox.
"""

from __future__ import annotations

import ctypes
import hashlib
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("wincontain is Windows-only")

from . import winjob
from .acl_prep import PROCESS_ACL_CACHE, apply_cached_grant
from .policy import IsolationPolicy
from .winacl import current_user_sid, grant_sid

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
userenv = ctypes.WinDLL("userenv", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009

TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ALL_FOR_RESTRICT = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES

DISABLE_MAX_PRIVILEGE = 0x1
SANDBOX_INERT = 0x2

TokenIntegrityLevel = 25
TokenIsAppContainer = 29
SE_GROUP_INTEGRITY = 0x00000020
SecurityImpersonation = 2
TokenPrimary = 1

WAIT_TIMEOUT = 0x00000102
STILL_ACTIVE = 259
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
HEAP_ZERO_MEMORY = 0x00000008

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
HANDLE_FLAG_INHERIT = 0x1

APPCONTAINER_NAME = "ExSoftware.Analyzer"
_GRANTED_PREFIXES: set[Path] = set()


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", ctypes.c_void_p),
        ("Capabilities", ctypes.c_void_p),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
kernel32.UpdateProcThreadAttribute.argtypes = [
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
kernel32.GetProcessHeap.restype = wintypes.HANDLE
kernel32.HeapAlloc.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_size_t]
kernel32.HeapAlloc.restype = ctypes.c_void_p
kernel32.HeapFree.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
kernel32.HeapFree.restype = wintypes.BOOL
kernel32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
kernel32.SetHandleInformation.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE

advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.CreateRestrictedToken.restype = wintypes.BOOL
advapi32.DuplicateTokenEx.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.DuplicateTokenEx.restype = wintypes.BOOL
advapi32.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
advapi32.SetTokenInformation.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
advapi32.GetTokenInformation.restype = wintypes.BOOL

userenv.CreateAppContainerProfile.restype = ctypes.c_long
userenv.CreateAppContainerProfile.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),
]
userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
advapi32.CreateProcessWithTokenW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.POINTER(PROCESS_INFORMATION),
]
advapi32.CreateProcessWithTokenW.restype = wintypes.BOOL


def _sid_from_string(sid: str) -> ctypes.c_void_p:
    ptr = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(ptr)):
        raise OSError(ctypes.get_last_error(), f"ConvertStringSidToSidW {sid}")
    return ptr


def appcontainer_sid() -> tuple[str, ctypes.c_void_p]:
    sid_ptr = ctypes.c_void_p()
    hr = userenv.CreateAppContainerProfile(
        APPCONTAINER_NAME,
        "ExSoftware analyzer",
        "Least-privilege static analyzer process",
        None,
        0,
        ctypes.byref(sid_ptr),
    )
    already = (hr & 0xFFFFFFFF) in {0x800700B7, 0x80071392, 0x80070050, 0x800700B7}
    if hr != 0 or not sid_ptr.value:
        sid_ptr = ctypes.c_void_p()
        hr = userenv.DeriveAppContainerSidFromAppContainerName(APPCONTAINER_NAME, ctypes.byref(sid_ptr))
        if hr != 0 or not sid_ptr.value:
            raise OSError(hr, f"AppContainer SID unavailable (create_hr_already={already})")
    string_sid = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(string_sid)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
    text = string_sid.value or ""
    kernel32.LocalFree(string_sid)
    return text, sid_ptr


def prepare_appcontainer_paths(workdir: Path, sid: str) -> list[str]:
    """Grant the AppContainer SID access to runtime paths it must read.

    The staged interpreter receives an inheritable ACE **before** files are
    copied, so this function must not recursively ``icacls /T`` that tree.
    A failed or timed-out grant is cached for the process so later probes do
    not wait through the same expensive failure again.
    """
    import tempfile

    from .winruntime import (
        acl_sid_marker_name,
        ensure_staged_cpython,
        extra_host_site_packages,
    )

    PROCESS_ACL_CACHE.raise_if_failed()
    granted: list[str] = []
    try:
        if not grant_sid(workdir, sid, "(OI)(CI)(F)", recursive=True):
            raise OSError(f"failed to grant AppContainer ACE on workspace {workdir}")
        granted.append(str(workdir))
        staged = ensure_staged_cpython(appcontainer_sid=sid)
        prefixes: list[Path] = [staged, *extra_host_site_packages()]
        cache_root = Path(tempfile.gettempdir()) / "exsoftware-isolate" / "acl-cache"
        cache_root.mkdir(parents=True, exist_ok=True)
        sid_key = hashlib.sha256(sid.encode("utf-8")).hexdigest()[:16]
        staged_resolved = staged.resolve()
        for prefix in prefixes:
            if not prefix.exists():
                continue
            resolved = prefix.resolve()
            prefix_key = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:16]
            key = f"{sid_key}-{prefix_key}"
            marker = cache_root / f"{key}.done"

            def do_grant(target: Path = resolved, staged_root: Path = staged_resolved) -> bool:
                # Staged runtime already inherited the ACE from the empty parent.
                if target == staged_root and (target / acl_sid_marker_name(sid)).is_file():
                    return True
                if target in _GRANTED_PREFIXES:
                    return True
                # Never recursively ACL a staged interpreter.
                recursive = target != staged_root
                return grant_sid(target, sid, "(OI)(CI)(RX)", recursive=recursive)

            apply_cached_grant(
                marker=marker,
                grant_fn=do_grant,
                cache=PROCESS_ACL_CACHE,
                key=key,
            )
            granted.append(str(resolved))
            _GRANTED_PREFIXES.add(resolved)
        return granted
    except OSError as exc:
        PROCESS_ACL_CACHE.record_failure(exc)
        raise


def _env_block(env: dict[str, str]) -> bytes:
    parts = [f"{key}={value}" for key, value in env.items()]
    return ("\0".join(parts) + "\0\0").encode("utf-16-le")


def _nul_handle() -> int:
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(sa)
    sa.bInheritHandle = True
    handle = kernel32.CreateFileW("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, ctypes.byref(sa), OPEN_EXISTING, 0, None)
    if handle in {0, INVALID_HANDLE_VALUE}:
        raise OSError(ctypes.get_last_error(), "CreateFileW NUL failed")
    return int(handle)


class WindowsChild:
    def __init__(self, info: PROCESS_INFORMATION, job: Any | None) -> None:
        self.hProcess = info.hProcess
        self.hThread = info.hThread
        self.pid = int(info.dwProcessId)
        self.returncode: int | None = None
        self._exsoftware_job = job
        self._handle = int(info.hProcess)

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        result = kernel32.WaitForSingleObject(self.hProcess, 0)
        if result == WAIT_TIMEOUT:
            return None
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(self.hProcess, ctypes.byref(code)):
            return None
        if int(code.value) == STILL_ACTIVE:
            return None
        self.returncode = int(code.value)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        # Poll loop rather than WaitForSingleObject(INFINITE/timeout). Some
        # AppContainer process handles do not honor WFSO timeouts reliably.
        deadline = None if timeout is None else (time.monotonic() + max(0.0, float(timeout)))
        while True:
            code = self.poll()
            if code is not None:
                return code
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(cmd="exsoftware-isolate-worker", timeout=timeout or 0)
            time.sleep(0.05)

    def kill(self) -> None:
        kernel32.TerminateProcess(self.hProcess, 1)

    def terminate(self) -> None:
        self.kill()

    def close(self) -> None:
        if self.hThread:
            kernel32.CloseHandle(self.hThread)
            self.hThread = None
        if self.hProcess:
            kernel32.CloseHandle(self.hProcess)
            self.hProcess = None


def _inherit_handle(handle: int) -> None:
    if not kernel32.SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT):
        raise OSError(ctypes.get_last_error(), "SetHandleInformation HANDLE_FLAG_INHERIT failed")


def _fill_startup(si: STARTUPINFOW, stdin_h: int, stdout_h: int, stderr_h: int, *, cb: int | None = None) -> None:
    si.cb = int(cb if cb is not None else ctypes.sizeof(STARTUPINFOW))
    si.dwFlags = STARTF_USESTDHANDLES
    si.hStdInput = stdin_h
    si.hStdOutput = stdout_h
    si.hStdError = stderr_h
    si.wShowWindow = 0
    _inherit_handle(stdin_h)
    _inherit_handle(stdout_h)
    _inherit_handle(stderr_h)


def launch_appcontainer(
    *,
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    stdout_handle: int,
    stderr_handle: int,
    job: Any,
) -> tuple[WindowsChild, dict[str, Any]]:
    sid_text, sid_ptr = appcontainer_sid()
    granted = prepare_appcontainer_paths(cwd, sid_text)
    caps = SECURITY_CAPABILITIES()
    caps.AppContainerSid = sid_ptr
    caps.Capabilities = None
    caps.CapabilityCount = 0

    size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    heap = kernel32.GetProcessHeap()
    attr = kernel32.HeapAlloc(heap, HEAP_ZERO_MEMORY, size.value)
    if not attr:
        raise OSError(ctypes.get_last_error(), "HeapAlloc attribute list failed")
    attr_ready = False
    stdin_h = None
    try:
        if not kernel32.InitializeProcThreadAttributeList(attr, 1, 0, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "InitializeProcThreadAttributeList failed")
        attr_ready = True
        if not kernel32.UpdateProcThreadAttribute(
            attr,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(caps),
            ctypes.sizeof(caps),
            None,
            None,
        ):
            raise OSError(ctypes.get_last_error(), "UpdateProcThreadAttribute SECURITY_CAPABILITIES failed")

        six = STARTUPINFOEXW()
        six.lpAttributeList = ctypes.c_void_p(attr)
        stdin_h = _nul_handle()
        # cb MUST remain sizeof(STARTUPINFOEXW). Overwriting it with STARTUPINFOW
        # makes CreateProcessW return ERROR_INVALID_PARAMETER (87).
        _fill_startup(
            six.StartupInfo,
            stdin_h,
            stdout_handle,
            stderr_handle,
            cb=ctypes.sizeof(STARTUPINFOEXW),
        )

        flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
        cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        env_block = ctypes.create_string_buffer(_env_block(env))
        info = PROCESS_INFORMATION()
        ok = kernel32.CreateProcessW(
            command[0],
            cmdline,
            None,
            None,
            True,
            flags,
            env_block,
            str(cwd),
            ctypes.byref(six),
            ctypes.byref(info),
        )
        err = ctypes.get_last_error()
        if not ok:
            raise OSError(err, "CreateProcessW AppContainer failed")
    finally:
        if attr_ready:
            kernel32.DeleteProcThreadAttributeList(attr)
        if attr:
            kernel32.HeapFree(heap, 0, attr)
        if stdin_h:
            kernel32.CloseHandle(stdin_h)
    child = WindowsChild(info, job)
    if job is not None:
        job.assign_handle(int(info.hProcess))
    kernel32.ResumeThread(info.hThread)
    meta = {
        "mechanism": "appcontainer",
        "appcontainer_sid": sid_text,
        "appcontainer_paths_granted": granted,
        "suspended_start": True,
        "pid": child.pid,
    }
    return child, meta


def _set_low_integrity(token: int) -> None:
    sid = _sid_from_string("S-1-16-4096")
    try:
        label = TOKEN_MANDATORY_LABEL()
        label.Label.Sid = sid
        label.Label.Attributes = SE_GROUP_INTEGRITY
        if not advapi32.SetTokenInformation(token, TokenIntegrityLevel, ctypes.byref(label), ctypes.sizeof(label)):
            raise OSError(ctypes.get_last_error(), "SetTokenInformation TokenIntegrityLevel failed")
    finally:
        kernel32.LocalFree(sid)


def launch_restricted_token(
    *,
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    stdout_handle: int,
    stderr_handle: int,
    job: Any,
) -> tuple[WindowsChild, dict[str, Any]]:
    process_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ALL_FOR_RESTRICT, ctypes.byref(process_token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    everyone = _sid_from_string("S-1-1-0")
    users = _sid_from_string("S-1-5-32-545")
    restricted = _sid_from_string("S-1-5-12")
    sids = (SID_AND_ATTRIBUTES * 3)()
    sids[0].Sid = everyone
    sids[1].Sid = users
    sids[2].Sid = restricted
    restricted_token = wintypes.HANDLE()
    try:
        if not advapi32.CreateRestrictedToken(
            process_token,
            DISABLE_MAX_PRIVILEGE | SANDBOX_INERT,
            0,
            None,
            0,
            None,
            3,
            sids,
            ctypes.byref(restricted_token),
        ):
            raise OSError(ctypes.get_last_error(), "CreateRestrictedToken failed")
        primary = wintypes.HANDLE()
        if not advapi32.DuplicateTokenEx(
            restricted_token,
            TOKEN_ALL_FOR_RESTRICT,
            None,
            SecurityImpersonation,
            TokenPrimary,
            ctypes.byref(primary),
        ):
            raise OSError(ctypes.get_last_error(), "DuplicateTokenEx failed")
        _set_low_integrity(int(primary.value))
        # Workspace must allow the restricting SIDs or the child cannot write response.json.
        grant_sid(cwd, "S-1-1-0", "(OI)(CI)(M)", recursive=True)
        si = STARTUPINFOW()
        stdin_h = _nul_handle()
        _fill_startup(si, stdin_h, stdout_handle, stderr_handle)
        flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT
        cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        env_block = ctypes.create_string_buffer(_env_block(env))
        info = PROCESS_INFORMATION()
        ok = advapi32.CreateProcessWithTokenW(
            primary,
            0,
            command[0],
            cmdline,
            flags,
            env_block,
            str(cwd),
            ctypes.byref(si),
            ctypes.byref(info),
        )
        err = ctypes.get_last_error()
        kernel32.CloseHandle(stdin_h)
        kernel32.CloseHandle(primary)
        kernel32.CloseHandle(restricted_token)
        if not ok:
            raise OSError(err, "CreateProcessWithTokenW failed")
        child = WindowsChild(info, job)
        if job is not None:
            job.assign_handle(int(info.hProcess))
        kernel32.ResumeThread(info.hThread)
        return child, {
            "mechanism": "restricted_token",
            "integrity_level": "low",
            "restricting_sids": ["S-1-1-0", "S-1-5-32-545", "S-1-5-12"],
            "suspended_start": True,
            "pid": child.pid,
            "current_user_sid": current_user_sid(),
        }
    finally:
        kernel32.CloseHandle(process_token)
        kernel32.LocalFree(everyone)
        kernel32.LocalFree(users)
        kernel32.LocalFree(restricted)


def query_child_token(child: WindowsChild) -> dict[str, Any]:
    token = wintypes.HANDLE()
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = child.hProcess
    if not advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
        return {"token_query": False, "error": ctypes.get_last_error()}
    try:
        info: dict[str, Any] = {"token_query": True}
        is_ac = wintypes.DWORD()
        needed = wintypes.DWORD()
        if advapi32.GetTokenInformation(token, TokenIsAppContainer, ctypes.byref(is_ac), 4, ctypes.byref(needed)):
            info["token_is_appcontainer"] = bool(is_ac.value)
        return info
    finally:
        kernel32.CloseHandle(token)


def apply_policy_from_launch(policy: IsolationPolicy, meta: dict[str, Any], job: Any) -> None:
    policy.mechanism = meta.get("mechanism") or "none"
    policy.process_boundary = "enforced"
    policy.wall_clock = "enforced"
    policy.output_limit = "enforced"
    policy.temporary_storage = "enforced"
    job_assigned = bool(job and getattr(job, "assigned", False))
    policy.evidence["job_assigned"] = job_assigned
    policy.evidence.update({k: v for k, v in meta.items() if k != "appcontainer_paths_granted"})
    if job_assigned:
        limits = getattr(job, "limits_applied", {}) or {}
        policy.process_tree_limit = "enforced"
        if limits.get("active_process_limit") == 1:
            policy.process_creation = "enforced"
            policy.reasons["process_creation"] = "Job ActiveProcessLimit=1 denies CreateProcess"
        elif limits.get("active_process_limit"):
            policy.process_creation = "degraded"
            policy.reasons["process_creation"] = "Job limits process count; creation is not fully denied"
        else:
            policy.process_creation = "degraded"
            policy.reasons["process_creation"] = "Job assigned without ActiveProcessLimit; descendants are killed, not prevented"
        if limits.get("job_memory_bytes"):
            policy.memory_limit = "enforced"
        else:
            policy.memory_limit = "unsupported"
            policy.reasons["memory_limit"] = "Job memory limit was not applied"
        if limits.get("job_cpu_seconds"):
            policy.cpu_limit = "enforced"
        else:
            policy.cpu_limit = "unsupported"
            policy.reasons["cpu_limit"] = "Job CPU limit was not applied"
    else:
        policy.process_tree_limit = "degraded"
        policy.process_creation = "degraded"
        policy.memory_limit = "unsupported"
        policy.cpu_limit = "unsupported"
        policy.reasons["process_tree_limit"] = "Job Object was not assigned; relying on taskkill /T"
    if policy.mechanism == "appcontainer" and meta.get("token_is_appcontainer"):
        policy.filesystem_restriction = "enforced"
        # Zero network capabilities block outbound connect. Bind/listen on loopback
        # may still succeed at the Winsock API; usable host↔worker loopback traffic
        # is a separate WFP property. Per-run claims stay degraded until
        # security-status live probes confirm communication denial.
        policy.network_restriction = "degraded"
        policy.reasons["filesystem_restriction"] = (
            "AppContainer token confirmed; host files outside granted paths return Permission denied"
        )
        policy.reasons["network_restriction"] = (
            "AppContainer with zero network capabilities; outbound connect is blocked. "
            "Bind/listen may still succeed; usable host↔worker loopback requires separate "
            "live evidence (see security-status host→worker probe)"
        )
    elif policy.mechanism == "appcontainer":
        policy.filesystem_restriction = "degraded"
        policy.network_restriction = "degraded"
        policy.reasons["filesystem_restriction"] = "AppContainer launch succeeded but TokenIsAppContainer was not confirmed"
        policy.reasons["network_restriction"] = "AppContainer launch succeeded but TokenIsAppContainer was not confirmed"
    elif policy.mechanism == "restricted_token":
        policy.filesystem_restriction = "degraded"
        policy.network_restriction = "unsupported"
        policy.reasons["filesystem_restriction"] = (
            "Restricted token denies objects that do not grant Everyone/Users; "
            "files with Users/Everyone ACEs remain readable"
        )
        policy.reasons["network_restriction"] = "Restricted tokens do not block sockets"
    else:
        policy.filesystem_restriction = "unsupported"
        policy.network_restriction = "unsupported"
        policy.reasons["filesystem_restriction"] = "No restricted token or AppContainer"
        policy.reasons["network_restriction"] = "No network isolation mechanism applied"
