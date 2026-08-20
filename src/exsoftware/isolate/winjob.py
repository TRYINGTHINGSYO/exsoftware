"""Windows Job Object helpers for analyzer process-tree control.

This is parser-process containment, not a sandbox. Nested job assignment can
fail when the parent already lives in a restrictive job (common under some
IDE terminals). Callers must handle that and fall back to taskkill.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Any

if sys.platform != "win32":  # pragma: no cover - imported only on Windows
    raise ImportError("winjob is Windows-only")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

JobObjectExtendedLimitInformation = 9

JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400

CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
CREATE_BREAKAWAY_FROM_JOB = 0x01000000  # must not be set on analyzer children

THREAD_SUSPEND_RESUME = 0x0002
TH32CS_SNAPTHREAD = 0x00000004
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_INFORMATION = 0x0400
SYNCHRONIZE = 0x00100000


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
    ]


kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
kernel32.CreateJobObjectW.restype = wintypes.HANDLE
kernel32.SetInformationJobObject.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
]
kernel32.SetInformationJobObject.restype = wintypes.BOOL
kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateJobObject.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32First.restype = wintypes.BOOL
kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32Next.restype = wintypes.BOOL


def last_error() -> int:
    return ctypes.get_last_error()


class WinJob:
    def __init__(
        self,
        *,
        memory_bytes: int | None,
        active_process_limit: int,
        cpu_seconds: float | None,
    ) -> None:
        self.handle = kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(last_error(), "CreateJobObjectW failed")
        self.assigned = False
        self.assign_error: int | None = None
        self.limits_applied: dict[str, Any] = {
            "kill_on_job_close": True,
            "active_process_limit": None,
            "job_memory_bytes": None,
            "job_cpu_seconds": None,
        }
        self._configure(
            memory_bytes=memory_bytes,
            active_process_limit=active_process_limit,
            cpu_seconds=cpu_seconds,
        )

    def _configure(
        self,
        *,
        memory_bytes: int | None,
        active_process_limit: int,
        cpu_seconds: float | None,
    ) -> None:
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        if active_process_limit and active_process_limit > 0:
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.BasicLimitInformation.ActiveProcessLimit = int(active_process_limit)
            self.limits_applied["active_process_limit"] = int(active_process_limit)
        if memory_bytes and memory_bytes > 0:
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY
            info.JobMemoryLimit = int(memory_bytes)
            self.limits_applied["job_memory_bytes"] = int(memory_bytes)
        if cpu_seconds and cpu_seconds > 0:
            # 100-nanosecond units of *CPU* time, not wall clock.
            flags |= JOB_OBJECT_LIMIT_JOB_TIME
            info.BasicLimitInformation.PerJobUserTimeLimit = int(cpu_seconds * 10_000_000)
            self.limits_applied["job_cpu_seconds"] = float(cpu_seconds)
        info.BasicLimitInformation.LimitFlags = flags
        ok = kernel32.SetInformationJobObject(
            self.handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if ok:
            return
        # Retry without optional memory/CPU limits if the host rejects them.
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if active_process_limit and active_process_limit > 0:
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.BasicLimitInformation.ActiveProcessLimit = int(active_process_limit)
        info.BasicLimitInformation.LimitFlags = flags
        self.limits_applied["job_memory_bytes"] = None
        self.limits_applied["job_cpu_seconds"] = None
        ok = kernel32.SetInformationJobObject(
            self.handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            raise OSError(last_error(), "SetInformationJobObject failed")

    def assign_handle(self, process_handle: int) -> bool:
        ok = bool(kernel32.AssignProcessToJobObject(self.handle, process_handle))
        self.assigned = ok
        if not ok:
            self.assign_error = last_error()
        return ok

    def assign_pid(self, pid: int) -> bool:
        access = PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION | SYNCHRONIZE
        handle = kernel32.OpenProcess(access, False, pid)
        if not handle:
            self.assign_error = last_error()
            return False
        try:
            return self.assign_handle(handle)
        finally:
            kernel32.CloseHandle(handle)

    def terminate(self, exit_code: int = 1) -> bool:
        if not self.handle:
            return False
        return bool(kernel32.TerminateJobObject(self.handle, exit_code))

    def close(self) -> None:
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None


def resume_process_handle(process_handle: int) -> int:
    """Resume a CREATE_SUSPENDED process. Returns NTSTATUS (0 is success)."""
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    return int(ntdll.NtResumeProcess(process_handle))


def resume_process(pid: int, process_handle: int | None = None) -> int:
    """Resume threads of a CREATE_SUSPENDED process. Returns threads resumed."""
    if process_handle:
        status = resume_process_handle(process_handle)
        if status == 0:
            return 1
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == INVALID_HANDLE_VALUE or not snap:
        raise OSError(last_error(), "CreateToolhelp32Snapshot failed")
    resumed = 0
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        more = kernel32.Thread32First(snap, ctypes.byref(entry))
        while more:
            if entry.th32OwnerProcessID == pid:
                thread = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, entry.th32ThreadID)
                if thread:
                    try:
                        kernel32.ResumeThread(thread)
                        resumed += 1
                    finally:
                        kernel32.CloseHandle(thread)
            more = kernel32.Thread32Next(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return resumed


def creation_flags(*, suspended: bool) -> int:
    flags = CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    if suspended:
        flags |= CREATE_SUSPENDED
    return flags
