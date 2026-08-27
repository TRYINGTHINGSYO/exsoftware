"""Spawn, monitor, terminate, and reap an isolated analyzer child."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .output import BoundedStream
from .policy import IsolationPolicy
from .protocol import PROTOCOL_NAME, PROTOCOL_VERSION
from .workspace import rmtree_retry


def worker_executable() -> str:
    """Avoid venv launchers that spawn a second process (breaks ActiveProcessLimit=1).

    On Windows, AppContainer children cannot read a machine-wide Python install
    (Administrators-owned). Launch the user-owned staged copy instead.
    """
    if sys.platform == "win32":
        try:
            from .winruntime import staged_python_executable

            staged = staged_python_executable()
            if staged.is_file():
                return str(staged)
        except OSError:
            pass
    base = getattr(sys, "_base_executable", None)
    if base and Path(base).is_file():
        return str(Path(base).resolve())
    return str(Path(sys.executable).resolve())


def pythonpath_for_child() -> str:
    parts: list[str]
    if sys.platform == "win32":
        from .winruntime import extra_host_site_packages, staged_python_root

        # Staged Lib/site-packages contains a copy of exsoftware plus interpreter
        # site-packages. Prefer it over the live src tree so AppContainer does not
        # need an ACE on the developer checkout (often a subst drive).
        staged_site = staged_python_root() / "Lib" / "site-packages"
        parts = [str(staged_site)]
        for site in extra_host_site_packages():
            if str(site) not in parts:
                parts.append(str(site))
    else:
        src = str(Path(__file__).resolve().parents[2])
        venv_site = str(Path(sys.prefix) / "Lib" / "site-packages")
        base_site = str(Path(sys.base_prefix) / "Lib" / "site-packages")
        parts = [src, venv_site, base_site]
    current = os.environ.get("PYTHONPATH", "")
    for item in current.split(os.pathsep):
        if item and item not in parts:
            parts.append(item)
    return os.pathsep.join(parts)


def child_env(*, test_mode: bool, workdir: Path) -> dict[str, str]:
    """Minimal environment. Do not copy the parent environment (secrets, paths)."""
    env: dict[str, str] = {
        "PYTHONPATH": pythonpath_for_child(),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1",
        "EXSOFTWARE_ISOLATE_WORKDIR": str(workdir),
        "EXSOFTWARE_ISOLATE_RESPONSE": str(workdir / "response.json"),
        "TEMP": str(workdir),
        "TMP": str(workdir),
        "TMPDIR": str(workdir),
        "HOME": str(workdir),
    }
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"
        python_exe = Path(worker_executable()).resolve()
        python_dir = str(python_exe.parent)
        from .winruntime import child_path_entries

        path_entries = child_path_entries(python_exe)
        env.update(
            {
                "SystemRoot": system_root,
                "SYSTEMROOT": system_root,
                "WINDIR": os.environ.get("WINDIR") or system_root,
                "PYTHONHOME": python_dir,
                "PATH": os.pathsep.join(
                    [
                        *path_entries,
                        str(Path(sys.prefix) / "Scripts"),
                        str(Path(system_root) / "System32"),
                        str(Path(system_root) / "System32" / "Wbem"),
                    ]
                ),
                "PATHEXT": os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
                "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64"),
                "NUMBER_OF_PROCESSORS": os.environ.get("NUMBER_OF_PROCESSORS", "1"),
                "COMSPEC": str(Path(system_root) / "System32" / "cmd.exe"),
                "USERPROFILE": str(workdir),
                "APPDATA": str(workdir),
                "LOCALAPPDATA": str(workdir),
            }
        )
    else:
        env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
        env["LANG"] = os.environ.get("LANG", "C.UTF-8")
        env["LC_ALL"] = "C.UTF-8"
        env["USER"] = "exsoftware-analyzer"
        env["LOGNAME"] = "exsoftware-analyzer"
    if test_mode:
        env["EXSOFTWARE_ISOLATE_TEST"] = "1"
    return env


def spawn_worker(
    *,
    workdir: Path,
    env: dict[str, str],
    policy: IsolationPolicy,
    stdout: BoundedStream,
    stderr: BoundedStream,
) -> tuple[Any, dict[str, Any]]:
    command = [worker_executable(), "-m", "exsoftware.isolate.worker", "--workdir", str(workdir)]
    meta: dict[str, Any] = {
        "platform": sys.platform,
        "protocol": PROTOCOL_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "sandbox": False,
    }
    stdout.start()
    stderr.start()
    if sys.platform == "win32":
        child, launch_meta = _spawn_windows(command, workdir, env, policy, stdout, stderr)
        meta.update(launch_meta)
        return child, meta
    child, launch_meta = _spawn_unix(command, workdir, env, policy, stdout, stderr)
    meta.update(launch_meta)
    return child, meta


def _spawn_windows(command, workdir, env, policy, stdout, stderr):
    from . import wincontain, winjob

    job = None
    try:
        job = winjob.WinJob(
            memory_bytes=policy.max_memory_bytes,
            active_process_limit=policy.max_processes,
            cpu_seconds=policy.max_cpu_seconds,
        )
    except OSError as exc:
        policy.reasons["job"] = str(exc)
        job = None
    errors: list[str] = []
    out_h = stdout.child_handle()
    err_h = stderr.child_handle()
    child = None
    launch_meta: dict[str, Any] = {}
    try:
        child, launch_meta = wincontain.launch_appcontainer(
            command=command,
            cwd=workdir,
            env=env,
            stdout_handle=out_h,
            stderr_handle=err_h,
            job=job,
        )
    except OSError as exc:
        errors.append(f"appcontainer: {exc}")
        try:
            child, launch_meta = wincontain.launch_restricted_token(
                command=command,
                cwd=workdir,
                env=env,
                stdout_handle=out_h,
                stderr_handle=err_h,
                job=job,
            )
        except OSError as exc2:
            errors.append(f"restricted_token: {exc2}")
            child, launch_meta = _spawn_windows_fallback(command, workdir, env, stdout, stderr, job)
            launch_meta["fallback_errors"] = errors
    stdout.close_write()
    stderr.close_write()
    if child is not None and launch_meta.get("mechanism") == "appcontainer":
        launch_meta.update(wincontain.query_child_token(child))
    wincontain.apply_policy_from_launch(policy, launch_meta, job)
    launch_meta["job_assigned"] = bool(job and getattr(job, "assigned", False))
    launch_meta["job_limits"] = dict(getattr(job, "limits_applied", {}) or {})
    if job and not getattr(job, "assigned", False):
        launch_meta["job_assign_error"] = getattr(job, "assign_error", None)
    child._exsoftware_job = job  # type: ignore[attr-defined]
    return child, launch_meta


def _spawn_windows_fallback(command, workdir, env, stdout, stderr, job):
    from . import winjob

    flags = winjob.creation_flags(suspended=True)
    proc = subprocess.Popen(
        command,
        cwd=str(workdir),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=stdout.child_fd,
        stderr=stderr.child_fd,
        close_fds=False,
        creationflags=flags,
    )
    assigned = False
    if job is not None:
        handle = getattr(proc, "_handle", None)
        if handle is not None:
            assigned = job.assign_handle(int(handle))
        else:
            assigned = job.assign_pid(proc.pid)
        job.assigned = assigned
    handle = int(getattr(proc, "_handle", 0) or 0) or None
    winjob.resume_process(proc.pid, process_handle=handle)
    proc._exsoftware_job = job  # type: ignore[attr-defined]
    return proc, {"mechanism": "job-only", "pid": proc.pid, "suspended_start": True, "job_assigned": assigned}


def _spawn_unix(command, workdir, env, policy, stdout, stderr):
    from .unixcontain import apply_unix_policy, describe_unix_support, unix_preexec

    allow = [Path(sys.prefix), Path(sys.base_prefix), Path(sys.executable).resolve().parent, Path(__file__).resolve().parents[2]]
    support = describe_unix_support()
    preexec = unix_preexec(policy, workdir, allow)
    proc = subprocess.Popen(
        command,
        cwd=str(workdir),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=stdout.child_fd,
        stderr=stderr.child_fd,
        close_fds=True,
        start_new_session=False,
        preexec_fn=preexec,
    )
    stdout.close_write()
    stderr.close_write()
    proc._exsoftware_job = None  # type: ignore[attr-defined]
    # Parent cannot observe preexec success. Map from kernel feature detection, not from a silent guess
    # that the restrict actually attached. security-status proves it. Per-run: unsupported unless probe env set.
    landlock = bool(support.get("landlock"))
    unshare = bool(support.get("unshare_net"))
    rlimit = bool(support.get("rlimit"))
    apply_unix_policy(
        policy,
        unshare_applied=unshare,
        landlock_applied=landlock,
        rlimit_cpu=rlimit,
        rlimit_as=rlimit,
    )
    if landlock:
        policy.reasons.setdefault(
            "filesystem_restriction",
            "Landlock attempted in preexec; treat as enforced only after security-status probe",
        )
        # Honest: feature exists so we apply it, but per-run we did not empirically probe.
        # The syscall is attempted. If available() was true, apply_landlock is called.
        # If apply fails, child still runs without landlock — that would overclaim.
        # Downgrade per-run FS/net to degraded when we cannot confirm.
        policy.filesystem_restriction = "degraded"
        policy.reasons["filesystem_restriction"] = (
            "Landlock is applied in preexec when available; this run did not empirically verify denial"
        )
    if unshare:
        policy.network_restriction = "degraded"
        policy.reasons["network_restriction"] = (
            "CLONE_NEWNET is attempted in preexec; this run did not empirically verify denial"
        )
    policy.mechanism = "unix-preexec"
    return proc, {"mechanism": policy.mechanism, "pid": proc.pid, "process_group": True, "unix_support": support}


def wait_or_timeout(proc: Any, timeout: float) -> int | None:
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def terminate_tree(proc: Any, *, escalate_after: float = 1.0) -> dict[str, Any]:
    log: dict[str, Any] = {"platform": sys.platform, "pid": getattr(proc, "pid", None), "steps": []}
    if proc.poll() is not None:
        log["already_exited"] = proc.returncode
        return log

    job = getattr(proc, "_exsoftware_job", None)
    if sys.platform == "win32":
        if job is not None:
            ok = job.terminate(1)
            log["steps"].append({"action": "TerminateJobObject", "ok": ok})
        if proc.poll() is None:
            _taskkill(proc.pid, log)
        if wait_or_timeout(proc, escalate_after) is None:
            try:
                proc.kill()
                log["steps"].append({"action": "kill", "ok": True})
            except OSError as exc:
                log["steps"].append({"action": "kill", "ok": False, "error": str(exc)})
            wait_or_timeout(proc, escalate_after)
        return log

    try:
        os.killpg(proc.pid, signal.SIGTERM)
        log["steps"].append({"action": "killpg-SIGTERM", "ok": True})
    except OSError as exc:
        log["steps"].append({"action": "killpg-SIGTERM", "ok": False, "error": str(exc)})
        try:
            proc.terminate()
            log["steps"].append({"action": "terminate", "ok": True})
        except OSError as exc2:
            log["steps"].append({"action": "terminate", "ok": False, "error": str(exc2)})
    if wait_or_timeout(proc, escalate_after) is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            log["steps"].append({"action": "killpg-SIGKILL", "ok": True})
        except OSError as exc:
            log["steps"].append({"action": "killpg-SIGKILL", "ok": False, "error": str(exc)})
            try:
                proc.kill()
                log["steps"].append({"action": "kill", "ok": True})
            except OSError as exc2:
                log["steps"].append({"action": "kill", "ok": False, "error": str(exc2)})
        wait_or_timeout(proc, escalate_after)
    return log


def _taskkill(pid: int, log: dict[str, Any]) -> None:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        completed = subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=10,
            creationflags=flags,
            check=False,
        )
        log["steps"].append({"action": "taskkill /F /T", "ok": completed.returncode == 0, "returncode": completed.returncode})
    except (OSError, subprocess.TimeoutExpired) as exc:
        log["steps"].append({"action": "taskkill /F /T", "ok": False, "error": str(exc)})


def close_job(proc: Any) -> None:
    job = getattr(proc, "_exsoftware_job", None)
    if job is not None:
        try:
            job.close()
        except OSError:
            pass
        proc._exsoftware_job = None
    closer = getattr(proc, "close", None)
    if callable(closer):
        try:
            closer()
        except OSError:
            pass


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        from . import winjob

        handle = winjob.kernel32.OpenProcess(winjob.SYNCHRONIZE | winjob.PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            winjob.kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            winjob.kernel32.GetExitCodeProcess.restype = wintypes.BOOL
            if not winjob.kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return int(code.value) == 259
        finally:
            winjob.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True
