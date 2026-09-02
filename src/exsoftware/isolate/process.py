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


def host_site_package_dirs() -> list[Path]:
    """Existing host site-packages directories the isolated child must import from.

    Windows uses ``Lib/site-packages``; Unix uses ``lib/pythonX.Y/site-packages``
    (and Debian ``dist-packages``). Editable/user installs may also live under
    the user site. ``site.getsitepackages()`` sometimes returns the interpreter
    prefix itself (notably on Windows CI images); those are normalized to the
    real site-packages directory when present.
    """
    import site

    ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    candidates: list[Path] = []
    for prefix in (Path(sys.prefix), Path(sys.base_prefix)):
        candidates.extend(
            [
                prefix / "Lib" / "site-packages",
                prefix / "lib" / ver / "site-packages",
                prefix / "lib" / "site-packages",
                prefix / "lib" / ver / "dist-packages",
                prefix / "local" / "lib" / ver / "dist-packages",
                prefix / "local" / "lib" / ver / "site-packages",
                prefix,
            ]
        )
    try:
        for item in site.getsitepackages():
            candidates.append(Path(item))
    except (AttributeError, OSError):
        pass
    try:
        user_site = site.getusersitepackages()
        if user_site:
            candidates.append(Path(user_site))
    except (AttributeError, OSError):
        pass

    found: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = _normalize_site_packages_dir(candidate, ver)
        if normalized is None:
            continue
        try:
            resolved = str(normalized.resolve())
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        found.append(Path(resolved))
    return found


def _normalize_site_packages_dir(path: Path, ver: str) -> Path | None:
    """Return a concrete site-/dist-packages directory, or None."""
    try:
        if not path.exists():
            return None
    except OSError:
        return None
    name = path.name.lower()
    if name in {"site-packages", "dist-packages"}:
        return path if path.is_dir() else None
    for child in (
        path / "Lib" / "site-packages",
        path / "lib" / ver / "site-packages",
        path / "lib" / ver / "dist-packages",
        path / "lib" / "site-packages",
        path / "lib" / "dist-packages",
    ):
        try:
            if child.is_dir():
                return child
        except OSError:
            continue
    return None


def pythonpath_for_child() -> str:
    parts: list[str]
    if sys.platform == "win32":
        from .winruntime import staged_python_root

        # Staged Lib/site-packages contains a copy of exsoftware plus interpreter
        # site-packages. Prefer it over the live src tree so AppContainer does not
        # need an ACE on the developer checkout (often a subst drive).
        staged_site = staged_python_root() / "Lib" / "site-packages"
        parts = [str(staged_site)]
    else:
        src = str(Path(__file__).resolve().parents[2])
        parts = [src]
        for site_dir in host_site_package_dirs():
            text = str(site_dir)
            if text not in parts:
                parts.append(text)
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
        env.update(
            {
                "SystemRoot": system_root,
                "SYSTEMROOT": system_root,
                "WINDIR": os.environ.get("WINDIR") or system_root,
                "PYTHONHOME": python_dir,
                "PATH": os.pathsep.join(windows_child_path_entries(python_exe, system_root)),
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


def windows_child_path_entries(python_exe: Path, system_root: str) -> list[str]:
    from .winruntime import child_path_entries

    return [
        *child_path_entries(python_exe),
        str(Path(system_root) / "System32"),
        str(Path(system_root) / "System32" / "Wbem"),
    ]


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
    try:
        stdout.start()
        stderr.start()
    except Exception as exc:
        policy.fail("output_limit", f"Bounded stdout/stderr setup failed: {exc}")
        raise
    policy.establish("output_limit", "Bounded stdout/stderr drainers started")
    try:
        if sys.platform == "win32":
            child, launch_meta = _spawn_windows(command, workdir, env, policy, stdout, stderr)
        else:
            child, launch_meta = _spawn_unix(command, workdir, env, policy, stdout, stderr)
    except Exception as exc:
        policy.fail("process_boundary", f"Worker process creation failed: {exc}")
        policy.fail("wall_clock", f"No worker process was returned for timeout enforcement: {exc}")
        raise
    policy.establish("process_boundary", "Worker process created and retained by the parent")
    policy.establish("wall_clock", "Parent retained the worker process for timeout and termination")
    meta.update(launch_meta)
    return child, meta


def create_output_streams(policy: IsolationPolicy) -> tuple[BoundedStream, BoundedStream]:
    """Create both bounded pipes without claiming enforcement before drain starts."""
    stdout: BoundedStream | None = None
    try:
        stdout = BoundedStream(limit=policy.max_output_bytes)
        stderr = BoundedStream(limit=policy.max_output_bytes)
        return stdout, stderr
    except Exception as exc:
        policy.fail("output_limit", f"Bounded stdout/stderr pipe creation failed: {exc}")
        if stdout is not None:
            stdout.finish()
        raise


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

    allow = [
        Path(sys.prefix),
        Path(sys.base_prefix),
        Path(sys.executable).resolve().parent,
        Path(__file__).resolve().parents[2],
        *host_site_package_dirs(),
    ]
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
        start_new_session=True,
        preexec_fn=preexec,
    )
    stdout.close_write()
    stderr.close_write()
    proc._exsoftware_job = None  # type: ignore[attr-defined]
    # Popen returning means the parent-established session exists. Landlock,
    # netns, and rlimit still run in preexec and are not parent-verified.
    landlock = bool(support.get("landlock"))
    unshare = bool(support.get("unshare_net"))
    rlimit = bool(support.get("rlimit"))
    apply_unix_policy(
        policy,
        unshare_applied=unshare,
        landlock_applied=landlock,
        rlimit_cpu=rlimit,
        rlimit_as=rlimit,
        session_established=True,
    )
    policy.mechanism = "unix-preexec"
    return proc, {
        "mechanism": policy.mechanism,
        "pid": proc.pid,
        "process_group": True,
        "start_new_session": True,
        "unix_support": support,
    }


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
