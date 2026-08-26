"""Deliberately broken analyzers for isolation tests.

Loaded only when EXSOFTWARE_ISOLATE_TEST=1. Never registered in ANALYZERS.
These are not malware samples. They do not execute submitted files.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from ..analyzers.base import Analyzer


class IsolateRaiseAnalyzer(Analyzer):
    name = "isolate_test.raise"
    title = "Test: raise"
    version = "1.0.0"

    def analyze(self, ctx):
        raise RuntimeError("synthetic analyzer exception")


class IsolateExitAnalyzer(Analyzer):
    name = "isolate_test.exit"
    title = "Test: sys.exit"
    version = "1.0.0"

    def analyze(self, ctx):
        sys.exit(17)


class IsolateHangAnalyzer(Analyzer):
    name = "isolate_test.hang"
    title = "Test: hang"
    version = "1.0.0"

    def analyze(self, ctx):
        while True:
            time.sleep(60)


class IsolateInvalidJsonAnalyzer(Analyzer):
    name = "isolate_test.invalid_json"
    title = "Test: invalid JSON"
    version = "1.0.0"

    def analyze(self, ctx):
        path = Path(os.environ["EXSOFTWARE_ISOLATE_RESPONSE"])
        path.write_text("this is not json {", encoding="utf-8")
        os._exit(0)


class IsolateOversizedAnalyzer(Analyzer):
    name = "isolate_test.oversized"
    title = "Test: oversized response"
    version = "1.0.0"

    def analyze(self, ctx):
        path = Path(os.environ["EXSOFTWARE_ISOLATE_RESPONSE"])
        pad = "A" * (2 * 1024 * 1024)
        path.write_text('{"pad":"' + pad + '"}', encoding="utf-8")
        os._exit(0)


class IsolateWrongProtocolAnalyzer(Analyzer):
    name = "isolate_test.wrong_protocol"
    title = "Test: wrong protocol"
    version = "1.0.0"

    def analyze(self, ctx):
        path = Path(os.environ["EXSOFTWARE_ISOLATE_RESPONSE"])
        path.write_text(
            '{"protocol":"not-exsoftware","protocol_version":99,"analyzer_id":"isolate_test.wrong_protocol",'
            '"analyzer_version":"1.0.0","status":"completed","result":{"name":"isolate_test.wrong_protocol",'
            '"title":"x","applies":true,"status":"completed","analyzer_version":"1.0.0","findings":[]}}',
            encoding="utf-8",
        )
        os._exit(0)


class IsolateSegfaultAnalyzer(Analyzer):
    name = "isolate_test.segfault"
    title = "Test: native crash"
    version = "1.0.0"

    def analyze(self, ctx):
        _synthetic_native_crash()
        return self.result(details={"failed": True, "reason": "crash_not_taken"})


class IsolateSpawnHangAnalyzer(Analyzer):
    name = "isolate_test.spawn_hang"
    title = "Test: spawn hanging child"
    version = "1.0.0"

    def analyze(self, ctx):
        pid_file = (ctx.extra or {}).get("pid_file")
        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(3600)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                close_fds=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return self.result(details={"spawned": False, "error": str(exc), "reason": "spawn_denied"})
        if pid_file:
            Path(pid_file).write_text(str(child.pid), encoding="utf-8")
        while True:
            time.sleep(60)


class IsolateReadOutsideAnalyzer(Analyzer):
    name = "isolate_test.read_outside"
    title = "Test: read host sentinel"
    version = "1.0.0"

    def analyze(self, ctx):
        target = (ctx.extra or {}).get("sentinel_read")
        details = {"target": target, "read_ok": False, "denied": False}
        try:
            text = Path(target).read_text(encoding="utf-8")
            details["read_ok"] = True
            details["data"] = text[:200]
        except OSError as exc:
            details["denied"] = True
            details["error"] = str(exc)
            details["errno"] = getattr(exc, "errno", None)
            details["winerror"] = getattr(exc, "winerror", None)
        return self.result(details=details)


class IsolateWriteOutsideAnalyzer(Analyzer):
    name = "isolate_test.write_outside"
    title = "Test: write host sentinel"
    version = "1.0.0"

    def analyze(self, ctx):
        target = (ctx.extra or {}).get("sentinel_write")
        details = {"target": target, "write_ok": False, "denied": False}
        try:
            Path(target).write_text("analyzer-wrote-this\n", encoding="utf-8")
            details["write_ok"] = True
        except OSError as exc:
            details["denied"] = True
            details["error"] = str(exc)
            details["winerror"] = getattr(exc, "winerror", None)
        return self.result(details=details)


class IsolateNetworkAnalyzer(Analyzer):
    name = "isolate_test.network"
    title = "Test: sockets"
    version = "1.0.0"

    def analyze(self, ctx):
        import socket

        extra = ctx.extra or {}
        host = extra.get("probe_host") or "127.0.0.1"
        port = extra.get("probe_port")
        host_v6 = extra.get("probe_host_v6") or "::1"
        port_v6 = extra.get("probe_port_v6")
        udp_port_v4 = extra.get("udp_probe_port_v4")
        udp_token_v4 = extra.get("udp_probe_token_v4")
        udp_port_v6 = extra.get("udp_probe_port_v6")
        udp_token_v6 = extra.get("udp_probe_token_v6")
        details: dict = {
            "connect_ok": False,
            "connect_v6_ok": False,
            "listen_ok": False,
            "listen_v6_ok": False,
            "external_connect_ok": False,
            "external_connect_v6_ok": False,
            "udp_localhost_send_ok": False,
            "udp_localhost_send_v6_ok": False,
            "denied": False,
        }
        if port is not None:
            try:
                with socket.create_connection((host, int(port)), timeout=1.0) as sock:
                    sock.sendall(b"x")
                details["connect_ok"] = True
            except OSError as exc:
                details["denied"] = True
                details["connect_error"] = str(exc)
                details["connect_errno"] = getattr(exc, "errno", None)
                details["connect_winerror"] = getattr(exc, "winerror", None)
        else:
            details["connect_skipped"] = True
        if port_v6 is not None:
            try:
                with socket.create_connection((host_v6, int(port_v6)), timeout=1.0) as sock:
                    sock.sendall(b"x")
                details["connect_v6_ok"] = True
            except OSError as exc:
                details["connect_v6_error"] = str(exc)
                details["connect_v6_errno"] = getattr(exc, "errno", None)
                details["connect_v6_winerror"] = getattr(exc, "winerror", None)
        else:
            details["connect_v6_skipped"] = True
        try:
            with socket.create_connection(("192.0.2.1", 80), timeout=1.0):
                details["external_connect_ok"] = True
        except OSError as exc:
            details["external_connect_error"] = str(exc)
            details["external_connect_errno"] = getattr(exc, "errno", None)
            details["external_connect_winerror"] = getattr(exc, "winerror", None)
        try:
            with socket.create_connection(("2001:db8::1", 80), timeout=1.0):
                details["external_connect_v6_ok"] = True
        except OSError as exc:
            details["external_connect_v6_error"] = str(exc)
            details["external_connect_v6_errno"] = getattr(exc, "errno", None)
            details["external_connect_v6_winerror"] = getattr(exc, "winerror", None)
        # Localhost UDP: parent-selected loopback endpoint + unique token.
        # TEST-NET sendto success/failure is not treated as containment evidence.
        if udp_port_v4 is not None and udp_token_v4:
            try:
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    udp.settimeout(1.0)
                    udp.sendto(str(udp_token_v4).encode("utf-8"), ("127.0.0.1", int(udp_port_v4)))
                    details["udp_localhost_send_ok"] = True
                finally:
                    udp.close()
            except OSError as exc:
                details["udp_localhost_send_error"] = str(exc)
                details["udp_localhost_send_errno"] = getattr(exc, "errno", None)
                details["udp_localhost_send_winerror"] = getattr(exc, "winerror", None)
        if udp_port_v6 is not None and udp_token_v6:
            try:
                udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                try:
                    udp6.settimeout(1.0)
                    udp6.sendto(str(udp_token_v6).encode("utf-8"), ("::1", int(udp_port_v6)))
                    details["udp_localhost_send_v6_ok"] = True
                finally:
                    udp6.close()
            except OSError as exc:
                details["udp_localhost_send_v6_error"] = str(exc)
                details["udp_localhost_send_v6_errno"] = getattr(exc, "errno", None)
                details["udp_localhost_send_v6_winerror"] = getattr(exc, "winerror", None)
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            details["listen_ok"] = True
            details["listen_port"] = srv.getsockname()[1]
            srv.close()
        except OSError as extra_exc:
            details["listen_error"] = str(extra_exc)
            details["listen_errno"] = getattr(extra_exc, "errno", None)
            details["listen_winerror"] = getattr(extra_exc, "winerror", None)
        try:
            srv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                if hasattr(socket, "IPV6_V6ONLY"):
                    srv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                srv6.bind(("::1", 0))
                srv6.listen(1)
                details["listen_v6_ok"] = True
                details["listen_v6_port"] = srv6.getsockname()[1]
            finally:
                srv6.close()
        except OSError as extra_exc:
            details["listen_v6_error"] = str(extra_exc)
            details["listen_v6_errno"] = getattr(extra_exc, "errno", None)
            details["listen_v6_winerror"] = getattr(extra_exc, "winerror", None)
        return self.result(details=details)


class IsolateNetworkListenAnalyzer(Analyzer):
    """Bind/listen and wait for an outside accept — used with a parent mid-flight connect.

    Writes ``network_listen_ready.json`` in the isolate workdir before accepting so
    the trusted parent can attempt a real host→worker connection.
    """

    name = "isolate_test.network_listen"
    title = "Test: listen and accept"
    version = "1.0.0"

    def analyze(self, ctx):
        import json
        import socket

        from ..isolate.protocol import WORKDIR_ENV

        extra = ctx.extra or {}
        wait_seconds = float(extra.get("listen_accept_seconds") or 6.0)
        workdir = os.environ.get(WORKDIR_ENV)
        details: dict = {
            "listen_ok": False,
            "listen_v6_ok": False,
            "accept_ok": False,
            "accept_v6_ok": False,
            "ready_written": False,
            "endpoints": [],
        }
        servers: list[tuple[Any, str, int]] = []
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = int(srv.getsockname()[1])
            servers.append((srv, "ipv4", port))
            details["listen_ok"] = True
            details["listen_port"] = port
            # Ready file carries family+port only; parent chooses 127.0.0.1 / ::1.
            details["endpoints"].append({"family": "ipv4", "port": port})
        except OSError as exc:
            details["listen_error"] = str(exc)
            details["listen_errno"] = getattr(exc, "errno", None)
            details["listen_winerror"] = getattr(exc, "winerror", None)
        try:
            srv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            if hasattr(socket, "IPV6_V6ONLY"):
                srv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            srv6.bind(("::1", 0))
            srv6.listen(1)
            port6 = int(srv6.getsockname()[1])
            servers.append((srv6, "ipv6", port6))
            details["listen_v6_ok"] = True
            details["listen_v6_port"] = port6
            details["endpoints"].append({"family": "ipv6", "port": port6})
        except OSError as exc:
            details["listen_v6_error"] = str(exc)
            details["listen_v6_errno"] = getattr(exc, "errno", None)
            details["listen_v6_winerror"] = getattr(exc, "winerror", None)

        if workdir and details["endpoints"]:
            ready_path = Path(workdir) / "network_listen_ready.json"
            ready_path.write_text(
                json.dumps(
                    {
                        "protocol": "exsoftware.network_listen_ready",
                        "protocol_version": 1,
                        "tcp": details["endpoints"],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            details["ready_written"] = True

        per_socket_wait = max(0.5, wait_seconds / max(len(servers), 1))
        for srv, family, _port in servers:
            try:
                srv.settimeout(per_socket_wait)
                conn, peer = srv.accept()
                try:
                    if family == "ipv6":
                        details["accept_v6_ok"] = True
                        details["accept_v6_peer"] = str(peer)
                    else:
                        details["accept_ok"] = True
                        details["accept_peer"] = str(peer)
                finally:
                    conn.close()
            except OSError as exc:
                key = "accept_v6_error" if family == "ipv6" else "accept_error"
                details[key] = str(exc)
            finally:
                try:
                    srv.close()
                except OSError:
                    pass
        return self.result(details=details)


class IsolateSpawnAnalyzer(Analyzer):
    name = "isolate_test.spawn"
    title = "Test: spawn process"
    version = "1.0.0"

    def analyze(self, ctx):
        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            child = subprocess.Popen(
                [sys.executable, "-c", "print('spawned')"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                close_fds=True,
            )
            child.wait(timeout=5)
            return self.result(details={"spawned": True, "returncode": child.returncode})
        except (OSError, subprocess.SubprocessError) as exc:
            return self.result(details={"spawned": False, "denied": True, "error": str(exc)})


class IsolateStdoutFloodAnalyzer(Analyzer):
    name = "isolate_test.stdout_flood"
    title = "Test: flood stdout"
    version = "1.0.0"

    def analyze(self, ctx):
        blob = "A" * 8192
        for _ in range(256):
            sys.stdout.write(blob)
            sys.stdout.flush()
        return self.result(details={"flooded": "stdout"})


class IsolateStderrFloodAnalyzer(Analyzer):
    name = "isolate_test.stderr_flood"
    title = "Test: flood stderr"
    version = "1.0.0"

    def analyze(self, ctx):
        blob = "B" * 8192
        for _ in range(256):
            sys.stderr.write(blob)
            sys.stderr.flush()
        return self.result(details={"flooded": "stderr"})


class IsolateSymlinkAnalyzer(Analyzer):
    name = "isolate_test.symlink"
    title = "Test: reparse response"
    version = "1.0.0"

    def analyze(self, ctx):
        workdir = Path(os.environ["EXSOFTWARE_ISOLATE_WORKDIR"])
        target = (ctx.extra or {}).get("sentinel_read")
        response = workdir / "response.json"
        details = {"symlink_ok": False, "denied": False}
        try:
            if response.exists():
                response.unlink()
            os.symlink(target, response)
            details["symlink_ok"] = True
        except OSError as exc:
            details["denied"] = True
            details["error"] = str(exc)
            details["winerror"] = getattr(exc, "winerror", None)
        if details["symlink_ok"]:
            os._exit(0)
        return self.result(details=details)


class IsolateOkAnalyzer(Analyzer):
    name = "isolate_test.ok"
    title = "Test: success"
    version = "1.0.0"

    def analyze(self, ctx):
        from ..models import Evidence, Finding

        return self.result(
            details={"ok": True, "analyzed_bytes": len(ctx.data), "name": ctx.name},
            findings=[
                Finding(
                    id="isolate_test.ok",
                    title="Isolation success fixture ran",
                    summary="The child analyzer process produced a valid AnalyzerResult.",
                    category="test",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["isolation", "test"],
                    evidence=[
                        Evidence(
                            kind="test",
                            summary="Controlled isolation fixture",
                            analyzer=self.name,
                            value=ctx.name,
                        )
                    ],
                )
            ],
        )


def _synthetic_native_crash() -> None:
    """Kill this process with a native abort. Not a malware sample.

    CPython on Windows often converts access-violation SEH into OSError, so
    RaiseException / null-pointer reads are not a reliable crash fixture there.
    abort() still terminates the child without returning an AnalyzerResult.
    """
    os.abort()


TEST_ANALYZERS: list[type[Analyzer]] = [
    IsolateRaiseAnalyzer,
    IsolateExitAnalyzer,
    IsolateHangAnalyzer,
    IsolateInvalidJsonAnalyzer,
    IsolateOversizedAnalyzer,
    IsolateWrongProtocolAnalyzer,
    IsolateSegfaultAnalyzer,
    IsolateSpawnHangAnalyzer,
    IsolateOkAnalyzer,
    IsolateReadOutsideAnalyzer,
    IsolateWriteOutsideAnalyzer,
    IsolateNetworkAnalyzer,
    IsolateNetworkListenAnalyzer,
    IsolateSpawnAnalyzer,
    IsolateStdoutFloodAnalyzer,
    IsolateStderrFloodAnalyzer,
    IsolateSymlinkAnalyzer,
]
