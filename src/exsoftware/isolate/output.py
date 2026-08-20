"""Bounded stdout/stderr capture so a child cannot flood the parent."""

from __future__ import annotations

import os
import threading
from typing import Any


class BoundedStream:
    def __init__(self, *, limit: int) -> None:
        self.limit = max(0, int(limit))
        self._read_fd, self._write_fd = os.pipe()
        os.set_inheritable(self._write_fd, True)
        os.set_inheritable(self._read_fd, False)
        self.captured = bytearray()
        self.truncated = False
        self.discarded = 0
        self._thread: threading.Thread | None = None
        self._closed = False

    @property
    def child_fd(self) -> int:
        return self._write_fd

    def child_handle(self) -> int:
        if os.name == "nt":
            import msvcrt

            return int(msvcrt.get_osfhandle(self._write_fd))
        return int(self._write_fd)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._drain, name="exsoftware-stdio", daemon=True)
        self._thread.start()

    def close_write(self) -> None:
        if self._write_fd >= 0:
            try:
                os.close(self._write_fd)
            except OSError:
                pass
            self._write_fd = -1

    def finish(self, timeout: float = 5.0) -> dict[str, Any]:
        self.close_write()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        if self._read_fd >= 0:
            try:
                os.close(self._read_fd)
            except OSError:
                pass
            self._read_fd = -1
        return {
            "captured_bytes": len(self.captured),
            "discarded_bytes": self.discarded,
            "truncated": self.truncated,
            "limit_bytes": self.limit,
            "preview": bytes(self.captured[:2048]).decode("utf-8", "replace"),
        }

    def _drain(self) -> None:
        while True:
            try:
                chunk = os.read(self._read_fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            remaining = self.limit - len(self.captured)
            if remaining > 0:
                self.captured.extend(chunk[:remaining])
                extra = chunk[remaining:]
            else:
                extra = chunk
            if extra:
                self.truncated = True
                self.discarded += len(extra)
