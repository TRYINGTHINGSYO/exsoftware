from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .identify import identify_bytes
from .limits import RecursionLimits

DEFAULT_MAX_BYTES = 64 * 1024 * 1024
HEAD_SAMPLE = 256 * 1024


@dataclass
class AnalysisContext:
    name: str
    source: str
    size: int
    data: bytes
    truncated: bool
    max_bytes: int
    path: Path | None = None
    identity: Any = None
    extra: dict[str, Any] = field(default_factory=dict)
    artifact_id: str | None = None
    investigation: Any = None
    depth: int = 0
    limits: RecursionLimits | None = None
    run_id: str | None = None

    @property
    def sample(self) -> bytes:
        return self.data[:HEAD_SAMPLE] if len(self.data) > HEAD_SAMPLE else self.data


def load_from_path(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> AnalysisContext:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Not a file: {resolved}")
    size = resolved.stat().st_size
    truncated = size > max_bytes
    with resolved.open("rb") as handle:
        data = handle.read(max_bytes if truncated else size)
    identity = identify_bytes(data, resolved.name, size=size)
    identity.path = str(resolved)
    identity.source = "path"
    return AnalysisContext(
        name=resolved.name,
        source="path",
        size=size,
        data=data,
        truncated=truncated,
        max_bytes=max_bytes,
        path=resolved,
        identity=identity,
    )


def load_from_bytes(
    data: bytes,
    *,
    name: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    extra: dict[str, Any] | None = None,
) -> AnalysisContext:
    size = len(data)
    truncated = size > max_bytes
    body = data[:max_bytes] if truncated else data
    identity = identify_bytes(body, name or "unnamed", size=size)
    identity.source = "bytes"
    return AnalysisContext(
        name=name or "unnamed",
        source="bytes",
        size=size,
        data=body,
        truncated=truncated,
        max_bytes=max_bytes,
        extra=extra or {},
        identity=identity,
    )
