from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RecursionLimits:
    """Hard safety bounds for archive recursion and analyzer runtime.

    These exist because archive members and parser inputs are attacker-controlled.
    They are not a sandbox.
    """

    enable_recursion: bool = True
    max_depth: int = 3
    max_member_count: int = 64
    max_total_expanded_bytes: int = 32 * 1024 * 1024
    max_member_bytes: int = 8 * 1024 * 1024
    max_compression_ratio: float = 100.0
    analyzer_timeout_seconds: float = 60.0
    max_zip_list_entries: int = 400
    isolate_analyzers: bool = True
    max_result_bytes: int = 16 * 1024 * 1024
    max_analyzer_workers: int = 4
    max_child_memory_bytes: int | None = 1024 * 1024 * 1024
    max_child_cpu_seconds: float | None = None
    max_child_processes: int = 1
    max_output_bytes: int = 64 * 1024
    max_workspace_bytes: int = 32 * 1024 * 1024
    max_blobs: int = 64

    def to_dict(self) -> dict:
        return {
            "enable_recursion": self.enable_recursion,
            "max_depth": self.max_depth,
            "max_member_count": self.max_member_count,
            "max_total_expanded_bytes": self.max_total_expanded_bytes,
            "max_member_bytes": self.max_member_bytes,
            "max_compression_ratio": self.max_compression_ratio,
            "analyzer_timeout_seconds": self.analyzer_timeout_seconds,
            "max_zip_list_entries": self.max_zip_list_entries,
            "isolate_analyzers": self.isolate_analyzers,
            "max_result_bytes": self.max_result_bytes,
            "max_analyzer_workers": self.max_analyzer_workers,
            "max_child_memory_bytes": self.max_child_memory_bytes,
            "max_child_cpu_seconds": self.max_child_cpu_seconds,
            "max_child_processes": self.max_child_processes,
            "max_output_bytes": self.max_output_bytes,
            "max_workspace_bytes": self.max_workspace_bytes,
            "max_blobs": self.max_blobs,
            "sandbox": False,
            "containment": "static-parser",
        }
