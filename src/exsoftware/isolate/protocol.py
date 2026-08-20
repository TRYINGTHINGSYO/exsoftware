"""Parent/child analyzer isolation protocol.

JSON files on a controlled work directory. No pickle. No shared Python objects.

See docs/ISOLATE_PROTOCOL.md.
"""

from __future__ import annotations

from typing import Any, Literal

PROTOCOL_NAME = "exsoftware.isolate"
PROTOCOL_VERSION = 1
TEST_ENV = "EXSOFTWARE_ISOLATE_TEST"
RESPONSE_ENV = "EXSOFTWARE_ISOLATE_RESPONSE"
WORKDIR_ENV = "EXSOFTWARE_ISOLATE_WORKDIR"

AnalyzerRunStatus = Literal[
    "completed",
    "unsupported",
    "skipped",
    "failed",
    "timeout",
    "terminated",
]

STATUSES: frozenset[str] = frozenset(
    ("completed", "unsupported", "skipped", "failed", "timeout", "terminated")
)
SEVERITIES: frozenset[str] = frozenset(("info", "low", "medium", "high"))
CONFIDENCES: frozenset[str] = frozenset(("low", "medium", "high"))
CERTAINTIES: frozenset[str] = frozenset(
    ("observed", "derived", "inferred", "unknown", "not_analyzed")
)

# Failure reasons recorded on AnalyzerResult.details["reason"].
REASON_EXCEPTION = "exception"
REASON_CHILD_EXIT = "child_exited"
REASON_CHILD_CRASH = "child_crashed"
REASON_TIMEOUT = "timeout"
REASON_TERMINATED = "terminated"
REASON_INVALID_RESPONSE = "invalid_analyzer_response"
REASON_OVERSIZED = "oversized_analyzer_response"
REASON_EMPTY_RESPONSE = "empty_analyzer_response"
REASON_SPAWN_FAILED = "spawn_failed"


def request_template(
    *,
    analyzer_id: str,
    analyzer_version: str,
    artifact_id: str,
    input_path: str,
    input_sha256: str,
    input_size: int,
    identity: dict[str, Any],
    context: dict[str, Any],
    timeout_seconds: float,
    max_result_bytes: int,
    max_memory_bytes: int | None,
    max_cpu_seconds: float | None,
    max_child_processes: int,
) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer_id": analyzer_id,
        "analyzer_version": analyzer_version,
        "artifact_id": artifact_id,
        "input": {
            "kind": "file",
            "path": input_path,
            "sha256": input_sha256,
            "size": input_size,
        },
        "identity": identity,
        "context": context,
        "limits": {
            "timeout_seconds": timeout_seconds,
            "max_result_bytes": max_result_bytes,
            "max_memory_bytes": max_memory_bytes,
            "max_cpu_seconds": max_cpu_seconds,
            "max_child_processes": max_child_processes,
        },
    }
