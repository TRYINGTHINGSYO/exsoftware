"""Requested vs observed isolation capabilities.

States are only ``enforced``, ``degraded``, ``unsupported``, or ``failed``.
A protection is never reported as enforced merely because an API returned success
without a live process actually holding the restriction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

CapabilityState = Literal["enforced", "degraded", "unsupported", "failed"]

CAPABILITIES = (
    "process_boundary",
    "process_tree_limit",
    "filesystem_restriction",
    "network_restriction",
    "memory_limit",
    "cpu_limit",
    "wall_clock",
    "output_limit",
    "temporary_storage",
    "process_creation",
)


@dataclass
class IsolationPolicy:
    """What we *want*, plus what a live child actually received."""

    timeout_seconds: float = 60.0
    max_result_bytes: int = 16 * 1024 * 1024
    max_output_bytes: int = 64 * 1024
    max_memory_bytes: int | None = 1024 * 1024 * 1024
    max_cpu_seconds: float | None = None
    max_processes: int = 1
    isolate_analyzers: bool = True

    mechanism: str = "none"
    sandbox: bool = False
    containment: str = "static-parser"

    process_boundary: CapabilityState = "unsupported"
    process_tree_limit: CapabilityState = "unsupported"
    filesystem_restriction: CapabilityState = "unsupported"
    network_restriction: CapabilityState = "unsupported"
    memory_limit: CapabilityState = "unsupported"
    cpu_limit: CapabilityState = "unsupported"
    wall_clock: CapabilityState = "unsupported"
    output_limit: CapabilityState = "unsupported"
    temporary_storage: CapabilityState = "unsupported"
    process_creation: CapabilityState = "unsupported"

    reasons: dict[str, str] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_limits(cls, limits: Any) -> IsolationPolicy:
        cpu = getattr(limits, "max_child_cpu_seconds", None)
        timeout = float(getattr(limits, "analyzer_timeout_seconds", 60.0) or 60.0)
        return cls(
            timeout_seconds=timeout,
            max_result_bytes=int(getattr(limits, "max_result_bytes", 16 * 1024 * 1024)),
            max_output_bytes=int(getattr(limits, "max_output_bytes", 64 * 1024)),
            max_memory_bytes=getattr(limits, "max_child_memory_bytes", 1024 * 1024 * 1024),
            max_cpu_seconds=cpu if cpu is not None else timeout,
            max_processes=int(getattr(limits, "max_child_processes", 1) or 1),
            isolate_analyzers=bool(getattr(limits, "isolate_analyzers", True)),
        )

    def capabilities(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in CAPABILITIES}

    def establish(self, capability: str, reason: str) -> None:
        """Record a protection only after the parent established it."""
        if capability not in CAPABILITIES:
            raise ValueError(f"unknown isolation capability: {capability}")
        setattr(self, capability, "enforced")
        self.reasons[capability] = reason

    def fail(self, capability: str, reason: str) -> None:
        """Record that setup was attempted but did not establish a protection."""
        if capability not in CAPABILITIES:
            raise ValueError(f"unknown isolation capability: {capability}")
        setattr(self, capability, "failed")
        self.reasons[capability] = reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "sandbox": False,
            "containment": self.containment,
            "capabilities": self.capabilities(),
            "reasons": dict(self.reasons),
            "evidence": dict(self.evidence),
            "limits": {
                "timeout_seconds": self.timeout_seconds,
                "max_result_bytes": self.max_result_bytes,
                "max_output_bytes": self.max_output_bytes,
                "max_memory_bytes": self.max_memory_bytes,
                "max_cpu_seconds": self.max_cpu_seconds,
                "max_processes": self.max_processes,
            },
        }
