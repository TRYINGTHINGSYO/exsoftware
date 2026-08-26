"""Declarative analyzer eligibility.

Trusted parent code. Reads only declarative attributes on AnalyzerSpec (or a
compatible object). Does not instantiate analyzers and does not call
analyzer-owned methods. Does not import analyzer implementation modules.
"""

from __future__ import annotations

from typing import Any


def is_eligible(analyzer: Any, identity: Any) -> bool:
    """Return True if *identity* matches the analyzer's declared types/families.

    ``detected_types is None`` and ``detected_families is None`` means always
    eligible (identity/hashes/strings and similar).
    """
    types = getattr(analyzer, "detected_types", None)
    families = getattr(analyzer, "detected_families", None)
    if types is None and families is None:
        return True
    if identity is None:
        return False
    detected_type = getattr(identity, "detected_type", None)
    detected_family = getattr(identity, "detected_family", None)
    if types is not None and detected_type in types:
        return True
    if families is not None and detected_family in families:
        return True
    return False


def skip_reason_for(analyzer: Any, identity: Any) -> str:
    detected = getattr(identity, "detected_type", None) if identity is not None else "unknown"
    return f"Not applicable to detected type '{detected}'."


def class_spec(analyzer: Any) -> dict[str, Any]:
    return {
        "id": getattr(analyzer, "name", None),
        "version": getattr(analyzer, "version", "1.0.0"),
        "title": getattr(analyzer, "title", getattr(analyzer, "name", "")),
        "timeout_seconds": getattr(analyzer, "timeout_seconds", None),
        "detected_types": _frozen_to_list(getattr(analyzer, "detected_types", None)),
        "detected_families": _frozen_to_list(getattr(analyzer, "detected_families", None)),
        "worker_module": getattr(analyzer, "worker_module", None),
        "worker_class": getattr(analyzer, "worker_class", None),
    }


def _frozen_to_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    return sorted(value)
