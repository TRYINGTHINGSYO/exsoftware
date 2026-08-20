"""Declarative analyzer eligibility.

Trusted parent code. Reads only class attributes. Does not instantiate analyzers
and does not call analyzer-owned methods.
"""

from __future__ import annotations

from typing import Any


def is_eligible(analyzer_cls: type, identity: Any) -> bool:
    """Return True if *identity* matches the analyzer's declared types/families.

    ``detected_types is None`` and ``detected_families is None`` means always
    eligible (identity/hashes/strings and similar).
    """
    types = getattr(analyzer_cls, "detected_types", None)
    families = getattr(analyzer_cls, "detected_families", None)
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


def skip_reason_for(analyzer_cls: type, identity: Any) -> str:
    detected = getattr(identity, "detected_type", None) if identity is not None else "unknown"
    return f"Not applicable to detected type '{detected}'."


def class_spec(analyzer_cls: type) -> dict[str, Any]:
    return {
        "id": analyzer_cls.name,
        "version": getattr(analyzer_cls, "version", "1.0.0"),
        "title": getattr(analyzer_cls, "title", analyzer_cls.name),
        "timeout_seconds": getattr(analyzer_cls, "timeout_seconds", None),
        "detected_types": _frozen_to_list(getattr(analyzer_cls, "detected_types", None)),
        "detected_families": _frozen_to_list(getattr(analyzer_cls, "detected_families", None)),
    }


def _frozen_to_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    return sorted(value)
