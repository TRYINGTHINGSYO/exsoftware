from .base import Analyzer
from .eligibility import class_spec, is_eligible, skip_reason_for
from .registry import (
    ANALYZER_REGISTRY,
    AnalyzerSpec,
    all_specs,
    get_spec,
    iter_specs,
    register_spec,
)

# Historical name: declarative registry used by the trusted parent.
# This package __init__ does not import analyzer implementation modules.
ANALYZERS = ANALYZER_REGISTRY


def register(analyzer_cls: type[Analyzer]) -> type[Analyzer]:
    """Register from an already-imported class (tests / extensions).

    Prefer :func:`register_spec` when the trusted parent must avoid importing
    the implementation module.
    """
    spec = AnalyzerSpec(
        name=analyzer_cls.name,
        version=getattr(analyzer_cls, "version", "1.0.0"),
        title=getattr(analyzer_cls, "title", analyzer_cls.name),
        worker_module=analyzer_cls.__module__,
        worker_class=analyzer_cls.__name__,
        detected_types=getattr(analyzer_cls, "detected_types", None),
        detected_families=getattr(analyzer_cls, "detected_families", None),
        timeout_seconds=getattr(analyzer_cls, "timeout_seconds", None),
    )
    register_spec(spec)
    return analyzer_cls


def get_analyzer_class(name: str) -> type[Analyzer] | None:
    """Load one implementation by id. Intended for workers, not the parent."""
    from .loader import load_analyzer_by_id

    return load_analyzer_by_id(name)


__all__ = [
    "ANALYZERS",
    "ANALYZER_REGISTRY",
    "Analyzer",
    "AnalyzerSpec",
    "all_specs",
    "class_spec",
    "get_analyzer_class",
    "get_spec",
    "is_eligible",
    "iter_specs",
    "register",
    "register_spec",
    "skip_reason_for",
]
