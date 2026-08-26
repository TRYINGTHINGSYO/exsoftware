"""Load analyzer implementation classes inside workers (or explicit test mode).

Trusted parent code must not call these helpers during normal isolated
analysis. Importing this module does not import analyzer implementations;
loading happens only when a function below is invoked.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from .registry import AnalyzerSpec, get_spec, iter_specs

if TYPE_CHECKING:
    from .base import Analyzer


def load_analyzer_class(spec: AnalyzerSpec) -> type[Analyzer]:
    module = importlib.import_module(spec.worker_module)
    cls = getattr(module, spec.worker_class)
    return cls


def load_analyzer_by_id(analyzer_id: str) -> type[Analyzer] | None:
    spec = get_spec(analyzer_id)
    if spec is None:
        return None
    return load_analyzer_class(spec)


def load_all_analyzer_classes() -> list[type[Analyzer]]:
    """Import every registered implementation. Worker/test helper only."""
    return [load_analyzer_class(spec) for spec in iter_specs()]
