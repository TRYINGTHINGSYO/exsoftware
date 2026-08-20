"""Exsoftware: deterministic static analysis that explains software."""

from .limits import RecursionLimits
from .models import Report
from .pipeline import analyze_bytes, analyze_path

__all__ = ["Report", "analyze_bytes", "analyze_path", "RecursionLimits"]
__version__ = "0.6.0"
