from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ..models import AnalyzerError, AnalyzerResult, Finding
from .eligibility import is_eligible

if TYPE_CHECKING:
    from ..context import AnalysisContext


class Analyzer(ABC):
    name: str
    title: str
    version: str = "1.0.0"
    timeout_seconds: float | None = None
    isolation: str = "subprocess"
    parser_libraries: tuple[str, ...] = ()
    # None/None = eligible for every artifact. Set frozensets to restrict.
    detected_types: frozenset[str] | None = None
    detected_families: frozenset[str] | None = None

    def applies(self, ctx: AnalysisContext) -> bool:
        """Child-side check. The trusted parent must not call this."""
        return is_eligible(type(self), ctx.identity)

    def skip_reason(self, ctx: AnalysisContext) -> str:
        detected = ctx.identity.detected_type if ctx.identity else "unknown"
        return f"Not applicable to detected type '{detected}'."

    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        raise NotImplementedError

    def result(
        self,
        *,
        details: dict | None = None,
        findings: list[Finding] | None = None,
        errors: list[AnalyzerError] | None = None,
        applies: bool = True,
        skipped: bool = False,
        skip_reason: str | None = None,
        status: str | None = None,
    ) -> AnalyzerResult:
        resolved_status = status
        if resolved_status is None:
            if skipped and not applies:
                resolved_status = "unsupported"
            elif skipped:
                resolved_status = "skipped"
            elif errors:
                resolved_status = "failed"
            else:
                resolved_status = "completed"
        return AnalyzerResult(
            name=self.name,
            title=self.title,
            applies=applies,
            skipped=skipped,
            skip_reason=skip_reason,
            details=details or {},
            findings=findings or [],
            errors=errors or [],
            status=resolved_status,  # type: ignore[arg-type]
            analyzer_version=self.version,
        )

    def skipped_result(self, ctx: AnalysisContext) -> AnalyzerResult:
        return self.result(
            applies=False,
            skipped=True,
            status="unsupported",
            skip_reason=self.skip_reason(ctx),
        )

    def failure(self, exc: BaseException) -> AnalyzerResult:
        return self.result(
            status="failed",
            errors=[
                AnalyzerError(
                    analyzer=self.name,
                    message=str(exc) or exc.__class__.__name__,
                    exception_type=exc.__class__.__name__,
                )
            ],
            details={"failed": True},
        )
