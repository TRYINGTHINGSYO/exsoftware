from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Literal

SCHEMA_VERSION = 1
SCHEMA_NAME = "exsoftware.report"
ENGINE_NAME = "exsoftware"
ENGINE_VERSION = "0.6.0"

Severity = Literal["info", "low", "medium", "high"]
Confidence = Literal["low", "medium", "high"]
Certainty = Literal["observed", "derived", "inferred", "unknown", "not_analyzed"]
AnalyzerStatus = Literal["completed", "unsupported", "skipped", "failed", "timeout", "terminated"]
ANALYZER_STATUSES: tuple[str, ...] = (
    "completed",
    "unsupported",
    "skipped",
    "failed",
    "timeout",
    "terminated",
)
RelationshipType = Literal[
    "CONTAINS",
    "EXTRACTED_FROM",
    "IMPORTS",
    "EMBEDS",
    "REFERENCES",
    "SIGNED_BY",
    "DEPENDS_ON",
    "LOADS",
    "LINKS_TO",
]


def _asdict_skip_none(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}


@dataclass
class Evidence:
    """Material supporting an observation or finding."""

    kind: str
    summary: str
    analyzer: str
    location: str | None = None
    value: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    id: str | None = None
    artifact_id: str | None = None
    analyzer_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "summary": self.summary,
            "location": self.location,
            "value": self.value,
            "analyzer_id": self.analyzer,
            "analyzer_version": self.analyzer_version,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        return cls(
            id=data.get("id"),
            artifact_id=data.get("artifact_id"),
            kind=data.get("kind", "unknown"),
            summary=data.get("summary", ""),
            analyzer=data.get("analyzer_id") or data.get("analyzer") or "unknown",
            analyzer_version=data.get("analyzer_version"),
            location=data.get("location"),
            value=data.get("value"),
            extra=dict(data.get("extra") or {}),
        )


@dataclass
class Observation:
    """A directly observed or explicitly qualified fact."""

    id: str
    artifact_id: str
    kind: str
    statement: str
    certainty: Certainty
    analyzer_id: str
    analyzer_version: str
    evidence_ids: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "statement": self.statement,
            "certainty": self.certainty,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "evidence_ids": list(self.evidence_ids),
            "data": dict(self.data),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Observation:
        return cls(
            id=data["id"],
            artifact_id=data["artifact_id"],
            kind=data.get("kind", "unknown"),
            statement=data.get("statement", ""),
            certainty=data.get("certainty", "observed"),
            analyzer_id=data.get("analyzer_id", "unknown"),
            analyzer_version=data.get("analyzer_version", "0.0.0"),
            evidence_ids=list(data.get("evidence_ids") or []),
            data=dict(data.get("data") or {}),
        )


@dataclass
class Finding:
    """Deterministic interpretation of observations. Not a malware verdict."""

    id: str
    title: str
    summary: str
    category: str
    severity: Severity
    confidence: Confidence
    analyzer: str
    evidence: list[Evidence] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    rule_id: str | None = None
    rule_version: str | None = None
    certainty: Certainty | None = None
    artifact_id: str | None = None
    analyzer_version: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    created_at: str | None = None
    legacy_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "legacy_id": self.legacy_id or self.id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "title": self.title,
            "summary": self.summary,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "certainty": self.certainty or "derived",
            "analyzer": self.analyzer,
            "analyzer_id": self.analyzer,
            "analyzer_version": self.analyzer_version,
            "artifact_id": self.artifact_id,
            "tags": list(self.tags),
            "evidence_ids": list(self.evidence_ids),
            "observation_ids": list(self.observation_ids),
            "created_at": self.created_at,
            "evidence": [item.to_dict() for item in self.evidence],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=data.get("id") or data.get("rule_id") or "unknown",
            legacy_id=data.get("legacy_id"),
            rule_id=data.get("rule_id"),
            rule_version=data.get("rule_version"),
            title=data.get("title", ""),
            summary=data.get("summary", ""),
            category=data.get("category", "unknown"),
            severity=data.get("severity", "info"),
            confidence=data.get("confidence", "medium"),
            certainty=data.get("certainty"),
            analyzer=data.get("analyzer_id") or data.get("analyzer") or "unknown",
            analyzer_version=data.get("analyzer_version"),
            artifact_id=data.get("artifact_id"),
            tags=list(data.get("tags") or []),
            evidence_ids=list(data.get("evidence_ids") or []),
            observation_ids=list(data.get("observation_ids") or []),
            created_at=data.get("created_at"),
            evidence=[Evidence.from_dict(item) for item in data.get("evidence") or []],
        )


@dataclass
class Relationship:
    id: str
    type: str
    source_id: str
    target_id: str
    certainty: Certainty
    analyzer_id: str
    analyzer_version: str
    evidence_ids: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "certainty": self.certainty,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "evidence_ids": list(self.evidence_ids),
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Relationship:
        return cls(
            id=data["id"],
            type=data["type"],
            source_id=data["source_id"],
            target_id=data["target_id"],
            certainty=data.get("certainty", "observed"),
            analyzer_id=data.get("analyzer_id", "unknown"),
            analyzer_version=data.get("analyzer_version", "0.0.0"),
            evidence_ids=list(data.get("evidence_ids") or []),
            extra=dict(data.get("extra") or {}),
        )


@dataclass
class Artifact:
    id: str
    kind: str
    content_id: str | None
    hashes: dict[str, str] = field(default_factory=dict)
    size: int | None = None
    names: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    detected_type: str | None = None
    detected_family: str | None = None
    detected_mime: str | None = None
    description: str | None = None
    complete: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def primary_name(self) -> str:
        return self.names[0] if self.names else self.id

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "content_id": self.content_id,
            "hashes": dict(self.hashes),
            "size": self.size,
            "names": list(self.names),
            "paths": list(self.paths),
            "detected_type": self.detected_type,
            "detected_family": self.detected_family,
            "detected_mime": self.detected_mime,
            "description": self.description,
            "complete": self.complete,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Artifact:
        return cls(
            id=data["id"],
            kind=data.get("kind", "file"),
            content_id=data.get("content_id"),
            hashes=dict(data.get("hashes") or {}),
            size=data.get("size"),
            names=list(data.get("names") or []),
            paths=list(data.get("paths") or []),
            detected_type=data.get("detected_type"),
            detected_family=data.get("detected_family"),
            detected_mime=data.get("detected_mime"),
            description=data.get("description"),
            complete=data.get("complete", True),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class AnalyzerError:
    analyzer: str
    message: str
    exception_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalyzerError:
        return cls(
            analyzer=data.get("analyzer", "unknown"),
            message=data.get("message", ""),
            exception_type=data.get("exception_type"),
        )


@dataclass
class AnalyzerResult:
    name: str
    title: str
    applies: bool
    skipped: bool = False
    skip_reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[AnalyzerError] = field(default_factory=list)
    duration_ms: float = 0.0
    status: AnalyzerStatus = "completed"
    analyzer_version: str = "1.0.0"
    artifact_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "analyzer_id": self.name,
            "analyzer_version": self.analyzer_version,
            "artifact_id": self.artifact_id,
            "applies": self.applies,
            "skipped": self.skipped,
            "status": self.status,
            "skip_reason": self.skip_reason,
            "duration_ms": round(self.duration_ms, 3),
            "errors": [err.to_dict() for err in self.errors],
            "finding_count": len(self.findings),
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalyzerResult:
        return cls(
            name=data.get("name") or data.get("analyzer_id") or "unknown",
            title=data.get("title", ""),
            applies=data.get("applies", True),
            skipped=data.get("skipped", False),
            skip_reason=data.get("skip_reason"),
            details=dict(data.get("details") or {}),
            errors=[AnalyzerError.from_dict(item) for item in data.get("errors") or []],
            duration_ms=float(data.get("duration_ms") or 0),
            status=data.get("status") or ("unsupported" if data.get("skipped") else "completed"),
            analyzer_version=data.get("analyzer_version", "1.0.0"),
            artifact_id=data.get("artifact_id"),
        )


@dataclass
class AnalyzerRun:
    id: str
    analyzer_id: str
    analyzer_version: str
    analyzer_title: str
    artifact_id: str
    status: AnalyzerStatus
    duration_ms: float = 0.0
    skip_reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    errors: list[AnalyzerError] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)

    def to_legacy_section(self) -> dict[str, Any]:
        return {
            "name": self.analyzer_id,
            "title": self.analyzer_title,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "artifact_id": self.artifact_id,
            "applies": self.status != "unsupported",
            "skipped": self.status in {"unsupported", "skipped"},
            "status": self.status,
            "skip_reason": self.skip_reason,
            "duration_ms": round(self.duration_ms, 3),
            "errors": [err.to_dict() for err in self.errors],
            "finding_count": len(self.finding_ids),
            "details": self.details,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.to_legacy_section()
        data.update(
            {
                "id": self.id,
                "finding_ids": list(self.finding_ids),
                "observation_ids": list(self.observation_ids),
            }
        )
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalyzerRun:
        return cls(
            id=data.get("id") or f"run:{data.get('analyzer_id', 'unknown')}",
            analyzer_id=data.get("analyzer_id") or data.get("name") or "unknown",
            analyzer_version=data.get("analyzer_version", "1.0.0"),
            analyzer_title=data.get("title") or data.get("analyzer_id") or "unknown",
            artifact_id=data.get("artifact_id") or "",
            status=data.get("status", "completed"),
            duration_ms=float(data.get("duration_ms") or 0),
            skip_reason=data.get("skip_reason"),
            details=dict(data.get("details") or {}),
            errors=[AnalyzerError.from_dict(item) for item in data.get("errors") or []],
            finding_ids=list(data.get("finding_ids") or []),
            observation_ids=list(data.get("observation_ids") or []),
        )


@dataclass
class FileIdentity:
    name: str
    path: str | None
    source: str
    extension: str
    size: int
    detected_type: str
    detected_family: str
    detected_mime: str
    description: str
    extension_matches: bool | None
    magic_offset: int
    magic_hex: str
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileIdentity:
        known = {item.name for item in fields(cls)}
        payload = {key: value for key, value in data.items() if key in known}
        return cls(**payload)


@dataclass
class Report:
    schema_version: int
    analyzed_at: str
    identity: FileIdentity
    overview: str
    next_steps: list[str]
    hashes: dict[str, str]
    findings: list[Finding]
    sections: list[AnalyzerResult]
    limits: dict[str, Any]
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    engine: dict[str, Any] = field(default_factory=dict)
    root_artifact_id: str | None = None
    artifacts: list[Artifact] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    evidence_store: list[Evidence] = field(default_factory=list)
    analyzer_runs: list[AnalyzerRun] = field(default_factory=list)
    composition: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_NAME,
            "schema_version": self.schema_version,
            "engine": dict(self.engine),
            "analyzed_at": self.analyzed_at,
            "root_artifact_id": self.root_artifact_id,
            "identity": self.identity.to_dict(),
            "overview": self.overview,
            "next_steps": list(self.next_steps),
            "hashes": dict(self.hashes),
            "capabilities": list(self.capabilities),
            "limits": dict(self.limits),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "relationships": [item.to_dict() for item in self.relationships],
            "observations": [item.to_dict() for item in self.observations],
            "evidence": [item.to_dict() for item in self.evidence_store],
            "findings": [finding.to_dict() for finding in self.findings],
            "analyzer_runs": [item.to_dict() for item in self.analyzer_runs],
            "analyzers": [section.to_dict() for section in self.sections],
            "composition": dict(self.composition) if self.composition else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Report:
        version = data.get("schema_version", 1)
        if isinstance(version, str):
            version = 1 if version in {"1", "1.0"} else version
        artifacts = [Artifact.from_dict(item) for item in data.get("artifacts") or []]
        evidence_store = [Evidence.from_dict(item) for item in data.get("evidence") or []]
        evidence_by_id = {item.id: item for item in evidence_store if item.id}
        findings = [Finding.from_dict(item) for item in data.get("findings") or []]
        for finding in findings:
            if not finding.evidence and finding.evidence_ids:
                finding.evidence = [evidence_by_id[eid] for eid in finding.evidence_ids if eid in evidence_by_id]
        sections = [AnalyzerResult.from_dict(item) for item in data.get("analyzers") or []]
        runs = [AnalyzerRun.from_dict(item) for item in data.get("analyzer_runs") or []]
        identity_data = data.get("identity") or {}
        return cls(
            schema_version=int(version) if str(version).isdigit() else 1,
            analyzed_at=data.get("analyzed_at", ""),
            identity=FileIdentity.from_dict(identity_data) if identity_data else FileIdentity(
                name="unknown", path=None, source="unknown", extension="", size=0,
                detected_type="unknown", detected_family="unknown", detected_mime="application/octet-stream",
                description="unknown", extension_matches=None, magic_offset=0, magic_hex="",
            ),
            overview=data.get("overview", ""),
            next_steps=list(data.get("next_steps") or []),
            hashes=dict(data.get("hashes") or {}),
            findings=findings,
            sections=sections,
            limits=dict(data.get("limits") or {}),
            capabilities=list(data.get("capabilities") or []),
            engine=dict(data.get("engine") or {}),
            root_artifact_id=data.get("root_artifact_id"),
            artifacts=artifacts,
            relationships=[Relationship.from_dict(item) for item in data.get("relationships") or []],
            observations=[Observation.from_dict(item) for item in data.get("observations") or []],
            evidence_store=evidence_store,
            analyzer_runs=runs,
            composition=dict(data["composition"]) if data.get("composition") else None,
        )
