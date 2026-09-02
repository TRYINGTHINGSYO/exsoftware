from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Iterable

from .content import content_id_from_digest, named_id
from .models import (
    AnalyzerError,
    AnalyzerResult,
    AnalyzerRun,
    Artifact,
    Evidence,
    Finding,
    Observation,
    Relationship,
)
from .rules.catalog import resolve_rule

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc


class Investigation:
    """In-memory graph for one analysis. JSON is the durable form."""

    def __init__(self) -> None:
        self.artifacts: dict[str, Artifact] = {}
        self.relationships: list[Relationship] = []
        self.observations: list[Observation] = []
        self.evidence: list[Evidence] = []
        self.findings: list[Finding] = []
        self.runs: list[AnalyzerRun] = []
        self.abandoned_runs: set[str] = set()
        self.limit_events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._counters = {"ev": 0, "obs": 0, "fnd": 0, "rel": 0, "run": 0, "stub": 0}

    def _next(self, prefix: str) -> str:
        self._counters[prefix] += 1
        return f"{prefix}-{self._counters[prefix]:04d}"

    def abandon(self, run_id: str | None) -> None:
        if run_id:
            with self._lock:
                self.abandoned_runs.add(run_id)

    def _active(self, run_id: str | None) -> bool:
        return not (run_id and run_id in self.abandoned_runs)

    def add_file_artifact(
        self,
        *,
        sha256: str,
        kind: str = "file",
        name: str | None = None,
        path: str | None = None,
        size: int | None = None,
        hashes: dict[str, str] | None = None,
        detected_type: str | None = None,
        detected_family: str | None = None,
        detected_mime: str | None = None,
        description: str | None = None,
        complete: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> Artifact:
        artifact_id = content_id_from_digest(sha256)
        with self._lock:
            existing = self.artifacts.get(artifact_id)
            if existing:
                if name and name not in existing.names:
                    existing.names.append(name)
                if path and path not in existing.paths:
                    existing.paths.append(path)
                if detected_type and not existing.detected_type:
                    existing.detected_type = detected_type
                    existing.detected_family = detected_family
                    existing.detected_mime = detected_mime
                    existing.description = description
                if hashes:
                    existing.hashes.update(hashes)
                if metadata:
                    existing.metadata.update(metadata)
                return existing
            artifact = Artifact(
                id=artifact_id,
                kind=kind,
                content_id=artifact_id,
                hashes=dict(hashes or {"sha256": sha256}),
                size=size,
                names=[name] if name else [],
                paths=[path] if path else [],
                detected_type=detected_type,
                detected_family=detected_family,
                detected_mime=detected_mime,
                description=description,
                complete=complete,
                metadata=dict(metadata or {}),
            )
            self.artifacts[artifact_id] = artifact
            return artifact

    def add_named_artifact(
        self,
        kind: str,
        value: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> Artifact:
        artifact_id = named_id(kind, value)
        with self._lock:
            existing = self.artifacts.get(artifact_id)
            if existing:
                if metadata:
                    existing.metadata.update(metadata)
                return existing
            artifact = Artifact(
                id=artifact_id,
                kind=kind,
                content_id=None,
                names=[value],
                complete=False,
                metadata={"value": value, **(metadata or {})},
            )
            self.artifacts[artifact_id] = artifact
            return artifact

    def add_stub_artifact(
        self,
        *,
        name: str,
        kind: str = "file",
        size: int | None = None,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> Artifact:
        with self._lock:
            artifact_id = f"unhashed:{self._next('stub')}:{name}"
            artifact = Artifact(
                id=artifact_id,
                kind=kind,
                content_id=None,
                size=size,
                names=[name],
                complete=False,
                metadata={"not_analyzed_reason": reason, **(metadata or {})},
            )
            self.artifacts[artifact_id] = artifact
            return artifact

    def add_evidence(
        self,
        *,
        artifact_id: str,
        kind: str,
        summary: str,
        analyzer_id: str,
        analyzer_version: str,
        location: str | None = None,
        value: str | None = None,
        extra: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> Evidence | None:
        with self._lock:
            if not self._active(run_id):
                return None
            item = Evidence(
                id=self._next("ev"),
                artifact_id=artifact_id,
                kind=kind,
                summary=summary,
                analyzer=analyzer_id,
                analyzer_version=analyzer_version,
                location=location,
                value=value,
                extra=dict(extra or {}),
            )
            self.evidence.append(item)
            return item

    def add_observation(
        self,
        *,
        artifact_id: str,
        kind: str,
        statement: str,
        analyzer_id: str,
        analyzer_version: str,
        certainty: str = "observed",
        evidence_ids: Iterable[str] | None = None,
        data: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> Observation | None:
        with self._lock:
            if not self._active(run_id):
                return None
            item = Observation(
                id=self._next("obs"),
                artifact_id=artifact_id,
                kind=kind,
                statement=statement,
                certainty=certainty,  # type: ignore[arg-type]
                analyzer_id=analyzer_id,
                analyzer_version=analyzer_version,
                evidence_ids=list(evidence_ids or []),
                data=dict(data or {}),
            )
            self.observations.append(item)
            return item

    def add_finding(
        self,
        *,
        artifact_id: str,
        analyzer_id: str,
        analyzer_version: str,
        title: str,
        summary: str,
        category: str,
        severity: str,
        confidence: str,
        certainty: str,
        rule_id: str,
        rule_version: str,
        evidence_ids: Iterable[str],
        observation_ids: Iterable[str],
        evidence: list[Evidence] | None = None,
        tags: Iterable[str] | None = None,
        legacy_id: str | None = None,
        created_at: str | None = None,
        run_id: str | None = None,
    ) -> Finding | None:
        with self._lock:
            if not self._active(run_id):
                return None
            item = Finding(
                id=self._next("fnd"),
                title=title,
                summary=summary,
                category=category,
                severity=severity,  # type: ignore[arg-type]
                confidence=confidence,  # type: ignore[arg-type]
                analyzer=analyzer_id,
                analyzer_version=analyzer_version,
                artifact_id=artifact_id,
                rule_id=rule_id,
                rule_version=rule_version,
                certainty=certainty,  # type: ignore[arg-type]
                evidence_ids=list(evidence_ids),
                observation_ids=list(observation_ids),
                evidence=list(evidence or []),
                tags=list(tags or []),
                legacy_id=legacy_id,
                created_at=created_at or datetime.now(tz=UTC).isoformat(),
            )
            self.findings.append(item)
            return item

    def add_relationship(
        self,
        type: str,
        source_id: str,
        target_id: str,
        *,
        analyzer_id: str,
        analyzer_version: str,
        certainty: str = "observed",
        evidence_ids: Iterable[str] | None = None,
        extra: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> Relationship | None:
        with self._lock:
            if not self._active(run_id):
                return None
            key = (type, source_id, target_id, tuple(sorted((extra or {}).items())))
            for existing in self.relationships:
                existing_key = (
                    existing.type,
                    existing.source_id,
                    existing.target_id,
                    tuple(sorted(existing.extra.items())),
                )
                if existing_key == key:
                    return existing
            item = Relationship(
                id=self._next("rel"),
                type=type,
                source_id=source_id,
                target_id=target_id,
                certainty=certainty,  # type: ignore[arg-type]
                analyzer_id=analyzer_id,
                analyzer_version=analyzer_version,
                evidence_ids=list(evidence_ids or []),
                extra=dict(extra or {}),
            )
            self.relationships.append(item)
            return item

    def begin_run(
        self,
        *,
        analyzer_id: str,
        analyzer_version: str,
        analyzer_title: str,
        artifact_id: str,
        status: str = "completed",
    ) -> AnalyzerRun:
        with self._lock:
            run = AnalyzerRun(
                id=self._next("run"),
                analyzer_id=analyzer_id,
                analyzer_version=analyzer_version,
                analyzer_title=analyzer_title,
                artifact_id=artifact_id,
                status=status,  # type: ignore[arg-type]
            )
            self.runs.append(run)
            return run

    def record_limit(self, code: str, message: str, extra: dict[str, Any] | None = None) -> None:
        with self._lock:
            self.limit_events.append({"code": code, "message": message, "extra": dict(extra or {})})

    def ingest_result(
        self,
        analyzer_id: str,
        analyzer_version: str,
        artifact_id: str,
        result: AnalyzerResult,
        run: AnalyzerRun,
    ) -> None:
        if not self._active(run.id):
            return
        run.status = result.status
        run.skip_reason = result.skip_reason
        run.details = result.details
        run.errors = list(result.errors)
        run.duration_ms = result.duration_ms
        run.artifact_id = artifact_id
        result.artifact_id = artifact_id
        result.analyzer_version = analyzer_version

        for finding in result.findings:
            ingested = self._ingest_finding(analyzer_id, analyzer_version, artifact_id, finding, run.id)
            if ingested:
                run.finding_ids.append(ingested.id)
                run.observation_ids.extend(ingested.observation_ids)
                finding.id = ingested.id
                finding.rule_id = ingested.rule_id
                finding.rule_version = ingested.rule_version
                finding.certainty = ingested.certainty
                finding.artifact_id = artifact_id
                finding.analyzer_version = analyzer_version
                finding.evidence_ids = ingested.evidence_ids
                finding.observation_ids = ingested.observation_ids
                finding.created_at = ingested.created_at
                finding.legacy_id = ingested.legacy_id
                finding.evidence = ingested.evidence

        self._emit_from_details(analyzer_id, analyzer_version, artifact_id, result, run.id)

    def _ingest_finding(
        self,
        analyzer_id: str,
        analyzer_version: str,
        artifact_id: str,
        finding: Finding,
        run_id: str,
    ) -> Finding | None:
        rule = resolve_rule(finding.legacy_id or finding.id, finding.rule_id, finding.rule_version)
        certainty = finding.certainty or rule.certainty
        evidence_ids: list[str] = []
        observation_ids: list[str] = []
        stored_evidence: list[Evidence] = []
        for raw in finding.evidence:
            ev = self.add_evidence(
                artifact_id=artifact_id,
                kind=raw.kind,
                summary=raw.summary,
                analyzer_id=analyzer_id,
                analyzer_version=analyzer_version,
                location=raw.location,
                value=raw.value,
                extra=raw.extra,
                run_id=run_id,
            )
            if ev is None or ev.id is None:
                continue
            evidence_ids.append(ev.id)
            stored_evidence.append(ev)
            obs = self.add_observation(
                artifact_id=artifact_id,
                kind=raw.kind,
                statement=raw.summary if not raw.value else f"{raw.summary}: {raw.value}",
                analyzer_id=analyzer_id,
                analyzer_version=analyzer_version,
                certainty="observed",
                evidence_ids=[ev.id],
                data={"location": raw.location, "value": raw.value},
                run_id=run_id,
            )
            if obs:
                observation_ids.append(obs.id)
        return self.add_finding(
            artifact_id=artifact_id,
            analyzer_id=analyzer_id,
            analyzer_version=analyzer_version,
            title=finding.title,
            summary=finding.summary,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            certainty=certainty,
            rule_id=rule.id,
            rule_version=rule.version,
            evidence_ids=evidence_ids,
            observation_ids=observation_ids,
            evidence=stored_evidence,
            tags=finding.tags,
            legacy_id=finding.legacy_id or finding.id,
            run_id=run_id,
        )

    def _emit_from_details(
        self,
        analyzer_id: str,
        analyzer_version: str,
        artifact_id: str,
        result: AnalyzerResult,
        run_id: str,
    ) -> None:
        details = result.details or {}
        if analyzer_id == "pe":
            for item in details.get("imports") or []:
                dll = item.get("dll")
                if not dll:
                    continue
                target = self.add_named_artifact("library", dll)
                ev = self.add_evidence(
                    artifact_id=artifact_id,
                    kind="import-table",
                    summary=f"PE import of {dll}",
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    value=dll,
                    extra={"functions": (item.get("functions") or [])[:40]},
                    run_id=run_id,
                )
                self.add_relationship(
                    "IMPORTS",
                    artifact_id,
                    target.id,
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    evidence_ids=[ev.id] if ev and ev.id else [],
                    extra={"function_count": item.get("count")},
                    run_id=run_id,
                )
            for path in details.get("pdb_paths") or []:
                target = self.add_named_artifact("path", path)
                self.add_relationship(
                    "REFERENCES",
                    artifact_id,
                    target.id,
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    extra={"kind": "pdb"},
                    run_id=run_id,
                )
            for item in _pe_import_features(details):
                raw_name = item.get("name") or "unknown"
                dll = item.get("dll") or "unknown"
                normalized_name = item.get("normalized_name")
                normalized_dll = item.get("normalized_dll")
                ev = self.add_evidence(
                    artifact_id=artifact_id,
                    kind="pe-import-function",
                    summary=f"PE import {dll}!{raw_name}",
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    location=f"import {dll}",
                    value=raw_name,
                    extra={
                        "dll": dll,
                        "normalized_dll": normalized_dll,
                        "normalized_name": normalized_name,
                        "import_kind": item.get("import_kind") or "name",
                        "ordinal": item.get("ordinal"),
                    },
                    run_id=run_id,
                )
                self.add_observation(
                    artifact_id=artifact_id,
                    kind="pe.import.function",
                    statement=f"PE imports {dll}!{raw_name}",
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    evidence_ids=[ev.id] if ev and ev.id else [],
                    data={
                        "dll": dll,
                        "normalized_dll": normalized_dll,
                        "name": raw_name,
                        "normalized_name": normalized_name,
                        "import_kind": item.get("import_kind") or "name",
                        "ordinal": item.get("ordinal"),
                    },
                    run_id=run_id,
                )
            for item in details.get("exported_functions") or []:
                raw_name = item.get("name") if isinstance(item, dict) else str(item)
                ev = self.add_evidence(
                    artifact_id=artifact_id,
                    kind="pe-export-function",
                    summary=f"PE export {raw_name}",
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    value=raw_name,
                    extra={
                        "normalized_name": item.get("normalized_name") if isinstance(item, dict) else None,
                        "ordinal": item.get("ordinal") if isinstance(item, dict) else None,
                    },
                    run_id=run_id,
                )
                self.add_observation(
                    artifact_id=artifact_id,
                    kind="pe.export.function",
                    statement=f"PE exports {raw_name}",
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    evidence_ids=[ev.id] if ev and ev.id else [],
                    data=dict(item) if isinstance(item, dict) else {"name": raw_name},
                    run_id=run_id,
                )
            manifest = details.get("manifest") or {}
            if manifest.get("present"):
                ev = self.add_evidence(
                    artifact_id=artifact_id,
                    kind="pe-manifest",
                    summary="PE manifest present",
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    value=str(manifest.get("requested_execution_level") or "requestedExecutionLevel unknown"),
                    extra=dict(manifest),
                    run_id=run_id,
                )
                self.add_observation(
                    artifact_id=artifact_id,
                    kind="pe.manifest",
                    statement="PE manifest is present",
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    evidence_ids=[ev.id] if ev and ev.id else [],
                    data=dict(manifest),
                    run_id=run_id,
                )
        elif analyzer_id == "strings":
            for item in details.get("urls") or []:
                url = item.get("url") if isinstance(item, dict) else str(item)
                host = item.get("host") if isinstance(item, dict) else None
                offset = item.get("offset") if isinstance(item, dict) else None
                target = self.add_named_artifact("url", url)
                ev = self.add_evidence(
                    artifact_id=artifact_id,
                    kind="string",
                    summary="URL string present in file bytes",
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    location=f"offset {offset}" if offset is not None else None,
                    value=url,
                    run_id=run_id,
                )
                self.add_relationship(
                    "REFERENCES",
                    artifact_id,
                    target.id,
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    evidence_ids=[ev.id] if ev and ev.id else [],
                    extra={"note": "String presence is not evidence of a runtime connection."},
                    run_id=run_id,
                )
                if host:
                    domain = self.add_named_artifact("domain", host.lower())
                    self.add_relationship(
                        "REFERENCES",
                        artifact_id,
                        domain.id,
                        analyzer_id=analyzer_id,
                        analyzer_version=analyzer_version,
                        certainty="observed",
                        run_id=run_id,
                    )
            for ip in details.get("ips") or []:
                target = self.add_named_artifact("ip", ip)
                self.add_relationship(
                    "REFERENCES",
                    artifact_id,
                    target.id,
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    extra={"note": "IPv4 literal in strings; may be a version number."},
                    run_id=run_id,
                )
        elif analyzer_id == "elf":
            for name in details.get("needed") or []:
                target = self.add_named_artifact("library", name)
                self.add_relationship(
                    "DEPENDS_ON",
                    artifact_id,
                    target.id,
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    run_id=run_id,
                )
        elif analyzer_id == "macho":
            for name in details.get("dylibs") or []:
                target = self.add_named_artifact("library", name)
                self.add_relationship(
                    "DEPENDS_ON",
                    artifact_id,
                    target.id,
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    run_id=run_id,
                )
        elif analyzer_id == "signature":
            for cert in details.get("certificates") or []:
                label = cert.get("subject") or cert.get("serial") or "certificate"
                target = self.add_named_artifact(
                    "certificate",
                    f"{cert.get('serial', '')}|{label}",
                    metadata=cert,
                )
                if label not in target.names:
                    target.names.append(label)
                self.add_relationship(
                    "SIGNED_BY",
                    artifact_id,
                    target.id,
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    extra={"trust_validated": False},
                    run_id=run_id,
                )
        elif analyzer_id == "script":
            for name in (details.get("python") or {}).get("imports") or []:
                target = self.add_named_artifact("python-module", name)
                self.add_relationship(
                    "IMPORTS",
                    artifact_id,
                    target.id,
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    run_id=run_id,
                )
        elif analyzer_id == "lnk":
            target_path = details.get("local_path") or details.get("relative_path")
            if target_path:
                target = self.add_named_artifact("path", target_path)
                self.add_relationship(
                    "LINKS_TO",
                    artifact_id,
                    target.id,
                    analyzer_id=analyzer_id,
                    analyzer_version=analyzer_version,
                    certainty="observed",
                    extra={"arguments": details.get("arguments")},
                    run_id=run_id,
                )

    def has_content(self, sha256: str) -> bool:
        return content_id_from_digest(sha256) in self.artifacts

    def get(self, artifact_id: str) -> Artifact | None:
        return self.artifacts.get(artifact_id)


def _pe_import_features(details: dict[str, Any]) -> list[dict[str, Any]]:
    features = details.get("imported_functions")
    if isinstance(features, list):
        return [item for item in features if isinstance(item, dict)]
    out: list[dict[str, Any]] = []
    for item in details.get("imports") or []:
        if not isinstance(item, dict):
            continue
        dll = item.get("dll") or "unknown"
        normalized_dll = item.get("normalized_dll")
        for fn in item.get("functions") or []:
            if isinstance(fn, dict):
                raw = fn.get("name") or "unknown"
                normalized_name = fn.get("normalized_name")
                import_kind = fn.get("import_kind") or ("ordinal" if str(raw).startswith("#") else "name")
                ordinal = fn.get("ordinal")
            else:
                raw = str(fn)
                normalized_name = None
                import_kind = "ordinal" if raw.startswith("#") else "name"
                ordinal = int(raw[1:]) if raw.startswith("#") and raw[1:].isdigit() else None
            out.append(
                {
                    "dll": dll,
                    "normalized_dll": normalized_dll,
                    "name": raw,
                    "normalized_name": normalized_name,
                    "import_kind": import_kind,
                    "ordinal": ordinal,
                }
            )
    return out
