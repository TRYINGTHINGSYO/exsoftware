from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from .analyzers.eligibility import is_eligible, skip_reason_for
from .analyzers.registry import all_specs
from .content import digest_bytes, sha256_file
from .context import DEFAULT_MAX_BYTES, AnalysisContext, load_from_bytes, load_from_path
from .identify import identify_bytes, refine_ole_type_from_streams, refine_zip_type_from_names
from .investigation import Investigation
from .isolate.container_runner import IsolatedContainerRunner
from .isolate.inventory import (
    aggregate_worker_isolation,
    analyzer_worker_isolation_record,
    worker_isolation_record,
)
from .isolate.ole_runner import IsolatedOleRunner
from .isolate.runner import IsolatedAnalyzerRunner
from .limits import RecursionLimits
from .models import (
    ENGINE_VERSION,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    AnalyzerResult,
    Evidence,
    Finding,
    Report,
)
from .recursion import is_zip_family, members_from_container, should_recurse
from .summary import build_overview, sort_findings

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc


def analyze_path(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    limits: RecursionLimits | None = None,
) -> Report:
    ctx = load_from_path(Path(path), max_bytes=max_bytes)
    return _analyze_context(ctx, limits=limits)


def analyze_bytes(
    data: bytes,
    *,
    name: str = "unnamed",
    max_bytes: int = DEFAULT_MAX_BYTES,
    extra: dict[str, Any] | None = None,
    limits: RecursionLimits | None = None,
) -> Report:
    ctx = load_from_bytes(data, name=name, max_bytes=max_bytes, extra=extra)
    return _analyze_context(ctx, limits=limits)


def _analyze_context(ctx: AnalysisContext, *, limits: RecursionLimits | None) -> Report:
    limits = limits or RecursionLimits()
    ctx.limits = limits
    inv = Investigation()
    ctx.investigation = inv
    hashes = digest_bytes(ctx.data)
    if ctx.path is not None and ctx.truncated:
        identity_sha = sha256_file(ctx.path)
        artifact_hashes = {"sha256": identity_sha, "analyzed_sha256": hashes["sha256"]}
        complete = True
    elif ctx.truncated:
        identity_sha = hashes["sha256"]
        artifact_hashes = hashes
        complete = False
    else:
        identity_sha = hashes["sha256"]
        artifact_hashes = hashes
        complete = True
    artifact = inv.add_file_artifact(
        sha256=identity_sha,
        name=ctx.name,
        path=str(ctx.path) if ctx.path else None,
        size=ctx.size,
        hashes=artifact_hashes,
        detected_type=ctx.identity.detected_type if ctx.identity else None,
        detected_family=ctx.identity.detected_family if ctx.identity else None,
        detected_mime=ctx.identity.detected_mime if ctx.identity else None,
        description=ctx.identity.description if ctx.identity else None,
        complete=complete,
        metadata={
            "source": ctx.source,
            "truncated": ctx.truncated,
            "analyzed_bytes": len(ctx.data),
            "analyzed_sha256": hashes["sha256"],
        },
    )
    ctx.artifact_id = artifact.id
    stats: dict[str, Any] = {
        "extracted_count": 0,
        "extracted_bytes": 0,
        "broker_workers": [],
    }
    members = _maybe_open_container(ctx, inv, stats)
    _maybe_refine_ole(ctx, inv, stats)
    root_sections = _run_analyzers(ctx, inv)
    _walk_container_members(ctx, inv, stats, members)
    report_hashes = artifact_hashes if "md5" in artifact_hashes else hashes
    hash_section = next((item for item in root_sections if item.name == "hashes"), None)
    if hash_section:
        report_hashes = dict(hash_section.details.get("hashes") or report_hashes)
    return _build_report(ctx, inv, report_hashes, root_sections, limits, stats)


def _run_analyzers(ctx: AnalysisContext, inv: Investigation) -> list[AnalyzerResult]:
    limits = ctx.limits or RecursionLimits()
    timeout_default = limits.analyzer_timeout_seconds
    planned: list[tuple[Any, Any, float, bool, bool]] = []
    identity = ctx.identity
    for spec in all_specs():
        timeout = spec.timeout_seconds if spec.timeout_seconds is not None else timeout_default
        run = inv.begin_run(
            analyzer_id=spec.name,
            analyzer_version=spec.version,
            analyzer_title=spec.title,
            artifact_id=ctx.artifact_id or "",
        )
        eligible = is_eligible(spec, identity)
        skip_redundant = False
        if eligible and spec.name == "archive" and _archive_covered_by_container(ctx, identity):
            eligible = False
            skip_redundant = True
        planned.append((spec, run, timeout, eligible, skip_redundant))

    isolated_jobs = [(spec, run, timeout) for spec, run, timeout, eligible, _redundant in planned if eligible]
    results: dict[str, AnalyzerResult] = {}
    if limits.isolate_analyzers:
        runner = IsolatedAnalyzerRunner(limits)
        workers = max(1, min(limits.max_analyzer_workers, len(isolated_jobs) or 1))
        if isolated_jobs:
            if workers == 1:
                for spec, run, timeout in isolated_jobs:
                    results[run.id] = runner.run(spec, ctx, timeout=timeout)
            else:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {
                        pool.submit(runner.run, spec, ctx, timeout=timeout): run.id
                        for spec, run, timeout in isolated_jobs
                    }
                    for future in as_completed(futures):
                        results[futures[future]] = future.result()
    else:
        from .analyzers.loader import load_analyzer_class

        for spec, run, timeout, eligible, _redundant in planned:
            if not eligible:
                continue
            analyzer = load_analyzer_class(spec)()
            started = perf_counter()
            try:
                result = analyzer.analyze(ctx)
            except Exception as exc:
                result = analyzer.failure(exc)
                result.details = {
                    **(result.details or {}),
                    "traceback": traceback.format_exc(),
                    "isolation": {"mode": "in-process", "sandbox": False, "containment": "none"},
                }
            result.duration_ms = (perf_counter() - started) * 1000
            results[run.id] = result

    sections: list[AnalyzerResult] = []
    for spec, run, timeout, eligible, skip_redundant in planned:
        if not eligible:
            if skip_redundant:
                result = AnalyzerResult(
                    name=spec.name,
                    title=spec.title,
                    applies=True,
                    skipped=True,
                    status="skipped",
                    skip_reason="ZIP-family listing already performed by the contained container worker.",
                    analyzer_version=spec.version,
                    details={"isolation": {"mode": "not-started", "reason": "redundant-container-listing", "sandbox": False}},
                )
            else:
                result = AnalyzerResult(
                    name=spec.name,
                    title=spec.title,
                    applies=False,
                    skipped=True,
                    status="unsupported",
                    skip_reason=skip_reason_for(spec, identity),
                    analyzer_version=spec.version,
                    details={"isolation": {"mode": "not-started", "reason": "unsupported", "sandbox": False}},
                )
        else:
            result = results[run.id]
        inv.ingest_result(spec.name, spec.version, ctx.artifact_id or "", result, run)
        sections.append(result)
    return sections


def _maybe_open_container(ctx: AnalysisContext, inv: Investigation, stats: dict[str, Any]) -> list:
    """List/extract ZIP-family members in a contained worker, then refine identity.

    Complex ZIP parsing does not run in this process. Member names from the
    validated manifest are metadata used only for subtype classification.
    """
    limits = ctx.limits or RecursionLimits()
    detected = ctx.identity.detected_type if ctx.identity else None
    if not is_zip_family(detected):
        return []
    if ctx.depth >= limits.max_depth:
        if limits.enable_recursion:
            _ingest_limit(
                ctx,
                inv,
                Finding(
                    id="rec.limit-depth",
                    title="Archive recursion depth limit reached",
                    summary=f"{ctx.name} was not expanded further (depth {ctx.depth}, max {limits.max_depth}).",
                    category="limitation",
                    severity="low",
                    confidence="high",
                    analyzer="archive",
                    tags=["recursion", "limit"],
                    evidence=[
                        Evidence(kind="limit", summary="Recursion depth", analyzer="archive", value=str(ctx.depth), extra={"max_depth": limits.max_depth, "name": ctx.name})
                    ],
                ),
            )
            inv.record_limit("max_depth", "Recursion depth cap reached", {"depth": ctx.depth, "name": ctx.name})
        return []

    result = IsolatedContainerRunner(limits).extract(
        ctx.data,
        artifact_id=ctx.artifact_id or "",
        container_type="zip",
        timeout=limits.analyzer_timeout_seconds,
        extract_contents=limits.enable_recursion,
    )
    stats["broker_workers"].append(
        worker_isolation_record(
            worker_type="archive_broker",
            worker_id="zip",
            artifact_id=ctx.artifact_id or "",
            status=result.status,
            isolation=result.isolation,
            reason=result.reason,
            message=result.message,
        )
    )
    ctx.extra["container_inspected"] = True
    _apply_zip_identity(ctx, inv, *refine_zip_type_from_names([item.original_name for item in result.members]))
    if result.status != "completed":
        _members, extra_findings = members_from_container(result)
        for finding in extra_findings:
            _ingest_limit(ctx, inv, finding)
        return []
    if not limits.enable_recursion or not should_recurse(result.zip_subtype):
        return []
    members, extra_findings = members_from_container(result)
    for finding in extra_findings:
        _ingest_limit(ctx, inv, finding)
    return members


def _walk_container_members(
    ctx: AnalysisContext,
    inv: Investigation,
    stats: dict[str, Any],
    members: list,
) -> None:
    limits = ctx.limits or RecursionLimits()
    parent_id = ctx.artifact_id or ""
    for member in members:
        if member.skip_reason == "directory":
            continue
        if member.skip_reason == "path-traversal":
            stub = inv.add_stub_artifact(
                name=member.name,
                size=member.size,
                reason="path-traversal",
                metadata={"archive_member": member.name},
            )
            inv.add_relationship(
                "CONTAINS",
                parent_id,
                stub.id,
                analyzer_id="archive",
                analyzer_version="1.0.0",
                certainty="observed",
                extra={
                    "member_name": member.name,
                    "extracted": False,
                    "reason": "path-traversal",
                    "archive_index": member.index,
                    "extraction_status": member.extraction_status,
                },
            )
            continue
        if member.skip_reason == "encrypted":
            stub = inv.add_stub_artifact(name=member.name, size=member.size, reason="encrypted")
            inv.add_relationship(
                "CONTAINS",
                parent_id,
                stub.id,
                analyzer_id="archive",
                analyzer_version="1.0.0",
                certainty="observed",
                extra={
                    "member_name": member.name,
                    "extracted": False,
                    "reason": "encrypted",
                    "archive_index": member.index,
                    "extraction_status": member.extraction_status,
                },
            )
            continue
        if member.data is None:
            stub = inv.add_stub_artifact(
                name=member.name,
                size=member.size,
                reason=member.skip_reason or "not-extracted",
            )
            inv.add_relationship(
                "CONTAINS",
                parent_id,
                stub.id,
                analyzer_id="archive",
                analyzer_version="1.0.0",
                certainty="observed",
                extra={
                    "member_name": member.name,
                    "extracted": False,
                    "reason": member.skip_reason,
                    "archive_index": member.index,
                    "extraction_status": member.extraction_status,
                },
            )
            continue

        child_hashes = dict(member.hashes) if member.hashes else digest_bytes(member.data)
        child_sha = child_hashes["sha256"]
        duplicate = inv.has_content(child_sha)
        child_ident = identify_bytes(member.data, member.name, size=len(member.data))
        child_artifact = inv.add_file_artifact(
            sha256=child_sha,
            name=member.name,
            size=len(member.data),
            hashes=child_hashes,
            detected_type=child_ident.detected_type,
            detected_family=child_ident.detected_family,
            detected_mime=child_ident.detected_mime,
            description=child_ident.description,
            complete=True,
            metadata={"archive_member": member.name, "parent_artifact_id": parent_id},
        )
        inv.add_relationship(
            "CONTAINS",
            parent_id,
            child_artifact.id,
            analyzer_id="archive",
            analyzer_version="1.0.0",
            certainty="observed",
            extra={
                "member_name": member.name,
                "extracted": True,
                "archive_index": member.index,
                "extraction_status": member.extraction_status,
                "compression_method": member.compression_method,
                "declared_size": member.declared_size,
                "actual_size": member.size,
            },
        )
        inv.add_relationship(
            "EXTRACTED_FROM",
            child_artifact.id,
            parent_id,
            analyzer_id="archive",
            analyzer_version="1.0.0",
            certainty="observed",
            extra={"member_name": member.name, "archive_index": member.index},
        )
        stats["extracted_count"] += 1
        stats["extracted_bytes"] += len(member.data)
        if duplicate:
            _ingest_limit(
                ctx,
                inv,
                Finding(
                    id="rec.duplicate",
                    title="ZIP member content already analyzed",
                    summary=f"{member.name!r} has the same SHA-256 as an artifact already in this report.",
                    category="archive",
                    severity="info",
                    confidence="high",
                    analyzer="archive",
                    tags=["recursion", "duplicate"],
                    evidence=[
                        Evidence(kind="hash", summary="Duplicate SHA-256", analyzer="archive", value=child_sha, extra={"member_name": member.name})
                    ],
                ),
            )
            continue
        child_ctx = AnalysisContext(
            name=member.name,
            source="archive-member",
            size=len(member.data),
            data=member.data,
            truncated=False,
            max_bytes=ctx.max_bytes,
            identity=child_ident,
            artifact_id=child_artifact.id,
            investigation=inv,
            depth=ctx.depth + 1,
            limits=limits,
            extra={"parent_artifact_id": parent_id, "member_name": member.name},
        )
        child_members = _maybe_open_container(child_ctx, inv, stats)
        _maybe_refine_ole(child_ctx, inv, stats)
        _run_analyzers(child_ctx, inv)
        _walk_container_members(child_ctx, inv, stats, child_members)


def _maybe_refine_ole(ctx: AnalysisContext, inv: Investigation, stats: dict[str, Any]) -> None:
    """Refine OLE subtype via a contained worker. olefile does not run here."""
    identity = ctx.identity
    if identity is None:
        return
    if not identity.extra.get("ole_subtype_pending"):
        return
    if identity.detected_type != "ole":
        return
    limits = ctx.limits or RecursionLimits()
    result = IsolatedOleRunner(limits).refine(
        ctx.data,
        artifact_id=ctx.artifact_id or "",
        timeout=limits.analyzer_timeout_seconds,
    )
    stats["broker_workers"].append(
        worker_isolation_record(
            worker_type="ole_broker",
            worker_id="ole-refine",
            artifact_id=ctx.artifact_id or "",
            status=result.status,
            isolation=result.isolation,
            reason=result.reason,
            message=result.message,
        )
    )
    extra = dict(identity.extra or {})
    extra.pop("ole_subtype_pending", None)
    if result.status != "completed":
        extra["ole_refinement"] = {
            "status": result.status,
            "reason": result.reason,
            "message": result.message,
            "containment": "static-parser",
            "fallback": False,
        }
        identity.extra = extra
        return
    kind, family, mime, description = refine_ole_type_from_streams(result.streams)
    if not result.is_ole:
        kind, family, mime, description = (
            "ole",
            "document",
            "application/x-ole-storage",
            "OLE Compound File",
        )
    extra["ole_subtype"] = kind
    extra["ole_refinement"] = {
        "status": "completed",
        "is_ole": result.is_ole,
        "stream_count": len(result.streams),
        "containment": "static-parser",
    }
    identity.extra = extra
    _apply_ole_identity(ctx, inv, kind, family, mime, description)


def _apply_zip_identity(ctx: AnalysisContext, inv: Investigation, kind: str, family: str, mime: str, description: str) -> None:
    if ctx.identity is not None:
        ctx.identity.detected_type = kind
        ctx.identity.detected_family = family
        ctx.identity.detected_mime = mime
        ctx.identity.description = description
        extra = dict(ctx.identity.extra or {})
        extra.pop("zip_subtype_pending", None)
        extra["zip_subtype"] = kind
        ctx.identity.extra = extra
    artifact = inv.artifacts.get(ctx.artifact_id or "")
    if artifact is not None:
        artifact.detected_type = kind
        artifact.detected_family = family
        artifact.detected_mime = mime
        artifact.description = description


def _apply_ole_identity(ctx: AnalysisContext, inv: Investigation, kind: str, family: str, mime: str, description: str) -> None:
    if ctx.identity is not None:
        ctx.identity.detected_type = kind
        ctx.identity.detected_family = family
        ctx.identity.detected_mime = mime
        ctx.identity.description = description
    artifact = inv.artifacts.get(ctx.artifact_id or "")
    if artifact is not None:
        artifact.detected_type = kind
        artifact.detected_family = family
        artifact.detected_mime = mime
        artifact.description = description


def _ingest_limit(ctx: AnalysisContext, inv: Investigation, finding: Finding) -> None:
    run = next((item for item in reversed(inv.runs) if item.analyzer_id == "archive" and item.artifact_id == ctx.artifact_id), None)
    if run is None:
        run = inv.begin_run(
            analyzer_id="archive",
            analyzer_version="1.0.0",
            analyzer_title="Archive / container",
            artifact_id=ctx.artifact_id or "",
        )
    dummy = AnalyzerResult(
        name="archive",
        title="Archive / container",
        applies=True,
        findings=[finding],
        analyzer_version="1.0.0",
        status="completed",
    )
    inv.ingest_result("archive", "1.0.0", ctx.artifact_id or "", dummy, run)


def _build_report(
    ctx: AnalysisContext,
    inv: Investigation,
    hashes: dict[str, str],
    root_sections: list[AnalyzerResult],
    limits: RecursionLimits,
    stats: dict[str, Any],
) -> Report:
    identity = ctx.identity
    assert identity is not None
    capabilities = []
    pe_section = next((item for item in root_sections if item.name == "pe" and item.status == "completed"), None)
    if pe_section:
        for cap in pe_section.details.get("capabilities") or []:
            capabilities.append(
                {
                    "name": cap,
                    "source": "pe.imports",
                    "confidence": "medium",
                    "certainty": "inferred",
                    "note": "Derived from imported APIs. This is capability, not observed runtime behavior.",
                }
            )
    analyzer_workers = [
        item
        for run in inv.runs
        if (item := analyzer_worker_isolation_record(run)) is not None
    ]
    worker_inventory = [*(stats.get("broker_workers") or []), *analyzer_workers]
    isolation_summary = aggregate_worker_isolation(worker_inventory)
    report = Report(
        schema_version=SCHEMA_VERSION,
        analyzed_at=datetime.now(tz=UTC).isoformat(),
        identity=identity,
        overview="",
        next_steps=[],
        hashes=hashes,
        findings=sort_findings(list(inv.findings)),
        sections=root_sections,
        limits={
            "max_bytes": ctx.max_bytes,
            "truncated": ctx.truncated,
            "analyzed_bytes": len(ctx.data),
            "file_size": ctx.size,
            "executed": False,
            "network": False,
            "static_only": True,
            "sandbox": False,
            "isolation": {
                "analyzers": "subprocess" if limits.isolate_analyzers else "in-process",
                "protocol": "exsoftware.isolate",
                "protocol_version": 1,
                "sandbox": False,
                "containment": "static-parser",
                **isolation_summary,
                "workers": worker_inventory,
                "container_protocol": "exsoftware.container",
                "container_protocol_version": 1,
                "ole_protocol": "exsoftware.ole",
                "ole_protocol_version": 1,
            },
            "recursion": limits.to_dict(),
            "recursion_events": list(inv.limit_events),
        },
        capabilities=capabilities,
        engine={"name": "exsoftware", "version": ENGINE_VERSION, "schema": SCHEMA_NAME},
        root_artifact_id=ctx.artifact_id,
        artifacts=list(inv.artifacts.values()),
        relationships=list(inv.relationships),
        observations=list(inv.observations),
        evidence_store=list(inv.evidence),
        analyzer_runs=list(inv.runs),
    )
    overview, next_steps = build_overview(report)
    report.overview = overview
    report.next_steps = next_steps
    from .composition import compose

    report.composition = compose(report).to_dict()
    return report


def _archive_covered_by_container(ctx: AnalysisContext, identity: Any) -> bool:
    limits = ctx.limits or RecursionLimits()
    if not limits.enable_recursion:
        return False
    detected = getattr(identity, "detected_type", None)
    if detected not in {"zip", "jar", "apk", "wheel"}:
        return False
    return bool(ctx.extra.get("container_inspected"))
