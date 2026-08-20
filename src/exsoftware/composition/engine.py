"""Build a CompositionReport from an investigation graph."""

from __future__ import annotations

from ..models import Report
from .capabilities import infer_capabilities
from .classifier import classify
from .completeness import build_completeness
from .components import build_components
from .dependencies import build_dependencies, named_kind, named_value
from .model import COMPOSITION_VERSION, CompositionIdentity, CompositionReport, graph_ref
from .prioritization import important_observations


def compose(report: Report) -> CompositionReport:
    root = next((item for item in report.artifacts if item.id == report.root_artifact_id), None)
    category, label = classify(report, root)
    notable, tree, stats = build_components(report)
    dependencies = build_dependencies(report)
    capabilities = infer_capabilities(report)
    completeness, gaps = build_completeness(report)
    important = important_observations(report, capabilities=capabilities)
    identity = _identity(report, root, category, label)
    return CompositionReport(
        version=COMPOSITION_VERSION,
        identity=identity,
        stats=stats,
        notable_components=notable,
        component_tree=tree,
        dependencies=dependencies,
        capabilities=capabilities,
        important_observations=important,
        external_references=_external(report),
        gaps=gaps,
        completeness=completeness,
    )


def _identity(report: Report, root, category: str, label: str) -> CompositionIdentity:
    sha = report.hashes.get("sha256")
    if root and root.hashes.get("sha256"):
        sha = root.hashes.get("sha256")
    signed, subject, trust, refs = _signature(report)
    identity_findings = [
        item for item in report.findings if item.legacy_id == "identity.extension-mismatch" or item.rule_id == "ID.EXT.MISMATCH.001"
    ]
    return CompositionIdentity(
        category=category,
        category_label=label,
        detected_type=report.identity.detected_type,
        detected_family=report.identity.detected_family,
        description=report.identity.description,
        extension_agrees=report.identity.extension_matches,
        sha256=sha,
        size=report.identity.size,
        signed=signed,
        certificate_subject=subject,
        trust_verified=trust,
        refs=graph_ref(
            artifact_ids=[report.root_artifact_id] if report.root_artifact_id else [],
            finding_ids=[item.id for item in identity_findings if item.id],
            relationship_ids=refs.get("relationship_ids", []),
            evidence_ids=refs.get("evidence_ids", []),
        ),
    )


def _signature(report: Report) -> tuple[str, str | None, bool, dict]:
    signed_rels = [rel for rel in report.relationships if rel.type == "SIGNED_BY"]
    if signed_rels:
        subject = None
        target = next((item for item in report.artifacts if item.id == signed_rels[0].target_id), None)
        if target:
            subject = next((name for name in target.names if "|" not in name), target.names[0] if target.names else None)
            meta = target.metadata or {}
            subject = meta.get("subject") or subject
        return (
            "certificate_present",
            subject,
            False,
            graph_ref(relationship_ids=[rel.id for rel in signed_rels], artifact_ids=[rel.target_id for rel in signed_rels]),
        )
    unsigned = [
        item
        for item in report.findings
        if item.legacy_id in {"pe.unsigned", "signature.absent"} or item.rule_id in {"SIG.ABSENT.001"}
    ]
    if unsigned or report.identity.detected_type == "pe":
        if unsigned or any(run.analyzer_id == "pe" and run.status == "completed" for run in report.analyzer_runs):
            return "none", None, False, graph_ref(finding_ids=[item.id for item in unsigned if item.id])
    return "not_applicable", None, False, graph_ref()


def _external(report: Report) -> dict[str, list[dict]]:
    buckets = {
        "urls": [],
        "domains": [],
        "ips": [],
        "file_paths": [],
        "registry_paths": [],
        "imported_modules": [],
        "referenced_libraries": [],
    }
    seen: set[tuple[str, str]] = set()
    for rel in report.relationships:
        kind = named_kind(rel.target_id)
        value = named_value(rel.target_id)
        row = {
            "value": value,
            "artifact_id": rel.source_id,
            "target_id": rel.target_id,
            "note": (rel.extra or {}).get("note"),
            "refs": graph_ref(
                artifact_ids=[rel.source_id, rel.target_id],
                relationship_ids=[rel.id],
                evidence_ids=list(rel.evidence_ids or []),
            ),
        }
        key = (kind, value.lower())
        if key in seen:
            continue
        dest = {
            "url": "urls",
            "domain": "domains",
            "ip": "ips",
            "path": "file_paths",
            "python-module": "imported_modules",
            "library": "referenced_libraries",
        }.get(kind)
        if dest is None and rel.type == "REFERENCES" and kind == "unknown":
            continue
        if dest is None:
            continue
        seen.add(key)
        buckets[dest].append(row)
    for finding in report.findings:
        if finding.legacy_id == "strings.registry" or finding.rule_id == "STR.REGISTRY.001":
            for ev in finding.evidence:
                value = ev.value or ""
                key = ("registry", value.lower())
                if not value or key in seen:
                    continue
                seen.add(key)
                buckets["registry_paths"].append(
                    {
                        "value": value,
                        "artifact_id": finding.artifact_id,
                        "target_id": None,
                        "note": "Registry path string; not evidence of a registry write.",
                        "refs": graph_ref(
                            artifact_ids=[finding.artifact_id] if finding.artifact_id else [],
                            finding_ids=[finding.id] if finding.id else [],
                            evidence_ids=[ev.id] if ev.id else [],
                            rule_ids=["STR.REGISTRY.001"],
                        ),
                    }
                )
    for key in buckets:
        buckets[key] = buckets[key][:40]
    return buckets
