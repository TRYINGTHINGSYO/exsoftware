"""Completeness state and explicit analysis gaps."""

from __future__ import annotations

from ..models import Report
from .model import graph_ref

ALWAYS_GAPS = [
    {
        "id": "GAP.RUNTIME.NOT_OBSERVED.001",
        "kind": "not_executed",
        "statement": "Whether this software was actually run is not established. Analysis is static only.",
        "refs": graph_ref(),
    }
]


def build_completeness(report: Report) -> tuple[dict, list[dict]]:
    statuses: dict[str, int] = {}
    for run in report.analyzer_runs:
        statuses[run.status] = statuses.get(run.status, 0) + 1
    encrypted = [
        item
        for item in report.artifacts
        if str((item.metadata or {}).get("not_analyzed_reason") or "") == "encrypted"
    ]
    if not encrypted:
        encrypted = [
            item
            for rel in report.relationships
            if rel.type == "CONTAINS" and rel.extra.get("reason") == "encrypted"
            for item in report.artifacts
            if item.id == rel.target_id
        ]
    limit_rejected = [
        rel
        for rel in report.relationships
        if rel.type == "CONTAINS"
        and rel.extra.get("reason") in {"member-too-large", "compression-ratio", "total-bytes", "member-count", "path-traversal"}
    ]
    failed = statuses.get("failed", 0)
    timeout = statuses.get("timeout", 0) + statuses.get("terminated", 0)
    truncated = bool((report.limits or {}).get("truncated"))
    encrypted_n = len({item.id for item in encrypted})
    limit_n = len(limit_rejected)

    if failed or timeout or truncated or encrypted_n or limit_n:
        if failed or timeout or truncated or encrypted_n >= 2 or limit_n >= 3:
            state = "significantly_incomplete"
        else:
            state = "partial"
    else:
        state = "complete_for_supported_static_analysis"

    explanation = {
        "complete_for_supported_static_analysis": (
            "Supported static analyzers finished for the artifacts that were opened. "
            "Unsupported formats were not applicable, which is not a failure."
        ),
        "partial": "Some members or analyzers were not fully analyzed.",
        "significantly_incomplete": "Analysis stopped short in a way that leaves important content unexplained.",
    }[state]

    completeness = {
        "state": state,
        "explanation": explanation,
        "completed": statuses.get("completed", 0),
        "unsupported": statuses.get("unsupported", 0),
        "skipped": statuses.get("skipped", 0),
        "failed": failed,
        "timeout": timeout,
        "encrypted_members": encrypted_n,
        "limit_rejected": limit_n,
        "truncated": truncated,
        "executed": False,
        "network_lookups": False,
    }

    gaps = list(ALWAYS_GAPS)
    if any((item.rule_id or "") == "STR.URL.001" or item.legacy_id == "strings.urls" for item in report.findings) or any(
        rel.type == "REFERENCES" and rel.target_id.startswith("name:url:") for rel in report.relationships
    ):
        gaps.append(
            {
                "id": "GAP.URL.NOT_FETCHED.001",
                "kind": "urls_not_fetched",
                "statement": "Referenced URLs were not fetched. String presence is not a connection.",
                "refs": graph_ref(rule_ids=["STR.URL.001"]),
            }
        )
    signed_rels = [rel for rel in report.relationships if rel.type == "SIGNED_BY"]
    if signed_rels:
        gaps.append(
            {
                "id": "GAP.SIG.TRUST_UNVERIFIED.001",
                "kind": "trust_not_verified",
                "statement": "A certificate is present. Whether the chain is trusted was not verified.",
                "refs": graph_ref(relationship_ids=[rel.id for rel in signed_rels], artifact_ids=[rel.target_id for rel in signed_rels]),
            }
        )
    unsigned = [item for item in report.findings if item.legacy_id == "pe.unsigned" or item.rule_id == "SIG.ABSENT.001" or item.legacy_id == "signature.absent"]
    if unsigned:
        gaps.append(
            {
                "id": "GAP.SIG.CATALOG_UNCHECKED.001",
                "kind": "catalog_not_checked",
                "statement": "No Authenticode table was parsed. Windows catalog signatures are not checked here.",
                "refs": graph_ref(finding_ids=[item.id for item in unsigned if item.id], rule_ids=["SIG.ABSENT.001"]),
            }
        )
    if any(run.analyzer_id == "pe" and run.status == "completed" for run in report.analyzer_runs):
        gaps.append(
            {
                "id": "GAP.PE.CAPABILITIES.IMPORTS_ONLY.001",
                "kind": "import_based_capabilities",
                "statement": (
                    "PE capability inference is based on static imports and visible strings. "
                    "Statically linked code, dynamically resolved APIs, obfuscated imports, "
                    "runtime-decoded functionality, and behavior without recognizable APIs may be missed."
                ),
                "refs": graph_ref(
                    artifact_ids=list(
                        dict.fromkeys(
                            run.artifact_id
                            for run in report.analyzer_runs
                            if run.analyzer_id == "pe" and run.status == "completed"
                        )
                    )
                ),
            }
        )
    if any(run.analyzer_id == "elf" and run.status == "completed" for run in report.analyzer_runs):
        gaps.append(
            {
                "id": "GAP.ELF.CAPABILITIES.IMPORTS_ONLY.001",
                "kind": "import_based_capabilities",
                "statement": (
                    "ELF capability inference is based on static dynamic-symbol imports and DT_NEEDED libraries. "
                    "Statically linked code, dlsym-resolved APIs, stripped or obfuscated symbols, "
                    "runtime-decoded functionality, and behavior without recognizable imports may be missed."
                ),
                "refs": graph_ref(
                    artifact_ids=list(
                        dict.fromkeys(
                            run.artifact_id
                            for run in report.analyzer_runs
                            if run.analyzer_id == "elf" and run.status == "completed"
                        )
                    )
                ),
            }
        )
    if any(run.analyzer_id == "macho" and run.status == "completed" for run in report.analyzer_runs):
        gaps.append(
            {
                "id": "GAP.MACHO.CAPABILITIES.IMPORTS_ONLY.001",
                "kind": "import_based_capabilities",
                "statement": (
                    "Mach-O capability inference is based on static undefined symbols and linked dylibs. "
                    "Statically linked code, dlsym-resolved APIs, stripped or obfuscated symbols, "
                    "runtime-decoded functionality, and behavior without recognizable imports may be missed. "
                    "No capability match means not observed by these static rules, not absent."
                ),
                "refs": graph_ref(
                    artifact_ids=list(
                        dict.fromkeys(
                            run.artifact_id
                            for run in report.analyzer_runs
                            if run.analyzer_id == "macho" and run.status == "completed"
                        )
                    )
                ),
            }
        )
    if encrypted_n:
        gaps.append(
            {
                "id": "GAP.MEMBER.ENCRYPTED.001",
                "kind": "encrypted",
                "statement": f"{encrypted_n} archive member(s) are encrypted and were not extracted. Their payload is unknown.",
                "refs": graph_ref(artifact_ids=[item.id for item in encrypted[:12]]),
            }
        )
    if timeout:
        runs = [run for run in report.analyzer_runs if run.status in {"timeout", "terminated"}]
        gaps.append(
            {
                "id": "GAP.ANALYZER.TIMEOUT.001",
                "kind": "timeout",
                "statement": "One or more analyzers timed out and those areas were not analyzed.",
                "refs": graph_ref(artifact_ids=list({run.artifact_id for run in runs})),
            }
        )
    if failed:
        runs = [run for run in report.analyzer_runs if run.status == "failed"]
        gaps.append(
            {
                "id": "GAP.ANALYZER.FAILED.001",
                "kind": "failed",
                "statement": "One or more analyzers failed. Treat those areas as not analyzed, not empty.",
                "refs": graph_ref(artifact_ids=list({run.artifact_id for run in runs})),
            }
        )
    if truncated:
        gaps.append(
            {
                "id": "GAP.INPUT.TRUNCATED.001",
                "kind": "truncated",
                "statement": "The analyzed prefix is smaller than the file. Content past the cap was not parsed.",
                "refs": graph_ref(artifact_ids=[report.root_artifact_id] if report.root_artifact_id else []),
            }
        )
    if limit_n:
        gaps.append(
            {
                "id": "GAP.LIMIT.MEMBERS.001",
                "kind": "limit_rejected",
                "statement": f"{limit_n} contained member(s) were not analyzed because of safety limits or path rejection.",
                "refs": graph_ref(relationship_ids=[rel.id for rel in limit_rejected[:20]]),
            }
        )
    root = next((item for item in report.artifacts if item.id == report.root_artifact_id), None)
    if root and (root.detected_type or "unknown") == "unknown":
        gaps.append(
            {
                "id": "GAP.TYPE.UNKNOWN.001",
                "kind": "unsupported",
                "statement": "The file type was not recognized. Format-specific parsers did not run.",
                "refs": graph_ref(artifact_ids=[root.id]),
            }
        )
    return completeness, gaps
