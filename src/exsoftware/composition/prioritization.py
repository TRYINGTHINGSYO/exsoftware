"""Deterministic important-observation ranking. Attention, not malice."""

from __future__ import annotations

from ..models import Finding, Report
from .model import graph_ref


def important_observations(report: Report, *, capabilities: list[dict]) -> list[dict]:
    items: list[dict] = []
    items.extend(_from_findings(report))
    items.extend(_from_graph(report, capabilities))
    seen: set[str] = set()
    out = []
    for item in items:
        key = item["id"] + "|" + (item.get("refs", {}).get("artifact_ids") or [""])[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out[:20]


def _from_findings(report: Report) -> list[dict]:
    rules = [
        ("ID.EXT.MISMATCH.001", "identity.extension-mismatch", "IMP.ID.EXT_MISMATCH.001", "File extension disagrees with detected type", "The name can hide the real format."),
        ("ARC.TRAVERSAL.001", "archive.path-traversal", "IMP.ARC.TRAVERSAL.001", "Archive member path looks like traversal", "Extraction with a naive unzip path can write outside the destination."),
        ("SCRIPT.PS.INDICATOR.001", "script.powershell-indicators", "IMP.SCRIPT.PS_IEX.001", "PowerShell language features of interest", "IEX/encoded/download helpers can hide what a script would do."),
        ("PE.IMPORT.INJECT.001", "pe.injection-import-set", "IMP.PE.INJECTION_SET.001", "Import set often used to run code in another process", "Multiple process-memory APIs appear together."),
        ("PE.ENTROPY.001", "pe.high-entropy-code", "IMP.ENTROPY.HIGH.001", "High-entropy executable content", "Packing or encryption can hide the real payload."),
        ("REC.CONTAINER.TIMEOUT.001", "rec.container-timeout", "IMP.ANALYSIS.TIMEOUT.001", "Contained parser timed out", "Archive contents may be missing."),
        ("ARC.PARSE.001", "archive.bad-zip", "IMP.ARC.PARSE.001", "Archive could not be parsed", "Contained files were not recovered."),
        ("SIG.PARSE.001", "signature.parse-error", "IMP.SIG.PARSE.001", "Signature blob could not be parsed", "Signing metadata is incomplete."),
    ]
    out = []
    for rule_id, legacy, imp_id, title, why in rules:
        matches = [
            item
            for item in report.findings
            if item.rule_id == rule_id or item.legacy_id == legacy or item.id == legacy
        ]
        for finding in matches:
            out.append(_item(imp_id, title, finding.summary, why, finding, [rule_id]))
    failed = [run for run in report.analyzer_runs if run.status in {"failed", "timeout", "terminated"}]
    if failed:
        run = failed[0]
        out.append(
            {
                "id": "IMP.ANALYSIS.INCOMPLETE.001",
                "title": f"Analyzer {run.analyzer_id} {run.status}",
                "summary": f"{len(failed)} analyzer run(s) did not complete.",
                "why_surfaced": "Incomplete analysis is easy to miss if you only read successful findings.",
                "severity": "medium",
                "refs": graph_ref(artifact_ids=list({item.artifact_id for item in failed})),
            }
        )
    return out


def _from_graph(report: Report, capabilities: list[dict]) -> list[dict]:
    out = []
    root = report.root_artifact_id
    unsigned = [
        item
        for item in report.findings
        if item.legacy_id in {"pe.unsigned", "signature.absent"} or item.rule_id in {"SIG.ABSENT.001"}
    ]
    if unsigned and report.identity.detected_type == "pe":
        finding = unsigned[0]
        out.append(
            _item(
                "IMP.SIG.UNSIGNED.001",
                "No Authenticode certificate table",
                finding.summary,
                "An unsigned Windows binary is common and not a verdict; it is still worth knowing.",
                finding,
                ["SIG.ABSENT.001"],
            )
        )
    signed = [rel for rel in report.relationships if rel.type == "SIGNED_BY"]
    if signed:
        subject = None
        target = next((item for item in report.artifacts if item.id == signed[0].target_id), None)
        if target and target.names:
            subject = next((name for name in target.names if name and "|" not in name), target.names[0])
        out.append(
            {
                "id": "IMP.SIG.PRESENT.001",
                "title": "Certificate present; trust not verified",
                "summary": f"Subject claim: {subject}" if subject else "A certificate is attached.",
                "why_surfaced": "Presence of a certificate is not the same as a trusted signature.",
                "severity": "info",
                "refs": graph_ref(relationship_ids=[rel.id for rel in signed], artifact_ids=[rel.target_id for rel in signed]),
            }
        )
    contained_exec = [
        item
        for item in report.artifacts
        if item.id != root and item.detected_type in {"pe", "elf", "macho64", "macho32"}
    ]
    if contained_exec:
        names = ", ".join(item.primary_name for item in contained_exec[:4])
        out.append(
            {
                "id": "IMP.EMBED.EXECUTABLE.001",
                "title": "Contained executable",
                "summary": f"Nested executable component(s): {names}",
                "why_surfaced": "The submitted file is not only a wrapper; it contains runnable native code.",
                "severity": "low",
                "refs": graph_ref(artifact_ids=[item.id for item in contained_exec[:8]]),
            }
        )
    contained_script = [
        item
        for item in report.artifacts
        if item.id != root and item.detected_type in {"python", "powershell", "javascript", "vbscript", "batch", "shell"}
    ]
    if contained_script:
        names = ", ".join(item.primary_name for item in contained_script[:4])
        out.append(
            {
                "id": "IMP.EMBED.SCRIPT.001",
                "title": "Contained script",
                "summary": f"Nested script(s): {names}",
                "why_surfaced": "Scripts inside a package are easy to miss if you only look at the outer type.",
                "severity": "low",
                "refs": graph_ref(artifact_ids=[item.id for item in contained_script[:8]]),
            }
        )
    encrypted = [
        rel
        for rel in report.relationships
        if rel.type == "CONTAINS" and rel.extra.get("reason") == "encrypted"
    ]
    if encrypted:
        out.append(
            {
                "id": "IMP.MEMBER.ENCRYPTED.001",
                "title": "Encrypted archive member(s)",
                "summary": "Encrypted members were listed and not extracted. No password guessing was attempted.",
                "why_surfaced": "The explanation is incomplete until those members are available some other way.",
                "severity": "medium",
                "refs": graph_ref(relationship_ids=[rel.id for rel in encrypted[:8]]),
            }
        )
    dyn = [
        item
        for item in capabilities
        if item["id"]
        in {
            "CAP.DYNAMIC_LOADING.PE_LOADLIBRARY.001",
            "CAP.DYNAMIC_LOADING.ELF_DLOPEN.001",
        }
    ]
    if dyn:
        out.append(
            {
                "id": "IMP.CAP.DYNAMIC_LOADING.001",
                "title": "Dynamic library loading capability",
                "summary": dyn[0]["statement"],
                "why_surfaced": "Code loaded later is not visible in the static import table alone.",
                "severity": "low",
                "refs": dyn[0]["refs"],
            }
        )
    return out


def _item(imp_id: str, title: str, summary: str, why: str, finding: Finding, rule_ids: list[str]) -> dict:
    return {
        "id": imp_id,
        "title": title,
        "summary": summary,
        "why_surfaced": why,
        "severity": finding.severity,
        "refs": graph_ref(
            artifact_ids=[finding.artifact_id] if finding.artifact_id else [],
            finding_ids=[finding.id] if finding.id else [],
            evidence_ids=list(finding.evidence_ids or []),
            observation_ids=list(finding.observation_ids or []),
            rule_ids=rule_ids,
        ),
    }
