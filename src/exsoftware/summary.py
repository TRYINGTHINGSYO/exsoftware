from __future__ import annotations

from .models import Finding, Report

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def build_overview(report: Report) -> tuple[str, list[str]]:
    identity = report.identity
    paragraphs: list[str] = []
    next_steps: list[str] = []

    match_text = {
        True: "The file extension matches that type.",
        False: "The file extension does not match that type; treat the detected type as authoritative.",
        None: "The extension was not used as a strong type hint.",
    }[identity.extension_matches]
    paragraphs.append(
        f"This looks like {identity.description.lower()} "
        f"(detected type `{identity.detected_type}`). {match_text}"
    )

    size = _size_label(identity.size)
    sha = report.hashes.get("sha256")
    hash_note = f" SHA-256 `{sha}`." if sha else ""
    paragraphs.append(f"Size on disk is {size}.{hash_note}")

    pe = _section(report, "pe")
    if pe and not pe.skipped:
        d = pe.details
        kind = "DLL" if d.get("is_dll") else "executable"
        paragraphs.append(
            f"PE details: {d.get('format')} {kind} for {d.get('machine')}, "
            f"subsystem {d.get('subsystem')}, {d.get('section_count')} section(s), "
            f"{len(d.get('imports') or [])} imported DLL(s)"
            + (" , .NET assembly" if d.get("is_dotnet") else "")
            + "."
        )
        caps = d.get("capabilities") or []
        if caps:
            paragraphs.append("Import-derived capabilities: " + ", ".join(caps) + ".")

    elf = _section(report, "elf")
    if elf and not elf.skipped and elf.details.get("needed"):
        needed = elf.details["needed"]
        paragraphs.append("ELF DT_NEEDED libraries: " + ", ".join(needed[:8]) + ("…" if len(needed) > 8 else "") + ".")

    archive = _section(report, "archive")
    if archive and not archive.skipped:
        count = archive.details.get("member_count")
        if count is not None:
            paragraphs.append(f"Container listing: {count} member(s) were enumerated.")
    child_files = [
        item for item in report.artifacts
        if item.kind == "file" and item.id != report.root_artifact_id and item.content_id
    ]
    if child_files:
        paragraphs.append(
            f"Recursive static analysis covered {len(child_files)} contained file artifact(s) using the same pipeline."
        )

    strings = _section(report, "strings")
    if strings and not strings.skipped:
        urls = strings.details.get("urls") or []
        ips = strings.details.get("ips") or []
        if urls or ips:
            paragraphs.append(
                f"Extracted network indicators: {len(urls)} URL(s), {len(ips)} IPv4 literal(s). "
                "They were not fetched."
            )

    entropy = _section(report, "entropy")
    if entropy and not entropy.skipped and "shannon" in entropy.details:
        paragraphs.append(f"Shannon entropy of analyzed bytes is {entropy.details['shannon']}/8.00.")

    attention = [f for f in report.findings if f.severity in {"medium", "high"}]
    if attention:
        titles = "; ".join(item.title for item in attention[:6])
        paragraphs.append("Highest-attention observations: " + titles + ".")

    errors = [err for section in report.sections for err in section.errors]
    skipped_failed = [section for section in report.sections if section.errors]
    if errors:
        names = ", ".join(section.name for section in skipped_failed)
        paragraphs.append(f"Some analyzers reported errors ({names}). See Technical Details rather than treating those areas as empty.")

    incomplete = [
        run
        for run in report.analyzer_runs
        if run.status in {"failed", "timeout", "terminated"}
    ]
    if incomplete:
        bits = [f"{run.analyzer_id}={run.status}" for run in incomplete[:8]]
        more = "" if len(incomplete) <= 8 else f" (+{len(incomplete) - 8} more)"
        paragraphs.append(
            "Analysis is incomplete for: "
            + ", ".join(bits)
            + more
            + ". That is not the same as an empty finding list."
        )
        next_steps.insert(
            0,
            "Re-run or inspect analyzer timeouts/failures; those areas were not fully analyzed.",
        )

    if identity.extension_matches is False:
        next_steps.append("Inspect why the extension disagrees with the detected type.")
    child_files = [item for item in report.artifacts if item.kind == "file" and item.id != report.root_artifact_id and item.content_id]
    if child_files:
        next_steps.append("Open contained artifacts in Findings; each has its own evidence and analyzer runs.")
    if _has(report, "strings.urls"):
        next_steps.append("Review extracted URLs and domains. This tool does not fetch them.")
    if _has(report, "pe.high-entropy-code") or _has(report, "entropy.high-for-executable"):
        next_steps.append("Inspect section entropy, overlay data, and the import table for packing.")
    if _has(report, "pe.injection-import-set"):
        next_steps.append("Review the cross-process memory APIs and whether they are expected for this program.")
    if _has(report, "pdf.javascript") or _has(report, "ole.vba-streams"):
        next_steps.append("Inspect document automation (JavaScript or VBA) before opening the file in a desktop app.")
    if _has(report, "archive.path-traversal"):
        next_steps.append("Do not extract this archive with a naive unzip path.")
    if _has(report, "signature.parse-error"):
        next_steps.append("Manually inspect the Authenticode blob; parsing failed.")
    if report.limits.get("truncated"):
        next_steps.append("Re-run with a larger --max-bytes if the interesting content may sit past the analyzed prefix.")
    if not next_steps:
        next_steps.append("Read Findings, then open Evidence for anything unexpected, then Technical Details for the raw analyzer output.")

    return " ".join(paragraphs), next_steps


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            _SEVERITY_RANK.get(item.severity, 9),
            item.category,
            item.rule_id or item.legacy_id or item.id,
            item.artifact_id or "",
        ),
    )


def _section(report: Report, name: str):
    for section in report.sections:
        if section.name == name:
            return section
    return None


def _has(report: Report, finding_id: str) -> bool:
    for item in report.findings:
        if finding_id in {item.id, item.legacy_id, item.rule_id}:
            return True
    return False


def _size_label(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB ({size} bytes)"
    return f"{size / (1024 * 1024):.2f} MiB ({size} bytes)"
