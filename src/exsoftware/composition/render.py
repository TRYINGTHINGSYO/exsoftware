"""Human-facing composition text. Deterministic, evidence-backed."""

from __future__ import annotations

from .. import __version__
from ..models import Report
from .model import CompositionReport


def render_text(report: Report, composition: CompositionReport | dict | None = None) -> str:
    comp = composition if isinstance(composition, dict) else (composition.to_dict() if composition is not None else report.composition)
    if not comp:
        from .engine import compose

        comp = compose(report).to_dict()
    ident = comp["identity"]
    lines = [
        "EXSOFTWARE",
        f"schema {report.schema_version}  engine {report.engine.get('version', __version__)}  composition {comp.get('version', 1)}  executed=no",
        "",
        "What this is",
        "-------------",
        ident.get("category_label") or ident.get("detected_type"),
        ident.get("description") or "",
    ]
    if ident.get("sha256"):
        lines.append(f"SHA-256: {ident['sha256']}")
    lines.append(f"Size: {ident.get('size')} bytes")
    ext = ident.get("extension_agrees")
    if ext is False:
        lines.append("Extension: does not match detected type")
    elif ext is True:
        lines.append("Extension: matches detected type")
    lines.append(_signed_line(ident))
    lines += ["", "Composition", "-----------"]
    stats = comp.get("stats") or {}
    by_role = stats.get("by_role") or {}
    if by_role:
        bits = [f"{count} {role.replace('_', ' ')}" for role, count in by_role.items() if count]
        lines.append("; ".join(bits) if bits else "No contained file components.")
    else:
        lines.append("Single artifact; no contained file components.")
    if stats.get("contained_entries"):
        lines.append(
            f"Contained entries: {stats['contained_entries']}  "
            f"unique content: {stats.get('unique_content_artifacts', 0)}  "
            f"duplicate occurrences: {stats.get('duplicate_occurrences', 0)}"
        )
    notable = comp.get("notable_components") or []
    if notable:
        lines.append("Notable components:")
        for item in notable[:12]:
            extra = f"  ({item['occurrence_count']} names)" if item.get("occurrence_count", 1) > 1 else ""
            lines.append(f"  * {item['label']}{extra}")
    tree = comp.get("component_tree") or []
    if tree and (tree[0].get("children") or []):
        lines += ["", "Component tree", "--------------"]
        lines.extend(_tree_lines(tree[0], prefix=""))
    caps = comp.get("capabilities") or []
    lines += ["", "Capabilities observed", "---------------------"]
    lines.append(comp.get("behavior_disclaimer") or "")
    if not caps:
        lines.append("(none derived from current analyzers)")
    else:
        for cap in caps:
            lines.append(f"* {cap['title']}")
            lines.append(f"    {cap['statement']}")
            lines.append(f"    Not established: {cap['not_established']}")
    important = comp.get("important_observations") or []
    lines += ["", "Important observations", "----------------------"]
    if not important:
        lines.append("(none beyond identity)")
    for item in important:
        lines.append(f"* {item['title']}")
        lines.append(f"    {item['summary']}")
        lines.append(f"    Why surfaced: {item['why_surfaced']}")
    deps = comp.get("dependencies") or []
    lines += ["", "Dependencies", "------------"]
    if not deps:
        lines.append("(none observed as imports/needed libraries)")
    else:
        current = None
        for dep in deps[:30]:
            if dep["group"] != current:
                current = dep["group"]
                lines.append(f"{current.replace('_', ' ')}:")
            lines.append(f"  {dep['name']}")
        if len(deps) > 30:
            lines.append(f"  ... {len(deps) - 30} more")
    refs = comp.get("external_references") or {}
    shown_refs = False
    for key, title in (
        ("urls", "URLs (strings; not fetched)"),
        ("ips", "IP literals (strings; not contacted)"),
        ("registry_paths", "Registry path strings"),
    ):
        values = refs.get(key) or []
        if not values:
            continue
        if not shown_refs:
            lines += ["", "External references", "-------------------"]
            shown_refs = True
        lines.append(title + ":")
        for item in values[:8]:
            lines.append(f"  {item['value']}")
    gaps = comp.get("gaps") or []
    lines += ["", "Analysis gaps", "-------------"]
    complete = comp.get("completeness") or {}
    lines.append(f"Coverage: {complete.get('state')}")
    if complete:
        lines.append(
            f"Analyzers completed={complete.get('completed')} unsupported={complete.get('unsupported')} "
            f"failed={complete.get('failed')} timeout={complete.get('timeout')} "
            f"encrypted members={complete.get('encrypted_members')} limit-rejected={complete.get('limit_rejected')}"
        )
    for gap in gaps:
        lines.append(f"* {gap['statement']}")
    lines += ["", "Findings (detail)", "-----------------"]
    name_by_id = {item.id: item.primary_name for item in report.artifacts}
    if not report.findings:
        lines.append("(none)")
    for finding in report.findings:
        label = finding.rule_id or finding.legacy_id or finding.id
        where = name_by_id.get(finding.artifact_id or "", "")
        where = f" @ {where}" if where else ""
        lines.append(
            f"[{finding.severity}/{finding.confidence}/{finding.certainty or 'derived'}] {label}{where}: {finding.title}"
        )
        lines.append(f"    {finding.summary}")
    incomplete = [run for run in report.analyzer_runs if run.status in {"failed", "timeout", "terminated"}]
    if incomplete:
        lines += ["", "Incomplete analyzers"]
        for run in incomplete:
            lines.append(f"- {run.analyzer_id}: {run.status}  result: not analyzed")
    return "\n".join(lines) + "\n"


def _signed_line(ident: dict) -> str:
    state = ident.get("signed")
    if state == "certificate_present":
        subject = ident.get("certificate_subject") or "subject present"
        return f"Signed: certificate present ({subject}); trust not verified"
    if state == "none":
        return "Signed: no Authenticode table; catalog signatures not checked"
    return "Signed: not applicable"


def _tree_lines(node: dict, *, prefix: str, is_last: bool = True, is_root: bool = True) -> list[str]:
    lines = []
    if is_root:
        lines.append(node.get("label") or node.get("artifact_id") or "root")
        child_prefix = ""
    else:
        branch = "`-- " if is_last else "|-- "
        lines.append(prefix + branch + (node.get("label") or node.get("summary") or ""))
        child_prefix = prefix + ("    " if is_last else "|   ")
    children = node.get("children") or []
    for index, child in enumerate(children[:24]):
        last = index == len(children[:24]) - 1 and len(children) <= 24
        lines.extend(_tree_lines(child, prefix=child_prefix, is_last=last, is_root=False))
    if len(children) > 24:
        lines.append(child_prefix + f"`-- ... {len(children) - 24} more")
    return lines
