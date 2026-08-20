"""Component tree and composition statistics."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ..models import Artifact, Report
from .model import ComponentNode

_EXECUTABLE = {"pe", "elf", "macho64", "macho32", "macho-fat", "macho32-be", "macho64-be", "dos-mz"}
_SCRIPT = {
    "python", "powershell", "javascript", "typescript", "vbscript", "batch", "shell",
    "ruby", "php", "script", "registry-script",
}
_ARCHIVE = {"zip", "jar", "apk", "wheel", "gzip", "tar", "7z", "rar"}
_IMAGE = {"png", "jpeg", "gif", "bmp", "webp", "ico"}
_CONFIG = {"json", "xml", "toml", "text", "html", "yaml"}
_BYTECODE = {"java-class", "pyc", "dex", "wasm"}
_DOCUMENT = {"pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt", "rtf", "ole"}
_NOTABLE_NAMES = {
    "androidmanifest.xml",
    "meta-inf/manifest.mf",
    "fabric.mod.json",
    "plugin.yml",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pkg-info",
    "wheel",
}

_GROUP_LIMIT = 8


def role_for(artifact: Artifact) -> str:
    detected = artifact.detected_type or "unknown"
    if not artifact.complete or artifact.content_id is None:
        reason = str((artifact.metadata or {}).get("not_analyzed_reason") or (artifact.metadata or {}).get("reason") or "")
        if "encrypt" in reason:
            return "encrypted"
        if "traversal" in reason or "path" in reason:
            return "rejected"
        if reason:
            return "not_analyzed"
        return "incomplete"
    if detected in _EXECUTABLE:
        return "native_library" if _looks_library(artifact) else "executable"
    if detected in _SCRIPT:
        return "script"
    if detected in _ARCHIVE:
        return "archive"
    if detected in _IMAGE:
        return "image"
    if detected in _BYTECODE:
        return "bytecode"
    if detected in _DOCUMENT:
        return "document"
    if detected in _CONFIG:
        return "configuration"
    if artifact.kind == "certificate":
        return "certificate"
    if detected == "unknown":
        return "unknown"
    return detected or "resource"


def is_notable(artifact: Artifact, role: str) -> bool:
    if role in {"executable", "script", "native_library", "archive", "encrypted", "rejected", "document"}:
        return True
    names = [name.replace("\\", "/").lower() for name in artifact.names]
    if any(name in _NOTABLE_NAMES or Path(name).name.lower() in _NOTABLE_NAMES for name in names):
        return True
    if any(name.endswith((".dll", ".exe", ".so", ".dylib", ".class")) for name in names) and role != "bytecode":
        return True
    if role == "configuration" and any(
        Path(name).name.lower() in {"manifest.mf", "fabric.mod.json", "androidmanifest.xml"} or name.lower().endswith(".dist-info/metadata")
        for name in names
    ):
        return True
    return False


def build_components(report: Report) -> tuple[list[ComponentNode], list[ComponentNode], dict]:
    artifacts = {item.id: item for item in report.artifacts}
    children: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    occurrence_names: dict[str, list[str]] = defaultdict(list)
    contained_entries = 0
    for rel in report.relationships:
        if rel.type != "CONTAINS":
            continue
        parent = artifacts.get(rel.source_id)
        child = artifacts.get(rel.target_id)
        if parent is None or child is None:
            continue
        if child.kind not in {"file"} and not child.id.startswith("unhashed:"):
            continue
        contained_entries += 1
        name = rel.extra.get("member_name") or child.primary_name
        occurrence_names[child.id].append(name)
        children[rel.source_id].append((rel.target_id, rel.extra or {}))

    file_artifacts = [item for item in report.artifacts if item.kind == "file" or item.id.startswith("unhashed:")]
    root_id = report.root_artifact_id or ""
    unique_content = {item.content_id for item in file_artifacts if item.content_id and item.id != root_id}
    duplicate_occurrences = 0
    for names in occurrence_names.values():
        if len(names) > 1:
            duplicate_occurrences += len(names) - 1

    tree = [_node(artifacts[root_id], children, artifacts, occurrence_names, depth=0)] if root_id in artifacts else []
    notable = _collect_notable(tree)
    by_role: dict[str, int] = defaultdict(int)
    for item in file_artifacts:
        if item.id == root_id:
            continue
        by_role[role_for(item)] += 1
    stats = {
        "contained_entries": contained_entries,
        "unique_content_artifacts": len(unique_content),
        "duplicate_occurrences": duplicate_occurrences,
        "by_role": dict(sorted(by_role.items())),
    }
    return notable, tree, stats


def _looks_library(artifact: Artifact) -> bool:
    names = [name.lower() for name in artifact.names]
    return any(name.endswith((".dll", ".so", ".dylib", ".ocx", ".sys")) for name in names)


def _node(
    artifact: Artifact,
    children: dict[str, list[tuple[str, dict]]],
    artifacts: dict[str, Artifact],
    occurrence_names: dict[str, list[str]],
    *,
    depth: int,
) -> ComponentNode:
    role = role_for(artifact)
    names = list(dict.fromkeys(occurrence_names.get(artifact.id) or artifact.names or [artifact.primary_name]))
    child_nodes: list[ComponentNode] = []
    grouped: dict[str, list[Artifact]] = defaultdict(list)
    seen_child = set()
    for child_id, _extra in children.get(artifact.id, []):
        if child_id in seen_child:
            continue
        seen_child.add(child_id)
        child = artifacts.get(child_id)
        if child is None:
            continue
        child_role = role_for(child)
        if child_role in {"bytecode", "image"} and not is_notable(child, child_role):
            grouped[child_role].append(child)
        else:
            child_nodes.append(_node(child, children, artifacts, occurrence_names, depth=depth + 1))
    for group_role, group in grouped.items():
        if len(group) <= 2:
            for item in group:
                child_nodes.append(_node(item, children, artifacts, occurrence_names, depth=depth + 1))
            continue
        label = {
            "bytecode": f"{len(group)} bytecode/class files",
            "image": f"{len(group)} image resources",
        }.get(group_role, f"{len(group)} {group_role} files")
        child_nodes.append(
            ComponentNode(
                artifact_id="",
                content_id=None,
                label=label,
                role="summary",
                detected_type=group_role,
                occurrence_count=len(group),
                names=[],
                notable=False,
                summary=label,
            )
        )
    child_nodes.sort(key=lambda item: (not item.notable, item.role, item.label.lower()))
    return ComponentNode(
        artifact_id=artifact.id,
        content_id=artifact.content_id,
        label=_label(artifact, role),
        role=role,
        detected_type=artifact.detected_type,
        occurrence_count=max(len(names), 1),
        names=names[:12],
        notable=is_notable(artifact, role) or depth == 0,
        children=child_nodes,
    )


def _label(artifact: Artifact, role: str) -> str:
    name = artifact.primary_name
    if name.startswith("sha256:") or name.startswith("unhashed:"):
        name = artifact.names[0] if artifact.names else "unnamed component"
    if role == "encrypted":
        return f"{name} (encrypted, not extracted)"
    if role == "rejected":
        return f"{name} (not extracted)"
    if role == "native_library":
        return f"{name} (native library)"
    if role == "executable":
        return f"{name} (executable)"
    if role == "script":
        kind = artifact.detected_type or "script"
        return f"{name} ({kind} script)" if "script" not in name.lower() else name
    if role == "archive":
        return f"{name} (archive)"
    return name


def _collect_notable(nodes: list[ComponentNode]) -> list[ComponentNode]:
    out: list[ComponentNode] = []

    def walk(items: list[ComponentNode], *, root: bool) -> None:
        for item in items:
            if item.notable and not root and item.role != "summary":
                out.append(
                    ComponentNode(
                        artifact_id=item.artifact_id,
                        content_id=item.content_id,
                        label=item.label,
                        role=item.role,
                        detected_type=item.detected_type,
                        occurrence_count=item.occurrence_count,
                        names=list(item.names),
                        notable=True,
                        summary=item.summary,
                    )
                )
            walk(item.children, root=False)

    walk(nodes, root=True)
    return out[:40]
