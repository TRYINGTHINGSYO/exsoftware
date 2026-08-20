"""Derived software-composition view. Not a replacement for schema 1."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

COMPOSITION_VERSION = 1
BEHAVIOR_DISCLAIMER = (
    "These are static observations. They do not mean the program ran, "
    "contacted a host, or performed the capability at runtime."
)


def graph_ref(
    *,
    artifact_ids: list[str] | None = None,
    observation_ids: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    finding_ids: list[str] | None = None,
    relationship_ids: list[str] | None = None,
    rule_ids: list[str] | None = None,
) -> dict[str, list[str]]:
    return {
        "artifact_ids": list(artifact_ids or []),
        "observation_ids": list(observation_ids or []),
        "evidence_ids": list(evidence_ids or []),
        "finding_ids": list(finding_ids or []),
        "relationship_ids": list(relationship_ids or []),
        "rule_ids": list(rule_ids or []),
    }


@dataclass
class CompositionIdentity:
    category: str
    category_label: str
    detected_type: str
    detected_family: str
    description: str
    extension_agrees: bool | None
    sha256: str | None
    size: int
    signed: str
    certificate_subject: str | None
    trust_verified: bool
    refs: dict[str, list[str]] = field(default_factory=graph_ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "category_label": self.category_label,
            "detected_type": self.detected_type,
            "detected_family": self.detected_family,
            "description": self.description,
            "extension_agrees": self.extension_agrees,
            "sha256": self.sha256,
            "size": self.size,
            "signed": self.signed,
            "certificate_subject": self.certificate_subject,
            "trust_verified": self.trust_verified,
            "refs": dict(self.refs),
        }


@dataclass
class ComponentNode:
    artifact_id: str
    content_id: str | None
    label: str
    role: str
    detected_type: str | None
    occurrence_count: int
    names: list[str]
    notable: bool
    summary: str | None = None
    children: list[ComponentNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "content_id": self.content_id,
            "label": self.label,
            "role": self.role,
            "detected_type": self.detected_type,
            "occurrence_count": self.occurrence_count,
            "names": list(self.names),
            "notable": self.notable,
            "summary": self.summary,
            "children": [item.to_dict() for item in self.children],
        }


@dataclass
class CompositionReport:
    version: int
    identity: CompositionIdentity
    stats: dict[str, Any]
    notable_components: list[ComponentNode]
    component_tree: list[ComponentNode]
    dependencies: list[dict[str, Any]]
    capabilities: list[dict[str, Any]]
    important_observations: list[dict[str, Any]]
    external_references: dict[str, list[dict[str, Any]]]
    gaps: list[dict[str, Any]]
    completeness: dict[str, Any]
    behavior_disclaimer: str = BEHAVIOR_DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "derived_from_schema": 1,
            "behavior_disclaimer": self.behavior_disclaimer,
            "identity": self.identity.to_dict(),
            "stats": dict(self.stats),
            "notable_components": [item.to_dict() for item in self.notable_components],
            "component_tree": [item.to_dict() for item in self.component_tree],
            "dependencies": list(self.dependencies),
            "capabilities": list(self.capabilities),
            "important_observations": list(self.important_observations),
            "external_references": dict(self.external_references),
            "gaps": list(self.gaps),
            "completeness": dict(self.completeness),
        }
