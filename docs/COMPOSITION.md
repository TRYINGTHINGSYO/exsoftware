# Composition report (derived view)

The investigation graph remains canonical (`schema_version` **1**).

Stage 6 adds an additive JSON object:

```text
composition
```

Old readers ignore it. `--json` still emits schema 1. Engine version is **0.6.0**.

## Choice

Embed the derived view on the same report rather than a second endpoint. One analyze call produces both the evidence graph and the human explanation. A future UI can still fetch `/api/analyze` once.

`composition` is **not** an analyzer. It does not parse hostile bytes. It only reads the graph.

## Shape

```json
{
  "version": 1,
  "derived_from_schema": 1,
  "behavior_disclaimer": "These are static observations. They do not mean the program ran…",
  "identity": {
    "category": "python_script",
    "category_label": "Python script",
    "detected_type": "python",
    "sha256": "…",
    "signed": "none | certificate_present | not_applicable",
    "trust_verified": false,
    "refs": { "artifact_ids": [], "observation_ids": [], "evidence_ids": [], "finding_ids": [], "relationship_ids": [], "rule_ids": [] }
  },
  "stats": { "contained_entries": 0, "unique_content_artifacts": 1, "duplicate_occurrences": 0, "by_role": {} },
  "notable_components": [],
  "component_tree": [],
  "dependencies": [],
  "capabilities": [],
  "important_observations": [],
  "external_references": { "urls": [], "domains": [], "ips": [], "file_paths": [], "registry_paths": [], "imported_modules": [], "referenced_libraries": [] },
  "gaps": [],
  "completeness": {
    "state": "complete_for_supported_static_analysis | partial | significantly_incomplete",
    "executed": false
  }
}
```

Every capability and important observation carries `refs` back into the graph.

## Completeness states

| State | Meaning |
| --- | --- |
| `complete_for_supported_static_analysis` | Supported analyzers finished for opened artifacts. Unsupported types are expected, not failures. |
| `partial` | Encrypted members, a failed analyzer, or a limit left something unexplained. |
| `significantly_incomplete` | Timeout, truncation, parser failure, or several missing members. |

Do not read this as “the file is safe” or “analysis saw everything a sandbox would see.”

## ZIP listing

When ZIP-family recursion is enabled, `ArchiveAnalyzer` is **skipped** because the contained container worker already listed/extracted members. That is an execution-environment optimization, not a detection change. Analyzer versions were not bumped.
