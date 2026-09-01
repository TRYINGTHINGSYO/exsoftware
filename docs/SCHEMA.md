# Report schema 1

`schema_version` is the integer **1**. Prototype reports used the string `"0.1"` and lacked the investigation graph.

The JSON document is intended to remain readable if ExSoftware disappears. Important facts are not stored only in Python objects.

## Compatibility

CLI commands are unchanged:

```powershell
exsoftware analyze file.exe
exsoftware analyze file.exe --json
exsoftware serve
```

`--json` now emits schema 1. Additive graph fields are always present. The previous UI fields still exist:

- `identity`, `hashes`, `overview`, `next_steps`, `findings`, `analyzers`, `limits`, `capabilities`

New fields:

- `schema`, `engine`, `root_artifact_id`
- `artifacts`, `relationships`, `observations`, `evidence`, `analyzer_runs`
- `composition` (Stage 6 derived explanation; ignore if unknown)

Findings gained `rule_id`, `rule_version`, `certainty`, `artifact_id`, `evidence_ids`, `observation_ids`, `legacy_id`, `created_at`. Nested `evidence` remains for display.

`analyzers` is the **root artifact** run list (same role as before). `analyzer_runs` includes contained artifacts.

## Top-level object

| Field | Type | Notes |
| --- | --- | --- |
| `schema` | string | `exsoftware.report` |
| `schema_version` | integer | `1` |
| `engine` | object | `{name, version, schema}` |
| `analyzed_at` | string | ISO-8601 UTC |
| `root_artifact_id` | string | Content id of the submitted file |
| `identity` | object | Original filename/path/type projection |
| `hashes` | object | md5/sha1/sha256/sha512 of the submitted file when available |
| `artifacts` | array | All artifacts |
| `relationships` | array | Typed edges |
| `observations` | array | Facts |
| `evidence` | array | Canonical evidence store |
| `findings` | array | Interpretations |
| `analyzer_runs` | array | Per-artifact analyzer outcomes |
| `analyzers` | array | Root-only legacy projection |
| `limits` | object | Size caps, recursion caps, `executed: false`, and report-wide worker isolation evidence |
| `overview` | string | Deterministic summary |
| `next_steps` | array | Deterministic checklist |
| `composition` | object | Derived software-composition explanation. Additive in 0.6.0. Not canonical evidence. See [COMPOSITION.md](COMPOSITION.md). |

## Versioning strategy

- Increment `schema_version` for breaking JSON changes.
- Additive fields may appear without a bump only if old readers can ignore them.
- Rule IDs are forever; do not reuse `PE.FORMAT.001` for a different meaning. Mint `PE.FORMAT.002`.
- Analyzer `version` is independent of schema version.

## Example (trimmed)

```json
{
  "schema": "exsoftware.report",
  "schema_version": 1,
  "engine": {"name": "exsoftware", "version": "0.6.0", "schema": "exsoftware.report"},
  "root_artifact_id": "sha256:2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3",
  "artifacts": [
    {
      "id": "sha256:2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3",
      "kind": "file",
      "content_id": "sha256:2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3",
      "names": ["sample.zip"],
      "detected_type": "zip"
    },
    {
      "id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "kind": "file",
      "names": ["script.ps1"],
      "detected_type": "powershell"
    }
  ],
  "relationships": [
    {
      "id": "rel-0001",
      "type": "CONTAINS",
      "source_id": "sha256:2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3",
      "target_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "certainty": "observed",
      "analyzer_id": "archive",
      "analyzer_version": "1.0.0",
      "extra": {"member_name": "script.ps1", "extracted": true}
    }
  ],
  "observations": [
    {
      "id": "obs-0001",
      "artifact_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "kind": "string",
      "statement": "Extracted URL: https://example.test/a",
      "certainty": "observed",
      "analyzer_id": "strings",
      "analyzer_version": "1.0.0",
      "evidence_ids": ["ev-0001"]
    }
  ],
  "evidence": [
    {
      "id": "ev-0001",
      "artifact_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "kind": "string",
      "summary": "Extracted URL",
      "location": "offset 12",
      "value": "https://example.test/a",
      "analyzer_id": "strings",
      "analyzer_version": "1.0.0"
    }
  ],
  "findings": [
    {
      "id": "fnd-0001",
      "legacy_id": "strings.urls",
      "rule_id": "STR.URL.001",
      "rule_version": "1.0.0",
      "certainty": "observed",
      "severity": "low",
      "confidence": "high",
      "title": "1 URL(s) extracted from strings",
      "summary": "The file contains URL-like strings. They were not fetched.",
      "artifact_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "analyzer_id": "strings",
      "analyzer_version": "1.0.0",
      "evidence_ids": ["ev-0001"],
      "observation_ids": ["obs-0001"]
    }
  ]
}
```

Load with `Report.from_dict(json.loads(text))`.

## Worker isolation inventory

`limits.isolation.workers[]` is an additive schema-1 field containing every
analyzer, archive broker, and OLE broker worker that was launched or whose
launch was attempted for the analysis. Each row records:

- `worker_type`, `worker_id`, `artifact_id`, and the analyzer `run_id` when applicable
- worker outcome `status` and whether a child was actually `launched`
- the actual `mechanism`, complete per-worker `capabilities`, fallback state,
  and non-enforced `weaker_capabilities`
- protocol identity plus bounded launch/token/job/policy evidence relevant to
  understanding a downgrade

The sibling `limits.isolation.mechanism` and `.capabilities` fields remain for
compatibility, but are conservative aggregates over the complete worker list.
`mechanism` is `mixed` when executed workers used different mechanisms or when
an attempted worker did not launch alongside launched workers. `mechanisms`
lists the actual mechanisms, and `mechanism_counts` includes `not-launched`.

Capability aggregation uses this weakest-to-strongest order:
`failed`, `unsupported`, `degraded`, `enforced`. The aggregate for a capability
is the weakest state reported by any worker. `capability_counts` shows the
per-state counts used to produce each aggregate.

Old schema-1 reports without `workers` remain loadable. Readers that do not
recognize the additive fields can continue using the corrected legacy summary.
