# Data model

ExSoftware’s durable investigation format is a graph, not a bag of UI strings.

```
file → identify → analyzers → observations + evidence → findings + relationships → report
```

The five core objects are **Artifact**, **Relationship**, **Observation**, **Evidence**, and **Finding**. They are serialized in the versioned JSON report (`schema_version: 1`). Python objects are a convenience. The JSON is the record.

## Artifact

A concrete object that was analyzed or discovered.

File-like artifacts are identified by **content**, not by filename:

```
sha256:<hex>
```

`malware.exe` and `cute-cat.jpg` with identical bytes are the same artifact. The filename is stored on `names[]` as metadata.

Entities without bytes (imported DLL names, URL strings, certificate subjects) use:

```
name:<kind>:<value>
```

These are not content-addressed. They exist so relationships have stable endpoints.

Members that could not be hashed (path traversal, encryption, size limits) use an `unhashed:` stub id and `complete: false`.

## Relationship

A typed edge with provenance.

| Type | Meaning |
| --- | --- |
| `CONTAINS` | Archive or container lists/holds a child |
| `EXTRACTED_FROM` | Child bytes were taken from a parent container |
| `IMPORTS` | Binary or script import table / AST import |
| `DEPENDS_ON` | ELF DT_NEEDED / Mach-O dylib |
| `REFERENCES` | A string or field names an URL, domain, IP, or path |
| `LINKS_TO` | Shortcut target |
| `SIGNED_BY` | Authenticode PKCS#7 certificate |
| `EMBEDS` | Reserved for nested payloads with their own bytes |
| `LOADS` | Reserved for future load-library observations |

Every relationship records `source_id`, `target_id`, `type`, `certainty`, `analyzer_id`, `analyzer_version`, and optional `evidence_ids`.

A URL string produces `REFERENCES` with certainty **observed**. It does **not** produce a fact that the program contacted that host.

## Observation

A fact close to the raw evidence.

Examples:

- SHA-256 equals X
- PE import table lists `winhttp.dll`
- ZIP central directory contains `../evil.exe`
- ASCII string `https://example.test` at offset 412

Observations default to certainty **observed**.

## Evidence

The material that backs an observation or finding: offsets, strings, parser fields, archive paths, AST locations, import names, hashes.

Canonical evidence lives in the report’s `evidence` array. Findings also include a resolved `evidence` view so older UI code can render “why?” without joining IDs.

## Finding

A deterministic interpretation of observations. Findings are not malware verdicts.

Each finding includes:

- instance `id` (`fnd-0001`) unique inside the report
- stable `rule_id` (`PE.IMPORT.INJECT.001`)
- `rule_version`
- `analyzer_id` / `analyzer_version`
- `severity` (attention) and `confidence` (how sure we are of the interpretation)
- `certainty` (observed / derived / inferred / unknown / not_analyzed)
- `artifact_id`
- `evidence_ids` and `observation_ids`
- `created_at`
- `legacy_id` (prototype dotted ids, for the 0.1 → 1.0 transition)

### Rule ID scheme

`AREA.SUBJECT.QUALIFIER.NNN`

Examples: `ID.EXT.MISMATCH.001`, `STR.URL.001`, `PE.IMPORT.NETWORK.001` is not used; networking APIs are `PE.IMPORT.NOTABLE.001` plus inferred capabilities. Injection-shaped import sets are `PE.IMPORT.INJECT.001`.

See `src/exsoftware/rules/catalog.py`.

## Certainty

These values are stored on findings, observations, and relationships. They are not just UI wording.

| Value | Meaning |
| --- | --- |
| `observed` | Directly present in bytes, parser output, or metadata |
| `derived` | Deterministic conclusion from observations (extension mismatch, high entropy for this format) |
| `inferred` | Plausible capability or intent-shaped reading (import set often used to inject code). Still not a runtime claim. |
| `unknown` | We could not tell |
| `not_analyzed` | We did not look, usually because a safety limit fired |

**Observed:** the file imports `WinHTTP`.  
**Inferred:** the program may perform HTTP networking.  
**Not allowed as fact:** the program contacts example.com at runtime, merely because that string exists.

## Analyzer provenance

Every analyzer class has a stable `name` and `version` (currently `1.0.0`). Every `analyzer_runs[]` row records:

- `status`: `completed` | `unsupported` | `skipped` | `failed` | `timeout` | `terminated`
- `analyzer_id`, `analyzer_version`, `artifact_id`
- errors, details, duration

Absence of a PE section on a ZIP is `unsupported` for that artifact, not proof that no PE exists inside it. Contained PE files get their own runs.

## Adding an analyzer

1. Subclass `exsoftware.analyzers.base.Analyzer`.
2. Set `name`, `title`, `version`.
3. Set `detected_types` / `detected_families` (leave both `None` for always-on). Child-side `applies()` uses the same metadata; the trusted parent must not call it.
4. Implement `analyze(ctx) -> AnalyzerResult`.
5. Return `details` (structured facts) and `findings` (interpretations with nested evidence).
6. Add a declarative `AnalyzerSpec` to `exsoftware.analyzers.registry` (id, version, title, worker module/class, eligibility sets). The trusted parent must not need to import the implementation module.
7. Add a rule mapping in `rules/catalog.py` if you introduce new finding ids.

See [ANALYZER_VERSIONING.md](ANALYZER_VERSIONING.md). Analyzer versions were not mass-changed in Stage 4.

The pipeline will:

- select analyzers from the declarative registry (`detected_types` / `detected_families` on `AnalyzerSpec`; trusted parent, no analyzer methods, no implementation imports)
- record the run (including unsupported/failed/timeout/terminated)
- lift findings into the graph with evidence + observed backing observations
- emit relationships from well-known `details` keys (`imports`, `urls`, `needed`, `certificates`, …)

Do not execute the sample. Do not fetch extracted URLs.

`analyze()` runs in a least-privilege child process. The contract is unchanged: return `AnalyzerResult`. Isolation details are documented in [ISOLATE_PROTOCOL.md](ISOLATE_PROTOCOL.md) and [SECURITY_MODEL.md](SECURITY_MODEL.md). Remaining model debt is listed in [ARCHITECTURE_DEBT.md](ARCHITECTURE_DEBT.md).
