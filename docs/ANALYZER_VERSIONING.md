# Analyzer versioning

Each analyzer class has a stable `name` and a `version` string (currently `1.0.0` unless a specific analyzer documents otherwise).

The version is recorded on `analyzer_runs`, findings, observations, relationships, and evidence. It survives the process isolation boundary: the child must echo the same `analyzer_id` / `analyzer_version` that the parent requested, and the parent rejects mismatches.

## When the version must change

Advance `Analyzer.version` when a change can alter observations, evidence, findings, or relationship-producing details for the same input.

Examples that **require** a bump:

- Parser bug fix that changes extracted fields, strings, imports, or hashes
- Detection logic change (new finding, removed finding, different severity/certainty)
- Evidence generation change (different offsets, values, or evidence kinds)
- Interpretation change (same bytes, different conclusion)

## When the version must not change

A cosmetic documentation, comment, or logging change does not require a version bump.

Internal isolation/protocol changes also do not require an analyzer version bump unless they change that analyzer’s observable results. Skipping `ArchiveAnalyzer` on ZIP-family artifacts when the contained container worker already listed members is an execution-environment change; analyzer versions were not bumped.

## What this milestone did not do

Analyzer versions were **not** mass-incremented for Stage 3, Stage 4, or Stage 5. Process isolation, parser containment, and moving ZIP extraction across the process boundary are execution-environment changes, not detection-logic changes.
