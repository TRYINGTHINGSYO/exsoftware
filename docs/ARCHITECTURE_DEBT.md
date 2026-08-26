# Architectural debt

These are known model issues. Trusted-core separation for analyzer imports and
OLE refinement is done. The items below remain.

## Entity model

`name:<kind>:<value>` currently represents non-file entities such as URLs and imported libraries inside artifact-like structures.

They are not files and they are not content-addressed. Long term they may belong in a distinct Observable/Entity model so `Artifact` can mean “bytes we analyzed.”

## Provisional identities

`unhashed:` identities are **not** content-addressed. They are stubs for members that were listed but not hashed (path traversal, encryption, size limits). Treat them as provisional. Do not compare them as if they were SHA-256 identities.

## Legacy analyzer lifting

Many analyzers still return legacy-style `details` plus `Finding` objects. The parent `Investigation.ingest_result` lifts those into observations, evidence, and relationships.

Long term, analyzers should emit normalized evidence and observations directly. Isolation serializes `AnalyzerResult` (including findings) across the process boundary; it does not replace this lifting step.

## Resolved: analyzer module import in the trusted parent

The trusted parent selects analyzers from `exsoftware.analyzers.registry.ANALYZER_REGISTRY` (declarative `AnalyzerSpec` metadata). Importing the engine does **not** import analyzer implementation modules.

`applies()` / `analyze()` still run only in isolated children. Workers load one implementation via `worker_module` / `worker_class` when that analyzer runs.

## Resolved: OLE refinement in the trusted parent

`identify_bytes` keeps OLE magic as `ole` with `ole_subtype_pending`. Stream listing uses `olefile` in a contained worker (`exsoftware.ole` protocol). The parent classifies subtype from **validated stream name strings** only (`refine_ole_type_from_streams`). There is no parent-side olefile fallback when the worker fails.
