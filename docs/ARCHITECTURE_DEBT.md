# Architectural debt

These are known model issues. Stage 5 moved ZIP-family parsing out of the trusted parent. It did not take the items below on.

## Entity model

`name:<kind>:<value>` currently represents non-file entities such as URLs and imported libraries inside artifact-like structures.

They are not files and they are not content-addressed. Long term they may belong in a distinct Observable/Entity model so `Artifact` can mean “bytes we analyzed.”

## Provisional identities

`unhashed:` identities are **not** content-addressed. They are stubs for members that were listed but not hashed (path traversal, encryption, size limits). Treat them as provisional. Do not compare them as if they were SHA-256 identities.

## Legacy analyzer lifting

Many analyzers still return legacy-style `details` plus `Finding` objects. The parent `Investigation.ingest_result` lifts those into observations, evidence, and relationships.

Long term, analyzers should emit normalized evidence and observations directly. Isolation serializes `AnalyzerResult` (including findings) across the process boundary; it does not replace this lifting step.

## Analyzer module import in the trusted parent

The parent still does `from .analyzers import ANALYZERS`. That **imports every analyzer implementation module** into the trusted process and runs their module-level code.

`applies()` / `analyze()` are not called in the parent (Stage 4). Eligibility uses class attributes. That is not the same as “analyzer code never executes here.”

Import-time side effects today are mostly class definitions and standard-library imports. `ArchiveAnalyzer` lazy-imports `zipfile`/`tarfile` inside `analyze()`, so those parsers are not loaded by the parent import. PE/PDF/image/OLE parser libraries are also imported inside `analyze()`.

Preferred long-term direction: a declarative eligibility registry that the parent can read without importing analyzer implementation modules. Not done in Stage 5.

## Remaining trusted parsers

`identify._refine_ole` still uses `olefile` in the parent. ZIP was moved; OLE was not.
