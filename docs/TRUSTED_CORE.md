# Trusted core

The trusted ExSoftware process is an **orchestrator**. It may touch hostile bytes, but it must not run complex format parsers on them.

This is static analysis with parser containment. It is not a malware sandbox.

## Trust architecture

```
HOSTILE FILE
    │
    ▼
TRUSTED CORE
    ├── bounded input acquisition
    ├── streaming hash
    ├── lightweight identification (magic / prefix)
    ├── declarative analyzer registry (no impl imports)
    ├── orchestration
    ├── protocol validation
    └── investigation graph
            │
            ▼
CONTAINED WORKERS
    ├── ZIP enumeration + extraction
    ├── OLE stream listing (identity refine)
    ├── PE / PDF / OLE / image / script parsers
    └── analyzer implementations
```

## Inventory

| Operation | Trusted parent? | Complexity |
| --- | --- | --- |
| Read up to `max_bytes` from a path | yes | bounded copy |
| SHA-256 / digest streaming | yes | hashing |
| Magic-prefix match (`identify_bytes` signatures) | yes | fixed comparisons on a prefix |
| PE `e_lfanew` check | yes | 4-byte read at a parsed offset |
| RIFF fourCC at offset 8 | yes | 4 bytes |
| Text/JSON/shebang heuristics | yes | bounded prefix, `json.loads` on ≤8 KiB text |
| ZIP central directory / member extract | **no** | contained worker (`exsoftware.container`) |
| ZIP subtype from **validated member names** | yes | string prefix checks, not ZIP parsing |
| OLE stream listing (`olefile`) | **no** | contained worker (`exsoftware.ole`) |
| OLE subtype from **validated stream names** | yes | string checks, not OLE parsing |
| PE parsing (`pefile`) | **no** | analyzer child |
| PDF (`pypdf`) | **no** | analyzer child |
| Archive listing (`zipfile` / `tarfile`) | **no** | `ArchiveAnalyzer` child |
| Protocol JSON parse | yes | schema-validated, size-capped |
| Blob open `blobs/NNNNNN.bin` | yes | parent-computed name, `O_NOFOLLOW` |

## `identify_bytes` decision

Kept in the trusted parent **except** ZIP and OLE refinement that need format parsers.

- Magic table, PE signature, RIFF, shebang, and text heuristics are small and deterministic.
- ZIP family subtype (jar/apk/docx/…) is **not** decided with `zipfile` in the parent. PK magic yields `zip`; a contained container worker lists members **before analyzers run**; the parent classifies from **names only**.
- OLE magic yields `ole` with `ole_subtype_pending`. A contained OLE worker lists streams; the parent classifies doc/xls/ppt/msi/msg from **names only**. Worker failure leaves type as `ole` and records `ole_refinement` without a parent-side olefile fallback.

## Container worker guarantee

- Enumeration and extraction of `.zip` / `.jar` / `.apk` / `.whl` happen in a Stage 4 isolated process.
- Extracted bytes land in opaque `blobs/000001.bin` slots. Archive names are metadata.
- The parent hashes blob fds itself. Child SHA-256 is ignored.
- Limits use **actual written bytes**, not ZIP header uncompressed sizes.
- There is **no OS disk quota**. The budget is enforced by the child copy loop and re-checked by the parent when opening blobs. A child can still write extra junk files in the workspace until timeout; the parent will not ingest them.

## OLE refine worker guarantee

- `olefile` runs only in the isolated OLE refine worker.
- The parent receives validated stream-name strings (length/count capped) and optional `is_ole`.
- On worker failure/timeout/invalid response, identity stays `ole` and `extra.ole_refinement` records the failure. The engine does not claim a refined subtype and does not parse OLE in-process as a fallback.

## Reparse / path guarantee

Parent blob open:

- slot must match `[0-9]{6}`
- path is `workdir/blobs/<slot>.bin` computed by the parent
- directory and file `lstat` must not be reparse points
- `O_NOFOLLOW` when the OS provides it
- child-supplied paths are never used

## Analyzer imports

The trusted parent reads `AnalyzerSpec` entries from `exsoftware.analyzers.registry`. It does not import analyzer implementation modules to learn eligibility. Workers import one implementation module when executing that analyzer. See [ARCHITECTURE_DEBT.md](ARCHITECTURE_DEBT.md) for remaining non-import debts.
