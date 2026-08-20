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
    ├── orchestration
    ├── protocol validation
    └── investigation graph
            │
            ▼
CONTAINED WORKERS
    ├── ZIP enumeration + extraction
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
| PE parsing (`pefile`) | **no** | analyzer child |
| PDF (`pypdf`) | **no** | analyzer child |
| OLE (`olefile`) in `identify._refine_ole` | **yes, remaining** | complex parser still in parent identify |
| Archive listing (`zipfile` / `tarfile`) | **no** | `ArchiveAnalyzer` child |
| Protocol JSON parse | yes | schema-validated, size-capped |
| Blob open `blobs/NNNNNN.bin` | yes | parent-computed name, `O_NOFOLLOW` |

## `identify_bytes` decision

Kept in the trusted parent **except** ZIP refinement.

- Magic table, PE signature, RIFF, shebang, and text heuristics are small and deterministic.
- ZIP family subtype (jar/apk/docx/…) is **not** decided with `zipfile` in the parent. PK magic yields `zip`; a contained container worker lists members **before analyzers run**; the parent classifies from **names only**.
- **OLE refinement still uses `olefile` in the parent.** That is remaining trusted-core complexity, documented here. Stage 5 moved ZIP, not OLE.

## Container worker guarantee

- Enumeration and extraction of `.zip` / `.jar` / `.apk` / `.whl` happen in a Stage 4 isolated process.
- Extracted bytes land in opaque `blobs/000001.bin` slots. Archive names are metadata.
- The parent hashes blob fds itself. Child SHA-256 is ignored.
- Limits use **actual written bytes**, not ZIP header uncompressed sizes.
- There is **no OS disk quota**. The budget is enforced by the child copy loop and re-checked by the parent when opening blobs. A child can still write extra junk files in the workspace until timeout; the parent will not ingest them.

## Reparse / path guarantee

Parent blob open:

- slot must match `[0-9]{6}`
- path is `workdir/blobs/<slot>.bin` computed by the parent
- directory and file `lstat` must not be reparse points
- `O_NOFOLLOW` when the OS provides it
- child-supplied paths are never used

## Analyzer imports

The trusted parent still imports analyzer implementation modules to read `detected_types` / `detected_families`. Module-level code in those files runs in the parent. See [ARCHITECTURE_DEBT.md](ARCHITECTURE_DEBT.md).
