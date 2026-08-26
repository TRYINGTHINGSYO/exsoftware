# Analysis pipeline

ExSoftware analyzes a file with **static, local, deterministic** methods. It does not execute the file, does not fetch extracted URLs, and does not use an LLM.

```
file
  -> load (path or bytes, size-capped)
  -> content-addressed artifact (SHA-256)
  -> identify (magic / prefix; PK -> zip; OLE magic -> ole pending)
  -> contained ZIP listing/extraction (if ZIP-family)
  -> contained OLE stream listing (if OLE pending)
  -> analyzers (each independently, per artifact, in an isolated child process)
  -> observations + evidence + findings + relationships
  -> derived composition report (no extra parsing)
  -> nested ZIP-family members through the same pipeline
  -> versioned JSON report
```

See also [DATA_MODEL.md](DATA_MODEL.md), [SCHEMA.md](SCHEMA.md), and [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Load

`exsoftware.context` reads the file:

- Path analysis hashes the **full** file for identity, then feeds at most `--max-bytes` (default 64 MiB) to format analyzers.
- Upload/bytes analysis hashes whatever was received. If that buffer was truncated, the artifact is marked incomplete.

The file is never launched as a process.

## Identify

`exsoftware.identify.identify_bytes` matches known magics, then refines RIFF/text in-process. PK magic yields `zip`; ZIP subtype (jar/apk/docx/…) is decided later from **contained listing names**, not by parent-side `zipfile`. OLE magic yields `ole`; subtype (doc/xls/…) is decided later from **contained OLE stream names**, not by parent-side `olefile`. The claimed extension is compared to the detected type. A mismatch is a **derived** finding, not a silent correction.

## Analyzers

Each analyzer has `name`, `version`, `applies(ctx)`, and `analyze(ctx)`. Register a declarative `AnalyzerSpec` in `exsoftware.analyzers.registry` (worker module/class identifiers plus eligibility metadata). Do not require the trusted parent to import the implementation module.

The trusted parent selects analyzers from the registry via `is_eligible`. It does not instantiate analyzers and does not call `applies()` or `analyze()`. Those methods run only in the isolated child, after the worker imports that analyzer’s implementation.

`applies()` in the child is a second check using the same declarative metadata.

The pipeline records every class for every artifact:

| status | Meaning |
| --- | --- |
| completed | Ran |
| unsupported | Does not apply to this type (no child process) |
| skipped | Applies but was not run |
| failed | Exception, crash, unexpected exit, or invalid child output |
| timeout | Exceeded analyzer timeout; child was killed; not analyzed |
| terminated | Child was killed for a non-timeout reason |

Always-on: identity, filesystem, hashes, entropy, strings, embedded.  
Conditional: pe, signature, elf, macho, lnk, archive, pdf, image, ole, script.

See [ISOLATE_PROTOCOL.md](ISOLATE_PROTOCOL.md) and [SECURITY_MODEL.md](SECURITY_MODEL.md). Parser isolation is not a sandbox.

## Recursion

ZIP-family containers (`zip`, `jar`, `apk`, `wheel`) are listed and extracted by a contained worker (`exsoftware.container`). The parent never uses `zipfile` on submitted archives. Extracted bytes land in opaque `blobs/NNNNNN.bin` slots; archive names are metadata. The parent hashes those slots itself.

Office Open XML (`docx`/`xlsx`/`pptx`) is listed for identity, then not exploded into XML parts.

See [TRUSTED_CORE.md](TRUSTED_CORE.md) and [ISOLATE_PROTOCOL.md](ISOLATE_PROTOCOL.md).

## Surfaces

- Library: `analyze_path`, `analyze_bytes`, `RecursionLimits`
- CLI: `exsoftware analyze FILE` and `--json`
- HTTP: `POST /api/analyze`, `POST /api/analyze-path`, UI at `/`
