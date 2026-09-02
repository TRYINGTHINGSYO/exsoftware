# Security model

ExSoftware is a **static analysis engine** with **parser process containment**.
It is not a malware sandbox, not a hypervisor, and not a verdict that a file is safe to open.

## Trust zones

```
HOST / TRUSTED ENGINE
  CLI, local API, pipeline, identify (magic/prefix), investigation graph,
  isolation runner, protocol validation, report assembly
        │
        │ constrained JSON protocol + least-privilege child
        ▼
LEAST-PRIVILEGE WORKERS
  ZIP-family enumeration/extraction (exsoftware.container)
  OLE stream listing for identity refine (exsoftware.ole)
  Analyzer.applies / Analyzer.analyze (exsoftware.isolate)
  third-party parsers (pefile, pypdf, Pillow, olefile, zipfile, …)
        │
        ▼
HOSTILE BYTES
  submitted file, archive members, malformed documents,
  unvalidated worker output
```

### Trusted

- Main ExSoftware engine (pipeline, investigation graph construction)
- Declarative analyzer registry (`AnalyzerSpec`: id/version/title, detected types/families, worker module/class identifiers)
- Result validation (`exsoftware.isolate.validate`)
- Workspace creation, process launch, timeout/kill, bounded stdio

### Partially trusted / untrusted

- Analyzer implementations (treated as compromiseable; imported only inside workers)
- Third-party parser libraries running in the child

### Completely hostile

- Submitted bytes and archive members
- Malformed documents
- Analyzer output until it passes protocol validation

An analyzer process is **not** trusted merely because its source lives in this repository.

## Static analysis

The submitted program is not intentionally executed. Recursive ZIP-family members are enumerated and extracted inside a contained worker, then hashed by the parent. Decompression is not execution.

See [TRUSTED_CORE.md](TRUSTED_CORE.md) for the hostile-byte inventory.

## Parser containment

Untrusted bytes are parsed in disposable, least-privilege child processes. The parent validates JSON and ingests an `AnalyzerResult`.

This is **not** a sandbox in the malware-analysis sense. There is no guest OS, no execution of the sample, and no claim of perfect isolation.

## What remains possible (assume this is incomplete)

- Kernel vulnerabilities
- Bugs in the isolation implementation (AppContainer launch, ACL grants, Landlock apply)
- Files that are readable to `Everyone` / `Users` / `ALL APPLICATION PACKAGES` when only a restricted token is in use
- Side channels (timing, memory pressure below the job limit)
- The trusted parent still **loads and identifies** hostile bytes. ZIP-family listing/extraction is **not** done with parent-side `zipfile`; it runs in a contained container worker. OLE stream listing for subtype refinement is **not** done with parent-side `olefile`; it runs in a contained OLE worker. The parent classifies OLE subtype from validated stream **names** only.
- `identify_bytes` magic matching runs in the parent on the analysis buffer
- Full-file hashing of a truncated path sample runs in the parent
- A child that can still spawn (degraded process_creation) may race the timeout
- Network restriction is OS-specific; if it is `unsupported` or `degraded`, sockets may work
- Python runtime files must remain readable to the child. On Windows this is a **user-owned staged CPython tree** plus the ExSoftware `src` tree and the active venv `site-packages`. Those paths are intentionally reachable.
- AppContainer with zero network capabilities blocks outbound connect. Bind/listen on loopback may still succeed at the Winsock API. That is **not** the same as a usable host↔worker communication path: Windows Filtering Platform loopback isolation typically prevents non-AppContainer processes from exchanging traffic with an AppContainer listener unless a CheckNetIsolation loopback exemption is configured. `exsoftware security-status` probes host→worker connect/accept (IPv4/IPv6), outbound connect, and **localhost UDP receipt** (parent-bound loopback receiver + unique token). It reports `network_restriction=enforced` only when required probes **completed with interpretable results**, the **network workers** themselves ran under a consistent AppContainer-class (or equivalent) mechanism, and usable communication was denied. Absence of success from crashed, timed-out, or incomplete probes never upgrades a claim to `enforced`. The listen ready file is treated as hostile child output: bounded no-follow read, schema/port validation, and parent-chosen `127.0.0.1` / `::1` only. Per-run analyzer capability claims remain `degraded` until that live evidence is collected. This cloud/CI documentation must not be read as a substitute for a real Windows `security-status` run.
- AppContainer/restricted-token setup can fail; the engine must then report `unsupported`/`degraded` rather than pretend
- A Job Object `ActiveProcessLimit=1` prevents creating a descendant; it does not prevent in-process thread creation or using already-loaded Win32 APIs

## Parent-side hostile bytes

These still execute in the trusted process:

| Code | Why |
| --- | --- |
| `context.load_from_path` / `load_from_bytes` | Must read the sample (capped) |
| `identify.identify_bytes` | Magic/prefix detection on the analysis buffer |
| `identify.refine_ole_type_from_streams` | String classification of **validated** OLE stream names |
| `identify.refine_zip_type_from_names` | String classification of **validated** member names |
| `content.sha256_file` / `digest_fd` / `digest_path` | Streaming identity of the original file and extracted blobs |
| container blob open `blobs/NNNNNN.bin` | Parent-computed slot, `O_NOFOLLOW`, independently hashed |

Format parsers (`pefile`, `pypdf`, `olefile`, `zipfile`, …) must not run in the parent.

## Capability states

Each analyzer run records `details.isolation.capabilities` with only:

- `enforced` — live child held the restriction (token/job query and/or denied probe)
- `degraded` — partial restriction
- `unsupported` — not available
- `failed` — claimed restriction did not hold

`exsoftware security-status` runs hostile helper analyzers and **will not report enforced if the forbidden operation succeeded**.

Analysis reports also contain `limits.isolation.workers[]`, a report-wide
inventory of analyzer, ZIP/container broker, and OLE broker worker attempts.
The legacy `limits.isolation.mechanism` and `capabilities` values are computed
from that complete inventory rather than copied from one analyzer. A stronger
worker cannot hide a weaker worker: different mechanisms are reported as
`mixed`, failed launches remain explicit, and every capability is aggregated
using the weakest worker state (`failed` → `unsupported` → `degraded` →
`enforced`). Per-worker capabilities and launch/fallback evidence remain in the
inventory so an aggregate downgrade is explainable.

## Workspace / IPC

The child receives `input.bin` in a random workspace. Original host paths are not placed in the request. Response files are opened without following reparse points/symlinks. Stdout/stderr are capped.

## Windows (this development host)

Primary mechanism, when `TokenIsAppContainer` is confirmed on the live child:

- **AppContainer** named `ExSoftware.Analyzer` with **zero** capabilities
- **Job Object** with `ActiveProcessLimit=1`, job memory, job CPU time, kill-on-close
- **ACL-scoped workspace** (current-user owner + AppContainer SID)
- **Staged CPython** under `%TEMP%\exsoftware-isolate\runtime` because a non-elevated parent cannot add AppContainer ACEs to a machine-wide `C:\Python314` tree

Observed on the Stage 4 Windows development host (historical; re-verify with `exsoftware security-status` after probe changes):

- Host sentinel **read** → `Permission denied`
- Host sentinel **write** → `Permission denied`
- Outbound connect to TEST-NET (`192.0.2.1`) → `WSAEACCES` (10013)
- Localhost **connect** → timed out (loopback isolation)
- Localhost **bind/listen** → Winsock API **succeeds** (creating a listening socket is not the same as receiving host traffic)
- Host→worker connect/accept → must be measured by the updated security-status probe; do not assume bind success implies a usable channel
- IPv6 (`::1` / `2001:db8::1`) TCP probes and **localhost UDP receipt** (not TEST-NET `sendto` alone) are included so a TCP/IPv4-only reading is not mistaken for full network isolation
- `CreateProcess` of a descendant → `ERROR_NOT_ENOUGH_QUOTA` (1816) from `ActiveProcessLimit=1`

Per-run AppContainer launches still record `network_restriction=degraded` because bind may succeed and a per-analyzer host→worker probe is not repeated on every file. `security-status` may report `enforced` only when **complete** live communication probes deny usable traffic **and** the network probe workers confirm the expected containment mechanism. Incomplete evidence stays `degraded`.

Fallback if AppContainer launch fails: restricted token + Low integrity (needs `SeImpersonatePrivilege`; often unavailable) then job-only (filesystem/network **unsupported**).

## Unix-family

The parent creates the worker in a new session (`subprocess.Popen(..., start_new_session=True)`). That parent-visible session is what makes `process_tree_limit=enforced` and lets timeout use `killpg`. Landlock, `CLONE_NEWNET`, and rlimits are still attempted in `preexec_fn` when the kernel supports them, but those child-side applies are not parent-verified. Per-run filesystem and network claims stay **degraded** (or **unsupported** if the feature is absent) unless live denial probes confirm the restriction held. CPU and memory claims remain **degraded** until there is parent-observable confirmation or a future validated bootstrap acknowledgment/probe for the child-side rlimit setup. A swallowed `setsid()` in preexec is not used as evidence.

See [ISOLATE_PROTOCOL.md](ISOLATE_PROTOCOL.md).
