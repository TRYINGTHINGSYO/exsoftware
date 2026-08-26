# Isolation protocol

Parent and child communicate with JSON files in a controlled temporary directory. There is no pickle, no shared memory, and no shared investigation graph.

Protocol name: `exsoftware.isolate`  
Protocol version: `1`

This is an implementation detail of analyzer execution. Report `schema_version` remains **1**.

## Layout

```
<temp>/exsoftware-isolate/w-*/
  input.bin        bytes the analyzer is allowed to parse
  request.json     IsolateRequest
  response.json    IsolateResponse (written by the child)

Stdout and stderr are captured through bounded pipes in the parent (default 64 KiB), not log files in the workspace.
```

The child’s current working directory is this folder. The input path in the request is `input.bin`. The original sample path is not passed to the child.

The parent deletes the directory after the child exits or is killed.

## IsolateRequest

```json
{
  "protocol": "exsoftware.isolate",
  "protocol_version": 1,
  "analyzer_id": "pe",
  "analyzer_version": "1.0.0",
  "artifact_id": "sha256:…",
  "input": {
    "kind": "file",
    "path": "input.bin",
    "sha256": "…",
    "size": 123
  },
  "identity": { "name": "file.exe", "path": null, "detected_type": "pe", "…" : "…" },
  "context": {
    "name": "file.exe",
    "source": "path",
    "size": 123,
    "truncated": false,
    "max_bytes": 67108864,
    "artifact_id": "sha256:…",
    "depth": 0,
    "extra": {
      "filesystem_snapshot": { "modified": "…", "path_withheld_from_analyzer_process": true },
      "hash_coverage": "full-file"
    }
  },
  "limits": {
    "timeout_seconds": 60,
    "max_result_bytes": 16777216,
    "max_memory_bytes": 1073741824,
    "max_cpu_seconds": 60,
    "max_child_processes": 1
  }
}
```

`identity.path` is always `null` in the request. Filesystem timestamps may be included as a snapshot taken by the parent.

## IsolateResponse

```json
{
  "protocol": "exsoftware.isolate",
  "protocol_version": 1,
  "analyzer_id": "pe",
  "analyzer_version": "1.0.0",
  "status": "completed",
  "result": {
    "name": "pe",
    "title": "PE / COFF",
    "analyzer_id": "pe",
    "analyzer_version": "1.0.0",
    "applies": true,
    "skipped": false,
    "status": "completed",
    "details": {},
    "findings": [],
    "errors": [],
    "duration_ms": 12.3
  },
  "error": null,
  "timing": { "duration_ms": 12.3 }
}
```

`result` is a serialized `AnalyzerResult` **including** `findings`. The public report still keeps findings at the top level; this payload exists so the parent can ingest them.

The child must not include `artifacts`, `relationships`, or `observations` on `result`. Those are parent-side graph objects.

## Parent validation

Before ingest, the parent checks:

- protocol name and version
- analyzer id and version match the request
- status is one of `completed`, `unsupported`, `skipped`, `failed`, `timeout`, `terminated`
- top-level status matches `result.status`
- required result fields and enum values (severity, confidence, certainty)
- finding/evidence `artifact_id` is absent or equals the requested artifact
- response file size ≤ `max_result_bytes`
- JSON parses as UTF-8

Failures become `status: failed` with `details.reason` of `invalid_analyzer_response` or `oversized_analyzer_response`. The engine continues.

## Statuses

| status | meaning |
| --- | --- |
| `completed` | Analyzer ran and returned a valid result |
| `unsupported` | Declarative eligibility did not match; no child process is started |
| `skipped` | Applies but was not run |
| `failed` | Exception, unexpected exit, crash, or invalid/oversized response |
| `timeout` | Wall-clock deadline exceeded; child was killed; **not analyzed** |
| `terminated` | Child was killed for a non-timeout reason (reserved) |

Timeout is never “no findings.” It is incomplete analysis.

## Process

Child command:

```text
python -m exsoftware.isolate.worker --workdir <temp>
```

The parent measures wall-clock time around wait(). On timeout it terminates the process tree (Windows Job Object + `taskkill /F /T`; Unix `killpg`), then deletes the temp directory.

The parent does not follow symlinks/reparse points when reading `response.json`. Stdout and stderr are pipes with a byte cap. The child environment is a minimal block, not a copy of the operator's environment.

Each run records `details.isolation.capabilities` (`enforced` / `degraded` / `unsupported` / `failed`). The engine must not report `enforced` unless the live child actually held that restriction.

## Container protocol (`exsoftware.container`)

ZIP-family listing and extraction use the same worker entrypoint and Stage 4 spawn path, with a different JSON protocol. Child output is hostile. The parent never opens a child-supplied filesystem path.

Workspace extra:

```
blobs/000001.bin
blobs/000002.bin
…
```

Slot names are six digits assigned in extraction order. Archive member names are metadata only.

### Request

```json
{
  "protocol": "exsoftware.container",
  "protocol_version": 1,
  "operation": "extract",
  "container_artifact_id": "sha256:…",
  "container_type": "zip",
  "input": {"kind": "file", "path": "input.bin", "sha256": "…", "size": 123},
  "limits": {
    "max_members": 64,
    "max_blobs": 64,
    "max_member_bytes": 8388608,
    "max_total_expanded_bytes": 33554432,
    "max_workspace_bytes": 33554432,
    "max_compression_ratio": 100.0,
    "max_list_entries": 400
  },
  "extract_contents": true
}
```

### Response (validated subset)

Each member includes `index`, `original_name`, `display_name`, declared/compressed sizes, `extraction_status`, and — if extracted — `slot` matching `000001`, `000002`, … in order.

Statuses: `extracted`, `directory`, `encrypted`, `path_traversal`, `malformed`, `rejected_size_limit`, `rejected_ratio`, `rejected_workspace_budget`, `not_processed_member_limit`, `not_processed_list_cap`, `skipped`.

The parent opens only `workdir/blobs/<slot>.bin` with no-follow checks, streams hashes from the fd, then reads the bytes. Child-supplied hashes and paths are ignored.

There is **no OS disk quota**. `max_workspace_bytes` is enforced on actual copied bytes by the child and re-checked by the parent. A child can still write extra junk files in the workspace until timeout; the parent will not ingest them.

## OLE refine protocol (`exsoftware.ole`)

OLE identity subtype refinement uses the same worker entrypoint and Stage 4 spawn path, with protocol `exsoftware.ole`. Child output is hostile. The parent never opens a child-supplied filesystem path.

### Request

```json
{
  "protocol": "exsoftware.ole",
  "protocol_version": 1,
  "operation": "refine",
  "artifact_id": "sha256:…",
  "input": {"kind": "file", "path": "input.bin", "sha256": "…", "size": 123},
  "limits": {
    "timeout_seconds": 60,
    "max_result_bytes": 16777216,
    "max_memory_bytes": 1073741824,
    "max_cpu_seconds": 60,
    "max_child_processes": 1
  }
}
```

### Response (validated subset)

```json
{
  "protocol": "exsoftware.ole",
  "protocol_version": 1,
  "operation": "refine",
  "artifact_id": "sha256:…",
  "status": "completed",
  "is_ole": true,
  "streams": ["/WordDocument"],
  "errors": [],
  "timing": {"duration_ms": 12.3}
}
```

`streams` are length/count-capped strings. The parent classifies doc/xls/ppt/msi/msg with `refine_ole_type_from_streams`. On non-completed status, identity stays `ole` and no in-process olefile fallback runs.
