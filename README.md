# exsoftware

Software that explains software.

Drop in a file and get a structured, evidence-backed report of what it is, what it contains, what it depends on, and what is unusual. The intelligence comes from parsers, hashes, signatures, strings, entropy, and format-specific static analysis — not from an LLM.

## What this milestone does

Static analysis only. The file is **not executed**. Extracted URLs and IPs are **not fetched**.

The engine builds a versioned investigation graph:

**Artifact · Relationship · Observation · Evidence · Finding**

File identity is content-addressed (`sha256:…`). Filenames are metadata. Recursive static analysis of ZIP-family members uses a contained container worker for listing/extraction, then the same isolated analyzer runner as the root file. The trusted parent does not parse ZIP archives with `zipfile`.

The default CLI print is a composition explanation (what it is, components, capabilities, gaps), then detailed findings. `--json` includes additive `composition` on schema 1.

Parser containment: each applicable analyzer runs in a least-privilege child process with a hard timeout, bounded output, and (where the OS allows) filesystem/network restrictions. That is **not** a malware sandbox. See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Install

Python 3.11+.

```powershell
cd A:\chatgptcodex\exsoftware
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Use

```powershell
exsoftware analyze .\some-file.exe
exsoftware analyze .\some-file.exe --json -o report.json
exsoftware security-status
exsoftware serve
```

Recursion controls (ZIP members):

```powershell
exsoftware analyze .\sample.zip --max-depth 2 --max-members 20
exsoftware analyze .\sample.zip --no-recurse
```

Library:

```python
from exsoftware import RecursionLimits, analyze_path

report = analyze_path(r"C:\Windows\System32\notepad.exe")
print(report.root_artifact_id)
print(report.to_dict()["schema_version"])  # 1
```

## Documentation

- [docs/PIPELINE.md](docs/PIPELINE.md) — how analysis runs
- [docs/DATA_MODEL.md](docs/DATA_MODEL.md) — artifacts, certainty, how to add an analyzer
- [docs/SCHEMA.md](docs/SCHEMA.md) — JSON schema 1 and the 0.1 → 1 change
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) — static analysis vs parser isolation vs sandbox
- [docs/ISOLATE_PROTOCOL.md](docs/ISOLATE_PROTOCOL.md) — parent/child JSON protocol
- [docs/ANALYZER_VERSIONING.md](docs/ANALYZER_VERSIONING.md) — when analyzer versions must change
- [docs/COMPOSITION.md](docs/COMPOSITION.md) — derived software-composition explanation
- [docs/ARCHITECTURE_DEBT.md](docs/ARCHITECTURE_DEBT.md) — known model and import-boundary debts

## Tests

```powershell
pytest
pytest tests/security
python -m compileall src
```

## Intentionally not in this milestone

- Executing programs
- AI-written explanations
- VirusTotal / cloud reputation
- Full Authenticode trust-chain validation
- A malware sandbox (parser isolation is not one)
- Repository-wide analysis
