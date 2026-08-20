from __future__ import annotations

import hashlib
from pathlib import Path

from ..models import Evidence, Finding
from .base import Analyzer


def _digest_bytes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def _digest_path(path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
    }


class HashAnalyzer(Analyzer):
    name = "hashes"
    title = "Hashes"

    def analyze(self, ctx):
        findings = []
        extra = ctx.extra or {}
        parent_hashes = extra.get("full_file_hashes")
        coverage_hint = extra.get("hash_coverage")
        if ctx.truncated and ctx.source == "bytes" and not parent_hashes:
            hashes = _digest_bytes(ctx.data)
            coverage = "truncated-buffer"
            findings.append(
                Finding(
                    id="hashes.truncated-upload",
                    title="Hashes cover only the analyzed prefix",
                    summary=(
                        f"The file is {ctx.size} bytes but only the first {len(ctx.data)} bytes "
                        "were available, so these hashes are not hashes of the original file."
                    ),
                    category="integrity",
                    severity="high",
                    confidence="high",
                    analyzer=self.name,
                    tags=["hashes", "limitation"],
                    evidence=[
                        Evidence(
                            kind="limitation",
                            summary="Hash input is the truncated analysis buffer",
                            analyzer=self.name,
                            value=str(len(ctx.data)),
                        )
                    ],
                )
            )
        elif parent_hashes:
            hashes = dict(parent_hashes)
            coverage = coverage_hint or "full-file"
        elif ctx.path is not None:
            hashes = _digest_path(ctx.path)
            coverage = "full-file"
        else:
            hashes = _digest_bytes(ctx.data)
            coverage = coverage_hint or ("truncated-buffer" if ctx.truncated else "full-buffer")

        if ctx.truncated and (ctx.source == "path" or parent_hashes):
            findings.append(
                Finding(
                    id="hashes.full-file-partial-analysis",
                    title="Hashes are for the full file; analysis is partial",
                    summary=(
                        f"Hashes were computed over all {ctx.size} bytes, but later analyzers "
                        f"only saw the first {len(ctx.data)} bytes."
                    ),
                    category="integrity",
                    severity="low",
                    confidence="high",
                    analyzer=self.name,
                    tags=["hashes", "limitation"],
                    evidence=[
                        Evidence(
                            kind="limitation",
                            summary="Full-file hash with truncated analysis buffer",
                            analyzer=self.name,
                            location=ctx.name,
                            extra={"size": ctx.size, "analyzed": len(ctx.data)},
                        )
                    ],
                )
            )

        return self.result(
            details={"hashes": hashes, "coverage": coverage, "size": ctx.size},
            findings=findings,
        )
