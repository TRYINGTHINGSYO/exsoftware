from __future__ import annotations

from ..identify import identify_bytes
from ..models import Evidence, Finding
from .base import Analyzer

# Distinctive magics worth reporting when they appear after offset 0.
_EMBEDDED = [
    (b"MZ", "pe-or-mz"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"7z\xbc\xaf'\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"\x00asm", "wasm"),
    (b"SQLite format 3\x00", "sqlite"),
]

_MAX_HITS = 40


class EmbeddedAnalyzer(Analyzer):
    name = "embedded"
    title = "Embedded files"

    def analyze(self, ctx):
        hits = []
        for magic, kind in _EMBEDDED:
            start = 0
            while True:
                idx = ctx.data.find(magic, start)
                if idx < 0:
                    break
                if idx == 0 and ctx.identity and _same_family(ctx.identity.detected_type, kind):
                    start = idx + 1
                    continue
                if kind == "pe-or-mz" and not _looks_like_pe(ctx.data, idx):
                    start = idx + 1
                    continue
                snippet = ctx.data[idx : idx + 256]
                ident = identify_bytes(snippet, f"embedded@{idx}", size=len(ctx.data) - idx)
                hits.append(
                    {
                        "offset": idx,
                        "kind": kind,
                        "detected_type": ident.detected_type,
                        "description": ident.description,
                        "magic_hex": magic.hex(" "),
                    }
                )
                if len(hits) >= _MAX_HITS:
                    break
                start = idx + 1
            if len(hits) >= _MAX_HITS:
                break

        findings = []
        if hits:
            findings.append(
                Finding(
                    id="embedded.signatures",
                    title=f"{len(hits)} embedded file signature(s) after the start of the file",
                    summary=(
                        "Known magics were found at non-zero offsets. This can be an appended "
                        "payload, a container, or a coincidence in binary data."
                    ),
                    category="embedded",
                    severity="low",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["embedded"],
                    evidence=[
                        Evidence(
                            kind="bytes",
                            summary=f"{hit['kind']} at offset {hit['offset']}",
                            analyzer=self.name,
                            location=f"offset {hit['offset']}",
                            value=hit["magic_hex"],
                            extra={"detected_type": hit["detected_type"]},
                        )
                        for hit in hits[:16]
                    ],
                )
            )
        details = {"hits": hits, "hit_count": len(hits), "capped": len(hits) >= _MAX_HITS}
        return self.result(details=details, findings=findings)


def _same_family(detected: str, kind: str) -> bool:
    mapping = {
        "pe-or-mz": {"pe", "dos-mz"},
        "zip": {"zip", "docx", "xlsx", "pptx", "jar", "apk", "wheel"},
        "ole": {"ole", "doc", "xls", "ppt", "msi", "msg"},
        "elf": {"elf"},
        "pdf": {"pdf"},
        "png": {"png"},
        "jpeg": {"jpeg"},
    }
    return detected in mapping.get(kind, {kind})


def _looks_like_pe(data: bytes, offset: int) -> bool:
    if offset + 64 > len(data) or data[offset : offset + 2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(data[offset + 60 : offset + 64], "little")
    pe_off = offset + e_lfanew
    if e_lfanew < 64 or pe_off + 4 > len(data):
        return False
    return data[pe_off : pe_off + 4] == b"PE\x00\x00"
