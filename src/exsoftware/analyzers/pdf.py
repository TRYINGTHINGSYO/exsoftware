from __future__ import annotations

import io

from ..models import Evidence, Finding
from .base import Analyzer


class PDFAnalyzer(Analyzer):
    name = "pdf"
    title = "PDF"
    detected_types = frozenset({"pdf"})

    def analyze(self, ctx):
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            return self.failure(exc)

        try:
            reader = PdfReader(io.BytesIO(ctx.data), strict=False)
        except Exception as exc:
            return self.result(
                details={"error": str(exc)},
                findings=[
                    Finding(
                        id="pdf.parse-error",
                        title="PDF parser failed",
                        summary=str(exc),
                        category="document",
                        severity="low",
                        confidence="high",
                        analyzer=self.name,
                        tags=["parse-error"],
                        evidence=[Evidence(kind="error", summary=exc.__class__.__name__, analyzer=self.name, value=str(exc))],
                    )
                ],
            )

        meta = {}
        if reader.metadata:
            for key, value in dict(reader.metadata).items():
                meta[str(key)] = str(value)[:500] if value is not None else None

        encrypted = bool(getattr(reader, "is_encrypted", False))
        pages = len(reader.pages) if not encrypted else None
        attachments = []
        try:
            named = reader.attachments or {}
            for name, blobs in named.items():
                attachments.append({"name": name, "count": len(blobs), "sizes": [len(b) for b in blobs]})
        except Exception as exc:
            attachments.append({"error": str(exc)})

        js_hits = []
        open_action = None
        trailer_text = ""
        try:
            root = reader.trailer.get("/Root") if reader.trailer else None
            if root:
                root_obj = root.get_object() if hasattr(root, "get_object") else root
                open_action = root_obj.get("/OpenAction")
                names = root_obj.get("/Names")
                if names:
                    trailer_text += str(names)[:2000]
                js_hits.extend(_scan_for_js(str(root_obj)[:4000]))
        except Exception:
            pass
        # Cheap whole-file scan for PDF JavaScript names.
        if b"/JavaScript" in ctx.data or b"/JS" in ctx.data:
            js_hits.append("name-/JavaScript-or-/JS")

        findings = [
            Finding(
                id="pdf.identity",
                title="PDF document",
                summary=(
                    f"PDF with {pages if pages is not None else 'unknown'} page(s)"
                    + ("; encrypted" if encrypted else "")
                    + (f"; {len(attachments)} attachment name(s)" if attachments else "")
                    + "."
                ),
                category="document",
                severity="info",
                confidence="high",
                analyzer=self.name,
                tags=["pdf"],
                evidence=[
                    Evidence(kind="field", summary="Pages", analyzer=self.name, value=str(pages)),
                    Evidence(kind="field", summary="Encrypted", analyzer=self.name, value=str(encrypted)),
                ],
            )
        ]
        if meta:
            findings.append(
                Finding(
                    id="pdf.metadata",
                    title="PDF document metadata",
                    summary="Info dictionary fields were parsed.",
                    category="metadata",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["metadata"],
                    evidence=[
                        Evidence(kind="field", summary=key, analyzer=self.name, value=str(value)[:300])
                        for key, value in list(meta.items())[:16]
                    ],
                )
            )
        if js_hits:
            findings.append(
                Finding(
                    id="pdf.javascript",
                    title="PDF JavaScript names present",
                    summary="The file contains /JavaScript or /JS names. That can be legitimate or used to run script when the document opens.",
                    category="document",
                    severity="medium",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["javascript"],
                    evidence=[
                        Evidence(kind="string", summary="JavaScript indicator", analyzer=self.name, value=str(hit)[:300])
                        for hit in js_hits[:8]
                    ],
                )
            )
        if open_action is not None:
            findings.append(
                Finding(
                    id="pdf.open-action",
                    title="PDF OpenAction present",
                    summary="An OpenAction can run when the document is opened.",
                    category="document",
                    severity="low",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["open-action"],
                    evidence=[
                        Evidence(kind="field", summary="/OpenAction", analyzer=self.name, value=str(open_action)[:400])
                    ],
                )
            )
        if attachments:
            findings.append(
                Finding(
                    id="pdf.attachments",
                    title="Embedded attachments",
                    summary="The PDF names embedded files.",
                    category="embedded",
                    severity="low",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["embedded"],
                    evidence=[
                        Evidence(kind="field", summary="Attachment", analyzer=self.name, value=str(item))
                        for item in attachments[:12]
                    ],
                )
            )
        details = {
            "pages": pages,
            "encrypted": encrypted,
            "metadata": meta,
            "attachments": attachments,
            "javascript_indicators": js_hits,
            "open_action": str(open_action)[:1000] if open_action is not None else None,
        }
        return self.result(details=details, findings=findings)


def _scan_for_js(text: str) -> list[str]:
    hits = []
    for token in ("/JavaScript", "/JS", "/OpenAction"):
        if token in text:
            hits.append(token)
    return hits
