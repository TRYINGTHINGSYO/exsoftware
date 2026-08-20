from __future__ import annotations

import io

from ..models import Evidence, Finding
from .base import Analyzer

_OLE_TYPES = {"ole", "doc", "xls", "ppt", "msi", "msg"}


class OLEAnalyzer(Analyzer):
    name = "ole"
    title = "OLE / Office compound file"
    detected_types = frozenset(_OLE_TYPES)

    def analyze(self, ctx):
        try:
            import olefile
        except ImportError as exc:
            return self.failure(exc)
        if not olefile.isOleFile(ctx.data):
            return self.result(details={"error": "olefile did not accept this buffer"})
        ole = olefile.OleFileIO(ctx.data)
        try:
            streams = ["/".join(parts) for parts in ole.listdir()]
            meta = {}
            for getter, label in (
                (ole.get_metadata, "metadata"),
            ):
                try:
                    parsed = getter()
                    for attr in (
                        "author", "title", "subject", "creating_application",
                        "create_time", "last_saved_by", "last_saved_time",
                        "company", "codepage",
                    ):
                        value = getattr(parsed, attr, None)
                        if value:
                            meta[attr] = str(value)[:400]
                except Exception as exc:
                    meta[label + "_error"] = str(exc)

            vba = any("vba" in name.lower() or name.lower().endswith("vba") or "/vba/" in ("/" + name.lower()) for name in streams)
            macros = any("macros" in name.lower() or name.lower().endswith("macro") for name in streams)
            findings = [
                Finding(
                    id="ole.streams",
                    title=f"OLE compound file with {len(streams)} stream(s)",
                    summary=f"Detected as {ctx.identity.detected_type}.",
                    category="document",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["ole"],
                    evidence=[
                        Evidence(kind="field", summary="Stream", analyzer=self.name, value=name)
                        for name in streams[:16]
                    ],
                )
            ]
            if vba or macros:
                findings.append(
                    Finding(
                        id="ole.vba-streams",
                        title="VBA / macro-related streams present",
                        summary="Stream names suggest VBA macros. Macro code is not executed.",
                        category="document",
                        severity="medium",
                        confidence="medium",
                        analyzer=self.name,
                        tags=["macros", "vba"],
                        evidence=[
                            Evidence(kind="field", summary="Stream", analyzer=self.name, value=name)
                            for name in streams
                            if "vba" in name.lower() or "macro" in name.lower()
                        ],
                    )
                )
            if meta:
                findings.append(
                    Finding(
                        id="ole.metadata",
                        title="OLE summary metadata",
                        summary="Compound-file metadata fields were parsed.",
                        category="metadata",
                        severity="info",
                        confidence="medium",
                        analyzer=self.name,
                        tags=["metadata"],
                        evidence=[
                            Evidence(kind="field", summary=key, analyzer=self.name, value=str(value)[:300])
                            for key, value in list(meta.items())[:16]
                        ],
                    )
                )
            details = {"streams": streams, "metadata": meta, "vba_streams": vba or macros}
            return self.result(details=details, findings=findings)
        finally:
            ole.close()
