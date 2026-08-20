from __future__ import annotations

from ..models import Evidence, Finding
from .base import Analyzer

_MULTI_EXT_INTERESTING = {
    ".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".cmd", ".bat", ".jar", ".msi", ".lnk", ".iso",
}


class IdentityAnalyzer(Analyzer):
    name = "identity"
    title = "File identity"

    def analyze(self, ctx):
        identity = ctx.identity
        findings = []
        details = identity.to_dict() if identity else {}
        if identity is None:
            return self.result(details={"error": "identity missing"})

        if identity.extension_matches is False:
            findings.append(
                Finding(
                    id="identity.extension-mismatch",
                    title="File extension does not match detected type",
                    summary=(
                        f"The name ends with '{identity.extension or '(none)'}' but the content "
                        f"was identified as {identity.detected_type} ({identity.description}). "
                        "Treat the detected type as authoritative."
                    ),
                    category="identity",
                    severity="medium",
                    confidence="high",
                    analyzer=self.name,
                    tags=["mismatch", "disguise"],
                    evidence=[
                        Evidence(
                            kind="field",
                            summary="Claimed extension versus detected type",
                            analyzer=self.name,
                            location="filename + magic bytes",
                            value=f"{identity.extension} -> {identity.detected_type}",
                            extra={"magic_hex": identity.magic_hex, "magic_offset": identity.magic_offset},
                        )
                    ],
                )
            )
        elif identity.extension_matches is True:
            findings.append(
                Finding(
                    id="identity.extension-matches",
                    title="Extension matches detected type",
                    summary=(
                        f"'{identity.extension}' is consistent with detected type "
                        f"{identity.detected_type}."
                    ),
                    category="identity",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["identity"],
                    evidence=[
                        Evidence(
                            kind="field",
                            summary="Extension and detected type agree",
                            analyzer=self.name,
                            value=identity.detected_type,
                        )
                    ],
                )
            )

        if identity.detected_type == "unknown":
            findings.append(
                Finding(
                    id="identity.unknown-type",
                    title="Type could not be identified from magic bytes",
                    summary=(
                        "No known file signature matched the start of this file, and it did not "
                        "look like text. It may be encrypted, custom, or simply uncommon."
                    ),
                    category="identity",
                    severity="low",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["unknown"],
                    evidence=[
                        Evidence(
                            kind="bytes",
                            summary="Leading bytes",
                            analyzer=self.name,
                            location="offset 0",
                            value=identity.magic_hex,
                        )
                    ],
                )
            )

        stem_parts = identity.name.split(".")
        if len(stem_parts) > 2:
            last = "." + stem_parts[-1].lower()
            previous = "." + stem_parts[-2].lower()
            if last in _MULTI_EXT_INTERESTING or previous in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt", ".html"}:
                findings.append(
                    Finding(
                        id="identity.double-extension",
                        title="Name contains multiple extensions",
                        summary=(
                            f"The file name '{identity.name}' has more than one suffix. "
                            "That is sometimes used to make an executable look like a document."
                        ),
                        category="identity",
                        severity="medium" if last in _MULTI_EXT_INTERESTING else "low",
                        confidence="high",
                        analyzer=self.name,
                        tags=["filename"],
                        evidence=[
                            Evidence(
                                kind="field",
                                summary="Original file name",
                                analyzer=self.name,
                                value=identity.name,
                            )
                        ],
                    )
                )

        if ctx.truncated:
            findings.append(
                Finding(
                    id="identity.truncated-analysis",
                    title="Analysis is based on a prefix of the file",
                    summary=(
                        f"The file is {ctx.size} bytes; only the first {len(ctx.data)} bytes "
                        f"(limit {ctx.max_bytes}) were given to format analyzers."
                    ),
                    category="limitation",
                    severity="low",
                    confidence="high",
                    analyzer=self.name,
                    tags=["limitation"],
                    evidence=[
                        Evidence(
                            kind="limitation",
                            summary="Partial read",
                            analyzer=self.name,
                            extra={"size": ctx.size, "analyzed": len(ctx.data), "max_bytes": ctx.max_bytes},
                        )
                    ],
                )
            )

        return self.result(details=details, findings=findings)
