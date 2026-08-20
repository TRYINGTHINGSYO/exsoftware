from __future__ import annotations

from math import log2

from ..models import Evidence, Finding
from .base import Analyzer

_PACKING_FAMILIES = {"executable", "bytecode", "unknown"}
_COMPRESSED_TYPES = {
    "png", "jpeg", "gif", "webp", "zip", "gzip", "bzip2", "xz", "7z", "rar",
    "pdf", "docx", "xlsx", "pptx", "jar", "apk", "wheel", "wasm",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * log2(p)
    return entropy


def window_stats(data: bytes, window: int = 4096) -> dict:
    if not data:
        return {"window": window, "count": 0, "min": 0.0, "max": 0.0, "mean": 0.0, "high_ratio": 0.0}
    values = []
    step = window
    for offset in range(0, len(data), step):
        chunk = data[offset : offset + window]
        if len(chunk) < 64:
            continue
        values.append(shannon_entropy(chunk))
    if not values:
        value = shannon_entropy(data)
        return {"window": window, "count": 1, "min": value, "max": value, "mean": value, "high_ratio": 1.0 if value >= 7.0 else 0.0}
    high = sum(1 for item in values if item >= 7.0)
    return {
        "window": window,
        "count": len(values),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "mean": round(sum(values) / len(values), 4),
        "high_ratio": round(high / len(values), 4),
    }


class EntropyAnalyzer(Analyzer):
    name = "entropy"
    title = "Entropy"

    def analyze(self, ctx):
        overall = shannon_entropy(ctx.data)
        windows = window_stats(ctx.data)
        detected = ctx.identity.detected_type if ctx.identity else "unknown"
        family = ctx.identity.detected_family if ctx.identity else "unknown"
        findings = []
        if overall >= 7.2 and detected not in _COMPRESSED_TYPES and family in _PACKING_FAMILIES:
            findings.append(
                Finding(
                    id="entropy.high-for-executable",
                    title="High overall entropy",
                    summary=(
                        f"The analyzed bytes have Shannon entropy {overall:.2f}/8.00. "
                        "For executables this often means compression, packing, or encryption, "
                        "but it is not proof of malice."
                    ),
                    category="packing",
                    severity="medium",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["entropy", "packing"],
                    evidence=[
                        Evidence(
                            kind="metric",
                            summary=f"Shannon entropy of analyzed bytes is {overall:.4f}",
                            analyzer=self.name,
                            location="entire analyzed buffer",
                            value=f"{overall:.4f}",
                            extra={"window_max": windows["max"], "high_ratio": windows["high_ratio"]},
                        )
                    ],
                )
            )
        elif overall >= 7.2:
            findings.append(
                Finding(
                    id="entropy.high-expected",
                    title="High entropy (expected for this format)",
                    summary=(
                        f"Entropy is {overall:.2f}/8.00. That is common for compressed or "
                        f"already-encoded formats such as {detected}."
                    ),
                    category="packing",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["entropy"],
                    evidence=[
                        Evidence(
                            kind="metric",
                            summary=f"Shannon entropy is {overall:.4f} for type {detected}",
                            analyzer=self.name,
                            value=f"{overall:.4f}",
                        )
                    ],
                )
            )
        if windows["high_ratio"] >= 0.6 and family in _PACKING_FAMILIES and detected not in _COMPRESSED_TYPES:
            findings.append(
                Finding(
                    id="entropy.high-windows",
                    title="Most of the file looks compressed or encrypted",
                    summary=(
                        f"{windows['high_ratio'] * 100:.0f}% of {windows['window']}-byte windows "
                        f"have entropy ≥ 7.0 (max {windows['max']:.2f})."
                    ),
                    category="packing",
                    severity="low",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["entropy"],
                    evidence=[
                        Evidence(
                            kind="metric",
                            summary="Sliding-window entropy summary",
                            analyzer=self.name,
                            value=str(windows),
                        )
                    ],
                )
            )
        return self.result(
            details={
                "shannon": round(overall, 4),
                "windows": windows,
                "bytes_analyzed": len(ctx.data),
            },
            findings=findings,
        )
