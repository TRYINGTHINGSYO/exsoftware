from __future__ import annotations

import io
from datetime import datetime

from ..models import Evidence, Finding
from .base import Analyzer

_IMAGE_TYPES = {"png", "jpeg", "gif", "bmp", "webp", "ico"}


class ImageAnalyzer(Analyzer):
    name = "image"
    title = "Image"
    detected_types = frozenset(_IMAGE_TYPES)

    def analyze(self, ctx):
        try:
            from PIL import Image, ExifTags
            from PIL.ExifTags import GPSTAGS, TAGS
        except ImportError as exc:
            return self.failure(exc)

        try:
            image = Image.open(io.BytesIO(ctx.data))
            image.load()
        except Exception as exc:
            return self.result(
                details={"error": str(exc)},
                findings=[
                    Finding(
                        id="image.parse-error",
                        title="Image parser failed",
                        summary=str(exc),
                        category="image",
                        severity="low",
                        confidence="high",
                        analyzer=self.name,
                        tags=["parse-error"],
                        evidence=[Evidence(kind="error", summary=exc.__class__.__name__, analyzer=self.name, value=str(exc))],
                    )
                ],
            )

        exif = {}
        gps = {}
        try:
            raw = image.getexif()
            if raw:
                for key, value in raw.items():
                    label = TAGS.get(key, str(key))
                    exif[label] = _stringify(value)
                gps_ifd = raw.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(ExifTags, "IFD") else None
                if gps_ifd:
                    for key, value in gps_ifd.items():
                        gps[GPSTAGS.get(key, str(key))] = _stringify(value)
        except Exception:
            pass

        findings = [
            Finding(
                id="image.identity",
                title=f"{image.format or ctx.identity.detected_type} image",
                summary=f"{image.format} {image.mode} {image.size[0]}×{image.size[1]}.",
                category="image",
                severity="info",
                confidence="high",
                analyzer=self.name,
                tags=["image"],
                evidence=[
                    Evidence(kind="field", summary="Format", analyzer=self.name, value=str(image.format)),
                    Evidence(kind="field", summary="Mode", analyzer=self.name, value=str(image.mode)),
                    Evidence(kind="field", summary="Size", analyzer=self.name, value=f"{image.size[0]}x{image.size[1]}"),
                ],
            )
        ]
        if exif:
            software = exif.get("Software") or exif.get("Artist") or exif.get("Make")
            findings.append(
                Finding(
                    id="image.exif",
                    title="EXIF metadata present",
                    summary="The image contains EXIF tags that may identify a camera, tool, or timestamp.",
                    category="metadata",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["exif"],
                    evidence=[
                        Evidence(kind="field", summary=key, analyzer=self.name, value=str(value)[:300])
                        for key, value in list(exif.items())[:16]
                    ],
                )
            )
            if software:
                findings[-1].tags.append("creator")
        if gps:
            findings.append(
                Finding(
                    id="image.gps",
                    title="GPS EXIF tags present",
                    summary="The image includes GPS EXIF fields.",
                    category="metadata",
                    severity="low",
                    confidence="high",
                    analyzer=self.name,
                    tags=["gps"],
                    evidence=[
                        Evidence(kind="field", summary=key, analyzer=self.name, value=str(value)[:300])
                        for key, value in list(gps.items())[:12]
                    ],
                )
            )
        details = {
            "format": image.format,
            "mode": image.mode,
            "width": image.size[0],
            "height": image.size[1],
            "info": {key: _stringify(value) for key, value in (image.info or {}).items()},
            "exif": exif,
            "gps": gps,
        }
        return self.result(details=details, findings=findings)


def _stringify(value) -> str:
    if isinstance(value, bytes):
        return value[:120].hex(" ")
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)[:500]
