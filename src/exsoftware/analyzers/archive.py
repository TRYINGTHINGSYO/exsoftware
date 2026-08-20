from __future__ import annotations

import io

from ..identify import identify_bytes
from ..models import Evidence, Finding
from .base import Analyzer

_ARCHIVE_TYPES = {"zip", "jar", "apk", "wheel", "docx", "xlsx", "pptx", "gzip", "tar"}
_MEMBER_PEEK = 4096
_MAX_LIST = 400
_MAX_PEEK = 25


class ArchiveAnalyzer(Analyzer):
    name = "archive"
    title = "Archive / container"
    detected_types = frozenset(_ARCHIVE_TYPES)

    def analyze(self, ctx):
        kind = ctx.identity.detected_type
        if kind in {"zip", "jar", "apk", "wheel", "docx", "xlsx", "pptx"}:
            return self._zip(ctx)
        if kind == "tar":
            return self._tar(ctx)
        if kind == "gzip":
            return self.result(
                details={"note": "gzip wrapper detected. Nested payload is not fully unpacked in this milestone."},
                findings=[
                    Finding(
                        id="archive.gzip",
                        title="gzip compressed data",
                        summary="The file is gzip-compressed. Full decompression of untrusted archives is limited in this milestone.",
                        category="archive",
                        severity="info",
                        confidence="high",
                        analyzer=self.name,
                        tags=["gzip"],
                        evidence=[
                            Evidence(kind="bytes", summary="gzip magic", analyzer=self.name, location="offset 0", value="1f 8b 08")
                        ],
                    )
                ],
            )
        return self.result(details={"note": f"No deep parser for {kind}."})

    def _zip(self, ctx):
        import zipfile

        findings: list[Finding] = []
        try:
            archive = zipfile.ZipFile(io.BytesIO(ctx.data))
        except zipfile.BadZipFile as exc:
            return self.result(
                details={"error": str(exc)},
                findings=[
                    Finding(
                        id="archive.bad-zip",
                        title="ZIP structure could not be parsed",
                        summary=str(exc),
                        category="archive",
                        severity="low",
                        confidence="high",
                        analyzer=self.name,
                        tags=["parse-error"],
                        evidence=[Evidence(kind="error", summary="zipfile.BadZipFile", analyzer=self.name, value=str(exc))],
                    )
                ],
            )

        members = []
        encrypted = []
        traversal = []
        peeked = []
        with archive:
            infos = archive.infolist()
            for info in infos[:_MAX_LIST]:
                item = {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "compress_type": info.compress_type,
                    "encrypted": bool(info.flag_bits & 0x1),
                    "crc": hex(info.CRC),
                }
                members.append(item)
                if item["encrypted"]:
                    encrypted.append(info.filename)
                if _is_traversal(info.filename):
                    traversal.append(info.filename)
            for info in infos[:_MAX_PEEK]:
                if info.is_dir() or info.file_size == 0 or info.flag_bits & 0x1:
                    continue
                if info.file_size > 1_000_000:
                    continue
                try:
                    blob = archive.read(info.filename)[:_MEMBER_PEEK]
                except Exception as exc:
                    peeked.append({"name": info.filename, "error": str(exc)})
                    continue
                ident = identify_bytes(blob, info.filename, size=info.file_size)
                peeked.append(
                    {
                        "name": info.filename,
                        "detected_type": ident.detected_type,
                        "description": ident.description,
                    }
                )

        if encrypted:
            findings.append(
                Finding(
                    id="archive.encrypted-members",
                    title="Encrypted ZIP member(s)",
                    summary="One or more ZIP entries have the encryption flag set.",
                    category="archive",
                    severity="medium",
                    confidence="high",
                    analyzer=self.name,
                    tags=["encrypted"],
                    evidence=[
                        Evidence(kind="field", summary="Encrypted member", analyzer=self.name, value=name)
                        for name in encrypted[:12]
                    ],
                )
            )
        if traversal:
            findings.append(
                Finding(
                    id="archive.path-traversal",
                    title="Archive member path looks like traversal",
                    summary="A member name contains '..' or an absolute path. That can be used to write outside an extract directory.",
                    category="archive",
                    severity="high",
                    confidence="high",
                    analyzer=self.name,
                    tags=["zip-slip"],
                    evidence=[
                        Evidence(kind="field", summary="Member name", analyzer=self.name, value=name)
                        for name in traversal[:12]
                    ],
                )
            )
        findings.append(
            Finding(
                id="archive.listing",
                title=f"ZIP-based container with {len(members)} listed member(s)",
                summary=f"Detected as {ctx.identity.detected_type}. Members were listed; they were not extracted to disk.",
                category="archive",
                severity="info",
                confidence="high",
                analyzer=self.name,
                tags=["archive"],
                evidence=[
                    Evidence(kind="count", summary="Member count", analyzer=self.name, value=str(len(members))),
                    Evidence(
                        kind="field",
                        summary="First members",
                        analyzer=self.name,
                        value=", ".join(item["name"] for item in members[:8]) or "(none)",
                    ),
                ],
            )
        )
        return self.result(
            details={
                "format": ctx.identity.detected_type,
                "member_count": len(members),
                "members": members,
                "peek": peeked,
                "encrypted_members": encrypted,
                "traversal_members": traversal,
            },
            findings=findings,
        )

    def _tar(self, ctx):
        import tarfile

        findings = []
        try:
            tar = tarfile.open(fileobj=io.BytesIO(ctx.data), mode="r:*")
        except tarfile.TarError as exc:
            return self.failure(exc)
        members = []
        with tar:
            for info in tar.getmembers()[:_MAX_LIST]:
                members.append(
                    {
                        "name": info.name,
                        "size": info.size,
                        "type": info.type.decode("ascii", "replace") if isinstance(info.type, bytes) else str(info.type),
                        "mode": oct(info.mode),
                        "linkname": info.linkname,
                    }
                )
        findings.append(
            Finding(
                id="archive.tar-listing",
                title=f"TAR archive with {len(members)} listed member(s)",
                summary="TAR members were listed. They were not extracted to disk.",
                category="archive",
                severity="info",
                confidence="high",
                analyzer=self.name,
                tags=["archive"],
                evidence=[
                    Evidence(kind="count", summary="Member count", analyzer=self.name, value=str(len(members)))
                ],
            )
        )
        return self.result(details={"members": members, "member_count": len(members)}, findings=findings)


def _is_traversal(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return True
    parts = normalized.split("/")
    return ".." in parts
