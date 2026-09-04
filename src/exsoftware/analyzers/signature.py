from __future__ import annotations

from datetime import datetime, timezone

from ..models import Evidence, Finding
from .authenticode import verify_authenticode
from .base import Analyzer

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc

WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


class SignatureAnalyzer(Analyzer):
    name = "signature"
    title = "Digital signature"
    detected_types = frozenset({"pe", "msi"})

    def analyze(self, ctx):
        if ctx.identity and ctx.identity.detected_type == "pe":
            return self._pe(ctx)
        return self.result(details={"note": "MSI catalog/signature parsing is not implemented in this milestone."})

    def _pe(self, ctx):
        try:
            import pefile
        except ImportError as exc:
            return self.failure(exc)

        pe = pefile.PE(data=ctx.data, fast_load=True)
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            offset = int(directory.VirtualAddress)
            size = int(directory.Size)
            if not offset or not size:
                return self.result(
                    details={"present": False, "offset": offset, "size": size},
                    findings=[
                        Finding(
                            id="signature.absent",
                            title="No embedded Authenticode signature",
                            summary="The PE security directory is empty. Catalog signatures are not checked in this milestone.",
                            category="signature",
                            severity="info",
                            confidence="medium",
                            analyzer=self.name,
                            tags=["signature"],
                            evidence=[
                                Evidence(kind="field", summary="Security directory", analyzer=self.name, value="empty")
                            ],
                        )
                    ],
                )
            blob = ctx.data[offset : offset + size]
            if len(blob) < 8:
                return self.result(
                    details={"present": True, "offset": offset, "size": size, "error": "truncated WIN_CERTIFICATE"},
                    findings=[
                        Finding(
                            id="signature.truncated",
                            title="Signature table is truncated",
                            summary="The security directory points outside the analyzed bytes.",
                            category="signature",
                            severity="low",
                            confidence="high",
                            analyzer=self.name,
                            tags=["signature", "limitation"],
                            evidence=[
                                Evidence(
                                    kind="structure",
                                    summary="WIN_CERTIFICATE truncated",
                                    analyzer=self.name,
                                    location=f"offset {offset}",
                                    extra={"size": size, "available": len(blob)},
                                )
                            ],
                        )
                    ],
                )
            dw_length = int.from_bytes(blob[0:4], "little")
            revision = int.from_bytes(blob[4:6], "little")
            cert_type = int.from_bytes(blob[6:8], "little")
            der = blob[8:dw_length] if dw_length <= len(blob) else blob[8:]
            parsed = _parse_pkcs7(der)
            verification = {
                "trust_verified": False,
                "revocation_checked": False,
                "catalog_checked": False,
                "digest_valid": None,
                "signature_valid": None,
                "errors": [],
            }
            if cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA and der:
                verification = verify_authenticode(ctx.data, _trim_der(der))
            details = {
                "present": True,
                "offset": offset,
                "size": size,
                "dw_length": dw_length,
                "revision": revision,
                "certificate_type": cert_type,
                "certificate_type_name": "PKCS_SIGNED_DATA" if cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA else hex(cert_type),
                "certificates": parsed.get("certificates", []),
                "parse_error": parsed.get("error"),
                "verification": verification,
            }
            findings = [
                Finding(
                    id="signature.embedded",
                    title="Embedded Authenticode blob present",
                    summary=(
                        f"WIN_CERTIFICATE at file offset {offset} ({size} bytes), type "
                        f"{details['certificate_type_name']}."
                    ),
                    category="signature",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["signature"],
                    evidence=[
                        Evidence(
                            kind="structure",
                            summary="WIN_CERTIFICATE header",
                            analyzer=self.name,
                            location=f"offset {offset}",
                            value=f"length={dw_length} revision={revision} type={cert_type}",
                        )
                    ],
                )
            ]
            certs = parsed.get("certificates") or []
            if certs:
                findings.append(
                    Finding(
                        id="signature.certificates",
                        title=f"{len(certs)} certificate(s) extracted from PKCS#7",
                        summary="Subjects and issuers were parsed from the Authenticode PKCS#7 blob. Windows/Microsoft-root trust, catalog signatures, and revocation are not checked.",
                        category="signature",
                        severity="info",
                        confidence="high",
                        analyzer=self.name,
                        tags=["signature", "certificate"],
                        evidence=[
                            Evidence(
                                kind="field",
                                summary=cert.get("subject") or "certificate",
                                analyzer=self.name,
                                value=f"issuer={cert.get('issuer')} valid={cert.get('not_before')} .. {cert.get('not_after')}",
                            )
                            for cert in certs[:8]
                        ],
                    )
                )
            elif parsed.get("error"):
                findings.append(
                    Finding(
                        id="signature.parse-error",
                        title="Authenticode blob could not be fully parsed",
                        summary=parsed["error"],
                        category="signature",
                        severity="low",
                        confidence="medium",
                        analyzer=self.name,
                        tags=["signature", "parse-error"],
                        evidence=[
                            Evidence(kind="error", summary="PKCS#7 parse error", analyzer=self.name, value=parsed["error"])
                        ],
                    )
                )
            findings.extend(_verification_findings(verification))
            return self.result(details=details, findings=findings)
        finally:
            pe.close()


def _trim_der(der: bytes) -> bytes:
    if not der:
        return der
    trimmed = der.rstrip(b"\x00")
    if not trimmed or trimmed[0] != 0x30:
        return trimmed
    try:
        if trimmed[1] < 0x80:
            total = 2 + trimmed[1]
        elif trimmed[1] == 0x81 and len(trimmed) >= 3:
            total = 3 + trimmed[2]
        elif trimmed[1] == 0x82 and len(trimmed) >= 4:
            total = 4 + int.from_bytes(trimmed[2:4], "big")
        elif trimmed[1] == 0x83 and len(trimmed) >= 5:
            total = 5 + int.from_bytes(trimmed[2:5], "big")
        else:
            return trimmed
        if 4 <= total <= len(trimmed):
            return trimmed[:total]
    except IndexError:
        return trimmed
    return trimmed


def _parse_pkcs7(der: bytes) -> dict:
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError as exc:
        return {"error": str(exc), "certificates": []}
    blob = _trim_der(der)
    try:
        certs = pkcs7.load_der_pkcs7_certificates(blob)
    except Exception as exc:
        return {"error": f"{exc.__class__.__name__}: {exc}", "certificates": []}
    out = []
    for cert in certs:
        out.append(
            {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial": hex(cert.serial_number),
                "not_before": _fmt_time(cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before),
                "not_after": _fmt_time(cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after),
            }
        )
    return {"certificates": out}


def _verification_findings(verification: dict) -> list[Finding]:
    findings: list[Finding] = []
    digest_valid = verification.get("digest_valid")
    signature_valid = verification.get("signature_valid")
    if digest_valid is True and signature_valid is True:
        findings.append(
            Finding(
                id="signature.crypto-valid",
                title="Embedded Authenticode digest and CMS signature verify",
                summary=(
                    "The PE Authenticode digest matches the PKCS#7 content and the CMS signature "
                    "verifies with the signing certificate from the blob. This is not Windows trust "
                    "validation; catalog signatures and revocation were not checked."
                ),
                category="signature",
                severity="info",
                confidence="high",
                analyzer="signature",
                tags=["signature", "crypto"],
                evidence=[
                    Evidence(
                        kind="field",
                        summary="Authenticode digest",
                        analyzer="signature",
                        value=str(verification.get("digest_embedded") or ""),
                        extra={
                            "algorithm": verification.get("digest_algorithm"),
                            "computed": verification.get("digest_computed"),
                        },
                    ),
                    Evidence(
                        kind="field",
                        summary="Signing certificate",
                        analyzer="signature",
                        value=(verification.get("signing_certificate") or {}).get("subject") or "unknown",
                    ),
                ],
            )
        )
    elif digest_valid is False or signature_valid is False:
        findings.append(
            Finding(
                id="signature.crypto-invalid",
                title="Embedded Authenticode digest or CMS signature did not verify",
                summary=(
                    "The Authenticode blob is present, but the PE digest and/or CMS signature "
                    "did not verify. This is not a malware verdict."
                ),
                category="signature",
                severity="medium",
                confidence="high",
                analyzer="signature",
                tags=["signature", "crypto"],
                evidence=[
                    Evidence(
                        kind="field",
                        summary="digest_valid",
                        analyzer="signature",
                        value=str(digest_valid),
                    ),
                    Evidence(
                        kind="field",
                        summary="signature_valid",
                        analyzer="signature",
                        value=str(signature_valid),
                    ),
                ],
            )
        )
    chain = verification.get("chain") or []
    if chain:
        complete = verification.get("chain_complete")
        findings.append(
            Finding(
                id="signature.chain-embedded",
                title="Embedded certificate chain reconstructed",
                summary=(
                    "Issuer/subject links were built from certificates inside the PKCS#7 bag only. "
                    + (
                        "The bag ends in a self-signed certificate; that is not a trusted root."
                        if complete
                        else "The embedded bag does not reach a self-signed certificate."
                    )
                ),
                category="signature",
                severity="info",
                confidence="high" if complete else "medium",
                analyzer="signature",
                tags=["signature", "certificate"],
                evidence=[
                    Evidence(
                        kind="field",
                        summary=item.get("role") or "certificate",
                        analyzer="signature",
                        value=item.get("subject") or item.get("serial"),
                    )
                    for item in chain[:8]
                ],
            )
        )
    if verification.get("timestamp_present"):
        findings.append(
            Finding(
                id="signature.timestamp-present",
                title="Timestamp countersignature present",
                summary=(
                    "A timestamp or countersignature attribute is present. "
                    "The TSA is not trusted or verified in this milestone."
                ),
                category="signature",
                severity="info",
                confidence="medium",
                analyzer="signature",
                tags=["signature", "timestamp"],
                evidence=[
                    Evidence(
                        kind="field",
                        summary="signing_time",
                        analyzer="signature",
                        value=str(verification.get("signing_time") or "present"),
                    )
                ],
            )
        )
    return findings


def _fmt_time(value) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.isoformat()
    return str(value)
