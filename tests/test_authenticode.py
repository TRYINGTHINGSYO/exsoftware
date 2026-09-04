from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from exsoftware.analyzers.authenticode import pe_authenticode_digest, verify_authenticode
from exsoftware.analyzers.signature import SignatureAnalyzer
from exsoftware.composition import compose
from exsoftware.investigation import Investigation
from exsoftware.models import FileIdentity, Report


def _name() -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ExSoftware Test")])


def _issue_cert(key, *, issuer_key=None, issuer_name=None, subject=None, ca=False):
    subject = subject or _name()
    issuer_name = issuer_name or subject
    issuer_key = issuer_key or key
    now = datetime.now(tz=timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


def _tlv(tag: int, body: bytes) -> bytes:
    length = len(body)
    if length < 0x80:
        return bytes((tag, length)) + body
    if length < 0x100:
        return bytes((tag, 0x81, length)) + body
    return bytes((tag, 0x82, (length >> 8) & 0xFF, length & 0xFF)) + body


def _oid(oid: str) -> bytes:
    parts = [int(item) for item in oid.split(".")]
    body = bytes([(parts[0] * 40) + parts[1]])
    for item in parts[2:]:
        stack = [item & 0x7F]
        item >>= 7
        while item:
            stack.append(0x80 | (item & 0x7F))
            item >>= 7
        body += bytes(reversed(stack))
    return _tlv(0x06, body)


def _int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _null() -> bytes:
    return b"\x05\x00"


def _build_pe32(*, payload: bytes = b"\x90" * 0x200, cert: bytes | None = None) -> bytes:
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 20, 0x1000)
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)
    section = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    header = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section
    header = header.ljust(0x200, b"\x00")
    body = header + payload.ljust(0x200, b"\x00")[:0x200]
    if not cert:
        return body
    aligned = len(cert) + ((8 - (len(cert) % 8)) % 8)
    cert_blob = cert + (b"\x00" * (aligned - len(cert)))
    data = bytearray(body + cert_blob)
    # Security data directory at optional+128; optional starts at 0x80+4+20=0x98
    struct.pack_into("<II", data, 0x98 + 128, len(body), aligned)
    return bytes(data)


def _win_certificate(der: bytes) -> bytes:
    dw_length = 8 + len(der)
    pad = (8 - (dw_length % 8)) % 8
    dw_length += pad
    return struct.pack("<IHH", dw_length, 0x0200, 0x0002) + der + (b"\x00" * pad)


def _spc_indirect(digest: bytes) -> bytes:
    digest_info = _tlv(
        0x30,
        _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1") + _null()) + _tlv(0x04, digest),
    )
    attr = _tlv(0x30, _oid("1.3.6.1.4.1.311.2.1.15"))
    return _tlv(0x30, attr + digest_info)


def _signed_attr(oid: str, value: bytes) -> bytes:
    return _tlv(0x30, _oid(oid) + _tlv(0x31, value))


def _authenticode_pkcs7(pe: bytes, key, cert, extra_certs=()) -> bytes:
    digest = pe_authenticode_digest(pe, "sha256")
    econtent = _spc_indirect(digest)
    message_digest = hashlib.sha256(econtent).digest()
    attrs = _signed_attr("1.2.840.113549.1.9.3", _oid("1.3.6.1.4.1.311.2.1.4")) + _signed_attr(
        "1.2.840.113549.1.9.4", _tlv(0x04, message_digest)
    )
    signed_set = _tlv(0x31, attrs)
    signature = key.sign(signed_set, padding.PKCS1v15(), hashes.SHA256())
    implicit_attrs = bytes((0xA0,)) + signed_set[1:]
    sid = _tlv(0x30, cert.issuer.public_bytes() + _int(cert.serial_number))
    signer_info = _tlv(
        0x30,
        _int(1)
        + sid
        + _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1") + _null())
        + implicit_attrs
        + _tlv(0x30, _oid("1.2.840.113549.1.1.1") + _null())
        + _tlv(0x04, signature),
    )
    encap = _tlv(0x30, _oid("1.3.6.1.4.1.311.2.1.4") + _tlv(0xA0, _tlv(0x04, econtent)))
    signed_data = _tlv(
        0x30,
        _int(1)
        + _tlv(0x31, _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1") + _null()))
        + encap
        + _tlv(0xA0, b"".join(item.public_bytes(serialization.Encoding.DER) for item in (cert, *extra_certs)))
        + _tlv(0x31, signer_info),
    )
    return _tlv(0x30, _oid("1.2.840.113549.1.7.2") + _tlv(0xA0, signed_data))


def _signed_pe() -> tuple[bytes, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _issue_cert(key)
    unsigned = _build_pe32()
    der = _authenticode_pkcs7(unsigned, key, cert)
    return _build_pe32(cert=_win_certificate(der)), cert


def _identity() -> FileIdentity:
    return FileIdentity(
        name="sample.exe",
        path=None,
        source="bytes",
        extension=".exe",
        size=1024,
        detected_type="pe",
        detected_family="executable",
        detected_mime="application/vnd.microsoft.portable-executable",
        description="Windows PE executable",
        extension_matches=True,
        magic_offset=0,
        magic_hex="4d5a",
    )


def test_unsigned_pe_does_not_claim_trust_or_crypto():
    data = _build_pe32()
    result = SignatureAnalyzer().analyze(SimpleNamespace(data=data, identity=_identity()))
    assert result.status == "completed"
    assert result.details["present"] is False
    ids = {item.id for item in result.findings}
    assert "signature.absent" in ids
    assert "signature.crypto-valid" not in ids


def test_valid_embedded_signature_verifies_without_claiming_trust():
    data, cert = _signed_pe()
    result = SignatureAnalyzer().analyze(SimpleNamespace(data=data, identity=_identity()))
    verification = result.details["verification"]
    assert verification["digest_valid"] is True
    assert verification["signature_valid"] is True
    assert verification["trust_verified"] is False
    assert verification["revocation_checked"] is False
    assert verification["catalog_checked"] is False
    assert verification["signing_certificate"]["subject"] == cert.subject.rfc4514_string()
    ids = {item.id for item in result.findings}
    assert "signature.crypto-valid" in ids
    assert "signature.crypto-invalid" not in ids
    assert any("not Windows trust" in item.summary for item in result.findings if item.id == "signature.crypto-valid")


def test_tampered_payload_fails_digest():
    data, _cert = _signed_pe()
    mutated = bytearray(data)
    mutated[0x200] ^= 0xFF
    result = SignatureAnalyzer().analyze(SimpleNamespace(data=mutated, identity=_identity()))
    verification = result.details["verification"]
    assert verification["digest_valid"] is False
    assert "signature.crypto-invalid" in {item.id for item in result.findings}


def test_investigation_keeps_trust_false_and_records_crypto_on_signed_by():
    data, cert = _signed_pe()
    analyzer = SignatureAnalyzer()
    result = analyzer.analyze(SimpleNamespace(data=data, identity=_identity()))
    inv = Investigation()
    artifact = inv.add_file_artifact(sha256="a" * 64, name="sample.exe", size=len(data), detected_type="pe")
    run = inv.begin_run(analyzer_id="signature", analyzer_version="1.0.0", analyzer_title="Digital signature", artifact_id=artifact.id)
    inv.ingest_result("signature", "1.0.0", artifact.id, result, run)
    signed = [rel for rel in inv.relationships if rel.type == "SIGNED_BY"]
    assert signed
    assert all(rel.extra.get("trust_validated") is False for rel in signed)
    assert any(rel.extra.get("crypto_valid") is True for rel in signed)
    assert cert.subject.rfc4514_string() in " ".join(inv.artifacts[rel.target_id].names[0] for rel in signed)
    report = Report(
        schema_version=1,
        analyzed_at=datetime.now(tz=timezone.utc).isoformat(),
        identity=_identity(),
        overview="",
        next_steps=[],
        hashes={"sha256": "a" * 64},
        findings=list(inv.findings),
        sections=[result],
        limits={"executed": False, "static_only": True},
        capabilities=[],
        engine={"name": "exsoftware", "version": "test", "schema": "exsoftware.report"},
        root_artifact_id=artifact.id,
        artifacts=list(inv.artifacts.values()),
        relationships=list(inv.relationships),
        observations=list(inv.observations),
        evidence_store=list(inv.evidence),
        analyzer_runs=list(inv.runs),
    )
    report.composition = compose(report).to_dict()
    assert report.composition["identity"]["trust_verified"] is False
    assert report.composition["identity"]["signed"] == "certificate_present"
    gap_ids = [item["id"] for item in report.composition["gaps"]]
    assert "GAP.SIG.TRUST_UNVERIFIED.001" in gap_ids
    assert "GAP.SIG.REVOCATION_UNCHECKED.001" in gap_ids
    trust_gap = next(item for item in report.composition["gaps"] if item["id"] == "GAP.SIG.TRUST_UNVERIFIED.001")
    assert "Windows/Microsoft roots" in trust_gap["statement"]
    important = [item["id"] for item in report.composition["important_observations"]]
    assert "IMP.SIG.CRYPTO_VALID.001" in important


def test_pe_digest_is_stable_for_unsigned_image():
    data = _build_pe32()
    first = pe_authenticode_digest(data, "sha256")
    second = pe_authenticode_digest(data, "sha256")
    assert first == second
    assert len(first) == 32


def test_embedded_ca_chain_emits_issued_by_without_trust():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _issue_cert(root_key, subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")]), ca=True)
    leaf = _issue_cert(
        leaf_key,
        issuer_key=root_key,
        issuer_name=root.subject,
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Leaf")]),
    )
    unsigned = _build_pe32()
    der = _authenticode_pkcs7(unsigned, leaf_key, leaf, extra_certs=(root,))
    data = _build_pe32(cert=_win_certificate(der))
    result = SignatureAnalyzer().analyze(SimpleNamespace(data=data, identity=_identity()))
    verification = result.details["verification"]
    assert verification["digest_valid"] is True
    assert verification["signature_valid"] is True
    assert verification["chain_complete"] is True
    assert verification["trust_verified"] is False
    roles = [item["role"] for item in verification["chain"] if item["role"] != "bag"]
    assert "leaf" in roles and "root" in roles

    inv = Investigation()
    artifact = inv.add_file_artifact(sha256="b" * 64, name="sample.exe", size=len(data), detected_type="pe")
    run = inv.begin_run(analyzer_id="signature", analyzer_version="1.0.0", analyzer_title="Digital signature", artifact_id=artifact.id)
    inv.ingest_result("signature", "1.0.0", artifact.id, result, run)
    issued = [rel for rel in inv.relationships if rel.type == "ISSUED_BY"]
    assert issued
    assert all(rel.extra.get("trust_validated") is False for rel in issued)
    assert all(rel.certainty == "derived" for rel in issued)


def test_verify_helper_does_not_set_trust_on_valid_blob():
    data, _cert = _signed_pe()
    # Reconstruct DER from WIN_CERTIFICATE
    cert_off = struct.unpack_from("<I", data, 0x98 + 128)[0]
    der = data[cert_off + 8 :]
    result = verify_authenticode(data, der)
    assert result["digest_valid"] is True
    assert result["signature_valid"] is True
    assert result["trust_verified"] is False
