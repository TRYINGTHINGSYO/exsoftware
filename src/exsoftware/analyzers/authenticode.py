"""Offline Authenticode structural checks. Not Windows trust validation."""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone
from typing import Any

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc

OID_SHA1 = "1.3.14.3.2.26"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_COUNTER_SIGNATURE = "1.2.840.113549.1.9.6"
OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"
OID_MS_COUNTER_SIGN = "1.3.6.1.4.1.311.3.3.1"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"

_HASH_OIDS = {
    OID_SHA1: "sha1",
    OID_SHA256: "sha256",
    OID_SHA384: "sha384",
    OID_SHA512: "sha512",
}
_HASH_LEN = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

_DER_CAP = 2_000_000


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


def verify_authenticode(pe_bytes: bytes, der: bytes) -> dict[str, Any]:
    """Verify the embedded Authenticode digest and CMS signature.

    Never claims Windows/Microsoft-root trust, catalog signing, or revocation.
    """
    result: dict[str, Any] = {
        "digest_algorithm": None,
        "digest_computed": None,
        "digest_embedded": None,
        "digest_valid": None,
        "signature_valid": None,
        "signing_certificate": None,
        "chain": [],
        "chain_complete": None,
        "chain_signatures_valid": None,
        "timestamp_present": False,
        "signing_time": None,
        "trust_verified": False,
        "revocation_checked": False,
        "catalog_checked": False,
        "errors": [],
    }
    try:
        signed = _parse_signed_data(der)
    except Exception as exc:
        result["errors"].append(f"{exc.__class__.__name__}: {exc}")
        return result

    result["timestamp_present"] = bool(signed.get("timestamp_present"))
    result["signing_time"] = signed.get("signing_time")
    algorithm = signed.get("digest_algorithm") or "sha256"
    result["digest_algorithm"] = algorithm
    embedded = signed.get("content_digest")
    if embedded:
        result["digest_embedded"] = embedded.hex()
    try:
        computed = pe_authenticode_digest(pe_bytes, algorithm)
        result["digest_computed"] = computed.hex()
        if embedded:
            result["digest_valid"] = computed == embedded
    except Exception as exc:
        result["errors"].append(f"digest:{exc.__class__.__name__}: {exc}")

    certs = signed.get("certificates") or []
    signer = signed.get("signer_cert")
    if signer is None and certs:
        signer = certs[0]
    if signer is not None:
        result["signing_certificate"] = _cert_dict(signer, role="leaf")
        chain, complete = _embedded_chain(certs, signer)
        result["chain"] = [_cert_dict(item, role=role) for item, role in chain]
        result["chain_complete"] = complete
        result["chain_signatures_valid"] = _chain_signatures_valid([item for item, _role in chain])
        try:
            result["signature_valid"] = _verify_signer(signer, signed)
        except Exception as exc:
            result["signature_valid"] = False
            result["errors"].append(f"signature:{exc.__class__.__name__}: {exc}")
    elif certs:
        result["chain"] = [_cert_dict(item, role="bag") for item in certs]
    return result


def pe_authenticode_digest(data: bytes, algorithm: str = "sha256") -> bytes:
    """Authenticode image digest: skip the PE checksum and certificate table."""
    if len(data) < 64:
        raise ValueError("truncated PE")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("invalid PE signature")
    coff = e_lfanew + 4
    nsections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    if opt + 64 + 4 > len(data):
        raise ValueError("truncated optional header")
    magic = struct.unpack_from("<H", data, opt)[0]
    checksum_off = opt + 64
    if magic == 0x10B:
        dd_off = opt + 96
    elif magic == 0x20B:
        dd_off = opt + 112
    else:
        raise ValueError(f"unsupported optional magic {magic:#x}")
    cert_dir_off = dd_off + 4 * 8
    if cert_dir_off + 8 > len(data):
        raise ValueError("truncated data directories")
    cert_off, cert_size = struct.unpack_from("<II", data, cert_dir_off)
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    hasher = hashlib.new(algorithm)
    hasher.update(data[:checksum_off])
    hasher.update(data[checksum_off + 4 : cert_dir_off])
    header_end = min(size_of_headers, len(data))
    if header_end > cert_dir_off + 8:
        hasher.update(data[cert_dir_off + 8 : header_end])

    sections = []
    sect = opt + opt_size
    for _ in range(min(int(nsections), 96)):
        if sect + 40 > len(data):
            break
        raw_size = struct.unpack_from("<I", data, sect + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, sect + 20)[0]
        if raw_size and raw_ptr:
            sections.append((raw_ptr, raw_size))
        sect += 40
    sections.sort()
    hashed_end = header_end
    for raw_ptr, raw_size in sections:
        start = raw_ptr
        end = min(raw_ptr + raw_size, len(data))
        if start >= end:
            continue
        hasher.update(data[start:end])
        hashed_end = max(hashed_end, end)
    extra_end = len(data)
    if cert_off and cert_size and cert_off <= len(data):
        extra_end = min(extra_end, cert_off)
    if extra_end > hashed_end:
        hasher.update(data[hashed_end:extra_end])
    return hasher.digest()


def _parse_signed_data(der: bytes) -> dict[str, Any]:
    from cryptography import x509

    blob = _trim_der(der[:_DER_CAP])
    root = _read_tlv(blob, 0)
    if root[0] != 0x30:
        raise ValueError("PKCS#7 is not a SEQUENCE")
    seq = root[2]
    first = _read_tlv(seq, 0)
    if first[0] == 0x06 and _oid(first[2]) == OID_SIGNED_DATA:
        inner = _read_tlv(seq, first[3])
        if inner[0] != 0xA0:
            raise ValueError("missing SignedData content")
        signed_seq = _read_tlv(inner[2], 0)
        body = signed_seq[2]
    else:
        body = seq

    pos = 0
    _version, pos = _next(body, pos)  # version
    _digests, pos = _next(body, pos)  # digestAlgorithms
    encap, pos = _next(body, pos)
    certificates = []
    timestamp_present = False
    if pos < len(body):
        tag, _ln, value, nxt = _read_tlv(body, pos)
        if tag == 0xA0:
            certificates = _load_certs(value)
            pos = nxt
        elif tag == 0xA1:
            pos = nxt
    if pos < len(body):
        tag, _ln, value, nxt = _read_tlv(body, pos)
        if tag == 0xA1:
            pos = nxt
    signers_tlv = _read_tlv(body, pos) if pos < len(body) else None
    content_type, econtent = _parse_encap(encap[2] if encap[0] == 0x30 else encap[2])
    content_digest, digest_algorithm = _spc_digest(econtent) if econtent else (None, None)

    signer_info = None
    if signers_tlv and signers_tlv[0] == 0x31 and signers_tlv[2]:
        first_signer, _end = _next(signers_tlv[2], 0)
        signer_body = first_signer[2] if first_signer[0] == 0x30 else signers_tlv[2]
        signer_info = _parse_signer_info(signer_body)
        timestamp_present = bool(signer_info.get("timestamp_present"))
        if not digest_algorithm:
            digest_algorithm = signer_info.get("digest_algorithm")

    signer_cert = None
    if signer_info and certificates:
        signer_cert = _match_signer(certificates, signer_info)

    if digest_algorithm is None:
        digest_algorithm = "sha256"
    if content_digest is None and econtent and digest_algorithm:
        content_digest = hashlib.new(digest_algorithm, econtent).digest()

    # Authenticode: the PE digest lives in SpcIndirectDataContent, not the hash of eContent.
    # messageDigest in signed attrs is hash(eContent).
    return {
        "content_type": content_type,
        "econtent": econtent,
        "content_digest": content_digest,
        "digest_algorithm": digest_algorithm,
        "certificates": certificates,
        "signer_cert": signer_cert,
        "signer_info": signer_info,
        "timestamp_present": timestamp_present,
        "signing_time": (signer_info or {}).get("signing_time"),
    }


def _parse_encap(data: bytes) -> tuple[str | None, bytes | None]:
    pos = 0
    oid_t, pos = _next(data, pos)
    content_type = _oid(oid_t[2]) if oid_t[0] == 0x06 else None
    econtent = None
    if pos < len(data):
        tagged, _pos = _next(data, pos)
        payload = tagged[2]
        if payload and payload[0] == 0x04:
            econtent = _read_tlv(payload, 0)[2]
        else:
            econtent = payload
    return content_type, econtent


def _spc_digest(econtent: bytes | None) -> tuple[bytes | None, str | None]:
    if not econtent:
        return None, None
    try:
        seq = _read_tlv(econtent, 0)
        body = seq[2] if seq[0] == 0x30 else econtent
        pos = 0
        _attr, pos = _next(body, pos)
        digest_info, _pos = _next(body, pos)
        if digest_info[0] != 0x30:
            return None, None
        alg, pos2 = _next(digest_info[2], 0)
        digest_t, _p = _next(digest_info[2], pos2)
        algorithm = None
        if alg[0] == 0x30:
            oid_t, _p = _next(alg[2], 0)
            if oid_t[0] == 0x06:
                algorithm = _HASH_OIDS.get(_oid(oid_t[2]))
        digest = digest_t[2] if digest_t[0] == 0x04 else None
        return digest, algorithm
    except Exception:
        return None, None


def _parse_signer_info(data: bytes) -> dict[str, Any]:
    pos = 0
    _ver, pos = _next(data, pos)
    sid, pos = _next(data, pos)
    digest_alg, pos = _next(data, pos)
    signed_attrs = None
    signed_attrs_raw = None
    if pos < len(data) and data[pos] == 0xA0:
        tag, length, value, nxt = _read_tlv(data, pos)
        signed_attrs = value
        # IMPLICIT [0] → SET OF for verification.
        signed_attrs_raw = bytes((0x31, *data[pos + 1 : nxt]))
        pos = nxt
    sig_alg, pos = _next(data, pos)
    signature_t, pos = _next(data, pos)
    unsigned = b""
    if pos < len(data) and data[pos] == 0xA1:
        unsigned = _read_tlv(data, pos)[2]
    attrs = _attr_map(signed_attrs) if signed_attrs is not None else {}
    return {
        "sid": sid,
        "digest_algorithm": _alg_name(digest_alg),
        "signature_algorithm": _alg_name(sig_alg),
        "signature": signature_t[2] if signature_t[0] == 0x04 else b"",
        "signed_attrs": attrs,
        "signed_attrs_raw": signed_attrs_raw,
        "signing_time": _parse_time(attrs.get(OID_SIGNING_TIME)),
        "timestamp_present": _has_timestamp(unsigned),
        "message_digest": attrs.get(OID_MESSAGE_DIGEST),
    }


def _attr_map(data: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    pos = 0
    while pos < len(data):
        attr, pos = _next(data, pos)
        if attr[0] != 0x30:
            continue
        oid_t, inner = _next(attr[2], 0)
        if oid_t[0] != 0x06:
            continue
        oid = _oid(oid_t[2])
        valueset, _p = _next(attr[2], inner)
        payload = valueset[2]
        if payload:
            first = _read_tlv(payload, 0)
            if oid == OID_MESSAGE_DIGEST and first[0] == 0x04:
                out[oid] = first[2]
            elif oid == OID_SIGNING_TIME:
                out[oid] = first[2]
            else:
                out[oid] = first[2]
        else:
            out[oid] = b""
    return out


def _has_timestamp(unsigned: bytes) -> bool:
    if not unsigned:
        return False
    blob = unsigned
    return any(
        token in blob
        for token in (
            _oid_der(OID_TIMESTAMP_TOKEN),
            _oid_der(OID_MS_COUNTER_SIGN),
            _oid_der(OID_COUNTER_SIGNATURE),
        )
    )


def _oid_der(oid: str) -> bytes:
    parts = [int(item) for item in oid.split(".")]
    body = bytes([(parts[0] * 40) + parts[1]])
    for item in parts[2:]:
        stack = [item & 0x7F]
        item >>= 7
        while item:
            stack.append(0x80 | (item & 0x7F))
            item >>= 7
        body += bytes(reversed(stack))
    return bytes((0x06, len(body))) + body


def _alg_name(tlv: tuple[int, int, bytes, int]) -> str | None:
    data = tlv[2] if tlv[0] == 0x30 else tlv[2]
    if not data:
        return None
    first = _read_tlv(data, 0)
    if first[0] == 0x06:
        return _HASH_OIDS.get(_oid(first[2])) or _oid(first[2])
    return None


def _load_certs(data: bytes) -> list[Any]:
    from cryptography import x509

    certs = []
    pos = 0
    while pos < len(data):
        tag, _ln, value, nxt = _read_tlv(data, pos)
        if tag == 0x30:
            try:
                certs.append(x509.load_der_x509_certificate(data[pos:nxt]))
            except Exception:
                pass
        pos = nxt
    return certs


def _match_signer(certs: list[Any], signer_info: dict[str, Any]) -> Any | None:
    sid = signer_info.get("sid")
    if not sid:
        return certs[0]
    tag, _ln, value, _n = sid if len(sid) == 4 else (sid[0], 0, sid[2], 0)
    if tag == 0x30:
        _issuer_t, pos = _next(value, 0)
        serial_t, _p = _next(value, pos)
        serial = int.from_bytes(serial_t[2], "big") if serial_t[0] == 0x02 else None
        if serial is not None:
            for cert in certs:
                if cert.serial_number == serial:
                    return cert
    if tag in {0x80, 0xA0}:
        ski = value
        from cryptography.x509.oid import ExtensionOID

        for cert in certs:
            try:
                ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                if ext.value.digest == ski:
                    return cert
            except Exception:
                continue
    return certs[0] if certs else None


def _verify_signer(cert: Any, signed: dict[str, Any]) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa

    info = signed.get("signer_info") or {}
    signature = info.get("signature") or b""
    if not signature:
        return False
    algorithm = info.get("digest_algorithm") or signed.get("digest_algorithm") or "sha256"
    hash_impl = _hash_for(algorithm)
    econtent = signed.get("econtent") or b""
    message_digest = info.get("message_digest")
    if message_digest is not None:
        if hashlib.new(algorithm, econtent).digest() != message_digest:
            return False
        to_verify = info.get("signed_attrs_raw")
        if not to_verify:
            return False
    else:
        to_verify = econtent
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        try:
            pub.verify(signature, to_verify, padding.PKCS1v15(), hash_impl)
            return True
        except Exception:
            try:
                pub.verify(signature, to_verify, padding.PSS(mgf=padding.MGF1(hash_impl), salt_length=padding.PSS.MAX_LENGTH), hash_impl)
                return True
            except Exception:
                return False
    if isinstance(pub, ec.EllipticCurvePublicKey):
        try:
            pub.verify(signature, to_verify, ec.ECDSA(hash_impl))
            return True
        except Exception:
            return False
    if isinstance(pub, dsa.DSAPublicKey):
        try:
            pub.verify(signature, to_verify, hash_impl)
            return True
        except Exception:
            return False
    if isinstance(pub, ed25519.Ed25519PublicKey):
        try:
            pub.verify(signature, to_verify)
            return True
        except Exception:
            return False
    return False


def _hash_for(name: str):
    from cryptography.hazmat.primitives import hashes

    mapping = {
        "sha1": hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }
    return mapping.get(name, hashes.SHA256())


def _embedded_chain(certs: list[Any], leaf: Any) -> tuple[list[tuple[Any, str]], bool]:
    remaining = [item for item in certs if item is not leaf]
    chain: list[tuple[Any, str]] = [(leaf, "leaf")]
    current = leaf
    seen: set[int] = set()
    while current.subject != current.issuer:
        ident = id(current)
        if ident in seen:
            return chain, False
        seen.add(ident)
        issuer = next((item for item in remaining if item.subject == current.issuer), None)
        if issuer is None:
            return chain, False
        remaining = [item for item in remaining if item is not issuer]
        role = "root" if issuer.subject == issuer.issuer else "intermediate"
        chain.append((issuer, role))
        current = issuer
    if chain[-1][0].subject == chain[-1][0].issuer and chain[-1][1] != "root":
        cert, _role = chain[-1]
        chain[-1] = (cert, "root" if len(chain) > 1 else "leaf")
    complete = chain[-1][0].subject == chain[-1][0].issuer
    extras = [(item, "bag") for item in remaining]
    return chain + extras, complete


def _chain_signatures_valid(certs: list[Any]) -> bool | None:
    if len(certs) < 2:
        return None
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

    ok = True
    for child, issuer in zip(certs, certs[1:]):
        try:
            pub = issuer.public_key()
            hash_alg = child.signature_hash_algorithm
            if hash_alg is None:
                return False
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), hash_alg)
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(hash_alg))
            elif isinstance(pub, dsa.DSAPublicKey):
                pub.verify(child.signature, child.tbs_certificate_bytes, hash_alg)
            else:
                return False
        except Exception:
            ok = False
            break
    return ok


def _cert_dict(cert: Any, *, role: str) -> dict[str, Any]:
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": hex(cert.serial_number),
        "not_before": _fmt_time(cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before),
        "not_after": _fmt_time(cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after),
        "role": role,
    }


def _fmt_time(value) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.isoformat()
    return str(value)


def _parse_time(raw: bytes | None) -> str | None:
    if not raw:
        return None
    text = raw.decode("ascii", "replace")
    for fmt, count in (("%y%m%d%H%M%SZ", 13), ("%Y%m%d%H%M%SZ", 15)):
        if len(text) >= count - 1:
            try:
                return datetime.strptime(text[: count if text.endswith("Z") else len(text)], fmt).replace(tzinfo=UTC).isoformat()
            except ValueError:
                continue
    return text


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, bytes, int]:
    if offset >= len(data):
        raise ValueError("DER truncated")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("DER truncated length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("DER reserved or oversized length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    if length < 0 or offset + length > len(data) or offset + length > _DER_CAP:
        raise ValueError("DER value out of bounds")
    value = data[offset : offset + length]
    return tag, length, value, offset + length


def _next(data: bytes, offset: int) -> tuple[tuple[int, int, bytes, int], int]:
    tlv = _read_tlv(data, offset)
    return tlv, tlv[3]


def _oid(data: bytes) -> str:
    if not data:
        return ""
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte < 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)
