"""Stable rule IDs.

Scheme: AREA.SUBJECT.QUALIFIER.NNN

AREA is a short analyzer/domain code. NNN is a zero-padded rule number
within that subject. Rule IDs are stable; instance finding IDs are not.

Legacy prototype IDs (dotted analyzer names) map here so old reports can be
compared during the 0.1 → 1.0 schema change.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    version: str = "1.0.0"
    certainty: str = "derived"


_RULES: dict[str, Rule] = {}


def _r(legacy: str, rule_id: str, *, certainty: str = "derived", version: str = "1.0.0") -> None:
    _RULES[legacy] = Rule(id=rule_id, version=version, certainty=certainty)


_r("identity.extension-mismatch", "ID.EXT.MISMATCH.001", certainty="derived")
_r("identity.extension-matches", "ID.EXT.MATCH.001", certainty="derived")
_r("identity.unknown-type", "ID.TYPE.UNKNOWN.001", certainty="observed")
_r("identity.double-extension", "ID.EXT.MULTI.001", certainty="observed")
_r("identity.truncated-analysis", "ID.TRUNCATED.001", certainty="observed")
_r("hashes.truncated-upload", "HASH.TRUNCATED.001", certainty="observed")
_r("hashes.full-file-partial-analysis", "HASH.PARTIAL.001", certainty="observed")
_r("entropy.high-for-executable", "ENT.HIGH.EXEC.001", certainty="derived")
_r("entropy.high-expected", "ENT.HIGH.FORMAT.001", certainty="derived")
_r("entropy.high-windows", "ENT.HIGH.WINDOWS.001", certainty="derived")
_r("strings.urls", "STR.URL.001", certainty="observed")
_r("strings.ipv4", "STR.IPV4.001", certainty="observed")
_r("strings.emails", "STR.EMAIL.001", certainty="observed")
_r("strings.registry", "STR.REGISTRY.001", certainty="observed")
_r("pe.mz-only", "PE.MZ.ONLY.001", certainty="observed")
_r("pe.identity", "PE.FORMAT.001", certainty="observed")
_r("pe.dotnet", "PE.DOTNET.001", certainty="observed")
_r("pe.wx-section", "PE.SECTION.WX.001", certainty="observed")
_r("pe.packer-section-name", "PE.PACKER.NAME.001", certainty="derived")
_r("pe.high-entropy-code", "PE.SECTION.ENTROPY.001", certainty="derived")
_r("pe.few-imports", "PE.IMPORT.SPARSE.001", certainty="derived")
_r("pe.interesting-imports", "PE.IMPORT.NOTABLE.001", certainty="derived")
_r("pe.injection-import-set", "PE.IMPORT.INJECT.001", certainty="inferred")
_r("pe.overlay", "PE.OVERLAY.001", certainty="observed")
_r("pe.pdb-path", "PE.PDB.001", certainty="observed")
_r("pe.version-info", "PE.VERSION.001", certainty="observed")
_r("pe.authenticode-blob", "PE.CERT.TABLE.001", certainty="observed")
_r("pe.unsigned", "PE.CERT.ABSENT.001", certainty="observed")
_r("elf.identity", "ELF.FORMAT.001", certainty="observed")
_r("elf.needed", "ELF.NEEDED.001", certainty="observed")
_r("elf.interpreter", "ELF.INTERP.001", certainty="observed")
_r("macho.fat", "MACHO.FAT.001", certainty="observed")
_r("macho.identity", "MACHO.FORMAT.001", certainty="observed")
_r("macho.dylibs", "MACHO.DYLIB.001", certainty="observed")
_r("macho.code-signature", "MACHO.CS.001", certainty="observed")
_r("lnk.target", "LNK.TARGET.001", certainty="observed")
_r("lnk.arguments", "LNK.ARGS.001", certainty="observed")
_r("lnk.parse-error", "LNK.PARSE.001", certainty="observed")
_r("archive.gzip", "ARC.GZIP.001", certainty="observed")
_r("archive.bad-zip", "ARC.PARSE.001", certainty="observed")
_r("archive.encrypted-members", "ARC.ENCRYPTED.001", certainty="observed")
_r("archive.path-traversal", "ARC.TRAVERSAL.001", certainty="observed")
_r("archive.listing", "ARC.LIST.001", certainty="observed")
_r("archive.tar-listing", "ARC.TAR.001", certainty="observed")
_r("pdf.parse-error", "PDF.PARSE.001", certainty="observed")
_r("pdf.identity", "PDF.FORMAT.001", certainty="observed")
_r("pdf.metadata", "PDF.META.001", certainty="observed")
_r("pdf.javascript", "PDF.JS.001", certainty="derived")
_r("pdf.open-action", "PDF.OPEN.001", certainty="observed")
_r("pdf.attachments", "PDF.ATTACH.001", certainty="observed")
_r("image.parse-error", "IMG.PARSE.001", certainty="observed")
_r("image.identity", "IMG.FORMAT.001", certainty="observed")
_r("image.exif", "IMG.EXIF.001", certainty="observed")
_r("image.gps", "IMG.GPS.001", certainty="observed")
_r("ole.streams", "OLE.STREAM.001", certainty="observed")
_r("ole.vba-streams", "OLE.VBA.001", certainty="derived")
_r("ole.metadata", "OLE.META.001", certainty="observed")
_r("script.shebang", "SCRIPT.SHEBANG.001", certainty="observed")
_r("script.python-parse-error", "SCRIPT.PY.PARSE.001", certainty="observed")
_r("script.python-imports", "SCRIPT.PY.IMPORT.001", certainty="observed")
_r("script.python-calls", "SCRIPT.PY.CALL.001", certainty="derived")
_r("script.powershell-indicators", "SCRIPT.PS.INDICATOR.001", certainty="derived")
_r("script.js-indicators", "SCRIPT.JS.INDICATOR.001", certainty="derived")
_r("script.identity", "SCRIPT.TEXT.001", certainty="observed")
_r("signature.absent", "SIG.ABSENT.001", certainty="observed")
_r("signature.truncated", "SIG.TRUNCATED.001", certainty="observed")
_r("signature.embedded", "SIG.EMBEDDED.001", certainty="observed")
_r("signature.certificates", "SIG.CERT.001", certainty="observed")
_r("signature.parse-error", "SIG.PARSE.001", certainty="observed")
_r("signature.crypto-valid", "SIG.CRYPTO.VALID.001", certainty="observed")
_r("signature.crypto-invalid", "SIG.CRYPTO.INVALID.001", certainty="observed")
_r("signature.chain-embedded", "SIG.CHAIN.EMBEDDED.001", certainty="derived")
_r("signature.timestamp-present", "SIG.TIMESTAMP.001", certainty="observed")
_r("embedded.signatures", "EMB.MAGIC.001", certainty="derived")
_r("rec.limit-depth", "REC.LIMIT.DEPTH.001", certainty="observed")
_r("rec.limit-count", "REC.LIMIT.COUNT.001", certainty="observed")
_r("rec.limit-bytes", "REC.LIMIT.BYTES.001", certainty="observed")
_r("rec.limit-member", "REC.LIMIT.MEMBER.001", certainty="observed")
_r("rec.limit-ratio", "REC.LIMIT.RATIO.001", certainty="observed")
_r("rec.skip-traversal", "REC.SKIP.TRAVERSAL.001", certainty="observed")
_r("rec.skip-encrypted", "REC.SKIP.ENCRYPTED.001", certainty="observed")
_r("rec.duplicate", "REC.DUP.001", certainty="observed")
_r("rec.not-analyzed", "REC.NOT_ANALYZED.001", certainty="unknown")
_r("rec.malformed-member", "REC.MEMBER.MALFORMED.001", certainty="observed")
_r("rec.container-timeout", "REC.CONTAINER.TIMEOUT.001", certainty="observed")
_r("rec.container-failed", "REC.CONTAINER.FAILED.001", certainty="observed")


def resolve_rule(legacy_id: str, explicit_rule_id: str | None = None, explicit_version: str | None = None) -> Rule:
    if explicit_rule_id:
        base = _RULES.get(legacy_id)
        return Rule(
            id=explicit_rule_id,
            version=explicit_version or (base.version if base else "1.0.0"),
            certainty=base.certainty if base else "derived",
        )
    if legacy_id in _RULES:
        return _RULES[legacy_id]
    if legacy_id.startswith("strings.pattern."):
        slug = legacy_id.split(".", 2)[2].upper().replace("-", "_")
        return Rule(id=f"STR.PATTERN.{slug}.001", version="1.0.0", certainty="observed")
    if legacy_id.startswith("slice0."):
        return resolve_rule(legacy_id.removeprefix("slice0."))
    slug = legacy_id.upper().replace("-", "_")
    return Rule(id=f"LEGACY.{slug}", version="1.0.0", certainty="derived")
