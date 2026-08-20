from __future__ import annotations

from dataclasses import dataclass

from .identify import identify_bytes, refine_zip_type_from_names
from .limits import RecursionLimits
from .models import Evidence, Finding

ZIP_TYPES = {"zip", "jar", "apk", "wheel", "docx", "xlsx", "pptx"}
RECURSE_TYPES = {"zip", "jar", "apk", "wheel"}


@dataclass
class MemberCandidate:
    name: str
    data: bytes | None
    size: int
    compressed_size: int
    encrypted: bool
    traversal: bool
    skip_reason: str | None
    limit_code: str | None = None
    extraction_status: str | None = None
    hashes: dict[str, str] | None = None
    index: int | None = None
    compression_method: int | None = None
    crc: str | None = None
    declared_size: int = 0


def is_zip_family(detected_type: str | None) -> bool:
    return detected_type in ZIP_TYPES or detected_type == "zip"


def should_recurse(detected_type: str | None) -> bool:
    """Office Open XML is ZIP-based but exploding XML parts is not useful yet."""
    return detected_type in RECURSE_TYPES


def _is_traversal(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return True
    return ".." in normalized.split("/")


def members_from_container(result) -> tuple[list[MemberCandidate], list[Finding]]:
    """Translate a validated container result into recursion candidates.

    *result* is IsolatedContainerRunner output. Blob bytes were hashed by the parent.
    """
    findings: list[Finding] = []
    members: list[MemberCandidate] = []
    if result.status != "completed":
        findings.append(
            Finding(
                id="archive.bad-zip" if result.reason not in {"timeout"} else "rec.container-timeout",
                title="ZIP structure could not be parsed during recursion"
                if result.reason != "timeout"
                else "Contained ZIP parser exceeded timeout",
                summary=result.message or result.reason or "container worker failed",
                category="archive" if result.reason != "timeout" else "limitation",
                severity="low" if result.reason != "timeout" else "medium",
                confidence="high",
                analyzer="archive",
                tags=["parse-error", "recursion"] if result.reason != "timeout" else ["recursion", "timeout"],
                evidence=[
                    Evidence(
                        kind="error",
                        summary=result.reason or "container_failed",
                        analyzer="archive",
                        value=result.message,
                    )
                ],
            )
        )
        return [], findings

    for item in result.members:
        traversal = item.extraction_status == "path_traversal" or _is_traversal(item.original_name)
        encrypted = item.encrypted or item.extraction_status == "encrypted"
        blob = item.blob
        skip, code = _skip_for_status(item.extraction_status)
        if item.extraction_status == "extracted" and blob is not None:
            members.append(
                MemberCandidate(
                    name=item.original_name,
                    data=blob.data,
                    size=blob.size,
                    compressed_size=item.compressed_size,
                    encrypted=False,
                    traversal=False,
                    skip_reason=None,
                    extraction_status="extracted",
                    hashes=blob.hashes,
                    index=item.index,
                    compression_method=item.compression_method,
                    crc=item.crc,
                    declared_size=item.declared_size,
                )
            )
            continue
        members.append(
            MemberCandidate(
                name=item.original_name,
                data=None,
                size=item.actual_size if item.actual_size is not None else item.declared_size,
                compressed_size=item.compressed_size,
                encrypted=encrypted,
                traversal=traversal,
                skip_reason=skip,
                limit_code=code,
                extraction_status=item.extraction_status,
                index=item.index,
                compression_method=item.compression_method,
                crc=item.crc,
                declared_size=item.declared_size,
            )
        )
        if code and item.extraction_status not in {"directory", "skipped"}:
            findings.append(_finding_for_member(item.original_name, item.extraction_status, code, item.error))
    if result.truncated_listing:
        findings.append(
            _limit_finding(
                "rec.limit-count",
                "ZIP central directory listing was capped",
                f"Archive lists {result.listed_count} members; only a prefix was considered.",
                {"listed": result.listed_count},
            )
        )
    return members, findings


def _skip_for_status(status: str) -> tuple[str | None, str | None]:
    mapping = {
        "encrypted": ("encrypted", "archive.encrypted-members"),
        "path_traversal": ("path-traversal", "archive.path-traversal"),
        "rejected_size_limit": ("member-too-large", "rec.limit-member"),
        "rejected_ratio": ("compression-ratio", "rec.limit-ratio"),
        "rejected_workspace_budget": ("total-bytes", "rec.limit-bytes"),
        "not_processed_member_limit": ("member-count", "rec.limit-count"),
        "not_processed_list_cap": ("member-count", "rec.limit-count"),
        "malformed": ("read-error:malformed", "rec.malformed-member"),
        "directory": ("directory", None),
        "skipped": ("not-extracted", "rec.not-analyzed"),
    }
    return mapping.get(status, (status or "not-extracted", "rec.not-analyzed"))


def _finding_for_member(name: str, status: str, code: str, error: str | None) -> Finding:
    titles = {
        "archive.path-traversal": ("Archive member path looks like traversal", "high"),
        "archive.encrypted-members": ("Encrypted ZIP member(s)", "medium"),
        "rec.skip-traversal": ("ZIP member not extracted because the path looks like traversal", "high"),
        "rec.limit-member": ("ZIP member exceeded max individual size", "medium"),
        "rec.limit-ratio": ("ZIP member compression ratio exceeded limit", "medium"),
        "rec.limit-bytes": ("ZIP recursion reached max expanded bytes", "medium"),
        "rec.limit-count": ("ZIP recursion reached max extracted member count", "medium"),
        "rec.malformed-member": ("ZIP member could not be read", "low"),
        "rec.not-analyzed": ("ZIP member was not analyzed", "low"),
        "rec.skip-encrypted": ("ZIP member is encrypted", "low"),
    }
    title, severity = titles.get(code, ("ZIP member was not analyzed", "low"))
    summary = f"{name!r} was not analyzed ({status})."
    if error:
        summary = f"{name}: {error}"
    extra = {"name": name, "extraction_status": status}
    if code.startswith("rec.limit"):
        return _limit_finding(code, title, summary, extra)
    return Finding(
        id=code,
        title=title,
        summary=summary,
        category="archive" if code != "rec.not-analyzed" else "limitation",
        severity=severity,  # type: ignore[arg-type]
        confidence="high",
        analyzer="archive",
        tags=["recursion", status.replace("_", "-")],
        evidence=[Evidence(kind="field", summary="Archive member name", analyzer="archive", value=name, extra=extra)],
    )


def _limit_finding(legacy_id: str, title: str, summary: str, extra: dict) -> Finding:
    return Finding(
        id=legacy_id,
        title=title,
        summary=summary,
        category="limitation",
        severity="medium",
        confidence="high",
        analyzer="archive",
        tags=["recursion", "limit"],
        evidence=[Evidence(kind="limit", summary=title, analyzer="archive", extra=extra)],
    )


def peek_member_type(name: str, data: bytes) -> str:
    return identify_bytes(data, name, size=len(data)).detected_type


def zip_subtype_from_names(names: list[str]) -> str:
    return refine_zip_type_from_names(names)[0]
