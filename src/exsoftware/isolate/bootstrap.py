"""Parent-validated Unix worker bootstrap acknowledgment.

Child-provided ACK bytes are a hostile attestation of apply results. The parent
performs a bounded no-follow read and strict schema validation, then checks
consistency with host feature detection. That is not independent proof that
Landlock, a network namespace, or rlimits took effect: a compromised worker
can still claim ``applied``. Missing, truncated, malformed, contradictory,
timed-out, or crash-before-ACK evidence must never produce an enforced
capability for those four restrictions.

Process-tree/session enforcement remains parent-visible
(``Popen(start_new_session=True)``) and is not granted from the ACK.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .policy import IsolationPolicy
from .workspace import OversizedWorkspaceFile, read_workspace_file

BOOTSTRAP_PROTOCOL = "exsoftware.isolate.bootstrap"
BOOTSTRAP_PROTOCOL_VERSION = 1
ACK_NAME = "bootstrap.ack"
ACK_MAX_BYTES = 4096
BOOTSTRAP_HOOK_ENV = "EXSOFTWARE_ISOLATE_BOOTSTRAP_HOOK"

ACK_RESULT_KEYS = ("filesystem", "network", "memory", "cpu", "session")
ACK_STATES = frozenset({"applied", "unsupported", "failed"})
ACK_REQUIRED_KEYS = frozenset(("protocol", "protocol_version", *ACK_RESULT_KEYS))

CAPABILITY_BY_ACK_KEY = {
    "filesystem": "filesystem_restriction",
    "network": "network_restriction",
    "memory": "memory_limit",
    "cpu": "cpu_limit",
}

SUPPORT_FLAG_BY_ACK_KEY = {
    "filesystem": "landlock",
    "network": "unshare_net",
    "memory": "rlimit",
    "cpu": "rlimit",
}

PROMOTABLE = frozenset(CAPABILITY_BY_ACK_KEY)

_ENFORCE_REASONS = {
    "filesystem": "Schema-validated child ACK attested Landlock applied",
    "network": "Schema-validated child ACK attested CLONE_NEWNET applied",
    "memory": "Schema-validated child ACK attested RLIMIT_AS applied",
    "cpu": "Schema-validated child ACK attested RLIMIT_CPU applied",
}
_UNSUPPORTED_REASONS = {
    "filesystem": "Schema-validated child ACK attested Landlock unsupported",
    "network": "Schema-validated child ACK attested CLONE_NEWNET unsupported",
    "memory": "Schema-validated child ACK attested RLIMIT_AS unsupported",
    "cpu": "Schema-validated child ACK attested RLIMIT_CPU unsupported",
}
_FAILED_REASONS = {
    "filesystem": "Schema-validated child ACK attested Landlock apply failed",
    "network": "Schema-validated child ACK attested CLONE_NEWNET apply failed",
    "memory": "Schema-validated child ACK attested RLIMIT_AS apply failed",
    "cpu": "Schema-validated child ACK attested RLIMIT_CPU apply failed",
}


class BootstrapAckError(ValueError):
    """ACK failed schema or semantic validation. Never promotes capabilities."""

    def __init__(self, message: str, *, status: str) -> None:
        super().__init__(message)
        self.status = status


def ack_payload(results: dict[str, str]) -> dict[str, Any]:
    """Build the child ACK object. *results* must already be schema-valid."""
    payload = {
        "protocol": BOOTSTRAP_PROTOCOL,
        "protocol_version": BOOTSTRAP_PROTOCOL_VERSION,
    }
    for key in ACK_RESULT_KEYS:
        payload[key] = results[key]
    return payload


def write_bootstrap_ack(workdir: Path, results: dict[str, str]) -> None:
    """Atomically write a schema-shaped ACK. Child-side helper."""
    payload = ack_payload(results)
    path = workdir / ACK_NAME
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)


def validate_bootstrap_ack(data: Any) -> dict[str, str]:
    """Strict schema check. Does not consult parent feature flags."""
    if not isinstance(data, dict):
        raise BootstrapAckError("bootstrap ACK is not an object", status="malformed")
    extra = set(data) - ACK_REQUIRED_KEYS
    missing = ACK_REQUIRED_KEYS - set(data)
    if extra:
        raise BootstrapAckError(
            f"bootstrap ACK has unknown fields: {sorted(extra)}",
            status="malformed",
        )
    if missing:
        raise BootstrapAckError(
            f"bootstrap ACK missing fields: {sorted(missing)}",
            status="malformed",
        )
    if data.get("protocol") != BOOTSTRAP_PROTOCOL:
        raise BootstrapAckError("bootstrap ACK protocol name is invalid", status="malformed")
    if data.get("protocol_version") != BOOTSTRAP_PROTOCOL_VERSION:
        raise BootstrapAckError("bootstrap ACK protocol version is invalid", status="malformed")
    results: dict[str, str] = {}
    for key in ACK_RESULT_KEYS:
        value = data[key]
        if not isinstance(value, str) or value not in ACK_STATES:
            raise BootstrapAckError(
                f"bootstrap ACK field {key!r} is not a valid result state",
                status="malformed",
            )
        results[key] = value
    return results


def ack_contradictions(results: dict[str, str], unix_support: dict[str, Any] | None) -> list[str]:
    """Return semantic contradictions. An applied result requires parent feature support."""
    support = unix_support if isinstance(unix_support, dict) else {}
    problems: list[str] = []
    for key, flag in SUPPORT_FLAG_BY_ACK_KEY.items():
        if results.get(key) == "applied" and not bool(support.get(flag)):
            problems.append(
                f"{key} reported applied but parent feature {flag!r} is unavailable"
            )
    return problems


def looks_like_crash(returncode: int | None) -> bool:
    if returncode is None:
        return False
    if returncode < 0:
        return True
    unsigned = returncode & 0xFFFFFFFF
    return unsigned >= 0xC0000000


def apply_validated_ack(
    policy: IsolationPolicy,
    results: dict[str, str],
) -> None:
    """Promote or downgrade FS/net/memory/cpu from a fully validated ACK.

    ``session`` is recorded by the caller as evidence only. ``process_tree_limit``
    stays under parent-visible ``start_new_session`` control.
    """
    for key in ("filesystem", "network", "memory", "cpu"):
        capability = CAPABILITY_BY_ACK_KEY[key]
        state = results[key]
        if state == "applied":
            setattr(policy, capability, "enforced")
            policy.reasons[capability] = _ENFORCE_REASONS[key]
        elif state == "unsupported":
            setattr(policy, capability, "unsupported")
            policy.reasons[capability] = _UNSUPPORTED_REASONS[key]
        else:
            setattr(policy, capability, "failed")
            policy.reasons[capability] = _FAILED_REASONS[key]
    policy.evidence["bootstrap_ack"] = dict(results)


def ingest_unix_bootstrap_ack(
    policy: IsolationPolicy,
    workdir: Path | None,
    *,
    timed_out: bool,
    returncode: int | None,
    unix_support: dict[str, Any] | None,
) -> dict[str, Any]:
    """Read and apply a Unix bootstrap ACK. Never promotes on invalid evidence."""
    evidence: dict[str, Any] = {
        "status": "missing",
        "protocol": BOOTSTRAP_PROTOCOL,
        "protocol_version": BOOTSTRAP_PROTOCOL_VERSION,
        "promoted": False,
    }
    if workdir is None:
        evidence["reason"] = "workspace was not available to read bootstrap ACK"
        return evidence

    try:
        raw = read_workspace_file(workdir, ACK_NAME, max_bytes=ACK_MAX_BYTES)
    except OversizedWorkspaceFile as exc:
        evidence["status"] = "oversized"
        evidence["reason"] = str(exc)
        evidence["size"] = exc.size
        return evidence
    except OSError:
        if timed_out:
            evidence["status"] = "timeout"
            evidence["reason"] = "worker timed out before a bootstrap ACK was readable"
        elif looks_like_crash(returncode):
            evidence["status"] = "crash_before_ack"
            evidence["reason"] = "worker crashed before a bootstrap ACK was readable"
        else:
            evidence["status"] = "missing"
            evidence["reason"] = "bootstrap ACK file was missing"
        return evidence

    evidence["size"] = len(raw)
    if not raw:
        evidence["status"] = "missing"
        evidence["reason"] = "bootstrap ACK file was empty"
        return evidence

    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        evidence["status"] = "malformed"
        evidence["reason"] = f"bootstrap ACK is not UTF-8 ({exc})"
        return evidence
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        stripped = text.strip()
        incomplete = (stripped.startswith("{") and not stripped.endswith("}")) or (
            stripped.startswith("[") and not stripped.endswith("]")
        )
        evidence["status"] = "truncated" if incomplete else "malformed"
        evidence["reason"] = f"bootstrap ACK is not valid JSON ({exc})"
        return evidence

    try:
        results = validate_bootstrap_ack(data)
    except BootstrapAckError as exc:
        evidence["status"] = exc.status
        evidence["reason"] = str(exc)
        return evidence

    contradictions = ack_contradictions(results, unix_support)
    if contradictions:
        evidence["status"] = "contradictory"
        evidence["reason"] = "; ".join(contradictions)
        evidence["results"] = dict(results)
        return evidence

    apply_validated_ack(policy, results)
    evidence["status"] = "ok"
    evidence["promoted"] = True
    evidence["results"] = dict(results)
    evidence["reason"] = (
        "bootstrap ACK passed bounded schema validation; this is child attestation, "
        "not independent proof the restriction held"
    )
    return evidence


def attach_bootstrap_ack(
    isolation: dict[str, Any],
    policy: IsolationPolicy,
    workdir: Path | None,
    *,
    timed_out: bool,
    returncode: int | None,
) -> None:
    """Unix-only: ingest ACK and refresh isolation capability snapshots.

    Windows launch evidence is left unchanged. A successful later analyzer
    result is not used as promotion evidence.
    """
    if sys.platform == "win32":
        return
    evidence = ingest_unix_bootstrap_ack(
        policy,
        workdir,
        timed_out=timed_out,
        returncode=returncode,
        unix_support=isolation.get("unix_support") if isinstance(isolation.get("unix_support"), dict) else None,
    )
    isolation["bootstrap_ack"] = evidence
    isolation["capabilities"] = policy.capabilities()
    isolation["mechanism"] = policy.mechanism
    isolation["policy"] = policy.to_dict()
