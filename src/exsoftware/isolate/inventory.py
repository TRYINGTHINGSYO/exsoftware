"""Normalize and conservatively aggregate per-worker isolation evidence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from ..models import AnalyzerRun
from .policy import CAPABILITIES

CAPABILITY_STRENGTH = {
    "failed": 0,
    "unsupported": 1,
    "degraded": 2,
    "enforced": 3,
}

FALLBACK_MECHANISMS = {
    "job-only",
    "restricted-token",
    "restricted_token",
}

ISOLATION_EVIDENCE_FIELDS = (
    "token_is_appcontainer",
    "job_assigned",
    "job_limits",
    "job_assign_error",
    "appcontainer_sid",
    "appcontainer_paths_granted",
    "fallback_errors",
    "spawn_error",
    "returncode",
    "still_alive",
    "termination",
    "suspended_start",
    "process_group",
    "unix_support",
    "workdir_removed",
)


def worker_isolation_record(
    *,
    worker_type: str,
    worker_id: str,
    artifact_id: str,
    status: str,
    isolation: Mapping[str, Any] | None,
    reason: str | None = None,
    message: str | None = None,
    run_id: str | None = None,
    worker_version: str | None = None,
    worker_title: str | None = None,
    launched: bool | None = None,
) -> dict[str, Any]:
    """Return the stable report projection for one attempted worker execution."""
    raw = dict(isolation or {})
    raw_caps = raw.get("capabilities")
    if not isinstance(raw_caps, Mapping):
        raw_caps = {}
    capabilities = {
        name: _capability_state(raw_caps.get(name))
        for name in CAPABILITIES
    }
    if launched is None:
        if "launched" in raw:
            launched = bool(raw.get("launched"))
        else:
            launched = raw.get("pid") is not None

    mechanism = raw.get("mechanism")
    mechanism = str(mechanism) if mechanism else None
    fallback_errors = [str(item) for item in raw.get("fallback_errors") or []]
    fallback_used = bool(fallback_errors) or mechanism in FALLBACK_MECHANISMS
    weaker = {
        name: state
        for name, state in capabilities.items()
        if state != "enforced"
    }
    evidence = {
        key: raw[key]
        for key in ISOLATION_EVIDENCE_FIELDS
        if key in raw
    }
    policy = raw.get("policy")
    if isinstance(policy, Mapping):
        if isinstance(policy.get("reasons"), Mapping):
            evidence["policy_reasons"] = dict(policy["reasons"])
        if isinstance(policy.get("evidence"), Mapping):
            evidence["policy_evidence"] = dict(policy["evidence"])

    record: dict[str, Any] = {
        "worker_type": worker_type,
        "worker_id": worker_id,
        "artifact_id": artifact_id,
        "status": status,
        "launched": bool(launched),
        "mechanism": mechanism,
        "capabilities": capabilities,
        "fallback_used": fallback_used,
        "fallback_errors": fallback_errors,
        "weaker_capabilities": weaker,
        "mode": raw.get("mode"),
        "protocol": raw.get("protocol"),
        "protocol_version": raw.get("protocol_version"),
        "operation": raw.get("operation"),
        "reason": reason,
        "message": message,
        "evidence": evidence,
    }
    if run_id is not None:
        record["run_id"] = run_id
    if worker_version is not None:
        record["worker_version"] = worker_version
    if worker_title is not None:
        record["worker_title"] = worker_title
    return record


def analyzer_worker_isolation_record(run: AnalyzerRun) -> dict[str, Any] | None:
    """Project an executed or launch-failed analyzer run into the inventory."""
    isolation = (run.details or {}).get("isolation")
    if not isinstance(isolation, Mapping) or isolation.get("mode") != "subprocess":
        return None
    message = run.errors[0].message if run.errors else None
    reason = (run.details or {}).get("reason") or run.skip_reason
    return worker_isolation_record(
        worker_type="analyzer",
        worker_id=run.analyzer_id,
        artifact_id=run.artifact_id,
        status=run.status,
        isolation=isolation,
        reason=str(reason) if reason else None,
        message=message,
        run_id=run.id,
        worker_version=run.analyzer_version,
        worker_title=run.analyzer_title,
    )


def aggregate_worker_isolation(workers: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate worker evidence without allowing a stronger worker to hide a weaker one."""
    records = [dict(worker) for worker in workers]
    if not records:
        return {
            "mechanism": None,
            "mechanisms": [],
            "mechanism_counts": {},
            "mechanism_uniform": False,
            "all_workers_launched": True,
            "worker_count": 0,
            "launched_worker_count": 0,
            "failed_worker_count": 0,
            "fallback_used": False,
            "worker_status_counts": {},
            "capabilities": {},
            "capability_counts": {},
        }

    launched_count = sum(bool(item.get("launched")) for item in records)
    all_launched = launched_count == len(records)
    actual_mechanisms = sorted(
        {
            str(item["mechanism"])
            for item in records
            if item.get("launched") and item.get("mechanism")
        }
    )
    missing_mechanism = any(
        item.get("launched") and not item.get("mechanism")
        for item in records
    )
    mechanism_uniform = all_launched and not missing_mechanism and len(actual_mechanisms) == 1
    if mechanism_uniform:
        mechanism: str | None = actual_mechanisms[0]
    elif launched_count:
        mechanism = "mixed"
    else:
        mechanism = "none"

    mechanism_counts: dict[str, int] = {}
    for item in records:
        name = str(item.get("mechanism") or "unknown") if item.get("launched") else "not-launched"
        mechanism_counts[name] = mechanism_counts.get(name, 0) + 1

    status_counts: dict[str, int] = {}
    for item in records:
        status = str(item.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    capabilities: dict[str, str] = {}
    capability_counts: dict[str, dict[str, int]] = {}
    for name in CAPABILITIES:
        states = [
            _capability_state((item.get("capabilities") or {}).get(name))
            for item in records
        ]
        capabilities[name] = min(states, key=CAPABILITY_STRENGTH.__getitem__)
        counts: dict[str, int] = {}
        for state in states:
            counts[state] = counts.get(state, 0) + 1
        capability_counts[name] = counts

    return {
        "mechanism": mechanism,
        "mechanisms": actual_mechanisms,
        "mechanism_counts": dict(sorted(mechanism_counts.items())),
        "mechanism_uniform": mechanism_uniform,
        "all_workers_launched": all_launched,
        "worker_count": len(records),
        "launched_worker_count": launched_count,
        "failed_worker_count": sum(
            str(item.get("status") or "") in {"failed", "timeout", "terminated"}
            for item in records
        ),
        "fallback_used": any(bool(item.get("fallback_used")) for item in records),
        "worker_status_counts": dict(sorted(status_counts.items())),
        "capabilities": capabilities,
        "capability_counts": capability_counts,
    }


def _capability_state(value: Any) -> str:
    state = str(value or "unsupported")
    return state if state in CAPABILITY_STRENGTH else "unsupported"
