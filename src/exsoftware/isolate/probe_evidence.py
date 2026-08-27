"""Evidence gates for filesystem and process capability claims.

Absence of a successful forbidden operation is not denial. A worker that never
launched, a helper that did not complete, or mechanism ``none`` cannot produce
an OS containment capability of ``enforced``.
"""

from __future__ import annotations

from typing import Any

from .protocol import REASON_SPAWN_FAILED

OS_CONTAINMENT_CAPABILITIES = (
    "filesystem_restriction",
    "network_restriction",
    "process_creation",
)

_NONE_MECHANISMS = frozenset({"", "none", None})
_COMPLETED = frozenset({"completed", "ok"})


def normalize_mechanism(mechanism: Any) -> str:
    text = str(mechanism or "none").strip() or "none"
    return text


def mechanism_allows_os_enforcement(mechanism: Any) -> bool:
    return normalize_mechanism(mechanism) not in {"none", ""}


def filesystem_mechanism_supports_enforced(
    mechanism: Any,
    *,
    token_is_appcontainer: bool = False,
) -> bool:
    mech = normalize_mechanism(mechanism)
    if mech == "appcontainer":
        return bool(token_is_appcontainer)
    if mech == "unix-preexec":
        return True
    return False


def assess_filesystem_mechanisms(
    read_probe: dict[str, Any],
    write_probe: dict[str, Any],
) -> dict[str, Any]:
    """Compare filesystem probe mechanisms. Aggregate report mechanism is not proof."""
    read_mech = normalize_mechanism(read_probe.get("mechanism"))
    write_mech = normalize_mechanism(write_probe.get("mechanism"))
    read_token = bool(read_probe.get("token_is_appcontainer"))
    write_token = bool(write_probe.get("token_is_appcontainer"))
    result: dict[str, Any] = {
        "read_mechanism": read_mech,
        "write_mechanism": write_mech,
        "read_token_is_appcontainer": read_token,
        "write_token_is_appcontainer": write_token,
        "filesystem_mechanism_consistent": False,
        "filesystem_mechanism_supports_enforced": False,
        "filesystem_claim_mechanism": "none",
        "filesystem_mechanism_reason": "",
    }
    if read_mech != write_mech:
        result["filesystem_mechanism_reason"] = (
            f"filesystem probe mechanisms disagree ({read_mech!r} vs {write_mech!r})"
        )
        return result
    result["filesystem_mechanism_consistent"] = True
    result["filesystem_claim_mechanism"] = read_mech
    if not mechanism_allows_os_enforcement(read_mech):
        result["filesystem_mechanism_reason"] = (
            "No OS containment mechanism; filesystem restriction cannot be enforced"
        )
        return result
    # AppContainer enforcement requires confirmed tokens on both filesystem workers.
    token_ok = read_token and write_token if read_mech == "appcontainer" else False
    if filesystem_mechanism_supports_enforced(read_mech, token_is_appcontainer=token_ok):
        result["filesystem_mechanism_supports_enforced"] = True
        if read_mech == "appcontainer":
            result["filesystem_mechanism_reason"] = (
                "AppContainer confirmed on filesystem read and write probes"
            )
        else:
            result["filesystem_mechanism_reason"] = (
                f"filesystem probes agree on mechanism {read_mech!r}"
            )
        return result
    if read_mech == "appcontainer":
        result["filesystem_mechanism_reason"] = (
            "AppContainer filesystem probes lack confirmed TokenIsAppContainer evidence"
        )
    else:
        result["filesystem_mechanism_reason"] = (
            f"mechanism {read_mech!r} does not support enforced filesystem restriction"
        )
    return result


def probe_worker_launched(probe: dict[str, Any] | None) -> bool:
    """True when the isolated child actually started."""
    if not probe:
        return False
    if probe.get("spawn_error"):
        return False
    details = probe.get("details") or {}
    if isinstance(details, dict) and details.get("reason") == REASON_SPAWN_FAILED:
        return False
    if probe.get("worker_launched") is False:
        return False
    if probe.get("worker_launched"):
        return True
    pid = probe.get("pid")
    if pid:
        return True
    spawn_meta = probe.get("spawn_meta") or {}
    if isinstance(spawn_meta, dict) and spawn_meta.get("pid"):
        return True
    return False


def probe_helper_complete(
    probe: dict[str, Any] | None,
    *,
    result_keys: tuple[str, ...] = (),
) -> tuple[bool, str]:
    """Whether the helper launched, finished, and returned the expected fields."""
    if not probe:
        return False, "probe worker did not run"
    if not probe_worker_launched(probe):
        return False, "probe worker failed before launch"
    status = str(probe.get("status") or "")
    if status not in _COMPLETED:
        return False, f"probe helper did not complete (status={status!r})"
    details = probe.get("details")
    if not isinstance(details, dict):
        return False, "probe helper response was not validated"
    for key in result_keys:
        if key not in details:
            return False, f"probe helper response missing {key!r}"
    return True, "probe helper completed with a validated response"


def operation_attempted(details: dict[str, Any] | None, ok_key: str) -> bool:
    """True when the helper actually tried the operation (success or OS denial)."""
    if not isinstance(details, dict):
        return False
    return bool(details.get(ok_key)) or bool(details.get("denied"))


def evaluate_filesystem_restriction(
    *,
    claimed: str,
    read_probe: dict[str, Any],
    write_probe: dict[str, Any],
    host_write_exists: bool,
    mechanism: Any = None,
    token_is_appcontainer: bool = False,
) -> tuple[str, str]:
    """Return (state, reason) from live filesystem probes.

    ``enforced`` requires launched workers under a consistent containment
    mechanism (each probe's own, not an aggregate report mechanism), a
    completed helper with a validated response, and an actual denied attempt.

    ``mechanism`` / ``token_is_appcontainer`` are ignored when probes carry
    their own mechanism fields; they remain only for older call sites.
    """
    claimed = claimed or "unsupported"
    read_details = read_probe.get("details") or {}
    write_details = write_probe.get("details") or {}
    if not isinstance(read_details, dict):
        read_details = {}
    if not isinstance(write_details, dict):
        write_details = {}

    # Prefer each probe's own mechanism; fall back only when probes omit it.
    if "mechanism" not in read_probe and mechanism is not None:
        read_probe = {**read_probe, "mechanism": mechanism}
    if "mechanism" not in write_probe and mechanism is not None:
        write_probe = {**write_probe, "mechanism": mechanism}
    if "token_is_appcontainer" not in read_probe and token_is_appcontainer:
        read_probe = {**read_probe, "token_is_appcontainer": token_is_appcontainer}
    if "token_is_appcontainer" not in write_probe and token_is_appcontainer:
        write_probe = {**write_probe, "token_is_appcontainer": token_is_appcontainer}

    fs_mech = assess_filesystem_mechanisms(read_probe, write_probe)

    read_ok = bool(read_details.get("read_ok"))
    write_ok = bool(write_details.get("write_ok")) or bool(host_write_exists)
    if read_ok or write_ok:
        if claimed == "enforced":
            return (
                "failed",
                "Child read or wrote a host sentinel while filesystem_restriction was claimed",
            )
        return (
            "unsupported" if claimed == "unsupported" else "failed",
            "Forbidden filesystem operation succeeded",
        )

    if not fs_mech["filesystem_mechanism_consistent"]:
        # Disagreeing probes (or one falling back to none) cannot yield enforced.
        state = "degraded" if claimed == "enforced" else claimed
        return state, fs_mech["filesystem_mechanism_reason"]

    if not mechanism_allows_os_enforcement(fs_mech["filesystem_claim_mechanism"]):
        return (
            "unsupported",
            fs_mech["filesystem_mechanism_reason"]
            or "No OS containment mechanism; filesystem restriction cannot be enforced",
        )

    read_complete, read_reason = probe_helper_complete(read_probe, result_keys=("read_ok", "denied"))
    write_complete, write_reason = probe_helper_complete(
        write_probe, result_keys=("write_ok", "denied")
    )
    if not read_complete:
        state = "degraded" if claimed == "enforced" else claimed
        return state, f"filesystem read probe incomplete: {read_reason}"
    if not write_complete:
        state = "degraded" if claimed == "enforced" else claimed
        return state, f"filesystem write probe incomplete: {write_reason}"
    if not operation_attempted(read_details, "read_ok"):
        state = "degraded" if claimed == "enforced" else claimed
        return state, "filesystem read operation was not attempted"
    if not operation_attempted(write_details, "write_ok") and not host_write_exists:
        # Write denial is an attempt; host_write_exists would already have failed above.
        if not write_details.get("denied"):
            state = "degraded" if claimed == "enforced" else claimed
            return state, "filesystem write operation was not attempted"

    if claimed == "enforced" and not fs_mech["filesystem_mechanism_supports_enforced"]:
        claimed = "degraded"

    if claimed in {"enforced", "degraded"}:
        return claimed, "Host sentinel read and write were denied"
    return claimed, "Host sentinel read and write were denied; no filesystem isolation was claimed"


def evaluate_process_creation(
    *,
    claimed: str,
    spawn_probe: dict[str, Any],
    mechanism: Any = None,
) -> tuple[str, str]:
    """Evaluate process_creation from the spawn probe's own mechanism.

    An aggregate report mechanism from another worker must not be used as proof.
    """
    claimed = claimed or "unsupported"
    # Spawn probe mechanism is authoritative; optional mechanism= is legacy fallback.
    mech = normalize_mechanism(
        spawn_probe.get("mechanism") if spawn_probe.get("mechanism") is not None else mechanism
    )
    details = spawn_probe.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    spawned = bool(details.get("spawned"))
    if spawned:
        if claimed == "enforced":
            return (
                "failed",
                "Child spawned a process while process_creation was claimed enforced",
            )
        if claimed == "degraded":
            return "degraded", "Operation succeeded; restriction is only partial"
        return (
            "unsupported" if claimed == "unsupported" else "failed",
            "Forbidden operation succeeded",
        )

    complete, complete_reason = probe_helper_complete(spawn_probe, result_keys=("spawned",))
    if not complete:
        state = "degraded" if claimed == "enforced" else claimed
        return state, f"process creation probe incomplete: {complete_reason}"
    if not operation_attempted(details, "spawned"):
        state = "degraded" if claimed == "enforced" else claimed
        return state, "process creation operation was not attempted"

    if not mechanism_allows_os_enforcement(mech):
        return (
            "unsupported",
            "No OS containment mechanism; process creation cannot be enforced",
        )
    if claimed in {"enforced", "degraded"}:
        return claimed, "CreateProcess/Popen failed in the child"
    return claimed, "CreateProcess/Popen failed in the child; no process-creation limit was claimed"


def evaluate_process_boundary(*, any_worker_launched: bool) -> tuple[str, str]:
    if not any_worker_launched:
        return (
            "unsupported",
            "Probe workers did not launch; process boundary was not established",
        )
    return "enforced", "Analyzer work runs in a child process"


def reject_os_enforcement_without_mechanism(
    capabilities: dict[str, Any],
    mechanism: Any,
    *,
    reasons: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Last-line invariant: mechanism none cannot yield OS containment as enforced."""
    if mechanism_allows_os_enforcement(mechanism):
        return capabilities
    for key in OS_CONTAINMENT_CAPABILITIES:
        if capabilities.get(key) == "enforced":
            capabilities[key] = "unsupported"
            if reasons is not None:
                reasons[key] = (
                    "No OS containment mechanism; cannot report enforced "
                    f"for {key}"
                )
    return capabilities
