"""High-confidence static capability indicators. Not runtime behavior."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import Report
from ..rules.pe_capabilities import (
    PE_CAPABILITY_RULES,
    PECapabilityRule,
    normalize_dll_name,
    normalize_windows_api_name,
)
from .dependencies import named_value
from .model import graph_ref

CAP_VERSION = "1.0.0"
BEHAVIOR_NOT = "This does not establish that the behavior occurred at runtime."


@dataclass(frozen=True)
class CapHit:
    rule_id: str
    family: str
    title: str
    statement: str
    not_established: str
    certainty: str
    artifact_id: str
    explanation: str
    refs: dict
    evidence: tuple[str, ...] = ()
    confidence: str = "medium"


def _dlls(report: Report, artifact_id: str) -> dict[str, object]:
    found: dict[str, object] = {}
    for rel in report.relationships:
        if rel.type != "IMPORTS" or rel.source_id != artifact_id:
            continue
        name = named_value(rel.target_id).lower()
        found[name] = rel
    return found


def _python_modules(report: Report, artifact_id: str) -> dict[str, object]:
    found: dict[str, object] = {}
    for rel in report.relationships:
        if rel.type != "IMPORTS" or rel.source_id != artifact_id:
            continue
        if not rel.target_id.startswith("name:python-module:"):
            continue
        found[named_value(rel.target_id).lower()] = rel
    return found


def _pe_functions(report: Report, artifact_id: str) -> set[str]:
    names: set[str] = set()
    for run in report.analyzer_runs:
        if run.analyzer_id != "pe" or run.artifact_id != artifact_id or run.status != "completed":
            continue
        for item in run.details.get("interesting_imports") or []:
            if item.get("name"):
                names.add(item["name"])
        for item in run.details.get("imports") or []:
            for fn in item.get("functions") or []:
                if isinstance(fn, str):
                    names.add(fn)
                elif isinstance(fn, dict) and fn.get("name"):
                    names.add(fn["name"])
    return names


def _finding(report: Report, *rule_ids: str):
    return [item for item in report.findings if (item.rule_id or item.legacy_id or item.id) in rule_ids or item.legacy_id in rule_ids]


def _rel_ref(report: Report, artifact_id: str, rel, extra_findings=None) -> dict:
    evidence_ids = list(getattr(rel, "evidence_ids", None) or [])
    for finding in extra_findings or []:
        evidence_ids.extend(finding.evidence_ids or [])
        for ev in finding.evidence:
            if ev.id:
                evidence_ids.append(ev.id)
    return graph_ref(
        artifact_ids=[artifact_id, getattr(rel, "target_id", "")] if rel is not None else [artifact_id],
        relationship_ids=[getattr(rel, "id", "")] if rel is not None else [],
        evidence_ids=list(dict.fromkeys(evidence_ids)),
        finding_ids=[item.id for item in (extra_findings or []) if item.id],
        rule_ids=[],
    )


def infer_capabilities(report: Report) -> list[dict]:
    hits: list[CapHit] = []
    artifacts = [item for item in report.artifacts if item.kind == "file"]
    for artifact in artifacts:
        aid = artifact.id
        dlls = _dlls(report, aid)
        py = _python_modules(report, aid)
        fns = _pe_functions(report, aid)
        hits.extend(_pe_caps(report, aid, dlls, fns))
        hits.extend(_python_caps(report, aid, py))
        hits.extend(_script_caps(report, aid))
    out = []
    seen = set()
    for hit in hits:
        key = (hit.rule_id, hit.artifact_id)
        if key in seen:
            continue
        seen.add(key)
        refs = dict(hit.refs)
        refs["rule_ids"] = [hit.rule_id]
        out.append(
            {
                "id": hit.rule_id,
                "version": CAP_VERSION,
                "family": hit.family,
                "title": hit.title,
                "statement": hit.statement,
                "not_established": hit.not_established,
                "certainty": hit.certainty,
                "confidence": hit.confidence,
                "artifact_id": hit.artifact_id,
                "explanation": hit.explanation,
                "evidence": list(hit.evidence),
                "refs": refs,
            }
        )
    family_order = {
        "PROCESS": 0,
        "SHELL": 1,
        "PROCESS_INJECTION": 2,
        "MEMORY": 3,
        "NETWORK": 4,
        "FILESYSTEM": 5,
        "REGISTRY": 6,
        "PERSISTENCE": 7,
        "PRIVILEGE": 8,
        "SECURITY": 9,
        "CRYPTOGRAPHY": 10,
        "ANTI_ANALYSIS": 11,
        "TIMING": 12,
        "SYSTEM_DISCOVERY": 13,
        "UI": 14,
        "SENSITIVE_DATA": 15,
        "SCRIPT_EXECUTION": 16,
        "DYNAMIC_LOADING": 17,
        "ARCHIVE": 18,
        "DATABASE": 19,
    }
    out.sort(key=lambda item: (family_order.get(item["family"], 50), item["id"], item["artifact_id"]))
    return out


def _pe_caps(report: Report, aid: str, dlls: dict, fns: set[str]) -> list[CapHit]:
    hits: list[CapHit] = []
    index = _pe_index(report, aid, dlls)
    if not index["imports"] and fns:
        index = _legacy_pe_index(aid, dlls, fns)
    for rule in PE_CAPABILITY_RULES:
        if not _rule_matches(rule, index):
            continue
        refs, evidence = _rule_refs(aid, rule, index)
        hits.append(
            CapHit(
                rule.id,
                rule.family,
                rule.title,
                rule.statement,
                BEHAVIOR_NOT,
                rule.certainty,
                aid,
                rule.explanation,
                refs,
                tuple(evidence),
                rule.confidence,
            )
        )
    return hits


def _pe_index(report: Report, aid: str, dlls: dict) -> dict[str, Any]:
    imports: dict[str, list[dict[str, Any]]] = {}
    dll_refs: dict[str, list[Any]] = {}
    registry_strings: list[dict[str, Any]] = []
    seen_imports: set[tuple[str, str, str]] = set()

    for dll, rel in dlls.items():
        dll_refs.setdefault(normalize_dll_name(dll), []).append(rel)
    for obs in report.observations:
        if obs.artifact_id != aid or obs.kind != "pe.import.function":
            continue
        data = obs.data or {}
        raw_name = str(data.get("name") or "unknown")
        normalized_name = data.get("normalized_name") or normalize_windows_api_name(raw_name)
        dll = str(data.get("dll") or "unknown")
        normalized_dll = normalize_dll_name(str(data.get("normalized_dll") or dll))
        key = (normalized_dll, raw_name, str(data.get("ordinal")))
        if key in seen_imports:
            continue
        seen_imports.add(key)
        hit = {
            "name": raw_name,
            "normalized_name": normalized_name,
            "dll": dll,
            "normalized_dll": normalized_dll,
            "evidence_ids": list(obs.evidence_ids or []),
            "observation_ids": [obs.id],
            "relationship_ids": [rel.id for rel in dll_refs.get(normalized_dll, []) if getattr(rel, "id", None)],
            "label": f"{dll}!{raw_name}",
        }
        if normalized_name:
            imports.setdefault(normalized_name, []).append(hit)
        dll_refs.setdefault(normalized_dll, [])

    # Backward-compatible fallback for reports produced before pe.import.function observations.
    for run in report.analyzer_runs:
        if run.analyzer_id != "pe" or run.artifact_id != aid or run.status != "completed":
            continue
        for item in _pe_import_features(run.details or {}):
            raw_name = str(item.get("name") or "unknown")
            normalized_name = item.get("normalized_name") or normalize_windows_api_name(raw_name)
            if not normalized_name:
                continue
            dll = str(item.get("dll") or "unknown")
            normalized_dll = normalize_dll_name(str(item.get("normalized_dll") or dll))
            key = (normalized_dll, raw_name, str(item.get("ordinal")))
            if key in seen_imports:
                continue
            seen_imports.add(key)
            imports.setdefault(normalized_name, []).append(
                {
                    "name": raw_name,
                    "normalized_name": normalized_name,
                    "dll": dll,
                    "normalized_dll": normalized_dll,
                    "evidence_ids": [],
                    "observation_ids": [],
                    "relationship_ids": [rel.id for rel in dll_refs.get(normalized_dll, []) if getattr(rel, "id", None)],
                    "label": f"{dll}!{raw_name}",
                }
            )

    for finding in report.findings:
        if finding.artifact_id != aid:
            continue
        if finding.legacy_id != "strings.registry" and finding.rule_id != "STR.REGISTRY.001":
            continue
        for ev in finding.evidence:
            value = ev.value or ""
            if not value:
                continue
            registry_strings.append(
                {
                    "value": value,
                    "evidence_ids": [ev.id] if ev.id else [],
                    "finding_ids": [finding.id] if finding.id else [],
                    "label": value,
                }
            )
    return {"imports": imports, "dll_refs": dll_refs, "registry_strings": registry_strings}


def _legacy_pe_index(aid: str, dlls: dict, fns: set[str]) -> dict[str, Any]:
    imports: dict[str, list[dict[str, Any]]] = {}
    dll_refs = {normalize_dll_name(dll): [rel] for dll, rel in dlls.items()}
    for fn in fns:
        normalized = normalize_windows_api_name(fn)
        if not normalized:
            continue
        imports.setdefault(normalized, []).append(
            {
                "name": fn,
                "normalized_name": normalized,
                "dll": "unknown",
                "normalized_dll": "unknown",
                "evidence_ids": [],
                "observation_ids": [],
                "relationship_ids": [],
                "label": fn,
            }
        )
    return {"imports": imports, "dll_refs": dll_refs, "registry_strings": []}


def _pe_import_features(details: dict[str, Any]) -> list[dict[str, Any]]:
    features = details.get("imported_functions")
    if isinstance(features, list):
        return [item for item in features if isinstance(item, dict)]
    out: list[dict[str, Any]] = []
    for item in details.get("imports") or []:
        if not isinstance(item, dict):
            continue
        dll = item.get("dll") or "unknown"
        normalized_dll = item.get("normalized_dll") or normalize_dll_name(str(dll))
        for fn in item.get("functions") or []:
            raw = fn.get("name") if isinstance(fn, dict) else str(fn)
            out.append(
                {
                    "dll": dll,
                    "normalized_dll": normalized_dll,
                    "name": raw,
                    "normalized_name": (fn.get("normalized_name") if isinstance(fn, dict) else None)
                    or normalize_windows_api_name(raw),
                    "import_kind": fn.get("import_kind") if isinstance(fn, dict) else ("ordinal" if str(raw).startswith("#") else "name"),
                    "ordinal": fn.get("ordinal") if isinstance(fn, dict) else None,
                }
            )
    return out


def _rule_matches(rule: PECapabilityRule, index: dict[str, Any]) -> bool:
    imports = index["imports"]
    dll_refs = index["dll_refs"]
    allowed_import_dlls = _rule_import_dlls(rule)
    if rule.imports_all and not all(_import_hits(imports, name, allowed_import_dlls) for name in rule.imports_all):
        return False
    if rule.imports_any and not any(_import_hits(imports, name, allowed_import_dlls) for name in rule.imports_any):
        return False
    if rule.dlls_all and not all(normalize_dll_name(name) in dll_refs for name in rule.dlls_all):
        return False
    if rule.dlls_any and not any(normalize_dll_name(name) in dll_refs for name in rule.dlls_any):
        return False
    if rule.registry_path_contains:
        values = [str(item.get("value") or "").lower().replace("/", "\\") for item in index["registry_strings"]]
        if not any(all(fragment in value for fragment in rule.registry_path_contains) for value in values):
            return False
    return True


def _rule_import_dlls(rule: PECapabilityRule) -> set[str]:
    if not (rule.imports_any or rule.imports_all):
        return set()
    return {normalize_dll_name(name) for name in (*rule.dlls_all, *rule.dlls_any)}


def _import_hits(imports: dict[str, list[dict[str, Any]]], name: str, allowed_dlls: set[str]) -> list[dict[str, Any]]:
    hits = imports.get(name) or []
    if not allowed_dlls:
        return hits
    return [hit for hit in hits if normalize_dll_name(str(hit.get("normalized_dll") or hit.get("dll") or "")) in allowed_dlls]


def _rule_refs(aid: str, rule: PECapabilityRule, index: dict[str, Any]) -> tuple[dict, list[str]]:
    evidence_ids: list[str] = []
    observation_ids: list[str] = []
    relationship_ids: list[str] = []
    finding_ids: list[str] = []
    labels: list[str] = []
    allowed_import_dlls = _rule_import_dlls(rule)

    wanted = [*rule.imports_all]
    if rule.imports_any:
        wanted.extend(name for name in rule.imports_any if _import_hits(index["imports"], name, allowed_import_dlls))
    for name in dict.fromkeys(wanted):
        matches = _import_hits(index["imports"], name, allowed_import_dlls)
        for hit in matches[:4]:
            evidence_ids.extend(hit.get("evidence_ids") or [])
            observation_ids.extend(hit.get("observation_ids") or [])
            relationship_ids.extend(hit.get("relationship_ids") or [])
            labels.append(hit.get("label") or hit.get("name") or name)

    for dll in [*rule.dlls_all, *rule.dlls_any]:
        for rel in index["dll_refs"].get(normalize_dll_name(dll), []):
            if getattr(rel, "id", None):
                relationship_ids.append(rel.id)
            evidence_ids.extend(getattr(rel, "evidence_ids", None) or [])
            labels.append(normalize_dll_name(dll))

    if rule.registry_path_contains:
        for item in index["registry_strings"]:
            value = str(item.get("value") or "").lower().replace("/", "\\")
            if all(fragment in value for fragment in rule.registry_path_contains):
                evidence_ids.extend(item.get("evidence_ids") or [])
                finding_ids.extend(item.get("finding_ids") or [])
                labels.append(item.get("label") or value)

    refs = graph_ref(
        artifact_ids=[aid],
        observation_ids=list(dict.fromkeys(observation_ids)),
        evidence_ids=list(dict.fromkeys(evidence_ids)),
        relationship_ids=list(dict.fromkeys(relationship_ids)),
        finding_ids=list(dict.fromkeys(finding_ids)),
        rule_ids=[rule.id],
    )
    return refs, list(dict.fromkeys(labels))[:12]


def _python_caps(report: Report, aid: str, py: dict) -> list[CapHit]:
    hits: list[CapHit] = []

    import_findings = [
        item
        for item in report.findings
        if item.artifact_id == aid and (item.rule_id == "SCRIPT.PY.IMPORT.001" or item.legacy_id == "script.python-imports")
    ]

    def mod_hit(mod: str, rule_id: str, family: str, title: str, statement: str) -> None:
        rel = py.get(mod)
        if rel is None:
            return
        hits.append(
            CapHit(
                rule_id,
                family,
                title,
                statement,
                BEHAVIOR_NOT,
                "derived",
                aid,
                f"Python AST import of {mod}.",
                _rel_ref(report, aid, rel, extra_findings=import_findings),
            )
        )

    mod_hit("subprocess", "CAP.PROCESS.PY_SUBPROCESS.001", "PROCESS", "subprocess module imported", "Imports Python subprocess, which can start processes.")
    mod_hit("socket", "CAP.NETWORK.PY_SOCKET.001", "NETWORK", "socket module imported", "Imports Python socket, which can create network sockets.")
    mod_hit("ssl", "CAP.NETWORK.PY_SSL.001", "NETWORK", "ssl module imported", "Imports Python ssl, which is used for TLS.")
    mod_hit("ctypes", "CAP.DYNAMIC_LOADING.PY_CTYPES.001", "DYNAMIC_LOADING", "ctypes module imported", "Imports ctypes, which can load native libraries and call them.")
    if "urllib" in py or "urllib.request" in py:
        rel = py.get("urllib.request") or py.get("urllib")
        hits.append(
            CapHit(
                "CAP.NETWORK.PY_URLLIB.001",
                "NETWORK",
                "urllib imported",
                "Imports urllib, which can fetch URLs.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "Python AST import of urllib.",
                _rel_ref(report, aid, rel, extra_findings=import_findings),
            )
        )
    if "requests" in py:
        mod_hit("requests", "CAP.NETWORK.PY_REQUESTS.001", "NETWORK", "requests module imported", "Imports the requests package, which can perform HTTP requests.")
    if "sqlite3" in py:
        mod_hit("sqlite3", "CAP.DATABASE.PY_SQLITE.001", "DATABASE", "sqlite3 module imported", "Imports sqlite3, which can open SQLite databases.")
    calls = [
        item
        for item in report.findings
        if item.artifact_id == aid and (item.rule_id == "SCRIPT.PY.CALL.001" or item.legacy_id == "script.python-calls")
    ]
    call_names = {ev.value or ev.summary for finding in calls for ev in finding.evidence}
    if call_names & {"os.system", "os.popen"}:
        hits.append(
            CapHit(
                "CAP.SHELL.PY_OS_SYSTEM.001",
                "SHELL",
                "os.system/os.popen referenced",
                "Calls os.system or os.popen, which run a shell command.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "Python call evidence includes os.system or os.popen.",
                graph_ref(artifact_ids=[aid], finding_ids=[item.id for item in calls if item.id], rule_ids=["SCRIPT.PY.CALL.001"]),
            )
        )
    return hits


def _script_caps(report: Report, aid: str) -> list[CapHit]:
    hits: list[CapHit] = []
    ps = [
        item
        for item in report.findings
        if item.artifact_id == aid and (item.rule_id == "SCRIPT.PS.INDICATOR.001" or item.legacy_id == "script.powershell-indicators")
    ]
    if not ps:
        return hits
    text = " ".join(item.summary for item in ps).lower()
    values = " ".join((ev.value or ev.summary or "") for item in ps for ev in item.evidence).lower()
    blob = text + " " + values
    if "invoke-expression" in blob or "iex" in blob:
        hits.append(
            CapHit(
                "CAP.SCRIPT_EXECUTION.PS_IEX.001",
                "SCRIPT_EXECUTION",
                "PowerShell Invoke-Expression referenced",
                "The text contains PowerShell Invoke-Expression / IEX, which can run generated code.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "PowerShell indicator finding includes IEX/Invoke-Expression.",
                graph_ref(artifact_ids=[aid], finding_ids=[item.id for item in ps if item.id], rule_ids=["SCRIPT.PS.INDICATOR.001"]),
            )
        )
    if "downloadstring" in blob or "invoke-webrequest" in blob or "invoke-restmethod" in blob:
        hits.append(
            CapHit(
                "CAP.NETWORK.PS_DOWNLOAD.001",
                "NETWORK",
                "PowerShell download helper referenced",
                "The text contains PowerShell download/web request helpers.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "PowerShell indicator finding includes a download helper.",
                graph_ref(artifact_ids=[aid], finding_ids=[item.id for item in ps if item.id], rule_ids=["SCRIPT.PS.INDICATOR.001"]),
            )
        )
    return hits
