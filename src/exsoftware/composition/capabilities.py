"""High-confidence static capability indicators. Not runtime behavior."""

from __future__ import annotations

from dataclasses import dataclass
from ..models import Report
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
                "artifact_id": hit.artifact_id,
                "explanation": hit.explanation,
                "refs": refs,
            }
        )
    family_order = {
        "NETWORK": 0, "PROCESS": 1, "SHELL": 2, "SCRIPT_EXECUTION": 3,
        "DYNAMIC_LOADING": 4, "REGISTRY": 5, "CRYPTOGRAPHY": 6, "FILESYSTEM": 7,
        "UI": 8, "SYSTEM_INFORMATION": 9, "ARCHIVE": 10, "DATABASE": 11,
    }
    out.sort(key=lambda item: (family_order.get(item["family"], 50), item["id"], item["artifact_id"]))
    return out


def _pe_caps(report: Report, aid: str, dlls: dict, fns: set[str]) -> list[CapHit]:
    hits: list[CapHit] = []

    def dll_hit(dll: str, rule_id: str, family: str, title: str, statement: str) -> None:
        rel = dlls.get(dll)
        if rel is None:
            return
        hits.append(
            CapHit(
                rule_id=rule_id,
                family=family,
                title=title,
                statement=statement,
                not_established=BEHAVIOR_NOT,
                certainty="derived",
                artifact_id=aid,
                explanation=f"PE import table lists {dll}.",
                refs=_rel_ref(report, aid, rel),
            )
        )

    dll_hit("winhttp.dll", "CAP.NETWORK.PE_WINHTTP.001", "NETWORK", "WinHTTP APIs referenced", "References WinHTTP networking APIs.")
    dll_hit("wininet.dll", "CAP.NETWORK.PE_WININET.001", "NETWORK", "WinINet APIs referenced", "References WinINet networking APIs.")
    dll_hit("ws2_32.dll", "CAP.NETWORK.PE_WS2.001", "NETWORK", "Windows Sockets APIs referenced", "References Windows Sockets (Winsock) APIs.")
    dll_hit("wsock32.dll", "CAP.NETWORK.PE_WSOCK.001", "NETWORK", "Windows Sockets APIs referenced", "References Windows Sockets (Winsock) APIs.")
    dll_hit("urlmon.dll", "CAP.NETWORK.PE_URLMON.001", "NETWORK", "URLMON APIs referenced", "References URLMON networking APIs.")
    dll_hit("bcrypt.dll", "CAP.CRYPTOGRAPHY.PE_BCRYPT.001", "CRYPTOGRAPHY", "BCrypt APIs referenced", "References Windows BCrypt cryptography APIs.")
    dll_hit("crypt32.dll", "CAP.CRYPTOGRAPHY.PE_CRYPT32.001", "CRYPTOGRAPHY", "Crypt32 APIs referenced", "References Windows Crypt32 APIs.")
    dll_hit("advapi32.dll", "CAP.REGISTRY.PE_ADVAPI.001", "REGISTRY", "Advapi32 APIs referenced", "References Advapi32, which includes registry and service APIs.")
    dll_hit("user32.dll", "CAP.UI.PE_USER32.001", "UI", "User32 APIs referenced", "References User32 windowing/UI APIs.")

    if fns & {"CreateProcessA", "CreateProcessW", "WinExec"}:
        hits.append(
            CapHit(
                "CAP.PROCESS.PE_CREATEPROCESS.001",
                "PROCESS",
                "Process-creation APIs referenced",
                "References APIs that can start a new process.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "PE imports include CreateProcess or WinExec.",
                graph_ref(artifact_ids=[aid]),
            )
        )
    if fns & {"ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW"}:
        hits.append(
            CapHit(
                "CAP.SHELL.PE_SHELLEXECUTE.001",
                "SHELL",
                "ShellExecute APIs referenced",
                "References ShellExecute, which can run a program or open a document.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "PE imports include ShellExecute.",
                graph_ref(artifact_ids=[aid]),
            )
        )
    if fns & {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress"}:
        hits.append(
            CapHit(
                "CAP.DYNAMIC_LOADING.PE_LOADLIBRARY.001",
                "DYNAMIC_LOADING",
                "Dynamic library loading APIs referenced",
                "References LoadLibrary/GetProcAddress, which can load code at runtime.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "PE imports include LoadLibrary and/or GetProcAddress.",
                graph_ref(artifact_ids=[aid]),
            )
        )
    if fns & {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"}:
        hits.append(
            CapHit(
                "CAP.REGISTRY.PE_REGWRITE.001",
                "REGISTRY",
                "Registry-write APIs referenced",
                "References APIs that can create or write registry values.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "PE imports include RegSetValueEx or RegCreateKeyEx.",
                graph_ref(artifact_ids=[aid]),
            )
        )
    if fns & {"CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt"}:
        hits.append(
            CapHit(
                "CAP.CRYPTOGRAPHY.PE_ENCRYPT.001",
                "CRYPTOGRAPHY",
                "Encryption APIs referenced",
                "References APIs that can encrypt or decrypt data.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "PE imports include CryptEncrypt/BCryptEncrypt (or decrypt equivalents).",
                graph_ref(artifact_ids=[aid]),
            )
        )
    if fns & {"CreateFileA", "CreateFileW", "WriteFile", "DeleteFileA", "DeleteFileW"}:
        hits.append(
            CapHit(
                "CAP.FILESYSTEM.PE_CREATEFILE.001",
                "FILESYSTEM",
                "Filesystem APIs referenced",
                "References APIs that can create, write, or delete files.",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "PE imports include CreateFile/WriteFile/DeleteFile.",
                graph_ref(artifact_ids=[aid]),
            )
        )
    if fns & {"WinHttpOpen", "WinHttpConnect", "InternetOpenA", "InternetOpenW", "WSAStartup", "URLDownloadToFileA", "URLDownloadToFileW"}:
        hits.append(
            CapHit(
                "CAP.NETWORK.PE_API.001",
                "NETWORK",
                "Networking APIs referenced",
                "References networking APIs (WinHTTP, WinINet, Winsock, or URLDownload).",
                BEHAVIOR_NOT,
                "derived",
                aid,
                "PE interesting-import set includes networking APIs.",
                graph_ref(artifact_ids=[aid]),
            )
        )
    return hits


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
