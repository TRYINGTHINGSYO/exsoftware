"""Dependency summaries from IMPORTS / DEPENDS_ON relationships."""

from __future__ import annotations

from ..models import Artifact, Relationship, Report
from .model import graph_ref

WINDOWS_SYSTEM = frozenset(
    {
        "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll",
        "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "comctl32.dll", "comdlg32.dll", "shlwapi.dll",
        "msvcrt.dll", "ucrtbase.dll", "sechost.dll", "bcrypt.dll", "bcryptprimitives.dll",
        "crypt32.dll", "cryptbase.dll", "ncrypt.dll", "ws2_32.dll", "wsock32.dll", "winhttp.dll",
        "wininet.dll", "iphlpapi.dll", "netapi32.dll", "secur32.dll", "sspicli.dll",
        "userenv.dll", "setupapi.dll", "version.dll", "winmm.dll", "imm32.dll", "uxtheme.dll",
        "dwmapi.dll", "msimg32.dll", "gdiplus.dll", "winspool.drv", "mpr.dll", "wtsapi32.dll",
        "psapi.dll", "dbghelp.dll", "imagehlp.dll", "urlmon.dll", "normaliz.dll", "dnsapi.dll",
        "dhcpcsvc.dll", "wldap32.dll", "clbcatq.dll", "msasn1.dll", "ntmarta.dll",
        "kernelbase.dll", "combase.dll", "msvcp_win.dll", "win32u.dll",
    }
)

PYTHON_STDLIB = frozenset(
    {
        "abc", "argparse", "ast", "asyncio", "base64", "builtins", "collections", "contextlib",
        "copy", "csv", "ctypes", "dataclasses", "datetime", "decimal", "enum", "functools",
        "glob", "gzip", "hashlib", "hmac", "html", "http", "importlib", "inspect", "io",
        "itertools", "json", "logging", "math", "multiprocessing", "os", "pathlib", "pickle",
        "pkgutil", "platform", "pprint", "random", "re", "secrets", "shutil", "signal",
        "socket", "sqlite3", "ssl", "string", "struct", "subprocess", "sys", "tempfile",
        "textwrap", "threading", "time", "traceback", "types", "typing", "urllib",
        "urllib.request", "urllib.parse", "uuid", "warnings", "weakref", "xml", "zipfile",
        "tarfile", "email", "marshal", "mmap", "select", "selectors", "stat", "fnmatch",
        "configparser", "ipaddress", "subprocess",
    }
)


def named_value(artifact_id: str) -> str:
    if artifact_id.startswith("name:"):
        parts = artifact_id.split(":", 2)
        if len(parts) == 3:
            return parts[2]
    return artifact_id


def named_kind(artifact_id: str) -> str:
    if artifact_id.startswith("name:"):
        parts = artifact_id.split(":", 2)
        if len(parts) >= 2:
            return parts[1]
    return "unknown"


def build_dependencies(report: Report) -> list[dict]:
    artifacts = {item.id: item for item in report.artifacts}
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for rel in report.relationships:
        if rel.type not in {"IMPORTS", "DEPENDS_ON"}:
            continue
        target = artifacts.get(rel.target_id)
        name = named_value(rel.target_id)
        kind = named_kind(rel.target_id)
        if target and target.names:
            name = target.names[0]
        key = (rel.type, name.lower())
        if key in seen:
            continue
        seen.add(key)
        group = _group(name, kind, rel)
        rows.append(
            {
                "name": name,
                "group": group,
                "kind": kind if kind != "unknown" else rel.type.lower(),
                "relationship_type": rel.type,
                "artifact_id": rel.target_id,
                "source_artifact_id": rel.source_id,
                "refs": graph_ref(
                    artifact_ids=[rel.source_id, rel.target_id],
                    relationship_ids=[rel.id],
                    evidence_ids=list(rel.evidence_ids or []),
                ),
            }
        )
    order = {"system": 0, "language_runtime": 1, "application": 2, "unresolved": 3}
    rows.sort(key=lambda item: (order.get(item["group"], 9), item["name"].lower()))
    return rows


def _group(name: str, kind: str, rel: Relationship) -> str:
    lowered = name.lower()
    if kind == "library" or lowered.endswith(".dll"):
        leaf = lowered.replace("\\", "/").split("/")[-1]
        if leaf in WINDOWS_SYSTEM:
            return "system"
        if leaf.startswith("api-ms-win-") or leaf.startswith("ext-ms-win-"):
            return "system"
    if kind == "python-module":
        top = lowered.split(".")[0]
        if lowered in PYTHON_STDLIB or top in PYTHON_STDLIB:
            return "language_runtime"
        return "application"
    if kind == "library":
        return "application"
    return "application"
