from __future__ import annotations

import ast
import re

from ..models import Evidence, Finding
from .base import Analyzer

_SCRIPT_TYPES = {
    "script", "python", "powershell", "javascript", "typescript", "vbscript",
    "batch", "shell", "ruby", "php", "text", "json", "html", "xml", "registry-script",
}

_CALL_NOTES = {
    "eval": "Evaluates a string as code.",
    "exec": "Executes a string or code object.",
    "compile": "Compiles source that may later be executed.",
    "os.system": "Runs a shell command.",
    "os.popen": "Runs a shell command and captures output.",
    "subprocess.run": "Starts a process.",
    "subprocess.Popen": "Starts a process.",
    "subprocess.call": "Starts a process.",
    "subprocess.check_output": "Starts a process and captures output.",
    "socket.socket": "Creates a network socket.",
    "urllib.request.urlopen": "Fetches a URL.",
    "requests.get": "Fetches a URL.",
    "requests.post": "Posts data to a URL.",
    "pickle.loads": "Deserializes Python objects; can run code if the payload is hostile.",
    "marshal.loads": "Deserializes marshalled objects.",
    "ctypes.windll": "Calls native Windows DLLs.",
    "ctypes.cdll": "Calls native libraries.",
}


class ScriptAnalyzer(Analyzer):
    name = "script"
    title = "Script / source"
    detected_types = frozenset(_SCRIPT_TYPES)
    detected_families = frozenset({"script", "text"})

    def analyze(self, ctx):
        text = _decode(ctx.data)
        kind = ctx.identity.detected_type if ctx.identity else "text"
        findings: list[Finding] = []
        details: dict = {
            "language": kind,
            "line_count": text.count("\n") + (1 if text else 0),
            "char_count": len(text),
        }

        shebang = text.splitlines()[0] if text.startswith("#!") else None
        if shebang:
            findings.append(
                Finding(
                    id="script.shebang",
                    title="Shebang present",
                    summary="The first line names an interpreter.",
                    category="script",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["shebang"],
                    evidence=[Evidence(kind="string", summary="First line", analyzer=self.name, location="line 1", value=shebang[:300])],
                )
            )
            details["shebang"] = shebang

        if kind == "python" or (kind in {"text", "script"} and _looks_python(text)):
            py = _python_ast(text)
            details["python"] = py
            findings.extend(_python_findings(self, py))
        if kind == "powershell" or _looks_powershell(text):
            ps = _powershell_scan(text)
            details["powershell"] = ps
            findings.extend(_ps_findings(self, ps))
        if kind in {"javascript", "typescript"} or _looks_js(text):
            js = _js_scan(text)
            details["javascript"] = js
            findings.extend(_js_findings(self, js))
        if kind == "batch":
            details["batch_flags"] = _batch_scan(text)

        if not findings:
            findings.append(
                Finding(
                    id="script.identity",
                    title=f"Source / text ({kind})",
                    summary=f"{details['line_count']} line(s) of decoded text were analyzed.",
                    category="script",
                    severity="info",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["script"],
                    evidence=[
                        Evidence(kind="count", summary="Line count", analyzer=self.name, value=str(details["line_count"]))
                    ],
                )
            )
        return self.result(details=details, findings=findings)


def _decode(data: bytes) -> str:
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16le", "replace")
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16be", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace")


def _looks_python(text: str) -> bool:
    return bool(re.search(r"(?m)^(import |from |def |class )", text))


def _looks_powershell(text: str) -> bool:
    return bool(re.search(r"(?i)\b(Invoke-Expression|IEX|Get-Process|New-Object|powershell)\b", text))


def _looks_js(text: str) -> bool:
    return bool(re.search(r"\b(function |const |let |require\(|import )", text))


def _python_ast(text: str) -> dict:
    info = {"parsed": False, "imports": [], "calls": [], "error": None}
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        info["error"] = f"{exc.msg} (line {exc.lineno})"
        return info
    info["parsed"] = True
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                info["imports"].append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                info["imports"].append(f"{module}.{alias.name}" if module else alias.name)
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name:
                info["calls"].append({"name": name, "line": getattr(node, "lineno", None)})
    return info


def _call_name(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    return None


def _python_findings(analyzer: ScriptAnalyzer, py: dict) -> list[Finding]:
    findings = []
    if py.get("error"):
        findings.append(
            Finding(
                id="script.python-parse-error",
                title="Python AST parse failed",
                summary=py["error"] + " Regex/string analysis still ran.",
                category="script",
                severity="info",
                confidence="high",
                analyzer=analyzer.name,
                tags=["parse-error"],
                evidence=[Evidence(kind="error", summary="SyntaxError", analyzer=analyzer.name, value=py["error"])],
            )
        )
    imports = py.get("imports") or []
    if imports:
        findings.append(
            Finding(
                id="script.python-imports",
                title="Python imports",
                summary="Imported modules were extracted from the AST when parsing succeeded.",
                category="dependencies",
                severity="info",
                confidence="high" if py.get("parsed") else "low",
                analyzer=analyzer.name,
                tags=["imports"],
                evidence=[
                    Evidence(kind="field", summary="import", analyzer=analyzer.name, value=name)
                    for name in list(dict.fromkeys(imports))[:20]
                ],
            )
        )
    notable = [call for call in py.get("calls") or [] if call["name"] in _CALL_NOTES]
    if notable:
        findings.append(
            Finding(
                id="script.python-calls",
                title="Python calls that often matter during review",
                summary="These calls can run code, start processes, use the network, or deserialize data.",
                category="script",
                severity="low",
                confidence="high",
                analyzer=analyzer.name,
                tags=["capabilities"],
                evidence=[
                    Evidence(
                        kind="field",
                        summary=call["name"],
                        analyzer=analyzer.name,
                        location=f"line {call['line']}" if call.get("line") else None,
                        value=_CALL_NOTES.get(call["name"], ""),
                    )
                    for call in notable[:20]
                ],
            )
        )
    return findings


def _powershell_scan(text: str) -> dict:
    flags = {
        "iex": bool(re.search(r"(?i)\b(IEX|Invoke-Expression)\b", text)),
        "encoded": bool(re.search(r"(?i)-enc(?:odedcommand)?\b", text)),
        "download": bool(re.search(r"(?i)DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod", text)),
        "hidden": bool(re.search(r"(?i)WindowStyle\s+Hidden", text)),
        "b64": bool(re.search(r"(?i)FromBase64String", text)),
    }
    return flags


def _ps_findings(analyzer: ScriptAnalyzer, ps: dict) -> list[Finding]:
    findings = []
    labels = {
        "iex": ("PowerShell Invoke-Expression", "Can run a string as PowerShell."),
        "encoded": ("EncodedCommand", "The real script is encoded and worth decoding separately."),
        "download": ("Download helper", "May fetch remote content."),
        "hidden": ("Hidden window", "Requests a hidden PowerShell window."),
        "b64": ("FromBase64String", "May decode an embedded payload."),
    }
    hits = [key for key, value in ps.items() if value]
    if not hits:
        return findings
    findings.append(
        Finding(
            id="script.powershell-indicators",
            title="PowerShell language features of interest",
            summary="These tokens were found in the text. They are observations, not a verdict.",
            category="script",
            severity="medium" if any(k in hits for k in ("iex", "encoded", "b64")) else "low",
            confidence="high",
            analyzer=analyzer.name,
            tags=["powershell"],
            evidence=[
                Evidence(kind="field", summary=labels[key][0], analyzer=analyzer.name, value=labels[key][1])
                for key in hits
            ],
        )
    )
    return findings


def _js_scan(text: str) -> dict:
    return {
        "eval": bool(re.search(r"\beval\s*\(", text)),
        "child_process": "child_process" in text,
        "activex": bool(re.search(r"ActiveXObject", text)),
        "wscrip": bool(re.search(r"WScript\.Shell", text)),
        "require": bool(re.search(r"\brequire\s*\(", text)),
    }


def _js_findings(analyzer: ScriptAnalyzer, js: dict) -> list[Finding]:
    hits = [key for key, value in js.items() if value]
    if not hits:
        return []
    return [
        Finding(
            id="script.js-indicators",
            title="JavaScript features of interest",
            summary="eval, child_process, ActiveX, or WScript usage can run code or start programs.",
            category="script",
            severity="low",
            confidence="medium",
            analyzer=analyzer.name,
            tags=["javascript"],
            evidence=[
                Evidence(kind="field", summary="indicator", analyzer=analyzer.name, value=key)
                for key in hits
            ],
        )
    ]


def _batch_scan(text: str) -> dict:
    return {
        "powershell": bool(re.search(r"(?i)\bpowershell\b", text)),
        "certutil": bool(re.search(r"(?i)\bcertutil\b", text)),
        "bitsadmin": bool(re.search(r"(?i)\bbitsadmin\b", text)),
        "reg": bool(re.search(r"(?i)\breg\s+(add|import)\b", text)),
    }
