"""Original PE capability rules built from normalized static features.

These rules describe primitives a Windows binary can probably use based on its
import table and corroborating static observations. They are not malware
verdicts and do not claim runtime behavior.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PureWindowsPath


@dataclass(frozen=True)
class PECapabilityRule:
    id: str
    family: str
    title: str
    statement: str
    imports_any: tuple[str, ...] = ()
    imports_all: tuple[str, ...] = ()
    dlls_any: tuple[str, ...] = ()
    dlls_all: tuple[str, ...] = ()
    registry_path_contains: tuple[str, ...] = ()
    confidence: str = "medium"
    certainty: str = "inferred"
    explanation: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


_STDCALL_SUFFIX = re.compile(r"@\d+$")
_EXPLICIT_API_ALIASES = {
    # DNSAPI spells ANSI/Unicode variants with an underscore before the suffix.
    # Keep this as an explicit exception instead of broadly stripping underscores.
    "dnsquery_a": "DnsQuery",
    "dnsquery_w": "DnsQuery",
}


def normalize_dll_name(value: str | None) -> str:
    """Normalize a PE imported DLL name for matching while preserving evidence elsewhere."""
    text = str(value or "").strip().replace("/", "\\")
    if not text:
        return "unknown"
    leaf = PureWindowsPath(text).name or text.rsplit("\\", 1)[-1]
    lowered = leaf.lower()
    if lowered and "." not in lowered:
        lowered += ".dll"
    return lowered


def normalize_windows_api_name(value: str | None) -> str | None:
    """Return a canonical Windows API spelling, or None for ordinal/unknown imports."""
    text = str(value or "").strip()
    if not text or text == "unknown" or text.startswith("#"):
        return None
    if text.startswith("__imp_"):
        text = text.removeprefix("__imp_")
    text = _STDCALL_SUFFIX.sub("", text)

    canonical = _canonical_api_name(text)
    if canonical:
        return canonical

    if text.startswith("_"):
        canonical = _canonical_api_name(text[1:])
        if canonical:
            return canonical
    return text


def _canonical_api_name(text: str) -> str | None:
    lowered = text.lower()
    canonical = _CANONICAL_API_BY_LOWER.get(lowered)
    if canonical:
        return canonical
    alias = _EXPLICIT_API_ALIASES.get(lowered)
    if alias:
        return alias
    if len(text) > 1 and text[-1:] in {"A", "W"}:
        return _CANONICAL_API_BY_LOWER.get(text[:-1].lower())
    return None


PE_CAPABILITY_RULES: tuple[PECapabilityRule, ...] = (
    PECapabilityRule(
        "CAP.PROCESS.PE_CREATE_PROCESS.001",
        "PROCESS",
        "Process creation",
        "Contains imports that can create a new process.",
        imports_any=("CreateProcess", "WinExec"),
        confidence="high",
        explanation="Process-creation imports are direct primitives for starting another process.",
    ),
    PECapabilityRule(
        "CAP.SHELL.PE_SHELL_EXECUTE.001",
        "SHELL",
        "Shell execution",
        "Contains ShellExecute imports that can run a program or open a document via the Windows shell.",
        imports_any=("ShellExecute", "ShellExecuteEx"),
        confidence="high",
        explanation="ShellExecute delegates execution/open behavior to the Windows shell.",
    ),
    PECapabilityRule(
        "CAP.SHELL.PE_C_RUNTIME_SYSTEM.001",
        "SHELL",
        "C runtime command execution",
        "Contains C runtime imports that can pass a command to the shell.",
        imports_any=("system", "_wsystem", "popen", "_popen", "_wpopen"),
        confidence="high",
        explanation="C runtime system/popen-style APIs execute shell commands.",
    ),
    PECapabilityRule(
        "CAP.DYNAMIC_LOADING.PE_DYNAMIC_API.001",
        "DYNAMIC_LOADING",
        "Dynamic library/API resolution",
        "Contains imports that can load libraries or resolve APIs at runtime.",
        imports_any=("LoadLibrary", "LoadLibraryEx", "GetProcAddress", "LdrLoadDll"),
        confidence="high",
        explanation="Dynamic loading can hide later code/API use from the static import table.",
    ),
    PECapabilityRule(
        "CAP.PROCESS.PE_OPEN_PROCESS.001",
        "PROCESS",
        "Open another process",
        "Contains imports that can obtain a handle to another process.",
        imports_any=("OpenProcess",),
        confidence="high",
        explanation="OpenProcess is the standard Win32 primitive for opening another process by PID.",
    ),
    PECapabilityRule(
        "CAP.MEMORY.PE_REMOTE_ALLOC.001",
        "MEMORY",
        "Allocate memory in another process",
        "Contains imports that can allocate memory in a remote process.",
        imports_any=("VirtualAllocEx", "NtAllocateVirtualMemory"),
        confidence="high",
        explanation="VirtualAllocEx/NtAllocateVirtualMemory can reserve or commit memory in a process handle.",
    ),
    PECapabilityRule(
        "CAP.MEMORY.PE_REMOTE_WRITE.001",
        "MEMORY",
        "Write another process's memory",
        "Contains imports that can write bytes into another process.",
        imports_any=("WriteProcessMemory", "NtWriteVirtualMemory"),
        confidence="high",
        explanation="WriteProcessMemory/NtWriteVirtualMemory are direct remote-memory write primitives.",
    ),
    PECapabilityRule(
        "CAP.MEMORY.PE_REMOTE_READ.001",
        "MEMORY",
        "Read another process's memory",
        "Contains imports that can read bytes from another process.",
        imports_any=("ReadProcessMemory", "NtReadVirtualMemory"),
        confidence="high",
        explanation="ReadProcessMemory/NtReadVirtualMemory are direct remote-memory read primitives.",
    ),
    PECapabilityRule(
        "CAP.MEMORY.PE_EXECUTABLE_PERMISSIONS.001",
        "MEMORY",
        "Change executable memory permissions",
        "Contains imports that can change page protections.",
        imports_any=("VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory"),
        confidence="medium",
        explanation="Page-protection APIs can make memory writable/executable, but legitimate programs use them too.",
    ),
    PECapabilityRule(
        "CAP.INJECTION.PE_REMOTE_THREAD.001",
        "PROCESS_INJECTION",
        "Create a thread in another process",
        "Contains imports that can create remote threads.",
        imports_any=("CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread"),
        confidence="high",
        explanation="Remote-thread creation is a direct primitive for executing code in another process.",
    ),
    PECapabilityRule(
        "CAP.INJECTION.PE_REMOTE_MEMORY_PRIMITIVES.001",
        "PROCESS_INJECTION",
        "Remote-process memory modification primitives",
        "Contains the common pair of imports for allocating and writing memory in another process.",
        imports_all=("VirtualAllocEx", "WriteProcessMemory"),
        confidence="high",
        explanation="The combination supports staging bytes into a remote process.",
    ),
    PECapabilityRule(
        "CAP.INJECTION.PE_CLASSIC_REMOTE_THREAD.001",
        "PROCESS_INJECTION",
        "Classic remote-thread injection primitives",
        "Contains the classic OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread import set.",
        imports_all=("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"),
        confidence="high",
        explanation="Together these imports materially strengthen the remote-process injection interpretation.",
    ),
    PECapabilityRule(
        "CAP.NETWORK.PE_WINSOCK.001",
        "NETWORK",
        "Socket networking",
        "Contains Winsock imports that can create TCP/UDP network sockets.",
        imports_any=("WSAStartup", "socket", "connect", "send", "recv", "sendto", "recvfrom", "bind", "listen", "accept"),
        dlls_any=("ws2_32.dll", "wsock32.dll"),
        confidence="high",
        explanation="Winsock imports from Winsock DLLs are direct socket networking primitives.",
    ),
    PECapabilityRule(
        "CAP.NETWORK.PE_WINHTTP_CLIENT.001",
        "NETWORK",
        "WinHTTP client behavior",
        "Contains WinHTTP imports for opening and sending HTTP requests.",
        imports_all=("WinHttpOpen", "WinHttpSendRequest"),
        confidence="high",
        explanation="WinHttpOpen with WinHttpSendRequest is strong evidence of HTTP client capability.",
    ),
    PECapabilityRule(
        "CAP.NETWORK.PE_WININET_HTTP.001",
        "NETWORK",
        "WinINet HTTP behavior",
        "Contains WinINet imports that can open URLs or send HTTP requests.",
        imports_any=("InternetOpen", "InternetOpenUrl", "HttpOpenRequest", "HttpSendRequest", "InternetReadFile"),
        confidence="high",
        explanation="WinINet URL/HTTP imports are direct HTTP client primitives.",
    ),
    PECapabilityRule(
        "CAP.NETWORK.PE_URLMON_DOWNLOAD.001",
        "NETWORK",
        "URL download helper",
        "Contains URLMON imports that can download a URL to a local file.",
        imports_any=("URLDownloadToFile", "URLDownloadToCacheFile", "URLOpenBlockingStream"),
        confidence="high",
        explanation="URLMON helper APIs wrap URL retrieval behavior.",
    ),
    PECapabilityRule(
        "CAP.NETWORK.PE_DNS_LOOKUP.001",
        "NETWORK",
        "DNS resolution",
        "Contains imports that can resolve host names.",
        imports_any=("getaddrinfo", "DnsQuery"),
        confidence="high",
        explanation="DNS/getaddrinfo imports resolve host names before network communication.",
    ),
    PECapabilityRule(
        "CAP.FILESYSTEM.PE_FILE_WRITE.001",
        "FILESYSTEM",
        "File creation or modification",
        "Contains imports that can create, modify, copy, move, or replace filesystem entries.",
        imports_any=("CreateFile", "WriteFile", "CopyFile", "MoveFile", "ReplaceFile"),
        confidence="high",
        explanation="These Win32 file APIs can create, write, copy, move, or replace files; arguments determine the exact operation.",
    ),
    PECapabilityRule(
        "CAP.FILESYSTEM.PE_FILE_DELETE.001",
        "FILESYSTEM",
        "Delete files or directories",
        "Contains imports that can delete filesystem entries.",
        imports_any=("DeleteFile", "RemoveDirectory"),
        confidence="high",
        explanation="DeleteFile/RemoveDirectory are direct deletion primitives.",
    ),
    PECapabilityRule(
        "CAP.FILESYSTEM.PE_ENUMERATE.001",
        "FILESYSTEM",
        "Enumerate files or directories",
        "Contains imports that can enumerate filesystem entries.",
        imports_any=("FindFirstFile", "FindNextFile"),
        confidence="high",
        explanation="FindFirstFile/FindNextFile are directory enumeration primitives.",
    ),
    PECapabilityRule(
        "CAP.REGISTRY.PE_READ.001",
        "REGISTRY",
        "Read registry keys or values",
        "Contains imports that can open or query the Windows registry.",
        imports_any=("RegOpenKeyEx", "RegQueryValueEx", "RegEnumKeyEx", "RegEnumValue"),
        confidence="high",
        explanation="Registry open/query/enumeration APIs are direct registry read primitives.",
    ),
    PECapabilityRule(
        "CAP.REGISTRY.PE_MODIFY.001",
        "REGISTRY",
        "Modify registry keys or values",
        "Contains imports that can create, set, or delete registry keys or values.",
        imports_any=("RegCreateKeyEx", "RegSetValueEx", "RegDeleteKey", "RegDeleteValue"),
        confidence="high",
        explanation="Registry create/set/delete APIs are direct modification primitives.",
    ),
    PECapabilityRule(
        "CAP.PERSISTENCE.PE_AUTORUN_REGISTRY.001",
        "PERSISTENCE",
        "May support autorun registry modification",
        "Combines registry-modification imports with an autorun registry path string.",
        imports_any=("RegCreateKeyEx", "RegSetValueEx"),
        registry_path_contains=("windows\\currentversion\\run",),
        confidence="medium",
        explanation="The API/path combination supports an autorun interpretation, but still does not prove persistence was installed.",
    ),
    PECapabilityRule(
        "CAP.PERSISTENCE.PE_SERVICE_CREATE.001",
        "PERSISTENCE",
        "Create or modify Windows services",
        "Contains service-control-manager imports for creating services.",
        imports_all=("OpenSCManager", "CreateService"),
        confidence="high",
        explanation="OpenSCManager plus CreateService is strong evidence of service-management capability.",
    ),
    PECapabilityRule(
        "CAP.PERSISTENCE.PE_SERVICE_CONTROL.001",
        "PERSISTENCE",
        "Control Windows services",
        "Contains imports that can open, start, or control Windows services.",
        imports_any=("OpenService", "StartService", "ControlService", "ChangeServiceConfig"),
        confidence="high",
        explanation="Service-control APIs can manage installed services.",
    ),
    PECapabilityRule(
        "CAP.PRIVILEGE.PE_TOKEN_ACCESS.001",
        "PRIVILEGE",
        "Token access",
        "Contains imports that can open or inspect access tokens.",
        imports_any=("OpenProcessToken", "OpenThreadToken", "GetTokenInformation"),
        confidence="high",
        explanation="Token APIs are security-context inspection/manipulation primitives.",
    ),
    PECapabilityRule(
        "CAP.PRIVILEGE.PE_ADJUST_PRIVILEGES.001",
        "PRIVILEGE",
        "Privilege adjustment",
        "Contains imports that can look up or adjust token privileges.",
        imports_any=("LookupPrivilegeValue", "AdjustTokenPrivileges"),
        confidence="high",
        explanation="AdjustTokenPrivileges can enable or disable privileges in a token.",
    ),
    PECapabilityRule(
        "CAP.SECURITY.PE_IMPERSONATION.001",
        "PRIVILEGE",
        "Impersonation",
        "Contains imports that can impersonate another security context.",
        imports_any=("ImpersonateLoggedOnUser", "ImpersonateNamedPipeClient", "RevertToSelf"),
        confidence="high",
        explanation="Impersonation APIs change the effective security context of a thread.",
    ),
    PECapabilityRule(
        "CAP.CRYPTOGRAPHY.PE_CNG.001",
        "CRYPTOGRAPHY",
        "Windows CNG cryptography",
        "Contains BCrypt/NCrypt imports for cryptographic operations.",
        imports_any=("BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom", "BCryptOpenAlgorithmProvider", "NCryptEncrypt", "NCryptDecrypt"),
        confidence="high",
        explanation="BCrypt/NCrypt APIs are Windows cryptography primitives.",
    ),
    PECapabilityRule(
        "CAP.CRYPTOGRAPHY.PE_CRYPTOAPI.001",
        "CRYPTOGRAPHY",
        "Windows CryptoAPI cryptography",
        "Contains CryptoAPI imports for encryption or cryptographic contexts.",
        imports_any=("CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenRandom"),
        confidence="high",
        explanation="CryptoAPI imports expose classic Windows cryptography primitives.",
    ),
    PECapabilityRule(
        "CAP.CRYPTOGRAPHY.PE_HASHING.001",
        "CRYPTOGRAPHY",
        "Hashing primitives",
        "Contains imports that can hash data.",
        imports_any=("CryptHashData", "BCryptHashData", "CryptCreateHash"),
        confidence="high",
        explanation="Hashing imports identify cryptographic digest primitives.",
    ),
    PECapabilityRule(
        "CAP.SENSITIVE_DATA.PE_DPAPI.001",
        "SENSITIVE_DATA",
        "Windows DPAPI data protection",
        "Contains DPAPI imports that can protect or unprotect local user/machine secrets.",
        imports_any=("CryptProtectData", "CryptUnprotectData"),
        confidence="medium",
        explanation="DPAPI APIs can handle protected local data; this does not identify credential theft.",
    ),
    PECapabilityRule(
        "CAP.ANTI_ANALYSIS.PE_DEBUGGER_CHECK.001",
        "ANTI_ANALYSIS",
        "Debugger detection",
        "Contains imports that can query debugger presence.",
        imports_any=("IsDebuggerPresent", "CheckRemoteDebuggerPresent"),
        confidence="high",
        explanation="Debugger-query APIs are direct debugger-presence primitives.",
    ),
    PECapabilityRule(
        "CAP.PROCESS.PE_NT_PROCESS_QUERY.001",
        "PROCESS",
        "Process information query",
        "Contains imports that can query process information through native Windows APIs.",
        imports_any=("NtQueryInformationProcess",),
        confidence="medium",
        explanation="NtQueryInformationProcess is argument-dependent; import evidence alone does not identify the queried information class.",
    ),
    PECapabilityRule(
        "CAP.TIMING.PE_TIMING_DELAY.001",
        "TIMING",
        "Timing and delay primitives",
        "Contains imports for sleeping or measuring elapsed time.",
        imports_any=("Sleep", "GetTickCount", "QueryPerformanceCounter", "timeGetTime"),
        confidence="medium",
        explanation="Timing APIs are common in normal programs; import evidence alone is not enough to infer anti-analysis intent.",
    ),
    PECapabilityRule(
        "CAP.DISCOVERY.PE_TOOLHELP_PROCESS_ENUM.001",
        "SYSTEM_DISCOVERY",
        "Toolhelp process enumeration",
        "Contains Toolhelp imports that can enumerate processes.",
        imports_all=("CreateToolhelp32Snapshot",),
        imports_any=("Process32First", "Process32Next"),
        confidence="high",
        explanation="CreateToolhelp32Snapshot plus Process32First/Process32Next supports a process-enumeration interpretation without assuming runtime snapshot flags.",
    ),
    PECapabilityRule(
        "CAP.DISCOVERY.PE_PSAPI_PROCESS_ENUM.001",
        "SYSTEM_DISCOVERY",
        "PSAPI process or module enumeration",
        "Contains PSAPI imports that can enumerate processes or loaded modules.",
        imports_any=("EnumProcesses", "EnumProcessModules"),
        confidence="high",
        explanation="PSAPI enumeration APIs expose process and module inventory.",
    ),
    PECapabilityRule(
        "CAP.DISCOVERY.PE_SYSTEM_INFO.001",
        "SYSTEM_DISCOVERY",
        "System, user, or computer discovery",
        "Contains imports that can query system, user, or computer identity.",
        imports_any=("GetComputerName", "GetUserName", "GetNativeSystemInfo", "GetSystemInfo", "GetVersionEx"),
        confidence="medium",
        explanation="These APIs collect environment and host metadata.",
    ),
    PECapabilityRule(
        "CAP.DISCOVERY.PE_ENVIRONMENT.001",
        "SYSTEM_DISCOVERY",
        "Environment variable inspection",
        "Contains imports that can read or expand environment variables.",
        imports_any=("GetEnvironmentVariable", "ExpandEnvironmentStrings"),
        confidence="medium",
        explanation="Environment-variable APIs reveal process/user configuration.",
    ),
    PECapabilityRule(
        "CAP.UI.PE_INPUT_HOOKS.001",
        "UI",
        "Windows input hooks",
        "Contains imports that can install Windows hook procedures.",
        imports_any=("SetWindowsHookEx",),
        confidence="high",
        explanation="SetWindowsHookEx is a direct primitive for installing Windows hook procedures.",
    ),
    PECapabilityRule(
        "CAP.UI.PE_KEYBOARD_STATE.001",
        "UI",
        "Keyboard state observation",
        "Contains imports that can inspect keyboard state.",
        imports_any=("GetAsyncKeyState", "GetKeyState"),
        confidence="medium",
        explanation="Keyboard state APIs can observe key state but do not by themselves establish input-hook installation.",
    ),
    PECapabilityRule(
        "CAP.UI.PE_CLIPBOARD.001",
        "UI",
        "Clipboard access",
        "Contains imports that can read or write clipboard data.",
        imports_any=("OpenClipboard", "GetClipboardData", "SetClipboardData"),
        confidence="high",
        explanation="Clipboard APIs are direct user-data interaction primitives.",
    ),
)


_CANONICAL_API_NAMES = tuple(
    dict.fromkeys(
        name
        for rule in PE_CAPABILITY_RULES
        for group in (rule.imports_any, rule.imports_all)
        for name in group
    )
)


def _build_canonical_api_map(names: tuple[str, ...]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in names:
        lowered = name.lower()
        existing = out.get(lowered)
        if existing is not None and existing != name:
            raise ValueError(f"Conflicting PE API canonical names for {lowered!r}: {existing!r}, {name!r}")
        out[lowered] = name
    return out


_CANONICAL_API_BY_LOWER = _build_canonical_api_map(_CANONICAL_API_NAMES)
