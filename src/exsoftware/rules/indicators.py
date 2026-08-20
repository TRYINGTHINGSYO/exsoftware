from __future__ import annotations

import re

# Observations, not verdicts. Matches should be evidence-backed.

INTERESTING_PATTERNS: list[tuple[str, str, str, str]] = [
    ("cmd-shell", "Command shell invocation", r"(?i)\bcmd(?:\.exe)?\b", "References a Windows command shell."),
    ("powershell", "PowerShell reference", r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b", "References PowerShell."),
    ("wscript", "Windows script host", r"(?i)\b(?:wscript|cscript)(?:\.exe)?\b", "References Windows Script Host."),
    ("rundll32", "rundll32 reference", r"(?i)\brundll32(?:\.exe)?\b", "References rundll32."),
    ("regsvr32", "regsvr32 reference", r"(?i)\bregsvr32(?:\.exe)?\b", "References regsvr32."),
    ("mshta", "mshta reference", r"(?i)\bmshta(?:\.exe)?\b", "References mshta."),
    ("certutil", "certutil reference", r"(?i)\bcertutil(?:\.exe)?\b", "References certutil, which can decode or download files."),
    ("bitsadmin", "bitsadmin reference", r"(?i)\bbitsadmin(?:\.exe)?\b", "References bitsadmin, which can transfer files."),
    ("schtasks", "Scheduled task reference", r"(?i)\bschtasks(?:\.exe)?\b", "References scheduled-task creation."),
    ("iex", "PowerShell IEX", r"(?i)\bIEX\b|\bInvoke-Expression\b", "PowerShell Invoke-Expression can run generated code."),
    ("downloadstring", "PowerShell download", r"(?i)DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod", "May download content from the network."),
    ("frombase64", "Base64 decode helper", r"(?i)FromBase64String|base64\.b64decode|certutil\s+-decode", "May decode base64 payloads."),
    ("eval", "Dynamic evaluation", r"(?i)\beval\s*\(|\bexec\s*\(|\bcompile\s*\(", "May evaluate code at runtime."),
    ("encoded-command", "Encoded PowerShell command", r"(?i)-enc(?:odedcommand)?\b", "EncodedCommand hides the real script from casual inspection."),
    ("hidden-window", "Hidden window flag", r"(?i)-WindowStyle\s+Hidden|/windowstyle\s+hidden", "Requests a hidden window."),
    ("registry-run", "Registry Run key", r"(?i)Software\\(?:Microsoft\\)?Windows\\CurrentVersion\\Run", "References an autostart registry location."),
    ("appdata", "AppData path", r"(?i)\\AppData\\", "References a per-user AppData path."),
    ("temp-path", "Temp path", r"(?i)\\(?:LocalSettings\\)?Temp\\|%TEMP%|%TMP%", "References a temporary directory."),
    ("http-url", "HTTP URL", r"https?://[^\s\"'<>]+", "Contains an HTTP or HTTPS URL."),
    ("ftp-url", "FTP URL", r"ftp://[^\s\"'<>]+", "Contains an FTP URL."),
    ("file-url", "file: URL", r"file://[^\s\"'<>]+", "Contains a file URL."),
    ("ip-literal", "IPv4 address", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", "Contains a dotted IPv4 address."),
    ("email", "Email address", r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", "Contains an email address."),
    ("private-key", "Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Contains a PEM private key block."),
    ("api-key-word", "Credential-like word", r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|pwd)\b", "Contains a credential-related word."),
    ("aws-akid", "AWS access key id pattern", r"\bAKIA[0-9A-Z]{16}\b", "Matches the shape of an AWS access key ID."),
    ("webhook", "Webhook URL", r"(?i)hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|outlook\.office\.com/webhook", "Contains a chat/webhook endpoint."),
]

INTERESTING_APIS: dict[str, str] = {
    "VirtualAlloc": "May allocate memory at runtime.",
    "VirtualAllocEx": "May allocate memory in another process.",
    "VirtualProtect": "May change memory permissions.",
    "VirtualProtectEx": "May change memory permissions in another process.",
    "WriteProcessMemory": "May write into another process.",
    "ReadProcessMemory": "May read another process's memory.",
    "CreateRemoteThread": "May start a thread in another process.",
    "NtUnmapViewOfSection": "Sometimes used when replacing a process image.",
    "QueueUserAPC": "May run code via an APC.",
    "SetWindowsHookExA": "May install a window or input hook.",
    "SetWindowsHookExW": "May install a window or input hook.",
    "GetAsyncKeyState": "May observe keyboard state.",
    "GetKeyState": "May observe keyboard state.",
    "BitBlt": "May copy screen or window pixels.",
    "CreateProcessA": "May start a new process.",
    "CreateProcessW": "May start a new process.",
    "WinExec": "May run another program.",
    "ShellExecuteA": "May run a program or open a document.",
    "ShellExecuteW": "May run a program or open a document.",
    "ShellExecuteExA": "May run a program or open a document.",
    "ShellExecuteExW": "May run a program or open a document.",
    "system": "May run a shell command.",
    "LoadLibraryA": "May load a DLL at runtime.",
    "LoadLibraryW": "May load a DLL at runtime.",
    "LoadLibraryExA": "May load a DLL at runtime.",
    "LoadLibraryExW": "May load a DLL at runtime.",
    "GetProcAddress": "May resolve APIs dynamically.",
    "URLDownloadToFileA": "May download a file.",
    "URLDownloadToFileW": "May download a file.",
    "InternetOpenA": "May use WinINet networking.",
    "InternetOpenW": "May use WinINet networking.",
    "InternetOpenUrlA": "May request a URL.",
    "InternetOpenUrlW": "May request a URL.",
    "HttpSendRequestA": "May send an HTTP request.",
    "HttpSendRequestW": "May send an HTTP request.",
    "WinHttpOpen": "May use WinHTTP networking.",
    "WinHttpConnect": "May connect to an HTTP server.",
    "WSAStartup": "May use Windows sockets.",
    "connect": "May connect a socket.",
    "socket": "May create a network socket.",
    "CryptEncrypt": "May encrypt data.",
    "CryptDecrypt": "May decrypt data.",
    "BCryptEncrypt": "May encrypt data.",
    "BCryptDecrypt": "May decrypt data.",
    "RegSetValueExA": "May write a registry value.",
    "RegSetValueExW": "May write a registry value.",
    "RegCreateKeyExA": "May create a registry key.",
    "RegCreateKeyExW": "May create a registry key.",
    "CreateServiceA": "May install a Windows service.",
    "CreateServiceW": "May install a Windows service.",
    "StartServiceA": "May start a Windows service.",
    "StartServiceW": "May start a Windows service.",
    "IsDebuggerPresent": "May check for a local debugger.",
    "CheckRemoteDebuggerPresent": "May check for a debugger.",
    "NtQueryInformationProcess": "May inspect process information, including debug state.",
    "CreateToolhelp32Snapshot": "May enumerate processes or modules.",
    "OpenProcess": "May open another process.",
    "TerminateProcess": "May terminate a process.",
    "Sleep": "May delay execution.",
    "GetTickCount": "May measure elapsed time.",
    "OutputDebugStringA": "May emit debug output.",
    "RaiseException": "May raise an exception, sometimes used as an anti-debug trick.",
    "CoCreateInstance": "May create a COM object.",
    "CLSIDFromString": "May resolve a COM class ID.",
}

PACKER_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2", ".upx",
    ".aspack", ".adata",
    ".themida",
    ".vmp0", ".vmp1", ".vmp2",
    ".enigma",
    "PECompact2",
    ".nsp0", ".nsp1",
    ".MPRESS1", ".MPRESS2",
}

INJECTION_SET = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "QueueUserAPC",
}

NETWORK_SET = {
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "HttpSendRequestA", "HttpSendRequestW",
    "WinHttpOpen", "WinHttpConnect",
    "WSAStartup", "socket", "connect",
}

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "us", "uk", "de", "fr", "ru",
    "cn", "jp", "br", "in", "au", "info", "biz", "xyz", "online", "site", "top", "app", "dev",
    "ai", "me", "tv", "cc", "ws", "club", "shop", "store", "tech", "cloud", "pro", "name",
    "local", "lan", "internal", "test", "example",
}

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]+")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:" + "|".join(sorted(COMMON_TLDS)) + r")\b", re.I)
WIN_PATH_RE = re.compile(r"(?i)(?:[A-Z]:\\|\\\\)[^\s\"'<>]{3,}")
POSIX_PATH_RE = re.compile(r"(?:/(?:usr|etc|var|tmp|home|opt|proc|sys|dev)/[^\s\"'<>]{1,})")
REGISTRY_RE = re.compile(r"(?i)\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"'<>]+")
ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
