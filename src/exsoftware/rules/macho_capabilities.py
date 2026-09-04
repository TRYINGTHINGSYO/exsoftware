"""Original Mach-O capability rules built from normalized static features.

These rules describe primitives a macOS/iOS binary can probably use based on
its undefined symbols and linked dylibs. They are not malware verdicts and
do not claim runtime behavior.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class MachOCapabilityRule:
    id: str
    family: str
    title: str
    statement: str
    symbols_any: tuple[str, ...] = ()
    symbols_all: tuple[str, ...] = ()
    libraries_any: tuple[str, ...] = ()
    libraries_all: tuple[str, ...] = ()
    confidence: str = "medium"
    certainty: str = "inferred"
    explanation: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


_LIB_VERSION = re.compile(r"^(lib.+?)(?:\.\d+)+(\.dylib)$", re.I)
_OBJC_CLASS = re.compile(r"^_?_OBJC_(?:META)?CLASS_\$_(.+)$")


def normalize_macho_library_name(value: str | None) -> str:
    """Normalize a Mach-O dylib / framework path for matching."""
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return "unknown"
    parts = [part for part in text.split("/") if part]
    for part in parts:
        if part.lower().endswith(".framework"):
            return part.lower()
    leaf = parts[-1] if parts else text
    lowered = leaf.lower()
    match = _LIB_VERSION.match(lowered)
    if match:
        return f"{match.group(1)}{match.group(2)}".lower()
    return lowered


def normalize_macho_symbol_name(value: str | None) -> str | None:
    """Return a canonical Mach-O import symbol, or None for empty/unknown names."""
    text = str(value or "").strip()
    if not text or text == "unknown":
        return None
    if text.startswith(".objc") or text.startswith("l_OBJC"):
        return None
    objc = _OBJC_CLASS.match(text)
    if objc:
        return objc.group(1) or None
    if text.startswith("_"):
        text = text[1:]
    return text or None


MACHO_CAPABILITY_RULES: tuple[MachOCapabilityRule, ...] = (
    MachOCapabilityRule(
        "CAP.PROCESS.MACHO_FORK.001",
        "PROCESS",
        "Process creation",
        "Contains imports that can create a new process.",
        symbols_any=("fork", "vfork", "posix_spawn", "posix_spawnp", "NSTask"),
        confidence="high",
        explanation="fork/posix_spawn/NSTask are direct primitives for starting another process.",
    ),
    MachOCapabilityRule(
        "CAP.PROCESS.MACHO_EXEC.001",
        "PROCESS",
        "Execute another program",
        "Contains imports that can replace the current process image.",
        symbols_any=("execve", "execv", "execvp", "execl", "execlp", "execle", "fexecve"),
        confidence="high",
        explanation="exec* imports overlay a new program image in the current process.",
    ),
    MachOCapabilityRule(
        "CAP.SHELL.MACHO_SYSTEM.001",
        "SHELL",
        "C library command execution",
        "Contains C library imports that can pass a command to the shell.",
        symbols_any=("system", "popen"),
        confidence="high",
        explanation="system/popen execute a shell command string.",
    ),
    MachOCapabilityRule(
        "CAP.DYNAMIC_LOADING.MACHO_DLOPEN.001",
        "DYNAMIC_LOADING",
        "Dynamic library loading",
        "Contains imports that can load libraries or resolve symbols at runtime.",
        symbols_any=("dlopen", "dlsym", "dlmopen", "NSLookupSymbolInImage", "NSLinkModule"),
        confidence="high",
        explanation="dlopen/dlsym/NSLookupSymbolInImage can hide later code use from the static dylib list.",
    ),
    MachOCapabilityRule(
        "CAP.NETWORK.MACHO_SOCKET.001",
        "NETWORK",
        "Socket networking",
        "Contains imports that can create TCP/UDP network sockets.",
        symbols_any=("socket", "connect", "send", "recv", "sendto", "recvfrom", "bind", "listen", "accept"),
        confidence="high",
        explanation="BSD socket imports are direct network communication primitives.",
    ),
    MachOCapabilityRule(
        "CAP.NETWORK.MACHO_DNS.001",
        "NETWORK",
        "DNS resolution",
        "Contains imports that can resolve host names.",
        symbols_any=("getaddrinfo", "gethostbyname", "getnameinfo"),
        confidence="high",
        explanation="Name-resolution imports resolve hosts before network communication.",
    ),
    MachOCapabilityRule(
        "CAP.NETWORK.MACHO_NSURLSESSION.001",
        "NETWORK",
        "NSURLSession / CFNetwork client",
        "Contains NSURLSession or CFNetwork imports that can perform HTTP or other transfers.",
        symbols_any=(
            "NSURLSession",
            "CFHTTPMessageCreateRequest",
            "CFReadStreamCreateForHTTPRequest",
            "nw_connection_create",
        ),
        confidence="high",
        explanation="NSURLSession/CFNetwork/Network.framework imports are direct client networking primitives.",
    ),
    MachOCapabilityRule(
        "CAP.FILESYSTEM.MACHO_OPEN_WRITE.001",
        "FILESYSTEM",
        "File creation or modification",
        "Contains imports that can create, open, rename, or remove filesystem entries.",
        symbols_any=("open", "openat", "creat", "unlink", "unlinkat", "rename", "renameat", "mkdir", "mkdirat"),
        confidence="high",
        explanation="These POSIX file APIs can create, open, rename, or delete files; arguments determine the exact operation.",
    ),
    MachOCapabilityRule(
        "CAP.MEMORY.MACHO_MMAP.001",
        "MEMORY",
        "Map or protect memory",
        "Contains imports that can map files/anonymous pages or change memory protections.",
        symbols_any=("mmap", "mprotect", "munmap"),
        confidence="medium",
        explanation="mmap/mprotect can make memory writable/executable, but legitimate loaders use them too.",
    ),
)
